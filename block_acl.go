package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var nodeJsPath string
var nodeJsSearch = []string{"($EXECUTABLE_PATH/node)", "/usr/bin/nodejs", "/usr/bin/node"}

var NamedAclFns = map[string](func(url.Values) (string, error)){
	"always-allow":      makeAclAlwaysAllow,
	"always-deny":       makeAclAlwaysDeny,
	"require-secret":    makeAclRequireSecret,
	"require-signature": makeAclRequireSignature,
}

func makeAclAlwaysAllow(params url.Values) (string, error) {
	return "allow();", nil
}

func makeAclAlwaysDeny(params url.Values) (string, error) {
	return "deny();", nil
}

func makeAclRequireSecret(params url.Values) (string, error) {
	if vs, ok := params["secret"]; !ok || len(vs) != 1 {
		return "", fmt.Errorf("parameter secret must be given exactly once")
	}
	secret := params.Get("secret")
	acl := `allowIff(httpHeader('Acl-Secret') === '` + secret + `');`
	return acl, nil
}

var keyUrlParamRe = regexp.MustCompile(`^key\[(.+)\]$`)

func makeAclRequireSignature(params url.Values) (string, error) {
	keys := map[string]string{}
	for k, vs := range params {
		match := keyUrlParamRe.FindStringSubmatch(k)
		if match != nil {
			keyId := match[1]
			if _, exists := keys[keyId]; exists || len(vs) != 1 {
				return "", fmt.Errorf("key '%s' given multiple times", keyId)
			} else {
				keyData := vs[0]
				_, err := DeserializePublicKey(keyData)
				if err != nil {
					return "", fmt.Errorf("key[%s] is malformed", keyId)
				}
				keys[keyId] = keyData
			}
		}
	}

	if len(keys) == 0 {
		return "", fmt.Errorf("at least one key[$name] parameter must be given")
	}

	keysJson, err := json.Marshal(keys)
	if err != nil {
		panic(err)
	}

	return `
		var keyId = httpHeader('Acl-Key-Id');
		denyIf(keyId === undefined);
		var pubKey = ` + string(keysJson) + `[keyId];
		denyIf(pubKey === undefined);
		var signature = httpHeader('Acl-Signature');
		denyIf(signature === undefined);
		verifySignature(
			pubKey,
			signature,
			{},
			'application/vnd.faust.faustctf-2018-restchain-access-signature',
			null,
			allow,
			deny
		);
	`, nil
}

func getCipher() cipher.Block {
	c, err := aes.NewCipher(GenesisBlockId[:16])
	logFatalOnErr("SerializeACL", err)
	return c
}

var aclSerializationHmacKey []byte
var aclSerializationReplacementes = [][2]string{
	{"\t", " "},
	{"\r", " "},
	{"\n", " "},
	{"  ", " "},
	{", ", ","},
	{" ,", ","},
	{"; ", ";"},
	{" ;", ";"},
	{"( ", "("},
	{" (", "("},
	{") ", ")"},
	{" )", ")"},
	{"+ ", "+"},
	{" +", "+"},
	{"= ", "="},
	{" =", "="},
}

type MACedACL struct {
	C string
	T string
}

func SerializeACL(acl string) string {
	oldLen := len(acl)
	for {
		acl = strings.TrimLeft(acl, " ")
		acl = strings.TrimRight(acl, " ")
		for _, r := range aclSerializationReplacementes {
			acl = strings.Replace(acl, r[0], r[1], -1)
		}
		if len(acl) < oldLen {
			oldLen = len(acl)
		} else {
			break
		}
	}
	mac := hmac.New(sha256.New, aclSerializationHmacKey)
	mac.Write([]byte(acl))
	macedAcl := MACedACL{C: acl, T: base64.StdEncoding.EncodeToString(mac.Sum(nil))}
	serializedAcl, err := json.Marshal(macedAcl)
	if err != nil {
		panic(err)
	}
	return string(serializedAcl)
}

func DeserializeACL(serialzedAcl string) (string, error) {
	acl := MACedACL{}
	err := json.Unmarshal([]byte(serialzedAcl), &acl)
	if err != nil {
		return "", fmt.Errorf("invalid ACL")
	}
	serializedTag, err := base64.StdEncoding.DecodeString(acl.T)
	if err != nil {
		return "", fmt.Errorf("invalid ACL")
	}
	mac := hmac.New(sha256.New, aclSerializationHmacKey)
	mac.Write([]byte(acl.C))
	if !hmac.Equal(mac.Sum(nil), serializedTag) {
		return "", fmt.Errorf("invalid ACL")
	}
	return acl.C, nil
}

var aclStdLib = bindata["restchain-acl-stdlib.js"]

func (b *Block) EvaluateACL(r *http.Request) (bool, error) {
	serializedAcl := b.Data.Header.Get("Acl")
	if serializedAcl == "" {
		// no acl set, assume block is public
		return true, nil
	}

	acl, err := DeserializeACL(serializedAcl)
	if err != nil {
		return false, err
	}

	// --nproc is per uid, so set it a bit lower than in the systemd unit, so
	// that the main process can still fork restchain-persist
	cmd := exec.Command("prlimit", "--cpu=2", "--nofile=32", "--nproc=1024", nodeJsPath)
	cmd.Env = make([]string, 0)
	for header, _ := range r.Header {
		envHeader := "HTTP_" + makeEnvHeader(header)
		cmd.Env = append(cmd.Env, envHeader+"="+r.Header.Get(header))
	}
	for header, _ := range b.Data.Header {
		envHeader := makeEnvHeader(header)
		cmd.Env = append(cmd.Env, envHeader+"="+b.Data.Header.Get(header))
	}
	cmd.Env = append(cmd.Env, "__RESTCHAIN_LISTEN="+flagListen)
	cmd.Stdin = io.MultiReader(bytes.NewReader(aclStdLib), bytes.NewReader([]byte(acl)))
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return false, err
	}
	done := make(chan error)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(10 * time.Second)
	select {
	case err := <-done:
		if !timer.Stop() {
			<-timer.C
		}
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.ExitStatus() == 13 {
					return false, nil
				} else {
					return false, err
				}
			} else {
				return false, err
			}
		} else {
			return true, nil
		}
	case <-timer.C:
		cmd.Process.Kill()
		return false, fmt.Errorf("evaluating ACL timed out, killed process")
	}
}

var headerEnvRe = regexp.MustCompile(`[^A-Z0-9]`)

func makeEnvHeader(h string) string {
	return headerEnvRe.ReplaceAllString(strings.ToUpper(h), "_")
}

func initBlockAcl() {
	if flagNode == "" {
		execFile, err := os.Executable()
		logFatalOnErr("getting executable path", err)
		nodeJsSearch[0] = filepath.Join(filepath.Dir(execFile), "node")
		for _, path := range nodeJsSearch {
			stat, err := os.Stat(path)
			if err == nil && stat.Mode()&0111 != 0 {
				nodeJsPath = path
				break
			}
		}
		if nodeJsPath == "" {
			log.Fatalf("could not find node.js binary (searched at: %v)", nodeJsSearch)
		}
	} else {
		nodeJsPath = flagNode
	}

	hmacFile := StoragePath("acl-hmac.key")
	var err error
	aclSerializationHmacKey, err = ioutil.ReadFile(hmacFile)
	if err != nil && os.IsNotExist(err) {
		aclSerializationHmacKey = make([]byte, 32)
		_, err = rand.Read(aclSerializationHmacKey)
		logFatalOnErr("cannot generate ACL serialization HMAC key", err)
		err = AtomicWriteFile(hmacFile, aclSerializationHmacKey)
		logFatalOnErr("cannot write ACL serialization HMAC key", err)
	} else {
		logFatalOnErr("cannot read ACL serialization HMAC key", err)
	}
}
