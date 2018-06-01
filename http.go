package main

import (
	"crypto/rand"
	"ed25519"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
)

func registerHttpHandlers() {
	http.HandleFunc("/", httpRoot)
	http.HandleFunc("/api/acl", httpApiAclList)
	http.HandleFunc("/api/acl/", httpApiAcl)
	http.HandleFunc("/api/block", httpApiBlockNoId)
	http.HandleFunc("/api/block/", httpApiBlock)
	http.HandleFunc("/api/crypto/privatekey", httpApiCryptoPrivatekey)
	http.HandleFunc("/api/crypto/sign", httpApiCryptoSign)
	http.HandleFunc("/api/crypto/verify", httpApiCryptoVerify)
	http.HandleFunc("/api/crypto/blockid", httpApiCryptoBlockId)
}

var indexHtmlTemplate = template.Must(template.New("index.html").Parse(string(bindata["public/index.html"])))

func httpRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html")
		data := struct {
			ApiUrl string
		}{
			"http:/" + "/" + r.Host + "/api",
		}
		err := indexHtmlTemplate.Execute(w, data)
		if err != nil {
			log.Printf("%s: failed to render template: %s", r.URL.Path, err)
			http.Error(w, "error", http.StatusInternalServerError)
		}
	} else if r.URL.Path == "/index.html" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.FileServer(http.Dir(StoragePath("public"))).ServeHTTP(w, r)
	}
}

func httpApiAclList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "allowed methods: GET", http.StatusMethodNotAllowed)
	}

	for name, _ := range NamedAclFns {
		fmt.Fprintln(w, name)
	}
}

var httpApiAclUrlRe = regexp.MustCompile("^/api/acl/(?P<name>[a-z-]*)$")

func httpApiAcl(w http.ResponseWriter, r *http.Request) {
	match := httpApiAclUrlRe.FindStringSubmatch(r.URL.Path)
	if match == nil {
		http.NotFound(w, r)
		return
	}
	aclName := match[1]
	if aclName == "" {
		httpApiAclList(w, r)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "allowed methods: GET", http.StatusMethodNotAllowed)
	}

	aclFn, ok := NamedAclFns[aclName]
	if !ok {
		http.NotFound(w, r)
		return
	}
	aclCode, err := aclFn(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	fmt.Fprintln(w, SerializeACL(aclCode))
}

var httpApiBlockUrlRe = regexp.MustCompile("^/api/block/(?P<blockId>[0-9a-z]{64})?$")

func httpApiBlock(w http.ResponseWriter, r *http.Request) {
	match := httpApiBlockUrlRe.FindStringSubmatch(r.URL.Path)
	if match == nil {
		http.NotFound(w, r)
		return
	}

	var blockId *[32]byte
	if match[1] != "" {
		b := [32]byte{}
		b, err := DeserializeBlockId(match[1])
		if err != nil {
			panic(err)
		}
		blockId = &b
	}

	switch r.Method {
	case "GET":
		httpApiBlockGET(w, r, blockId)
	case "PUT":
		httpApiBlockPUT(w, r, blockId)
	default:
		http.Error(w, "allowed methods: GET, PUT", http.StatusMethodNotAllowed)
	}
}

func httpApiBlockNoId(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		httpApiBlockGET(w, r, nil)
	case "PUT":
		httpApiBlockPUT(w, r, nil)
	default:
		http.Error(w, "allowed methods: GET, PUT", http.StatusMethodNotAllowed)
	}
}

func httpApiBlockGET(w http.ResponseWriter, r *http.Request, blockId *[32]byte) {
	if blockId == nil {
		http.NotFound(w, r)
		return
	}
	block, err := NewBlockFromDisk(*blockId)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			log.Printf("%s: failed to load block: %s", r.URL.Path, err)
			http.Error(w, "error", http.StatusInternalServerError)
		}
		return
	}
	aclResult, err := block.EvaluateACL(r)
	if err != nil {
		log.Printf("%s: failed evaluating block ACL: %s", r.URL.Path, err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if !aclResult {
		block.SetMetaHeadersOnReponse(w)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	err = block.WriteToResponse(w)
	if err != nil {
		log.Printf("%s: failed to write response: %s", r.URL.Path, err)
		return
	}
}

func httpApiBlockPUT(w http.ResponseWriter, r *http.Request, blockId *[32]byte) {
	block, err := NewBlockFromRequest(w, r, blockId)
	if err != nil {
		log.Printf("PUT %s: invalid block: %s", r.URL.Path, err)
		http.Error(w, "invalid block", http.StatusBadRequest)
		return
	}

	err = block.WriteToDisk()
	if err != nil {
		log.Printf("PUT %s: write to disk failed: %s", r.URL.Path, err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("X-Restchain-Id", SerializeBlockId(block.ID))
	block.SetMetaHeadersOnReponse(w)
	if blockId == nil {
		http.Redirect(w, r, "/api/block/"+SerializeBlockId(block.ID), http.StatusSeeOther)
	}
	fmt.Fprintln(w, "OK")
}

func httpApiCryptoPrivatekey(w http.ResponseWriter, r *http.Request) {
	privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Restchain-Private-Key", SerializeSecretKey(privateKey))
	w.Header().Set("X-Restchain-Public-Key", SerializePublicKey(privateKey.Public()))
	fmt.Fprintln(w, "OK")
}

func httpApiCryptoSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "allowed methods: POST", http.StatusMethodNotAllowed)
		return
	}

	serializedSecretKey := r.Header.Get("X-Restchain-Private-Key")
	if serializedSecretKey == "" {
		http.Error(w, "X-Restchain-Private-Key missing", http.StatusBadRequest)
		return
	}

	privateKey, err := DeserializeSecretKey(serializedSecretKey)
	if err != nil {
		http.Error(w, "X-Restchain-Private-Key invalid", http.StatusBadRequest)
		return
	}

	encodedRawData := r.Header.Get("X-Restchain-Raw-Data")
	if encodedRawData != "" {
		rawData, err := hex.DecodeString(encodedRawData)
		if err != nil {
			http.Error(w, "X-Restchain-Raw-Data invalid", http.StatusBadRequest)
		}
		signature := ed25519.Sign(privateKey, rawData)
		w.Header().Set("X-Restchain-Signature", SerializeSignature(signature))
	} else {
		message, err := NewSignedMessageDataFromRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		signature := message.Sign(privateKey)
		w.Header().Set("X-Restchain-Signature", SerializeSignature(signature))

		err = message.WriteResponse(w)
		if err != nil {
			log.Printf("%s: failed to write response: %s", r.URL.Path, err)
			return
		}
	}
}

func httpApiCryptoVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "allowed methods: POST", http.StatusMethodNotAllowed)
		return
	}

	serializedPublicKey := r.Header.Get("X-Restchain-Public-Key")
	if serializedPublicKey == "" {
		http.Error(w, "X-Restchain-Public-Key missing", http.StatusBadRequest)
		return
	}

	publicKey, err := DeserializePublicKey(serializedPublicKey)
	if err != nil {
		http.Error(w, "X-Restchain-Public-Key invalid", http.StatusBadRequest)
		return
	}

	serializedSignature := r.Header.Get("X-Restchain-Signature")
	if serializedSignature == "" {
		http.Error(w, "X-Restchain-Signature missing", http.StatusBadRequest)
		return
	}

	signature, err := DeserializeSignature(serializedSignature)
	if err != nil {
		http.Error(w, "X-Restchain-Signature invalid", http.StatusBadRequest)
		return
	}

	signatureValid := false
	encodedRawData := r.Header.Get("X-Restchain-Raw-Data")
	if encodedRawData != "" {
		rawData, err := hex.DecodeString(encodedRawData)
		if err != nil {
			http.Error(w, "X-Restchain-Raw-Data invalid", http.StatusBadRequest)
		}
		signatureValid = ed25519.Verify(publicKey, rawData, signature)
	} else {
		message, err := NewSignedMessageDataFromRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signatureValid = message.Verify(publicKey, signature)
	}

	if signatureValid {
		fmt.Fprintln(w, "OK")
	} else {
		http.Error(w, "FAIL", http.StatusTeapot)
	}
}

func httpApiCryptoBlockId(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "allowed methods: POST", http.StatusMethodNotAllowed)
		return
	}

	block, err := NewBlockFromRequest(w, r, nil)
	if err != nil {
		log.Printf("PUT %s: invalid block: %s", r.URL.Path, err)
		http.Error(w, "invalid block", http.StatusBadRequest)
		return
	}
	fmt.Fprintln(w, hex.EncodeToString(block.ID[:]))
}
