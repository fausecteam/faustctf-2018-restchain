package main

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

func StoragePath(elem ...string) string {
	return path.Join(append([]string{flagStorage}, elem...)...)
}

var restchainPersistPath string

func AtomicWriteFile(filePath string, data []byte) error {
	cmd := exec.Command(restchainPersistPath, filePath)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = ioutil.Discard
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func initStorage() {
	// locate and check restchain-persist binary
	if flagPersist == "" {
		execFile, err := os.Executable()
		logFatalOnErr("getting executable path", err)
		restchainPersistPath = filepath.Join(filepath.Dir(execFile), "restchain-persist")
		stat, err := os.Stat(restchainPersistPath)
		if err != nil {
			log.Fatalf("cannot stat %s: %s", restchainPersistPath, err)
		} else if stat.Mode()&0111 == 0 {
			log.Fatalf("%s exists but is not executable", StoragePath())
		}
	} else {
		restchainPersistPath = flagPersist
	}

	// ensure storage path exists
	stat, err := os.Stat(StoragePath())
	if err != nil {
		log.Fatalf("cannot stat %s: %s", StoragePath(), err)
	} else if !stat.IsDir() {
		log.Fatalf("storage location %s exists but is not a directory", StoragePath())
	}

	// extract http public directory
	for key, value := range bindata {
		if strings.HasPrefix(key, "public/") {
			err := AtomicWriteFile(StoragePath(key), value)
			logFatalOnErr("extracting http public", err)
			delete(bindata, key)
		}
	}

	// write the genesis block if it does not exist already
	err = AtomicWriteFile(BlockFileName(GenesisBlockId), bindata["genesis-block"])
	logFatalOnErr("writing genesis block", err)

	// everything done in the following go routine is not critical for the
	// operation of the service, but should still be done some time soon
	go initStorageDelayed()
}

func initStorageDelayed() {
	// initialize block storage
	for i := 0x00; i <= 0xff; i++ {
		subdir := hex.EncodeToString([]byte{byte(i)})
		err := AtomicWriteFile(StoragePath("blocks", subdir, ".keep"), []byte{})
		logFatalOnErr("creating block dirs", err)
	}
}
