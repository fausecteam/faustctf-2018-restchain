package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
)

var blockIdRe = regexp.MustCompile("^[0-9a-z]{64}$")

func BlockFileNameString(blockId string) string {
	return path.Join(flagStorage, "blocks", blockId[:2], blockId)
}

func BlockFileName(blockId [32]byte) string {
	return BlockFileNameString(SerializeBlockId(blockId))
}

func SerializeBlockId(blockId [32]byte) string {
	return hex.EncodeToString(blockId[:])
}

func DeserializeBlockId(s string) ([32]byte, error) {
	var blockId [32]byte
	n, err := hex.Decode(blockId[:], []byte(s))
	if err != nil {
		return blockId, err
	}
	if n != 32 {
		return blockId, fmt.Errorf("DeserializeBlockId: only read %d bytes", n)
	}
	return blockId, nil
}

type Block struct {
	ID         [32]byte
	PreviousID [32]byte
	Data       SignedMessageData
	Signer     ed25519.PublicKey
	Signature  ed25519.Signature
}

func NewBlockFromDisk(blockId [32]byte) (*Block, error) {
	blockFile, err := os.Open(BlockFileName(blockId))
	if err != nil {
		return nil, err
	}

	response, err := http.ReadResponse(bufio.NewReader(blockFile), nil)
	if err != nil {
		return nil, err
	}

	block := &Block{ID: blockId}
	err = block.Data.ReadFromResponse(response)
	if err != nil {
		return nil, err
	}

	serializedPrevious := response.Header.Get("X-Restchain-Previous")
	if serializedPrevious == "" {
		return nil, fmt.Errorf("X-Restchain-Previous missing")
	}
	block.PreviousID, err = DeserializeBlockId(serializedPrevious)
	if err != nil {
		return nil, fmt.Errorf("X-Restchain-Previous invalid: %s", err)
	}

	serializedSigner := response.Header.Get("X-Restchain-Signer")
	if serializedSigner == "" {
		return nil, fmt.Errorf("X-Restchain-Signer missing")
	}
	block.Signer, err = DeserializePublicKey(serializedSigner)
	if err != nil {
		return nil, fmt.Errorf("X-Restchain-Signer invalid: %s", err)
	}

	serializedSignature := response.Header.Get("X-Restchain-Signature")
	if serializedSignature == "" {
		return nil, fmt.Errorf("X-Restchain-Signature missing")
	}
	signature, err := DeserializeSignature(serializedSignature)
	if err != nil {
		return nil, fmt.Errorf("X-Restchain-Signature invalid: %s", err)
	}
	block.Signature = signature

	err = block.Verify()
	if err != nil {
		return nil, err
	}

	return block, nil
}

func NewBlockFromRequest(w http.ResponseWriter, r *http.Request, blockId *[32]byte) (*Block, error) {
	block := &Block{}
	err := block.Data.ReadFromRequest(w, r)
	if err != nil {
		return nil, err
	}

	serializedPrevious := r.Header.Get("X-Restchain-Previous")
	if serializedPrevious == "" {
		return nil, fmt.Errorf("X-Restchain-Previous missing")
	}
	if !blockIdRe.MatchString(serializedPrevious) {
		return nil, fmt.Errorf("X-Restchain-Previous malformed")
	}
	block.PreviousID, err = DeserializeBlockId(serializedPrevious)
	if err != nil {
		return nil, fmt.Errorf("X-Restchain-Previous invalid: %s", err)
	}

	serializedSigner := r.Header.Get("X-Restchain-Signer")
	if serializedSigner == "" {
		return nil, fmt.Errorf("X-Restchain-Signer missing")
	}
	block.Signer, err = DeserializePublicKey(serializedSigner)
	if err != nil {
		return nil, fmt.Errorf("X-Restchain-Signer invalid: %s", err)
	}

	serializedSignature := r.Header.Get("X-Restchain-Signature")
	if serializedSignature == "" {
		return nil, fmt.Errorf("X-Restchain-Signature missing")
	}
	signature, err := DeserializeSignature(serializedSignature)
	if err != nil {
		return nil, fmt.Errorf("X-Restchain-Signature invalid: %s", err)
	}
	block.Signature = signature

	if blockId == nil {
		block.ID = block.Hash()
	} else {
		block.ID = *blockId
	}

	err = block.Verify()
	if err != nil {
		return nil, err
	}

	return block, nil
}

func (b *Block) Verify() error {
	if !b.Data.Verify(b.Signer, b.Signature) {
		return fmt.Errorf("block signature invalid")
	}

	if b.Hash() != b.ID {
		return fmt.Errorf("block ID invalid, got %#v expected %#v", b.Hash(), b.ID)
	}

	if b.ID == GenesisBlockId {
		if b.ID != b.PreviousID {
			return fmt.Errorf("X-Restchain-Block-Previous of genesis block is not itself")
		}
	} else {
		stat, err := os.Stat(BlockFileName(b.PreviousID))
		if err != nil || !stat.Mode().IsRegular() {
			return fmt.Errorf("X-Restchain-Previous references unknown block")
		}
	}

	return nil
}

func (b *Block) BytesFull() []byte {
	extraHeaders := make(http.Header)
	extraHeaders.Set("X-Restchain-Previous", SerializeBlockId(b.PreviousID))
	extraHeaders.Set("X-Restchain-Payload-Hash", b.Data.HashString())
	extraHeaders.Set("X-Restchain-Signer", SerializePublicKey(b.Signer))
	extraHeaders.Set("X-Restchain-Signature", SerializeSignature(b.Signature))
	//log.Println("---BEGIN---")
	//log.Println(string(b.BytesNew()))
	//log.Println("---END---")
	return b.Data.BytesWithExtraHeaders(extraHeaders)
}

func (b *Block) Bytes() []byte {
	response := http.Response{
		Proto:      "HTTP",
		ProtoMajor: 1,
		ProtoMinor: 0,
		StatusCode: 200,
		Header:     make(http.Header, 0),
	}
	//response.Header.Set("Content-Type", m.ContentType)
	response.Header.Set("X-Restchain-Previous", SerializeBlockId(b.PreviousID))
	response.Header.Set("X-Restchain-Payload-Hash", b.Data.HashString())
	response.Header.Set("X-Restchain-Signer", SerializePublicKey(b.Signer))
	response.Header.Set("X-Restchain-Signature", SerializeSignature(b.Signature))

	buffer := bytes.NewBuffer(nil)
	response.Write(buffer)

	return buffer.Bytes()
}

func (b *Block) Hash() [32]byte {
	hash := sha256.Sum256(b.Bytes())
	if hash == GenesisBlockId {
		hash = GenesisBlockSha256
	} else if hash == GenesisBlockSha256 {
		hash = GenesisBlockId
	}
	// log.Printf("Hash: %#v", hash)
	// fmt.Println("---------- BEGIN MESSAGE ----------")
	// fmt.Println(string(b.Bytes()))
	// fmt.Println("---------- END MESSAGE ----------")
	return hash
}

func (b *Block) SetMetaHeadersOnReponse(w http.ResponseWriter) {
	w.Header().Set("X-Restchain-Payload-Hash", b.Data.HashString())
	w.Header().Set("X-Restchain-Previous", SerializeBlockId(b.PreviousID))
	w.Header().Set("X-Restchain-Signer", SerializePublicKey(b.Signer))
	w.Header().Set("X-Restchain-Signature", SerializeSignature(b.Signature))
}

func (b *Block) WriteToResponse(w http.ResponseWriter) error {
	b.SetMetaHeadersOnReponse(w)
	return b.Data.WriteResponse(w)
}

func (b *Block) WriteToDisk() error {
	err := AtomicWriteFile(BlockFileName(b.ID), b.BytesFull())
	if err != nil {
		log.Printf("writing block to disk failed: %s", err)
	}
	return err
}

func (b *Block) IdToString() string {
	return hex.EncodeToString(b.ID[:])
}
