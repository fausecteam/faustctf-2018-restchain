package main

import (
	"bytes"
	"crypto/sha256"
	"ed25519"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"
)

type SignedMessageData struct {
	Header      http.Header
	ContentType string
	Body        []byte
}

func NewSignedMessageDataFromRequest(w http.ResponseWriter, r *http.Request) (*SignedMessageData, error) {
	m := &SignedMessageData{}
	err := m.ReadFromRequest(w, r)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *SignedMessageData) ReadFromRequest(w http.ResponseWriter, r *http.Request) error {
	body, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, BlockMaxBodyLength))
	if err != nil {
		return err
	}

	m.Header = make(http.Header, 0)
	m.ContentType = r.Header.Get("Content-Type")
	m.Body = body

	for header, values := range r.Header {
		if strings.HasPrefix(header, BlockHeaderPrefix) {
			trimmedHeader := strings.TrimPrefix(header, BlockHeaderPrefix)
			for _, value := range values {
				m.Header.Add(trimmedHeader, value)
			}
		}
	}

	return nil
}

func (m *SignedMessageData) ReadFromResponse(r *http.Response) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	m.Header = make(http.Header, 0)
	m.ContentType = r.Header.Get("Content-Type")
	m.Body = body

	for header, values := range r.Header {
		if strings.HasPrefix(header, BlockHeaderPrefix) {
			trimmedHeader := strings.TrimPrefix(header, BlockHeaderPrefix)
			for _, value := range values {
				m.Header.Add(trimmedHeader, value)
			}
		}
	}

	return nil
}

func (m *SignedMessageData) Bytes() []byte {
	return m.BytesWithExtraHeaders(nil)
}

func (m *SignedMessageData) Hash() [32]byte {
	return sha256.Sum256(m.Bytes())
}

func (m *SignedMessageData) HashString() string {
	h := m.Hash()
	return hex.EncodeToString(h[:])
}

func (m *SignedMessageData) BytesWithExtraHeaders(extraHeaders http.Header) []byte {
	response := http.Response{
		Proto:         "HTTP",
		ProtoMajor:    1,
		ProtoMinor:    0,
		StatusCode:    200,
		Header:        make(http.Header, 0),
		Body:          ioutil.NopCloser(bytes.NewBuffer(m.Body)),
		ContentLength: int64(len(m.Body)),
	}
	response.Header.Set("Content-Type", m.ContentType)

	for header, values := range m.Header {
		for _, value := range values {
			response.Header.Add(BlockHeaderPrefix+header, value)
		}
	}

	for header, values := range extraHeaders {
		for _, value := range values {
			response.Header.Add(header, value)
		}
	}

	buffer := bytes.NewBuffer(nil)
	response.Write(buffer)

	return buffer.Bytes()
}

func (m *SignedMessageData) Sign(privateKey ed25519.SecretKey) ed25519.Signature {
	h := m.Hash()
	return ed25519.Sign(privateKey, h[:])
}

func (m *SignedMessageData) Verify(publicKey ed25519.PublicKey, signature ed25519.Signature) bool {
	h := m.Hash()
	return ed25519.Verify(publicKey, h[:], signature)
}

func (m *SignedMessageData) WriteResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", m.ContentType)

	for header, values := range m.Header {
		prefixedHeader := BlockHeaderPrefix + header
		w.Header().Del(prefixedHeader)
		for _, value := range values {
			w.Header().Add(prefixedHeader, value)
		}
	}

	_, err := w.Write(m.Body)
	if err != nil {
		return err
	}

	return nil
}
