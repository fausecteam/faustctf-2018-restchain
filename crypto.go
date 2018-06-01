package main

import (
	"ed25519"
	"fmt"
)

func SerializeSecretKey(privateKey ed25519.SecretKey) string {
	return string(privateKey)
}

func DeserializeSecretKey(serializedSecretKey string) (ed25519.SecretKey, error) {
	privateKey := ed25519.SecretKey(serializedSecretKey)
	if err := privateKey.Check(); err != nil {
		return "", fmt.Errorf("invalid ed25519 secret key")
	}
	return privateKey, nil
}

func SerializePublicKey(publicKey ed25519.PublicKey) string {
	return string(publicKey)
}

func DeserializePublicKey(serializedPublicKey string) (ed25519.PublicKey, error) {
	publicKey := ed25519.PublicKey(serializedPublicKey)
	if err := publicKey.Check(); err != nil {
		return "", fmt.Errorf("invalid ed25519 public key")
	}
	return publicKey, nil
}

func SerializeSignature(signature ed25519.Signature) string {
	return string(signature)
}

func DeserializeSignature(serializedSignature string) (ed25519.Signature, error) {
	signature := ed25519.Signature(serializedSignature)
	if err := signature.Check(); err != nil {
		return "", fmt.Errorf("invalid ed25519 signature")
	}
	return signature, nil
}
