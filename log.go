package main

import (
	"log"
)

func logFatalOnErr(message string, err error) {
	if err != nil {
		log.Fatalf("%s: %s", message, err)
	}
}
