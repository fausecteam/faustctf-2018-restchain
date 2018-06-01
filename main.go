package main

import (
	"flag"
	"net/http"
)

var flagListen string
var flagStorage string
var flagPersist string
var flagNode string

func main() {
	flag.StringVar(&flagListen, "listen", ":6060", "'address:port' to listen on")
	flag.StringVar(&flagStorage, "storage", "./data", "directory to store data")
	flag.StringVar(&flagPersist, "persist", "", "path to restchain-persist (default: auto-detect)")
	flag.StringVar(&flagNode, "node", "", "path to node (default: auto-detect)")
	flag.Parse()

	initStorage()
	initBlockAcl()
	registerHttpHandlers()

	// err := http.ListenAndServe(flagListen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	// 	http.DefaultServeMux.ServeHTTP(w, r)
	// }))
	err := http.ListenAndServe(flagListen, nil)
	if err != nil {
		panic(err)
	}
}
