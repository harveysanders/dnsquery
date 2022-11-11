package main

import (
	"log"

	"github.com/harveysanders/dnsquery"
)

func main() {
	err := dnsquery.Run()
	if err != nil {
		log.Fatal(err)
	}
}
