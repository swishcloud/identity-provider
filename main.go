package main

import (
	"log"

	"github.com/swishcloud/identity-provider/cmd"
)

func main() {
	log.Println("pre-starting idp...")
	cmd.Execute()
}
