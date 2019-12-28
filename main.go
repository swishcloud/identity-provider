package main

import (
	"log"

	"github.com/swishcloud/identity-provider/cmd"
)

func main() {
	log.Println("pre-starting idp...")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile | log.LUTC)
	cmd.Execute()
}
