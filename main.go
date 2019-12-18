package main

import (
	"github.com/swishcloud/identity-provider/cmd"
	"github.com/swishcloud/identity-provider/global"
)

func main() {
	global.InfoLogger.Println("pre-starting idp...")
	cmd.Execute()
}
