package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "identity-provider",
	Short: "identity-provider is a identity provider",
	Long:  `identity-provider is a identity provider`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("welcome to IDP")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}
