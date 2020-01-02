package cmd

import (
	"log"

	"github.com/swishcloud/identity-provider/flagx"
	"github.com/swishcloud/identity-provider/server"

	"github.com/spf13/cobra"
)

const SERVER_CONFIG_FILE = "IDENTITY_PROVIDER_CONFIG"

var serveCmd = &cobra.Command{
	Use: "serve",
	Run: func(cmd *cobra.Command, args []string) {
		path := flagx.MustGetString(cmd, "config")
		skip_tls_verify, err := cmd.Flags().GetBool("skip-tls-verify")
		if err != nil {
			log.Fatal(err)
		}
		server := server.NewIDPServer(path, skip_tls_verify)
		server.Serve()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringP("config", "c", "config.yaml", "server config file")
	serveCmd.Flags().Bool("skip-tls-verify", false, "skip tls verify")
}
