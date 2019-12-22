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
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile | log.LUTC)
		path := flagx.MustGetString(cmd, "config")
		server := server.NewIDPServer(path)
		server.Serve()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringP("config", "c", "config.yaml", "server config file")
	serveCmd.PersistentFlags().Bool("dangerous-force-http", false, "DO NOT USE THIS IN PRODUCTION - Disables HTTP/2 over TLS (HTTPS) and serves HTTP instead")
}
