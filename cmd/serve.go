package cmd

import (
	"io/ioutil"
	"log"

	"github.com/swishcloud/identity-provider/flagx"

	"github.com/spf13/cobra"
	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/server"
	"gopkg.in/yaml.v2"
)

const SERVER_CONFIG_FILE = "IDENTITY_PROVIDER_CONFIG"

var serveCmd = &cobra.Command{
	Use: "serve",
	Run: func(cmd *cobra.Command, args []string) {
		path := flagx.MustGetString(cmd, "config")
		b, err := ioutil.ReadFile(path)
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(b, &global.Config)
		if err != nil {
			panic(err)
		}
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile | log.LUTC)
		server.Serve()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringP("config", "c", "config.yaml", "server config file")
	serveCmd.PersistentFlags().Bool("dangerous-force-http", false, "DO NOT USE THIS IN PRODUCTION - Disables HTTP/2 over TLS (HTTPS) and serves HTTP instead")
}
