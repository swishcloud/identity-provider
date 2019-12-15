package cmd

import (
	"log"

	"github.com/swishcloud/identity-provider/flagx"

	"github.com/golang-migrate/migrate"
	_ "github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"
	"github.com/spf13/cobra"
)

var migrateSqlCmd = &cobra.Command{
	Use:   "sql",
	Short: "migrate sql scripts",
	Run: func(cmd *cobra.Command, args []string) {
		connInfo := flagx.MustGetString(cmd, "conn_info")
		log.Println("migration connection string:", connInfo)
		m, err := migrate.New(
			"file://migrations",
			connInfo)
		if err != nil {
			log.Fatal(err)
		}
		if err := m.Up(); err != nil {
			log.Fatal(err)
		}
		log.Println("successfully updated database")
	},
}

func init() {
	migrateCmd.AddCommand(migrateSqlCmd)

	migrateSqlCmd.Flags().String("conn_info", "", "connection string of database")
	migrateSqlCmd.MarkFlagRequired("conn_info")
}
