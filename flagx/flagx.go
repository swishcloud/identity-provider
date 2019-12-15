package flagx

import (
	"github.com/spf13/cobra"
)

// MustGetString returns a string flag or fatals if an error occurs.
func MustGetString(cmd *cobra.Command, name string) string {
	s, err := cmd.Flags().GetString(name)
	if err != nil {
		panic(err)
	}
	return s
}
