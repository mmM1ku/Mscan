package cobra

import (
	"Mscan/configs"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "mscan",
	Short: "Mscan is a port scan and service identification tool.",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configs.IpTarget, "target", "i", "", "scan targets: 127.0.0.1, 192.168.0.0/24...")
	rootCmd.PersistentFlags().StringVarP(&configs.Ports, "port", "p", "", "scan ports: 80, 8000-8100...")
	rootCmd.PersistentFlags().IntVarP(&configs.Thread, "thread", "t", 10, "scan threads")
	rootCmd.PersistentFlags().StringVarP(&configs.Output, "output", "o", "", "output mode: json")
}
