package cobra

import (
	"Mscan/configs"
	"Mscan/pkg/task"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "port scan and service identification",
	Run: func(cmd *cobra.Command, args []string) {
		t := task.New("scan", configs.IpTarget, configs.Ports)
		t.Run()
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
