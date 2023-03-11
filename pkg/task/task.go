package task

import (
	"Mscan/configs"
	"Mscan/internal/utils"
	"Mscan/pkg/scan"
	"github.com/gookit/slog"
)

type Task struct {
	Mode       string
	IpList     []string
	PortList   []int
	TargetList []string
	Thread     int
	Output     string
}

func New(mode string, target string, port string) *Task {
	ipList, err := utils.GenIpList(target)
	if err != nil {
		slog.Errorf("ip target error: %v\n", err.Error())
	}
	var portList []int
	if port != "" {
		portList, err = utils.GenPortList(port)
		if err != nil {
			slog.Errorf("port target error: %v\n", err.Error())
		}
	} else {
		portList = configs.DefaultPorts
	}

	targetList := utils.GetTaskTarget(ipList, portList)
	return &Task{
		Mode:       mode,
		IpList:     ipList,
		PortList:   portList,
		TargetList: targetList,
		Thread:     configs.Thread,
		Output:     configs.Output,
	}
}

func (t *Task) Run() {
	if t.Mode == "scan" {
		scan.Run(t.TargetList)
	} else if t.Mode == "brute" {

	}
}
