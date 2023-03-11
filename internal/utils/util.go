package utils

import (
	"Mscan/common/util"
	"fmt"
	"github.com/malfunkt/iprange"
	"net"
	"strconv"
	"strings"
)

// GenIpList 生成扫描任务ip目标
func GenIpList(target string) ([]string, error) {
	list, err := iprange.ParseList(target)
	if err != nil {
		return nil, err
	}
	rangeList := list.Expand()
	var ipList []string
	for _, ip := range rangeList {
		ipList = append(ipList, ip.String())
	}
	return ipList, nil
}

func GenPortList(ports string) ([]int, error) {
	var portList []int
	//处理端口为空的情况，为空默认扫全端口
	if ports == "" {
		portList = util.DefaultPorts
		return portList, nil
	}
	commaSplit := strings.Split(ports, ",")
	for _, str := range commaSplit {
		str = strings.TrimSpace(str)
		if strings.Contains(str, "-") {
			parts := strings.Split(str, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("格式错误: %s", str)
			}
			port1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("端口号错误: %s", parts[0])
			}
			port2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("端口号错误: %s", parts[1])
			}
			if port1 > port2 {
				return nil, fmt.Errorf("端口范围错误: %d-%d", port1, port2)
			}
			for i := port1; i <= port2; i++ {
				portList = append(portList, i)
			}
		} else {
			if port, err := strconv.Atoi(str); err != nil {
				return nil, fmt.Errorf("端口号错误: %s", str)
			} else {
				portList = append(portList, port)
			}
		}
	}
	return portList, nil
}

func GetTaskTarget(ipList []string, portList []int) []string {
	var targetList []string
	for _, ip := range ipList {
		ip := ip
		for _, port := range portList {
			port := port
			target := net.JoinHostPort(ip, strconv.Itoa(port))
			targetList = append(targetList, target)
		}
	}
	return targetList
}
