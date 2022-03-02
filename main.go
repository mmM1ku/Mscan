package main

import (
	"Mscan/common/ScanTask"
	"Mscan/common/util"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	ips         = kingpin.Flag("ip", "IP Range").Required().Short('i').String()
	ports       = kingpin.Flag("port", "Port Range").Short('p').String()
	thread      = kingpin.Flag("thread", "Scan Threads").Default("50").Short('t').Int()
	module      = kingpin.Flag("module", "Brute Module").Short('m').String()
	brutethread = kingpin.Flag("brute", "Brute Threads").Default("10").Short('b').Int()
	userpath    = kingpin.Flag("upath", "User Dic Path").Short('u').String()
	passpath    = kingpin.Flag("ppath", "Pass Dic Path").Short('w').String()
	output      = kingpin.Flag("output", "Output Result").Short('o').String()
	webscan     = kingpin.Flag("webscan", "Webscan").Default("false").Bool()
)

func main() {
	defer util.TimeCost()()
	util.InitLogo()
	kingpin.Parse()
	task := ScanTask.NewTask(*ips, *ports, *thread, *module, *brutethread, *userpath, *passpath, *output, *webscan)
	task.Run()
	task.Wg.Wait()
}
