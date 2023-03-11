package main

import (
	"gopkg.in/alecthomas/kingpin.v2"
	_ "net/http/pprof"
)

var (
	ips         = kingpin.Flag("ip", "IP Range").Required().Short('i').String()
	ports       = kingpin.Flag("port", "Port Range").Short('p').String()
	thread      = kingpin.Flag("thread", "Scan Threads").Default("50").Short('t').Int()
	module      = kingpin.Flag("module", "Brute Module").Default("all").Short('m').String()
	brutethread = kingpin.Flag("brute", "Brute Threads").Default("10").Short('b').Int()
	userpath    = kingpin.Flag("upath", "User Dic Path").Short('u').String()
	passpath    = kingpin.Flag("ppath", "Pass Dic Path").Short('w').String()
	output      = kingpin.Flag("output", "Output Result").Short('o').String()
)

func main() {
	/*defer util.TimeCost()()
	util.InitLogo()
	kingpin.Parse()
	task := ScanTask.NewTask(*ips, *ports, *thread, *module, *brutethread, *userpath, *passpath, *output)
	task.Run()
	task.Wg.Wait()*/
}
