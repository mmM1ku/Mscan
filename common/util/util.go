package util

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/kpango/glg"
	mail "github.com/xhit/go-simple-mail/v2"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// MakeRangeSlice 生成连续切片，给全端口号使用
func MakeRangeSlice(min, max int) []int {
	s := make([]int, max-min+1)
	for i := range s {
		s[i] = min + i
	}
	return s
}

// ReadDicFile 读取字典文件
func ReadDicFile(dir string) []string {
	var list []string
	file, err := os.Open(dir)
	if err != nil {
		glg.Error(err)
	}
	defer file.Close()

	buf := bufio.NewScanner(file)
	for {
		if !buf.Scan() {
			break
		}
		line := buf.Text()
		list = append(list, line)
	}
	return list
}

// GetProgress 获取当前完成扫描队列
func GetProgress(now int64, total int64) {
	if now == total {
		glg.Logf("[+]当前已完成队列: %v/%v", now, total)
	} else {
		glg.Logf("[+]当前已完成队列: %v/%v", now, total)
	}
}

// TimeCost 计算扫描耗时
func TimeCost() func() {
	start := time.Now()
	return func() {
		cost := time.Since(start)
		glg.Successf("[+]本次扫描耗时：%v", cost)
	}
}

// InitLogo 初始化logo
func InitLogo() {
	var str = "███╗   ███╗███████╗ ██████╗ █████╗ ███╗   ██╗\n████╗ ████║██╔════╝██╔════╝██╔══██╗████╗  ██║\n██╔████╔██║███████╗██║     ███████║██╔██╗ ██║\n██║╚██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║\n██║ ╚═╝ ██║███████║╚██████╗██║  ██║██║ ╚████║\n╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n\nauthor: M1ku    Version:0.2\n"
	fmt.Println(str)
}

// 读取config配置文件
func readConfig() ([]byte, error) {
	content, err := ioutil.ReadFile("./config.yaml")
	if err != nil {
		return nil, err
	}
	return content, nil
}

// Email 发送email功能
func Email(addr, user, pass, to string, port int, result []Result) {
	server := mail.NewSMTPClient()
	server.Host = addr
	server.Port = port
	server.Username = user
	server.Password = pass

	var htmlBody = "<table border=\"1\"><tr><td>地址</td><td>用户名</td><td>密码</td></tr>"
	for _, res := range result {
		htmlBody = htmlBody + "<tr><td>" + *res.Addr + "</td><td>" + res.User + "</td><td>" + res.Pass + "</td></tr>"
	}
	htmlBody = htmlBody + "</table>"

	server.ConnectTimeout = 6 * time.Second
	server.SendTimeout = 6 * time.Second
	server.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	client, err := server.Connect()
	if err != nil {
		glg.Error(err)
	}

	email := mail.NewMSG()
	email.SetFrom(user).AddTo(to).SetSubject("WeakPass")
	email.SetBody(mail.TextHTML, htmlBody)

	err = email.Send(client)
	if err != nil {
		glg.Error(err)
	} else {
		glg.Success("Email sent successfully")
	}
}

func Client() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
		},
		/*CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},*/
	}
}

// RemoveRepByLoop 字符串切片去重
func RemoveRepByLoop(slc []string) []string {
	result := []string{} // 存放结果
	for i := range slc {
		flag := true
		for j := range result {
			if slc[i] == result[j] {
				flag = false // 存在重复元素，标识为false
				break
			}
		}
		if flag { // 标识为false，不添加进结果
			result = append(result, slc[i])
		}
	}
	return result
}

// GetSrcPort 创建随机源端口，范围（10000-60000）
func GetSrcPort() int {
	rand.Seed(time.Now().UnixNano())
	port := rand.Intn(50000) + 10000
	return port
}

//获取内网ip
func getLocalIP(dstip net.IP) (net.IP, error) {
	addr, err := net.ResolveUDPAddr("udp", dstip.String()+":23333")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	if conn, err := net.DialUDP("udp", nil, addr); err == nil {
		if localaddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return localaddr.IP, nil
		}
	}
	return nil, err
}

// GetLocalDevice 获取本地网卡信息
func GetLocalDevice() (string, string, error) {
	var deviceName, deviceAddr string
	var dstIp = net.ParseIP("10.10.10.10")
	localIp, err := getLocalIP(dstIp)
	if err != nil {
		fmt.Println(err)
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", "", err
	}
	for _, device := range devices {
		for _, srcIp := range device.Addresses {
			if strings.Contains(srcIp.IP.String(), localIp.String()) {
				deviceName = device.Name
				deviceAddr = srcIp.IP.String()
			}
		}
	}
	return deviceName, deviceAddr, nil
}
