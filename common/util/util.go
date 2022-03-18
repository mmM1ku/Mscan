package util

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/kpango/glg"
	"math/rand"
	"net/http"
	"os"
	"strconv"
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

func toStringSlice(a []int) []string {
	var s []string
	for _, v := range a {
		s = append(s, strconv.Itoa(v))
	}
	return s
}
