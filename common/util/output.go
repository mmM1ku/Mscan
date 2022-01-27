package util

import (
	"encoding/csv"
	"github.com/blinkbean/dingtalk"
	"github.com/kpango/glg"
	"gopkg.in/yaml.v2"
	"os"
	"strconv"
)

type yamlStruct struct {
	Email struct {
		Address  string `yaml:"address"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Sendto   string `yaml:"sendto"`
	}
	DingTalk struct {
		Token  []string `yaml:"token"`
		Key    string   `yaml:"key"`
		Secret string   `yaml:"secret"`
	}
}

// Output 输出选项
func Output(outputmod string, result []Result) {
	switch outputmod {
	case "csv":
		outputCsv(result)
	case "dingding":
		dingTalk(result)
	case "email":
		sendmail(result)
	}
}

func outputCsv(result []Result) {
	csvFile, err := os.Create("result.csv")
	if err != nil {
		glg.Error(err)
	}
	defer csvFile.Close()

	csvFile.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(csvFile)
	writer.Write([]string{"序号", "IP:Port", "用户名", "密码"})
	for n, res := range result {
		writer.Write([]string{strconv.Itoa(n + 1), *res.Addr, res.User, res.Pass})
		n++
	}
	writer.Flush()
}

// 钉钉机器人消息
func dingTalk(result []Result) {
	var t yamlStruct
	content, err := readConfig()
	if err != nil {
		glg.Error(err)
	}
	err = yaml.Unmarshal(content, &t)
	if err != nil {
		glg.Error(err)
	}
	msg := []string{"### 弱口令结果"}
	for _, res := range result {
		msg = append(msg, "- 地址:"+*res.Addr+",用户名:"+res.User+",密码:"+res.Pass)
	}
	if t.DingTalk.Secret == "" {
		cli := dingtalk.InitDingTalk(t.DingTalk.Token, t.DingTalk.Key)
		cli.SendMarkDownMessageBySlice("Result", msg)
	} else {
		cli := dingtalk.InitDingTalkWithSecret(t.DingTalk.Token[0], t.DingTalk.Secret)
		cli.SendMarkDownMessageBySlice("Result", msg)
	}
}

func sendmail(result []Result) {
	var t yamlStruct
	content, err := readConfig()
	if err != nil {
		glg.Error(err)
	}
	err = yaml.Unmarshal(content, &t)
	if err != nil {
		glg.Error(err)
	}
	Email(t.Email.Address, t.Email.Username, t.Email.Password, t.Email.Sendto, t.Email.Port, result)
}
