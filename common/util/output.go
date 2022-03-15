package util

import (
	"encoding/json"
	"github.com/kpango/glg"
	"os"
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
func Output(outputmod string, result map[string]*DetailResult) {
	switch outputmod {
	case "json":
		outputJson(result)
	}
}

func outputJson(result map[string]*DetailResult) {
	data, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		glg.Error(err)
	}
	file, err := os.OpenFile("result.json", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		glg.Error(err)
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		glg.Error(err)
	}
}
