package util

import (
	"encoding/json"
	"github.com/kpango/glg"
	"os"
)

type Csv struct {
	Ip       string `csv:"ip"`
	Ports    string `csv:"ports"`
	WebTitle string `csv:"web_title"`
	Finger   string `csv:"finger"`
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
	file, err := os.OpenFile("./result.json", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		glg.Error(err)
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		glg.Error(err)
	}
}
