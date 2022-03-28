package brute

import (
	"Mscan/common/util"
)

type Dic struct {
	User string
	Pwd  string
}

func genDic() []Dic {
	var dics []Dic
	for _, username := range util.UserList {
		for _, pwd := range util.PassList {
			dics = append(dics, Dic{username, pwd})
		}
	}
	return dics
}

/* todo 字典文件读取 */
