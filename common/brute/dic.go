package brute

import "Mscan/common/util"

func GetDic(userpath, passpath, module string, scanresult []string) ([]string, []string, int64) {
	var userDicList, passDicList []string
	var bruteTotal int64
	if userpath == "" && passpath == "" {
		userDicList = util.UserList
		passDicList = util.PassList
		if module == "redis" {
			bruteTotal = int64(len(scanresult))
		} else {
			bruteTotal = int64(len(scanresult)) * int64(len(userDicList)) * int64(len(passDicList))
		}
		return userDicList, passDicList, bruteTotal
	} else if userpath == "" {
		userDicList = util.UserList
		passDicList = util.ReadDicFile(passpath)
		if module == "redis" {
			bruteTotal = int64(len(scanresult))
		} else {
			bruteTotal = int64(len(scanresult)) * int64(len(userDicList)) * int64(len(passDicList))
		}
		return userDicList, passDicList, bruteTotal
	} else if passpath == "" {
		userDicList = util.ReadDicFile(userpath)
		passDicList = util.PassList
		if module == "redis" {
			bruteTotal = int64(len(scanresult))
		} else {
			bruteTotal = int64(len(scanresult)) * int64(len(userDicList)) * int64(len(passDicList))
		}
		return userDicList, passDicList, bruteTotal
	}
	userDicList = util.ReadDicFile(userpath)
	passDicList = util.ReadDicFile(passpath)
	if module == "redis" {
		bruteTotal = int64(len(scanresult))
	} else {
		bruteTotal = int64(len(scanresult)) * int64(len(userDicList)) * int64(len(passDicList))
	}
	return userDicList, passDicList, bruteTotal
}

func MakeDic(userdic *[]string, passdic *[]string, dicchan *chan string) {
	var dic string
	for _, user := range *userdic {
		for _, pass := range *passdic {
			dic = user + "???" + pass
			*dicchan <- dic
		}
	}
	close(*dicchan)
}
