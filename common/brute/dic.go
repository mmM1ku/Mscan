package brute

import "Mscan/common/util"

func GetDic(userpath, passpath string) ([]string, []string) {
	var userDicList, passDicList []string
	if userpath == "" && passpath == "" {
		userDicList = util.UserList
		passDicList = util.PassList
		return userDicList, passDicList
	} else if userpath == "" {
		userDicList = util.UserList
		passDicList = util.ReadDicFile(passpath)
		return userDicList, passDicList
	} else if passpath == "" {
		userDicList = util.ReadDicFile(userpath)
		passDicList = util.PassList
		return userDicList, passDicList
	}
	userDicList = util.ReadDicFile(userpath)
	passDicList = util.ReadDicFile(passpath)
	return userDicList, passDicList
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
