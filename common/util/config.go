package util

//var UserList = []string{"root", "administrator"}
//var PassList = []string{"root", "!@", "wubao", "password", "123456", "admin", "12345", "1234", "p@ssw0rd", "123", "1", "jiamima", "test", "root123", "!", "!q@w", "!qaz@wsx", "idc!@", "admin!@", "alpine", "qwerty", "12345678", "111111", "123456789", "1q2w3e4r", "123123", "default", "1234567", "qwe123", "1qaz2wsx", "1234567890", "abcd1234", "000000", "user", "toor", "qwer1234", "1q2w3e", "asdf1234", "redhat", "1234qwer", "cisco", "12qwaszx", "test123", "1q2w3e4r5t", "admin123", "changeme", "1qazxsw2", "123qweasd", "q1w2e3r4", "letmein", "server", "root1234", "master", "abc123", "rootroot", "a", "system", "pass", "1qaz2wsx3edc", "p@$$w0rd", "112233", "welcome", "!QAZ2wsx", "linux", "123321", "manager", "1qazXSW@", "q1w2e3r4t5", "oracle", "asd123", "admin123456", "ubnt", "123qwe", "qazwsxedc", "administrator", "superuser", "zaq12wsx", "121212", "654321", "ubuntu", "0000", "zxcvbnm", "root@123", "1111", "vmware", "q1w2e3", "qwerty123", "cisco123", "11111111", "pa55w0rd", "asdfgh", "11111", "123abc", "asdf", "centos", "888888", "54321", "password123"}

var FtpUser = []string{"ftp", "admin", "test"}
var FtpPwd = []string{"ftp", "admin", "123456", "test"}

var MssqlUser = []string{"sa"}
var MssqlPwd = []string{"123456", "sa"}

var MysqlUser = []string{"root"}
var MysqlPwd = []string{"root", "123456", "password", "root!@#"}

var PostgresUser = []string{"postgres"}
var PostgresPwd = []string{"postgres"}

var SmbUser = []string{"administrator"}
var SmbPwd = []string{"password", "123456", "test", "admin", "administrator123", "Passw0rd", "123qwe", "test123", "admin123", "1q2w3e4r", "1qaz2wsx", "123456qwerty", "qazwsx", "root", "12345", "123", "qwerty"}

var SshUser = []string{"root", "admin"}
var SshPwd = []string{"root", "admin", "123456"}

var DefaultPorts = []int{21, 22, 23, 25, 80, 81, 110, 111, 123, 135, 139, 389, 443, 445, 465, 500, 515, 548, 623, 636, 873, 902, 1080, 1099, 1433, 1521, 1883, 2049, 2181, 2375, 2379, 3128, 3306, 3389, 4730, 5222, 5432, 5555, 5601, 5672, 5900, 5938, 5984, 6000, 6379, 7001, 7077, 8080, 8081, 8443, 8545, 8686, 9000, 9001, 9042, 9092, 9100, 9200, 9418, 9999, 11211, 27017, 37777, 50000, 50070, 61616}

type Target struct {
	Service string
	Target  string
}

type Result struct {
	Addr *string
	User string
	Pass string
}

type WebResult struct {
	StatusCode string
	Title      string
	Finger     []string
}

type HttpRes struct {
	Target         string
	Url            string
	RespTitle      string
	RespStatusCode string
	RespHeader     string
	RespBody       string
}

type DetailResult struct {
	Ports   []int
	Service []string
	WebInfo map[string]*WebResult
}
