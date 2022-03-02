package util

var UserList = []string{"root", "administrator"}
var PassList = []string{"root", "!@", "wubao", "password", "123456", "admin", "12345", "1234", "p@ssw0rd", "123", "1", "jiamima", "test", "root123", "!", "!q@w", "!qaz@wsx", "idc!@", "admin!@", "alpine", "qwerty", "12345678", "111111", "123456789", "1q2w3e4r", "123123", "default", "1234567", "qwe123", "1qaz2wsx", "1234567890", "abcd1234", "000000", "user", "toor", "qwer1234", "1q2w3e", "asdf1234", "redhat", "1234qwer", "cisco", "12qwaszx", "test123", "1q2w3e4r5t", "admin123", "changeme", "1qazxsw2", "123qweasd", "q1w2e3r4", "letmein", "server", "root1234", "master", "abc123", "rootroot", "a", "system", "pass", "1qaz2wsx3edc", "p@$$w0rd", "112233", "welcome", "!QAZ2wsx", "linux", "123321", "manager", "1qazXSW@", "q1w2e3r4t5", "oracle", "asd123", "admin123456", "ubnt", "123qwe", "qazwsxedc", "administrator", "superuser", "zaq12wsx", "121212", "654321", "ubuntu", "0000", "zxcvbnm", "root@123", "1111", "vmware", "q1w2e3", "qwerty123", "cisco123", "11111111", "pa55w0rd", "asdfgh", "11111", "123abc", "asdf", "centos", "888888", "54321", "password123"}

type Result struct {
	Addr *string
	User string
	Pass string
}

type WebResult struct {
	Url        string
	StatusCode int
	Title      string
	Finger     []string
}

type Finger struct {
	Path        string
	Method      string
	ReqHeaders  map[string]string
	ReqData     string
	StatusCode  int
	RespHeaders map[string]string
	Keyword     []string
	FaviconHash []string
	Name        string
}

var PostService = map[string]string{
	"ssh":      "22",
	"redis":    "6379",
	"mysql":    "3306",
	"smb":      "445",
	"ftp":      "21",
	"postgres": "5432",
	"mongo":    "27017",
	"mssql":    "1433",
}
