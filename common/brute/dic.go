package brute

import "Mscan/common/util"

type Dic struct {
	User string
	Pwd  string
}

func (b *Brute) genDic() {
	/*var dics []Dic
	for _, username := range util.UserList {
		for _, pwd := range util.PassList {
			dics = append(dics, Dic{username, pwd})
		}
	}
	return dics*/
	//ftp
	for _, username := range util.FtpUser {
		for _, pwd := range util.FtpPwd {
			b.ftpDic = append(b.ftpDic, Dic{username, pwd})
		}
	}
	//mssql
	for _, username := range util.MssqlUser {
		for _, pwd := range util.MssqlPwd {
			b.mssqlDic = append(b.mssqlDic, Dic{username, pwd})
		}
	}
	//mysql
	for _, username := range util.MysqlUser {
		for _, pwd := range util.MysqlPwd {
			b.mysqlDic = append(b.mysqlDic, Dic{username, pwd})
		}
	}
	//postgres
	for _, username := range util.PostgresUser {
		for _, pwd := range util.PostgresPwd {
			b.postgresDic = append(b.postgresDic, Dic{username, pwd})
		}
	}
	//smb
	for _, username := range util.SmbUser {
		for _, pwd := range util.SmbPwd {
			b.smbDic = append(b.smbDic, Dic{username, pwd})
		}
	}
	//ssh
	for _, username := range util.SshUser {
		for _, pwd := range util.SshPwd {
			b.sshDic = append(b.sshDic, Dic{username, pwd})
		}
	}
}

/* todo 字典文件读取 */
