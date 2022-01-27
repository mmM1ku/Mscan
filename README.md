# Mscan
***
## 简介
***
一个用go编写的端口扫描和弱口令爆破工具。
## 使用
***
端口扫描
```shell
mscan -i 127.0.0.1 -p 22
```
弱口令爆破
```shell
mscan -i 127.0.0.1 -p 22 -m ssh
```
参数说明
```shell
mscan --help
-i 指定ip地址,支持nmap写法
-p 指定端口,支持逗号,分隔符方式,例如80,443或者8000-8100
-t 扫描线程数,默认50
-b 爆破线程数,默认10
-u 用户名字典路径,不指定默认root,administrator
-w 密码字典路径,不指定默认内部top100
-o 输出方式,目前支持csv,邮件,钉钉bot.邮件和钉钉需在config.yaml文件内配置信息
```
##参考链接
***
[fscan](https://github.com/shadow1ng/fscan)

[Ladongo](https://github.com/k8gege/LadonGo)


