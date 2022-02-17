# Mscan

## 简介

一个用go编写的端口扫描和弱口令爆破工具。
## 使用

端口扫描
```shell
mscan -i 192.168.0.1/24,10.0.0.1-64 -p 22,80,8000-8010
mscan -i 127.0.0.1 -p 22 -t 100
```
弱口令爆破
```shell
mscan -i 127.0.0.1 -p 22 -m ssh -b 50
```
结果输出
```shell
#本地生成result.csv
mscan -i 127.0.0.1 -p 22 -m ssh -o csv
#发送结果到邮箱
mscan -i 127.0.0.1 -p 22 -m ssh -o email
#发送结果到钉钉群机器人
mscan -i 127.0.0.1 -p 22 -m ssh -o dingding
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
## TodoList

- [x] 20220215: 优化爆破队列的计数方式
- [x] 20220217: 添加mssql,mongo,porgres等协议支持
- [ ] 支持服务默认端口爆破方式
- [ ] 支持全部服务爆破方式
- [ ] 支持飞书群机器人
- [x] ~~优化windows平台日志显示方式~~
- [ ] 支持半开端口扫描

## 运行截图
![运行截图](https://github.com/mmM1ku/Mscan/blob/main/imgs/E3D2A0DF-9441-4099-9442-03374D62639E.png?raw=true "运行截图")

## 参考链接

[fscan](https://github.com/shadow1ng/fscan)

[Ladongo](https://github.com/k8gege/LadonGo)


