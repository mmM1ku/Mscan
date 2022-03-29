# Mscan

## 简介

Mscan是一款基于go语言开发的内网资产探测工具，致力于帮企业梳理内部资产情况。

## 编译

项目基于golang 1.17版本进行开发，如需自行编译
```shell
git clone https://github.com/mmM1ku/Mscan
cd Mscan
#m1 mac
sudo CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -a -ldflags '-s -w --extldflags "-static -fpic"' -o mscan_darwin_arm64
#intel mac
sudo CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -ldflags '-s -w --extldflags "-static -fpic"' -o mscan_darwin_amd64
#linux
sudo CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w --extldflags "-static -fpic"' -o mscan_linux_amd64
#windows
sudo CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -ldflags '-s -w --extldflags "-static -fpic"' -o mscan_windows_amd64.exe
```

## 使用

端口扫描
```shell
#指定端口扫描
mscan -i 192.168.0.1/24,10.0.0.1-64 -p 22,80,8000-8010 -t 100
#默认扫描top端口
mscan -i 127.0.0.1 -t 100
```
弱口令爆破
```shell
#指定爆破模块
mscan -i 127.0.0.1 -p 22 -m ssh -t 100
#默认全协议爆破(需发现协议端口存在)
mscan -i 127.0.0.1 -t 100
```
结果输出
```shell
#本地生成result.json
mscan -i 127.0.0.1 -t 100 -o json
```
参数说明
```shell
mscan --help
-i 指定ip地址,支持nmap写法
-p 可选参数,指定端口,支持逗号,分隔符方式,例如80,443或者8000-8100
-t 扫描线程数,默认50
-u 用户名字典路径,不指定默认root,administrator
-w 密码字典路径,不指定默认内部top100
-o 输出方式,目前仅支持json输出
```


## 运行截图
![运行截图](https://raw.githubusercontent.com/mmM1ku/Mscan/main/imgs/WechatIMG22.png "运行截图")

## 参考链接

[fscan](https://github.com/shadow1ng/fscan)

[Ladongo](https://github.com/k8gege/LadonGo)

[Dismap](https://github.com/zhzyker/dismap)

## 感谢

感谢[FingerprintHub](https://github.com/0x727/FingerprintHub) 提供的指纹


