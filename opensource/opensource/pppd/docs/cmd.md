
#### 设置pptp/l2tp拨号方式，并进行用户名密码，VPN server，第二连接方式信息的填写
```c
/* 设置pptp/l2tp拨号方式，并进行用户名密码，VPN server，第二连接方式信息的填写 */

/* 第一连接为L2TP,第二连接为动态获取IP */
echo '{"params":{"wan":{"dial_type":"l2tp", "user_info":{"username":"l2tp", "password":"l2tp", "vpn_server":"192.168.100.127"}, "secondary_connection":"dynamic_ip"}}}' | tmpcli -o 0x420C

/* 第一连接为L2TP,第二连接为静态获取IP */
echo '{"params":{"wan":{"dial_type":"l2tp", "user_info":{"username":"l2tp", "password":"l2tp", "vpn_server":"192.168.100.127"}, "secondary_connection":"static_ip", "connection_info":{"ip":"192.168.100.150", "mask":"255.255.255.0", "gateway":"192.168.100.1", "dns":"192.168.100.1"}}}}' | tmpcli -o 0x420C

/* 第一连接为PPTP,第二连接为动态获取IP */
echo '{"params":{"wan":{"dial_type":"pptp", "user_info":{"username":"pptp", "password":"pptp", "vpn_server":"192.168.100.127"}, "secondary_connection":"dynamic_ip"}}}' | tmpcli -o 0x420C

/* 第一连接为PPTP,第二连接为静态获取IP */
echo '{"params":{"wan":{"dial_type":"pptp", "user_info":{"username":"pptp", "password":"pptp", "vpn_server":"192.168.100.127"}, "secondary_connection":"static_ip", "connection_info":{"ip":"192.168.100.150", "mask":"255.255.255.0", "gateway":"192.168.100.1", "dns":"192.168.100.1"}}}}' | tmpcli -o 0x420C
```
#### 各个阶段获取 pptp/l2tp的拨号状态以及错误信息
```c
/* onboarding获取internet信息 */
tmpcli -o 0x400C {}

/* advanced查看WAN信息 */
tmpcli -o 0x4004 {}

/* advanced获取device list中会有拨号成功失败信息 */
tmpcli -o 0x400F {}
```
