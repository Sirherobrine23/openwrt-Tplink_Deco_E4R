# vlan设计文档
## 概述：
本模块功能是根据用户配置完成Deco 设备的vlan设置，以及在变更wan口的情况下，同步wan口的vlan配置


## 数据结构与存储：
1).  常用数据结构

```json
用户配置vlan信息：
{
"enable":true,
/*enable=false时，无需处理isp_name以及id*/
"isp_name":<base64>,
"id":10
}

swconfig加载的vlan配置信息：
{
config switch
        option name 'switch0'
        option enable_vlan '1'
        option reset '1'

config switch_vlan
        option ports '0t 1 2 3 4'
        option device 'switch0'
        option vlan '1'

config switch_vlan
        option ports '0t 5'
        option device 'switch0'
        option vlan '2'
}
```

2).  数据存储

a. 用户配置的vlan信息存储：

存放在/etc/config/network中的section vlan，default-config中增加相应字段，默认vlan.enable=0，vlan.isp_name=0，vlan.id=0 

b. swconfig加载的vlan配置信息存储：

存放在/etc/vlan.d/vlan中，在开机加载switch时，会去判断是否开启vlan并且是否需要更新vlan信息到/etc/vlan.d/vlan，然后switch加载该配置文件启动

## 主要流程：

## vlan详细设计：
### 处理用户配置--开启vlan：

1).   用户开启vlan时，首先判断当前是否已开启vlan，若是则清除当前信息，包括/etc/config/network以及ifconfig中的设备

2).	配置/etc/config/network中的vlan节，以及新建device节，name设为br-wan.x，将wan的ifname改为br-wan.x

3).	根据network配置/etc/vlan.d/vlan，swconfig reload新的vlan配置

### 处理用户配置--关闭vlan：

1).   用户关闭vlan时，配置/etc/config/network中的vlan节，删除br-wan.x，并将wan的ifname改为br-wan

2).  根据network配置/etc/vlan.d/vlan，swconfig reload新的vlan配置

3).  删除ifconfig中的br-wan.x设备

### switch加载时，更新/etc/vlan.d/vlan信息

1).  /etc/vlan.d/vlan每次重启都会恢复初始设置

2).  在/etc/init.d/switch加载过程中，会读取/etc/config/network的vlan配置信息，并根据需要更新/etc/vlan.d/vlan配置文件，switch加载该配置文件

### wan口变更时，vlan信息更新到新的wan口

1). wan口变更信息由wanDetect提供，动作为"update"与"clear"，见/etc/hotplug.d/bridge/01-vlanstate脚本

2).  当开启vlan，又没有拨上号时，将两个端口都打上标签

3). "update"时，说明wan口拨上号了，此时将lan口去掉标签

4). "clear"时，说明当前没有lan口(wanDetect默认将两个端口设为wan口)，那么将两个端口打上标签


#### 对外接口：

```lua
admin.mobile_app.network
local dispatch_tbl = {  
    vlan = {
        ["read"] = {cb = get_wan_vlan},
        ["write"] = {cb = set_wan_vlan}
     }
}
```
- 配置vlan信息：form=vlan，operation=write

- 读取vlan信息：form=vlan，operation=read

## 附录
[Checklist.md](Checklist.md)

[cmd.md](cmd.md)


