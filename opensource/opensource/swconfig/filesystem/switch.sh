#!/bin/sh
# Copyright (C) 2009 OpenWrt.org

#update vlan info to config -- /etc/vlan.d/vlan
lock_vlan="/var/run/vlan.lock"

update_vlan_config() {
	vlan_id=$(uci get network.vlan.id)
	wan_port_1=$(brctl show br-wan | sed -n '2,1p' | awk '{print $4}')
	if [ -n $wan_port_1 ];then
		[ "$wan_port_1" == "eth0 " ] && {
			uci -c /etc/vlan.d set vlan.@switch_vlan[1].ports="0t 5t"
			uci -c /etc/vlan.d set vlan.@switch_vlan[1].vid="$vlan_id"
			wan_port_2=$(brctl show br-wan | sed -n '3,1p' | awk '{print $1}')
			[ "$wan_port_2" == "eth1 " ] && {
				uci -c /etc/vlan.d set vlan.@switch_vlan[1].ports="0t 4t 5t"
				uci -c /etc/vlan.d set vlan.@switch_vlan[1].vid="$vlan_id"
			}
		}

		[ "$wan_port_1" == "eth1 " ] && {
			uci -c /etc/vlan.d set vlan.@switch_vlan[0].ports="0t 4t"
			uci -c /etc/vlan.d set vlan.@switch_vlan[0].vid="$vlan_id"
			wan_port_2=$(brctl show br-wan | sed -n '3,1p' | awk '{print $1}')
			# should not be here
			[ "$wan_port_2" == "eth0 " ] && {
				uci -c /etc/vlan.d set vlan.@switch_vlan[1].ports="0t 4t 5t"
				uci -c /etc/vlan.d set vlan.@switch_vlan[1].vid="$vlan_id"
			}
		}
	fi
}


setup_switch_dev() {
	config_get name "$1" name
	name="${name:-$1}"

	device_id=$(getfirm DEV_ID)
	role=$(uci get bind_device_list."$device_id".role)
	vlan_enable=$(uci get network.vlan.enable)
	if [ "$vlan_enable" == "1" -o "$vlan_enable" == "0" ];then
		[ "$vlan_enable" == "1" ] && {
			[ "$role" != "RE" ] && {
				update_vlan_config
			}
		}
	else
		uci set network.vlan=vlan
		uci set network.vlan.enable=0
		uci set network.vlan.isp_name=0
		uci set network.vlan.id=0
		uci set network_sync.vlan=vlan
		uci set network_sync.vlan.enable=0
		uci set network_sync.vlan.isp_name=0
		uci set network_sync.vlan.id=0
		uci commit network
		uci commit network_sync
		saveconfig 
	fi
	
	#set switch name
	[ -d "/sys/class/net/$name" ] && ifconfig "$name" up
	device_name=$(uci -c /etc/vlan.d get vlan.@switch[0].name)
	[ "$device_name" != "$name" ] && {
		uci -c /etc/vlan.d set vlan.@switch[0].name="$name"
		uci -c /etc/vlan.d set vlan.@switch_vlan[0].device="$name"
		uci -c /etc/vlan.d set vlan.@switch_vlan[1].device="$name"
		uci -c /etc/vlan.d set vlan.@switch_vlan[2].device="$name"
	}

	#todo uci get network vlan info -> /etc/vlan.d/vlan
	#swconfig dev "$name" load /etc/vlan.d/vlan
}

set_switch_default_fdb() {
	mac=$(getfirm MAC)
	# bind lan mac to cpu port to avoid ARP attack #
	ssdk_sh fdb entry add $mac 1 forward forward 0 yes no no no no no no no
}

setup_switch() {
    trap "" INT TERM ABRT QUIT ALRM KILL
    lock $lock_vlan

	config_load network
	config_foreach setup_switch_dev switch
	set_switch_default_fdb

    lock -u $lock_vlan
}


DEBUG_OUTOUT=1

switch_echo() {
    if [ "$DEBUG_OUTOUT" -gt 0 ]; then
            echo "${1}: ""$2"> /dev/console
        fi
}

set_wan_vlan() {

    local is_eth0_at_wan=`brctl show br-wan | grep eth0`
    local is_eth1_at_wan=`brctl show br-wan | grep eth1`

    trap "" INT TERM ABRT QUIT ALRM KILL
    lock $lock_vlan
    switch_name=$(uci -c /etc/vlan.d get vlan.@switch[0].name)
	vlan_id=$(uci get network.vlan.id)


    if [ -z "$is_eth0_at_wan" -a -z "$is_eth1_at_wan" ]; then
        switch_echo switch "no interface at br-wan"

    elif [ -z "$is_eth0_at_wan" ]; then
        switch_echo switch "eth1 at br-wan"

        uci -c /etc/vlan.d set vlan.@switch_vlan[0].vid=$vlan_id
        uci -c /etc/vlan.d set vlan.@switch_vlan[0].ports="0t 1 2 3 4t"

        uci commit -c /etc/vlan.d
        #swconfig dev $switch_name load /etc/vlan.d/vlan

    elif [ -z "$is_eth1_at_wan" ]; then
        switch_echo switch "eth0 at br-wan"

        uci -c /etc/vlan.d set vlan.@switch_vlan[1].vid=$vlan_id
        uci -c /etc/vlan.d set vlan.@switch_vlan[1].ports="0t 5t"

        uci commit -c /etc/vlan.d
        #swconfig dev $switch_name load /etc/vlan.d/vlan
    else
        switch_echo switch "both eth0 and eth1 at br-wan"

        uci -c /etc/vlan.d set vlan.@switch_vlan[0].vid="1"
        uci -c /etc/vlan.d set vlan.@switch_vlan[0].ports="0t 1 2 3 4"
        uci -c /etc/vlan.d set vlan.@switch_vlan[1].vid=$vlan_id
        uci -c /etc/vlan.d set vlan.@switch_vlan[1].ports="0t 4t 5t"

        uci commit -c /etc/vlan.d
        #swconfig dev $switch_name load /etc/vlan.d/vlan

    fi

    lock -u $lock_vlan
}


reset_wan_vlan()
{
    trap "" INT TERM ABRT QUIT ALRM KILL
    lock $lock_vlan
    switch_name=$(uci -c /etc/vlan.d get vlan.@switch[0].name)
    uci -c /etc/vlan.d set vlan.@switch_vlan[0].ports="0t 1 2 3 4"
    uci -c /etc/vlan.d set vlan.@switch_vlan[0].vid="1"
    uci -c /etc/vlan.d set vlan.@switch_vlan[1].ports="0t 5"
    uci -c /etc/vlan.d set vlan.@switch_vlan[1].vid="2"
    uci commit -c /etc/vlan.d
    #swconfig dev $switch_name load /etc/vlan.d/vlan

    lock -u $lock_vlan
}


