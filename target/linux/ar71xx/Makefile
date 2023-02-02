#
# Copyright (c) 2013 The Linux Foundation. All rights reserved.
# Copyright (C) 2008-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

ARCH:=mips
BOARD:=ar71xx
BOARDNAME:=Atheros AR7xxx/AR9xxx
FEATURES:=squashfs jffs2 targz jffs2_nand
CFLAGS:=-Os -pipe -mips32r2 -mtune=74kc -fno-caller-saves -freorder-blocks
SUBTARGETS:=generic nand

#LINUX_VERSION:=3.3.8

LINUX_SRC_VERSION:=$(shell basename $(TOPDIR)/qca/src/linux-*.* | sed 's/[^0-9.]*\([0-9.]*\).*/\1/')

CONFIG_EXTERNAL_KERNEL_TREE=$(shell \
      grep -q CONFIG_EXTERNAL_KERNEL_TREE="[^\/]*.\/" $(TOPDIR)/.config && \
      sed -n 's,CONFIG_EXTERNAL_KERNEL_TREE="\(.*\)",\1,p' $(TOPDIR)/.config || \
      echo '$(TOPDIR)/qca/src/linux-$(LINUX_SRC_VERSION)')
$(eval _LINUX_DIR:=$(CONFIG_EXTERNAL_KERNEL_TREE))
$(shell touch $(_LINUX_DIR)/.scmversion)
_LINUX_MAJOR:=$(shell sed -n 's,VERSION = \([0-9]*\)$$,\1,p' $(_LINUX_DIR)/Makefile)
_LINUX_MINOR:=$(shell sed -n 's,PATCHLEVEL = \([0-9]*\)$$,\1,p' $(_LINUX_DIR)/Makefile)
_LINUX_SUBLEVEL:=$(shell sed -n 's,SUBLEVEL = \([0-9]*\)$$,\1,p' $(_LINUX_DIR)/Makefile)
_LINUX_EXTRAVERSION:=$(shell sed -n 's,EXTRAVERSION = \([-rc0-9]*\)$$,\1,p' $(_LINUX_DIR)/Makefile)
LINUX_VERSION:=$(_LINUX_MAJOR).$(_LINUX_MINOR)$(if $(_LINUX_SUBLEVEL),.$(_LINUX_SUBLEVEL))$(if $(_LINUX_EXTRAVERSION),$(_LINUX_EXTRAVERSION))

include $(INCLUDE_DIR)/target.mk

DEFAULT_PACKAGES += \
	kmod-leds-gpio kmod-gpio-button-hotplug kmod-wdt-ath79 swconfig \
	kmod-ledtrig-default-on kmod-ledtrig-timer kmod-ledtrig-netdev \
	kmod-button-hotplug kmod-ath9k wpad-mini uboot-envtools

define Target/Description
	Build firmware images for Atheros AR7xxx/AR9xxx based boards.
endef

$(eval $(call BuildTarget))
