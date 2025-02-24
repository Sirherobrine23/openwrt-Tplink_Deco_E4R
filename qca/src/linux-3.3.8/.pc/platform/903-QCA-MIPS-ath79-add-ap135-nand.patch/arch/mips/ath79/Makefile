#
# Makefile for the Atheros AR71XX/AR724X/AR913X specific parts of the kernel
#
# Copyright (c) 2013 The Linux Foundation. All rights reserved.
# Copyright (C) 2008-2011 Gabor Juhos <juhosg@openwrt.org>
# Copyright (C) 2008 Imre Kaloz <kaloz@openwrt.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.

obj-y	:= prom.o setup.o irq.o common.o clock.o gpio.o

obj-$(CONFIG_EARLY_PRINTK)		+= early_printk.o
obj-$(CONFIG_PCI)			+= pci.o

#
# Devices
#
obj-y					+= dev-common.o
obj-$(CONFIG_ATH79_DEV_AP9X_PCI)	+= dev-ap9x-pci.o
obj-$(CONFIG_ATH79_DEV_AUDIO)		+= dev-audio.o
obj-$(CONFIG_ATH79_DEV_DSA)		+= dev-dsa.o
obj-$(CONFIG_ATH79_DEV_ETH)		+= dev-eth.o
obj-$(CONFIG_ATH79_DEV_GPIO_BUTTONS)	+= dev-gpio-buttons.o
obj-$(CONFIG_ATH79_DEV_LEDS_GPIO)	+= dev-leds-gpio.o
obj-$(CONFIG_ATH79_DEV_M25P80)		+= dev-m25p80.o
obj-$(CONFIG_ATH79_DEV_NAND)		+= dev-nand.o
obj-$(CONFIG_ATH79_DEV_NFC)		+= dev-nfc.o
obj-$(CONFIG_ATH79_DEV_SPI)		+= dev-spi.o
obj-$(CONFIG_ATH79_DEV_I2C)		+= dev-i2c.o
obj-$(CONFIG_ATH79_DEV_USB)		+= dev-usb.o
obj-$(CONFIG_ATH79_DEV_WMAC)		+= dev-wmac.o

#
# Miscellaneous objects
#
obj-$(CONFIG_ATH79_NAND_CALDATA_FIXUP)	+= nand-caldata-fixup.o
obj-$(CONFIG_ATH79_NVRAM)		+= nvram.o
obj-$(CONFIG_ATH79_PCI_ATH9K_FIXUP)	+= pci-ath9k-fixup.o
obj-$(CONFIG_ATH79_ROUTERBOOT)		+= routerboot.o

#
# Machines
#
obj-$(CONFIG_ATH79_MACH_ALFA_AP96)	+= mach-alfa-ap96.o
obj-$(CONFIG_ATH79_MACH_ALFA_NX)	+= mach-alfa-nx.o
obj-$(CONFIG_ATH79_MACH_ALL0258N)	+= mach-all0258n.o
obj-$(CONFIG_ATH79_MACH_ALL0315N)	+= mach-all0315n.o
obj-$(CONFIG_ATH79_MACH_AP113)		+= mach-ap113.o
obj-$(CONFIG_ATH79_MACH_AP121)		+= mach-ap121.o
obj-$(CONFIG_ATH79_MACH_AP135)		+= mach-ap135.o
obj-$(CONFIG_ATH79_MACH_AP136)		+= mach-ap136.o
obj-$(CONFIG_ATH79_MACH_AP143)		+= mach-ap143.o
obj-$(CONFIG_ATH79_MACH_AP147)		+= mach-ap147.o
obj-$(CONFIG_ATH79_MACH_AP151)		+= mach-ap151.o
obj-$(CONFIG_ATH79_MACH_AP152)		+= mach-ap152.o
obj-$(CONFIG_ATH79_MACH_AP81)		+= mach-ap81.o
obj-$(CONFIG_ATH79_MACH_AP83)		+= mach-ap83.o
obj-$(CONFIG_ATH79_MACH_AP96)		+= mach-ap96.o
obj-$(CONFIG_ATH79_MACH_AW_NR580)	+= mach-aw-nr580.o
obj-$(CONFIG_ATH79_MACH_CAP4200AG)	+= mach-cap4200ag.o
obj-$(CONFIG_ATH79_MACH_CUS227)		+= mach-cus227.o
obj-$(CONFIG_ATH79_MACH_DB120)		+= mach-db120.o
obj-$(CONFIG_ATH79_MACH_DB120_TB388)	+= mach-db120-tb388.o
obj-$(CONFIG_ATH79_MACH_DIR_600_A1)	+= mach-dir-600-a1.o
obj-$(CONFIG_ATH79_MACH_DIR_615_C1)	+= mach-dir-615-c1.o
obj-$(CONFIG_ATH79_MACH_DIR_825_B1)	+= mach-dir-825-b1.o
obj-$(CONFIG_ATH79_MACH_EW_DORIN)	+= mach-ew-dorin.o
obj-$(CONFIG_ATH79_MACH_EAP7660D)	+= mach-eap7660d.o
obj-$(CONFIG_ATH79_MACH_JA76PF)		+= mach-ja76pf.o
obj-$(CONFIG_ATH79_MACH_JWAP003)	+= mach-jwap003.o
obj-$(CONFIG_ATH79_MACH_HORNET_UB)	+= mach-hornet-ub.o
obj-$(CONFIG_ATH79_MACH_MR600)		+= mach-mr600.o
obj-$(CONFIG_ATH79_MACH_MZK_W04NU)	+= mach-mzk-w04nu.o
obj-$(CONFIG_ATH79_MACH_MZK_W300NH)	+= mach-mzk-w300nh.o
obj-$(CONFIG_ATH79_MACH_NBG460N)	+= mach-nbg460n.o
obj-$(CONFIG_ATH79_MACH_OM2P)		+= mach-om2p.o
obj-$(CONFIG_ATH79_MACH_PB42)		+= mach-pb42.o
obj-$(CONFIG_ATH79_MACH_PB44)		+= mach-pb44.o
obj-$(CONFIG_ATH79_MACH_PB92)		+= mach-pb92.o
obj-$(CONFIG_ATH79_MACH_RB4XX)		+= mach-rb4xx.o
obj-$(CONFIG_ATH79_MACH_RB750)		+= mach-rb750.o
obj-$(CONFIG_ATH79_MACH_RB2011)		+= mach-rb2011.o
obj-$(CONFIG_ATH79_MACH_RUBBERDUCK)	+= mach-rubberduck.o
obj-$(CONFIG_ATH79_MACH_RW2458N)	+= mach-rw2458n.o
obj-$(CONFIG_ATH79_MACH_TEW_632BRP)	+= mach-tew-632brp.o
obj-$(CONFIG_ATH79_MACH_TEW_673GRU)	+= mach-tew-673gru.o
obj-$(CONFIG_ATH79_MACH_TEW_712BR)	+= mach-tew-712br.o
obj-$(CONFIG_ATH79_MACH_TL_MR11U)	+= mach-tl-mr11u.o
obj-$(CONFIG_ATH79_MACH_TL_MR3020)	+= mach-tl-mr3020.o
obj-$(CONFIG_ATH79_MACH_TL_MR3X20)	+= mach-tl-mr3x20.o
obj-$(CONFIG_ATH79_MACH_TL_WA901ND)	+= mach-tl-wa901nd.o
obj-$(CONFIG_ATH79_MACH_TL_WA901ND_V2)	+= mach-tl-wa901nd-v2.o
obj-$(CONFIG_ATH79_MACH_TL_WDR4300)     += mach-tl-wdr4300.o
obj-$(CONFIG_ATH79_MACH_TL_WR741ND)	+= mach-tl-wr741nd.o
obj-$(CONFIG_ATH79_MACH_TL_WR741ND_V4)	+= mach-tl-wr741nd-v4.o
obj-$(CONFIG_ATH79_MACH_TL_WR841N_V1)	+= mach-tl-wr841n.o
obj-$(CONFIG_ATH79_MACH_TL_WR841N_V8)	+= mach-tl-wr841n-v8.o
obj-$(CONFIG_ATH79_MACH_TL_WR941ND)	+= mach-tl-wr941nd.o
obj-$(CONFIG_ATH79_MACH_TL_WR1041N_V2)	+= mach-tl-wr1041n-v2.o
obj-$(CONFIG_ATH79_MACH_TL_WR1043ND)	+= mach-tl-wr1043nd.o
obj-$(CONFIG_ATH79_MACH_TL_WR2543N)	+= mach-tl-wr2543n.o
obj-$(CONFIG_ATH79_MACH_TL_WR703N)	+= mach-tl-wr703n.o
obj-$(CONFIG_ATH79_MACH_UBNT)		+= mach-ubnt.o
obj-$(CONFIG_ATH79_MACH_UBNT_XM)	+= mach-ubnt-xm.o
obj-$(CONFIG_ATH79_MACH_WHR_HP_G300N)	+= mach-whr-hp-g300n.o
obj-$(CONFIG_ATH79_MACH_WLAE_AG300N)	+= mach-wlae-ag300n.o
obj-$(CONFIG_ATH79_MACH_WNDR3700)	+= mach-wndr3700.o
obj-$(CONFIG_ATH79_MACH_WNR2000)	+= mach-wnr2000.o
obj-$(CONFIG_ATH79_MACH_WP543)		+= mach-wp543.o
obj-$(CONFIG_ATH79_MACH_WPE72)		+= mach-wpe72.o
obj-$(CONFIG_ATH79_MACH_WRT160NL)	+= mach-wrt160nl.o
obj-$(CONFIG_ATH79_MACH_WRT400N)	+= mach-wrt400n.o
obj-$(CONFIG_ATH79_MACH_WZR_HP_G300NH)	+= mach-wzr-hp-g300nh.o
obj-$(CONFIG_ATH79_MACH_WZR_HP_G300NH2)	+= mach-wzr-hp-g300nh2.o
obj-$(CONFIG_ATH79_MACH_WZR_HP_AG300H)	+= mach-wzr-hp-ag300h.o
obj-$(CONFIG_ATH79_MACH_WZR_HP_G450H)	+= mach-wzr-hp-g450h.o
obj-$(CONFIG_ATH79_MACH_ZCN_1523H)	+= mach-zcn-1523h.o

