/*
 *  Atheros AR7XXX/AR9XXX USB Host Controller device
 *
 *  Copyright (C) 2008-2011 Gabor Juhos <juhosg@openwrt.org>
 *  Copyright (C) 2008 Imre Kaloz <kaloz@openwrt.org>
 *
 *  Parts of this file are based on Atheros' 2.6.15 BSP
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 as published
 *  by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/usb/ehci_pdriver.h>
#include <linux/usb/ohci_pdriver.h>

#include <asm/mach-ath79/ath79.h>
#include <asm/mach-ath79/ar71xx_regs.h>
#include "common.h"
#include "dev-usb.h"

static struct resource ath79_ohci_resources[2];

static u64 ath79_ohci_dmamask = DMA_BIT_MASK(32);

static struct usb_ohci_pdata ath79_ohci_pdata = {
};

static struct platform_device ath79_ohci_device = {
	.name		= "ohci-platform",
	.id		= -1,
	.resource	= ath79_ohci_resources,
	.num_resources	= ARRAY_SIZE(ath79_ohci_resources),
	.dev = {
		.dma_mask		= &ath79_ohci_dmamask,
		.coherent_dma_mask	= DMA_BIT_MASK(32),
		.platform_data		= &ath79_ohci_pdata,
	},
};

static u64 ath79_ehci_dmamask = DMA_BIT_MASK(32);

static struct usb_ehci_pdata ath79_ehci_pdata_v1 = {
	.has_synopsys_hc_bug	= 1,
	.port_power_off		= 1,
};

static struct resource ath79_ehci0_resources[2];
struct usb_ehci_pdata ath79_ehci0_pdata_v2 = {
	.caps_offset		= 0x100,
	.has_tt			= 1,
	.port_power_off		= 1,
};
static struct platform_device ath79_ehci0_device = {
	.name		= "ehci-platform",
	.id		= 0,
	.resource	= ath79_ehci0_resources,
	.num_resources	= ARRAY_SIZE(ath79_ehci0_resources),
	.dev = {
		.dma_mask		= &ath79_ehci_dmamask,
		.coherent_dma_mask	= DMA_BIT_MASK(32),
	},
};

static struct resource ath79_ehci1_resources[2];
struct usb_ehci_pdata ath79_ehci1_pdata_v2 = {
	.caps_offset		= 0x100,
	.has_tt			= 1,
	.port_power_off		= 1,
};
static struct platform_device ath79_ehci1_device = {
	.name		= "ehci-platform",
	.id		= 1,
	.resource	= ath79_ehci1_resources,
	.num_resources	= ARRAY_SIZE(ath79_ehci1_resources),
	.dev = {
		.dma_mask		= &ath79_ehci_dmamask,
		.coherent_dma_mask	= DMA_BIT_MASK(32),
	},
};

static void __init ath79_usb_init_resource(struct resource res[2],
					   unsigned long base,
					   unsigned long size,
					   int irq)
{
	memset(res, 0, sizeof(res));

	res[0].flags = IORESOURCE_MEM;
	res[0].start = base;
	res[0].end = base + size - 1;

	res[1].flags = IORESOURCE_IRQ;
	res[1].start = irq;
	res[1].end = irq;
}

#define AR71XX_USB_RESET_MASK	(AR71XX_RESET_USB_HOST | \
				 AR71XX_RESET_USB_PHY | \
				 AR71XX_RESET_USB_OHCI_DLL)

static void __init ath79_usb_setup(void)
{
	void __iomem *usb_ctrl_base;

	ath79_device_reset_set(AR71XX_USB_RESET_MASK);
	mdelay(1000);
	ath79_device_reset_clear(AR71XX_USB_RESET_MASK);

	usb_ctrl_base = ioremap(AR71XX_USB_CTRL_BASE, AR71XX_USB_CTRL_SIZE);

	/* Turning on the Buff and Desc swap bits */
	__raw_writel(0xf0000, usb_ctrl_base + AR71XX_USB_CTRL_REG_CONFIG);

	/* WAR for HW bug. Here it adjusts the duration between two SOFS */
	__raw_writel(0x20c00, usb_ctrl_base + AR71XX_USB_CTRL_REG_FLADJ);

	iounmap(usb_ctrl_base);

	mdelay(900);

	ath79_usb_init_resource(ath79_ohci_resources, AR71XX_OHCI_BASE,
				AR71XX_OHCI_SIZE, ATH79_MISC_IRQ_OHCI);
	platform_device_register(&ath79_ohci_device);

	ath79_usb_init_resource(ath79_ehci0_resources, AR71XX_EHCI_BASE,
				AR71XX_EHCI_SIZE, ATH79_CPU_IRQ_USB);
	ath79_ehci0_device.dev.platform_data = &ath79_ehci_pdata_v1;
	platform_device_register(&ath79_ehci0_device);
}

static void __init ar7240_usb_setup(void)
{
	void __iomem *usb_ctrl_base;

	ath79_device_reset_clear(AR7240_RESET_OHCI_DLL);
	ath79_device_reset_set(AR7240_RESET_USB_HOST);

	mdelay(1000);

	ath79_device_reset_set(AR7240_RESET_OHCI_DLL);
	ath79_device_reset_clear(AR7240_RESET_USB_HOST);

	usb_ctrl_base = ioremap(AR7240_USB_CTRL_BASE, AR7240_USB_CTRL_SIZE);

	/* WAR for HW bug. Here it adjusts the duration between two SOFS */
	__raw_writel(0x3, usb_ctrl_base + AR71XX_USB_CTRL_REG_FLADJ);

	iounmap(usb_ctrl_base);

	ath79_usb_init_resource(ath79_ohci_resources, AR7240_OHCI_BASE,
				AR7240_OHCI_SIZE, ATH79_CPU_IRQ_USB);
	platform_device_register(&ath79_ohci_device);
}

static void __init ar724x_usb_setup(void)
{
	ath79_device_reset_set(AR724X_RESET_USBSUS_OVERRIDE);
	mdelay(10);

	ath79_device_reset_clear(AR724X_RESET_USB_HOST);
	mdelay(10);

	ath79_device_reset_clear(AR724X_RESET_USB_PHY);
	mdelay(10);

	ath79_usb_init_resource(ath79_ehci0_resources, AR724X_EHCI_BASE,
				AR724X_EHCI_SIZE, ATH79_CPU_IRQ_USB);
	ath79_ehci0_device.dev.platform_data = &ath79_ehci0_pdata_v2;
}

static void __init ar913x_usb_setup(void)
{
	ath79_device_reset_set(AR913X_RESET_USBSUS_OVERRIDE);
	mdelay(10);

	ath79_device_reset_clear(AR913X_RESET_USB_HOST);
	mdelay(10);

	ath79_device_reset_clear(AR913X_RESET_USB_PHY);
	mdelay(10);

	ath79_usb_init_resource(ath79_ehci0_resources, AR913X_EHCI_BASE,
				AR913X_EHCI_SIZE, ATH79_CPU_IRQ_USB);
	ath79_ehci0_device.dev.platform_data = &ath79_ehci0_pdata_v2;
}

static void __init ar933x_usb_setup(void)
{
	ath79_device_reset_set(AR933X_RESET_USBSUS_OVERRIDE);
	mdelay(10);

	ath79_device_reset_clear(AR933X_RESET_USB_HOST);
	mdelay(10);

	ath79_device_reset_clear(AR933X_RESET_USB_PHY);
	mdelay(10);

	ath79_usb_init_resource(ath79_ehci0_resources, AR933X_EHCI_BASE,
				AR933X_EHCI_SIZE, ATH79_CPU_IRQ_USB);
	ath79_ehci0_device.dev.platform_data = &ath79_ehci0_pdata_v2;
}

static void __init ar934x_usb_setup(void)
{
	u32 bootstrap;

	bootstrap = ath79_reset_rr(AR934X_RESET_REG_BOOTSTRAP);
	if (bootstrap & AR934X_BOOTSTRAP_USB_MODE_DEVICE)
		return;

	ath79_device_reset_set(AR934X_RESET_USBSUS_OVERRIDE);
	udelay(1000);

	ath79_device_reset_clear(AR934X_RESET_USB_PHY);
	udelay(1000);

	ath79_device_reset_clear(AR934X_RESET_USB_PHY_ANALOG);
	udelay(1000);

	ath79_device_reset_clear(AR934X_RESET_USB_HOST);
	udelay(1000);

	ath79_usb_init_resource(ath79_ehci0_resources, AR934X_EHCI_BASE,
				AR934X_EHCI_SIZE, ATH79_CPU_IRQ_USB);
	ath79_ehci0_device.dev.platform_data = &ath79_ehci0_pdata_v2;
}

static void __init qca953x_usb_setup(void)
{
	u32 bootstrap;

	bootstrap = ath79_reset_rr(QCA953X_RESET_REG_BOOTSTRAP);

	ath79_device_reset_set(QCA953X_RESET_USBSUS_OVERRIDE);
	udelay(1000);

	ath79_device_reset_clear(QCA953X_RESET_USB_PHY);
	udelay(1000);

	ath79_device_reset_clear(QCA953X_RESET_USB_PHY_ANALOG);
	udelay(1000);

	ath79_device_reset_clear(QCA953X_RESET_USB_HOST);
	udelay(1000);

	ath79_usb_init_resource(ath79_ehci0_resources, QCA953X_EHCI_BASE,
				QCA953X_EHCI_SIZE, ATH79_CPU_IRQ_USB);
	ath79_ehci0_device.dev.platform_data = &ath79_ehci0_pdata_v2;
}

static void __init qca955x_usb_setup(u32 id)
{
	if (!id) {
		ath79_usb_init_resource(ath79_ehci0_resources,
				QCA955X_EHCI0_BASE, QCA955X_EHCI_SIZE,
				ATH79_IP3_IRQ(0));
		ath79_ehci0_device.dev.platform_data = &ath79_ehci0_pdata_v2;
	} else {
		ath79_usb_init_resource(ath79_ehci1_resources,
				QCA955X_EHCI1_BASE, QCA955X_EHCI_SIZE,
				ATH79_IP3_IRQ(1));
		ath79_ehci1_device.dev.platform_data = &ath79_ehci1_pdata_v2;
	}
}

void ath79_init_usb_pdata(void)
{
	if (soc_is_ar7241() || soc_is_ar7242())
		ar724x_usb_setup();
	else if (soc_is_ar913x())
		ar913x_usb_setup();
	else if (soc_is_ar933x())
		ar933x_usb_setup();
	else if (soc_is_ar934x())
		ar934x_usb_setup();
	else if (soc_is_qca953x())
		qca953x_usb_setup();
	else if (soc_is_qca955x()) {
		qca955x_usb_setup(0);
		qca955x_usb_setup(1);
	} else
		BUG();
}

void __init ath79_register_usb(void)
{
	if (soc_is_ar71xx())
		ath79_usb_setup();
	else if (soc_is_ar7240())
		ar7240_usb_setup();
	else {
		ath79_init_usb_pdata();
		platform_device_register(&ath79_ehci0_device);

		if (soc_is_qca955x())
			platform_device_register(&ath79_ehci1_device);
	}
}
