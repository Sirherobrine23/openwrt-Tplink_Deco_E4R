/*
 *  Atheros AR71XX/AR724X/AR913X common devices
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
#include <linux/platform_device.h>
#include <linux/serial_8250.h>
#include <linux/clk.h>
#include <linux/err.h>

#include <asm/mach-ath79/ath79.h>
#include <asm/mach-ath79/ar71xx_regs.h>
#include <asm/mach-ath79/ar933x_uart_platform.h>
#include "common.h"
#include "dev-common.h"

static struct resource ath79_uart_resources[] = {
	{
		.start	= AR71XX_UART_BASE,
		.end	= AR71XX_UART_BASE + AR71XX_UART_SIZE - 1,
		.flags	= IORESOURCE_MEM,
	},
};

#define AR71XX_UART_FLAGS (UPF_BOOT_AUTOCONF | UPF_SKIP_TEST | UPF_IOREMAP)
static struct plat_serial8250_port ath79_uart_data[] = {
	{
		.mapbase	= AR71XX_UART_BASE,
		.irq		= ATH79_MISC_IRQ_UART,
		.flags		= AR71XX_UART_FLAGS,
		.iotype		= UPIO_MEM32,
		.regshift	= 2,
	}, {
		/* terminating entry */
	}
};

static struct platform_device ath79_uart_device = {
	.name		= "serial8250",
	.id		= PLAT8250_DEV_PLATFORM,
	.resource	= ath79_uart_resources,
	.num_resources	= ARRAY_SIZE(ath79_uart_resources),
	.dev = {
		.platform_data	= ath79_uart_data
	},
};

static struct resource ar933x_uart_resources[] = {
	{
		.start	= AR933X_UART_BASE,
		.end	= AR933X_UART_BASE + AR71XX_UART_SIZE - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= ATH79_MISC_IRQ_UART,
		.end	= ATH79_MISC_IRQ_UART,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct ar933x_uart_platform_data ar933x_uart_data;
static struct platform_device ar933x_uart_device = {
	.name		= "ar933x-uart",
	.id		= -1,
	.resource	= ar933x_uart_resources,
	.num_resources	= ARRAY_SIZE(ar933x_uart_resources),
	.dev = {
		.platform_data	= &ar933x_uart_data,
	},
};

void __init ath79_register_uart(void)
{
	struct clk *clk;

	clk = clk_get(NULL, "uart");
	if (IS_ERR(clk))
		panic("unable to get UART clock, err=%ld", PTR_ERR(clk));

	if (soc_is_ar71xx())
		ath79_gpio_function_enable(AR71XX_GPIO_FUNC_UART_EN);
	else if (soc_is_ar724x())
		ath79_gpio_function_enable(AR724X_GPIO_FUNC_UART_EN);
	else if (soc_is_ar913x())
		ath79_gpio_function_enable(AR913X_GPIO_FUNC_UART_EN);
	else if (soc_is_ar933x())
		ath79_gpio_function_enable(AR933X_GPIO_FUNC_UART_EN);

	if (soc_is_ar71xx() ||
	    soc_is_ar724x() ||
	    soc_is_ar913x() ||
	    soc_is_ar934x() ||
	    soc_is_qca953x() ||
	    soc_is_qca955x()) {
		ath79_uart_data[0].uartclk = clk_get_rate(clk);
		platform_device_register(&ath79_uart_device);
	} else if (soc_is_ar933x()) {
		ar933x_uart_data.uartclk = clk_get_rate(clk);
		platform_device_register(&ar933x_uart_device);
	} else {
		BUG();
	}
}

static struct platform_device ath79_wdt_device = {
	.name		= "ath79-wdt",
	.id		= -1,
};

void __init ath79_register_wdt(void)
{
	platform_device_register(&ath79_wdt_device);
}
