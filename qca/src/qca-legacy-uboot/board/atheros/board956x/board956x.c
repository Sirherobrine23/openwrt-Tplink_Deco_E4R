/* 
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 */

#include <common.h>
#include <command.h>
#include <asm/mipsregs.h>
#include <asm/addrspace.h>
#include <config.h>
#include <version.h>
#include <atheros.h>

extern int ath_ddr_initial_config(uint32_t refresh);
extern int ath_ddr_find_size(void);

#ifdef COMPRESSED_UBOOT
#	define prmsg(...)
#	define args		char *s
#	define board_str(a)	do {			\
	char ver[] = "0";				\
	strcpy(s, a " - Dragonfly 1.");			\
	ver[0] += ath_reg_rd(RST_REVISION_ID_ADDRESS)	\
						& 0xf;	\
	strcat(s, ver);					\
} while (0)
#else
#	define prmsg	printf
#	define args		void
#	define board_str(a)				\
	printf(a " - Dragonfly 1.%d", ath_reg_rd		\
			(RST_REVISION_ID_ADDRESS) & 0xf)
#endif

void
ath_usb1_initial_config(void)
{
#define unset(a)	(~(a))

	ath_reg_wr_nf(SWITCH_CLOCK_SPARE_ADDRESS,
		ath_reg_rd(SWITCH_CLOCK_SPARE_ADDRESS) |
		SWITCH_CLOCK_SPARE_USB_REFCLK_FREQ_SEL_SET(5));
	udelay(1000);

	ath_reg_rmw_set(RST_RESET_ADDRESS,
				RST_RESET_USB_PHY_SUSPEND_OVERRIDE_SET(1));
	udelay(1000);
	ath_reg_rmw_clear(RST_RESET_ADDRESS, RST_RESET_USB_PHY_RESET_SET(1));
	udelay(1000);
	ath_reg_rmw_clear(RST_RESET_ADDRESS, RST_RESET_USB_PHY_ARESET_SET(1));
	udelay(1000);
	ath_reg_rmw_clear(RST_RESET_ADDRESS, RST_RESET_USB_HOST_RESET_SET(1));
	udelay(1000);

	ath_reg_rmw_clear(RST_RESET_ADDRESS, RST_RESET_USB_PHY_PLL_PWD_EXT_SET(1));
	udelay(10);

	ath_reg_rmw_set(RST_RESET2_ADDRESS, RST_RESET2_USB1_EXT_PWR_SEQ_SET(1));
	udelay(10);
}

void
ath_usb2_initial_config(void)
{
	if (is_drqfn()) {
		return;
	}

	ath_reg_rmw_set(RST_RESET2_ADDRESS, RST_RESET2_USB2_MODE_SET(1));
	udelay(10);
	ath_reg_rmw_set(RST_RESET2_ADDRESS,
				RST_RESET2_USB_PHY2_SUSPEND_OVERRIDE_SET(1));
	udelay(1000);
	ath_reg_rmw_clear(RST_RESET2_ADDRESS, RST_RESET2_USB_PHY2_RESET_SET(1));
	udelay(1000);
	ath_reg_rmw_clear(RST_RESET2_ADDRESS, RST_RESET2_USB_PHY2_ARESET_SET(1));
	udelay(1000);
	ath_reg_rmw_clear(RST_RESET2_ADDRESS, RST_RESET2_USB_HOST2_RESET_SET(1));
	udelay(1000);

	ath_reg_rmw_clear(RST_RESET2_ADDRESS, RST_RESET2_USB_PHY2_PLL_PWD_EXT_SET(1));
	udelay(10);

	ath_reg_rmw_set(RST_RESET2_ADDRESS, RST_RESET2_USB2_EXT_PWR_SEQ_SET(1));
	udelay(10);
}


void ath_gpio_config(void)
{
#if defined(CONFIG_CUS249)
    /* Turn on System LED GPIO18 for CUS249 */
    ath_reg_rmw_clear(GPIO_OUT_ADDRESS, (1 << 18));
#endif

#if defined(CONFIG_PRODUCT_E4)
 	ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 1));//e4 red
 	ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 21));//e4 green
 	ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 2));//e4 green
 	ath_reg_rmw_clear(GPIO_OUT_ADDRESS, (1 << 1) + (1 << 21));//e4 red
 	ath_reg_rmw_set(GPIO_OUT_ADDRESS, (1 << 2));//e4 red
#else
 	/* turn on gpio for deco_m4 led  */
 	ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 1));//red
 	ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 7));//green
#endif

 //ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 9)); //blue

	/* Turn off JUMPST_LED and 5Gz LED during bootup */
//	ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 15));
//	ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 12));
}

int
ath_mem_config(void)
{
	unsigned int type, reg32, *tap;
	extern uint32_t *ath_ddr_tap_cal(void);

#if !defined(CONFIG_ATH_EMULATION)

#if !defined(CONFIG_ATH_NAND_BR)
	type = ath_ddr_initial_config(CFG_DDR_REFRESH_VAL);
	tap = ath_ddr_tap_cal();
//	tap = (uint32_t *)0xbd001f10;
//	prmsg("Tap (low, high) = (0x%x, 0x%x)\n", tap[0], tap[1]);

	tap = (uint32_t *)TAP_CONTROL_0_ADDRESS;
	prmsg("Tap values = (0x%x, 0x%x, 0x%x, 0x%x)\n",
		tap[0], tap[1], tap[2], tap[3]);

	/* Take WMAC out of reset */
	reg32 = ath_reg_rd(RST_RESET_ADDRESS);
	reg32 = reg32 & ~RST_RESET_RTC_RESET_SET(1);
	ath_reg_wr_nf(RST_RESET_ADDRESS, reg32);
#endif

#if defined(CONFIG_USB)
	ath_usb1_initial_config();
	ath_usb2_initial_config();
#else
    //turn off not support interface register
    reg32 = ath_reg_rd(RST_RESET_ADDRESS);
    reg32 = reg32 | RST_RESET_USB_PHY_PLL_PWD_EXT_SET(1);
    ath_reg_wr_nf(RST_RESET_ADDRESS, reg32);
    reg32 = ath_reg_rd(RST_CLKGAT_EN_ADDRESS);
    reg32 = reg32 & ~(RST_CLKGAT_EN_PCIE_EP_SET(1) | RST_CLKGAT_EN_PCIE_RC_SET(1) |
            RST_CLKGAT_EN_PCIE_RC2_SET(1) | RST_CLKGAT_EN_CLK100_PCIERC_SET(1) | 
            RST_CLKGAT_EN_CLK100_PCIERC2_SET(1) | RST_CLKGAT_EN_USB1_SET(1) |
            RST_CLKGAT_EN_USB2_SET(1));
    ath_reg_wr_nf(RST_CLKGAT_EN_ADDRESS, reg32);
    reg32 = ath_reg_rd(RST_RESET2_ADDRESS);
    reg32 = reg32 | RST_RESET2_USB_PHY2_PLL_PWD_EXT_SET(1);
    ath_reg_wr_nf(RST_RESET2_ADDRESS, reg32);

    ath_reg_wr_nf(BIAS4_ADDRESS, 0x6df6ffe0);
    ath_reg_wr_nf(BIAS5_ADDRESS, 0x7ffffffe);
#endif

	ath_gpio_config();
#endif /* !defined(CONFIG_ATH_EMULATION) */

	return ath_ddr_find_size();
}

long int initdram(int board_type)
{
	return (ath_mem_config());
}

int	checkboard(args)
{
	board_str(CONFIG_BOARD_NAME);
	return 0;
}
