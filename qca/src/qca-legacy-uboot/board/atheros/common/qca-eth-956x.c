/* 
 * Copyright (c) 2014, 2016 The Linux Foundation. All rights reserved.
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

#include <config.h>
#include <common.h>
#include <malloc.h>
#include <net.h>
#include <command.h>
#include <asm/io.h>
#include <asm/addrspace.h>
#include <asm/types.h>

#ifdef CONFIG_ATH_NAND_BR
#include <nand.h>
#endif

#include <atheros.h>
#include "qca-eth-956x.h"
#include "qca-eth-956x_phy.h"
#define SGMII_LINK_WAR_MAX_TRY 10

#if (CONFIG_COMMANDS & CFG_CMD_MII)
#include <miiphy.h>
#endif
#define ath_gmac_unit2mac(_unit)     ath_gmac_macs[(_unit)]
#define ath_gmac_name2mac(name)	   is_drqfn() ? ath_gmac_unit2mac(1):strcmp(name,"eth0") ? ath_gmac_unit2mac(1) : ath_gmac_unit2mac(0)

int ath_gmac_miiphy_read(char *devname, uint32_t phaddr, uint8_t reg, uint16_t *data);
int ath_gmac_miiphy_write(char *devname, uint32_t phaddr, uint8_t reg, uint16_t data);

#ifndef CFG_ATH_GMAC_NMACS
#define CFG_ATH_GMAC_NMACS	1
#endif /* CFG_ATH_GMAC_NMACS */

ath_gmac_mac_t *ath_gmac_macs[CFG_ATH_GMAC_NMACS];


#ifdef CONFIG_VIR_PHY
extern int athr_vir_phy_setup(int unit);
extern int athr_vir_phy_is_up(int unit);
extern int athr_vir_phy_is_fdx(int unit);
extern int athr_vir_phy_speed(int unit);
extern void athr_vir_reg_init(void);
#endif

#ifdef  CONFIG_ATHRS17_PHY
extern void athrs17_reg_init(void);
extern void athrs17_reg_init_wan(void);
#endif

#ifdef CFG_ATHRS27_PHY
extern void athrs27_reg_init();
extern void athrs27_reg_init_lan();
#endif


#ifdef CONFIG_ATH_NAND_BR

#define ATH_ETH_MAC_READ_SIZE 4096
extern unsigned long long
ath_nand_get_cal_offset(const char *ba);
#endif

static int
ath_gmac_send(struct eth_device *dev, volatile void *packet, int length)
{
	int i;

	ath_gmac_mac_t *mac = (ath_gmac_mac_t *)dev->priv;

	ath_gmac_desc_t *f = mac->fifo_tx[mac->next_tx];

	f->pkt_size = length;
	f->res1 = 0;
	f->pkt_start_addr = virt_to_phys(packet);

	ath_gmac_tx_give_to_dma(f);
	flush_cache((u32) packet, length);
	ath_gmac_reg_wr(mac, ATH_DMA_TX_DESC, virt_to_phys(f));
	ath_gmac_reg_wr(mac, ATH_DMA_TX_CTRL, ATH_TXE);

	for (i = 0; i < MAX_WAIT; i++) {
		udelay(10);
		if (!ath_gmac_tx_owned_by_dma(f))
			break;
	}
	if (i == MAX_WAIT)
		printf("Tx Timed out\n");

	f->pkt_start_addr = 0;
	f->pkt_size = 0;

	if (++mac->next_tx >= NO_OF_TX_FIFOS)
		mac->next_tx = 0;

	return (0);
}

static int ath_gmac_recv(struct eth_device *dev)
{
	int length;
	ath_gmac_desc_t *f;
	ath_gmac_mac_t *mac;
    	volatile int dmaed_pkt=0;
	int count = 0;

	mac = (ath_gmac_mac_t *)dev->priv;

	for (;;) {
	     f = mac->fifo_rx[mac->next_rx];
        if (ath_gmac_rx_owned_by_dma(f)) { 
	 /* check if the current Descriptor is_empty is 1,But the DMAed count is not-zero 
	    then move to desciprot where the packet is available */ 
	   dmaed_pkt = (ath_gmac_reg_rd(mac, 0x194) >> 16);
            if (!dmaed_pkt) {
	        break ;
              } else {  
                if (f->is_empty == 1) {
                    while ( count < NO_OF_RX_FIFOS ) {
                        if (++mac->next_rx >= NO_OF_RX_FIFOS) {
                            mac->next_rx = 0;
                        }
                        f = mac->fifo_rx[mac->next_rx];
                        /*
                         * Break on valid data in the desc by checking
                         *  empty bit.
                         */
                        if (!f->is_empty){
                            count = 0;
                            break;
                        }
                        count++;
                    }
               }
            } 
	} 
 
		length = f->pkt_size;

		NetReceive(NetRxPackets[mac->next_rx] , length - 4);
		flush_cache((u32) NetRxPackets[mac->next_rx] , PKTSIZE_ALIGN);

		ath_gmac_reg_wr(mac,0x194,1);
		ath_gmac_rx_give_to_dma(f);

		if (++mac->next_rx >= NO_OF_RX_FIFOS)
			mac->next_rx = 0;
	}

	if (!(ath_gmac_reg_rd(mac, ATH_DMA_RX_CTRL))) {
		ath_gmac_reg_wr(mac, ATH_DMA_RX_DESC, virt_to_phys(f));
		ath_gmac_reg_wr(mac, ATH_DMA_RX_CTRL, 1);
	}

	return (0);
}

void ath_gmac_mii_setup(ath_gmac_mac_t *mac)
{
	u32 mgmt_cfg_val;


	if (RST_BOOTSTRAP_REF_CLK_GET(ath_reg_rd(RST_BOOTSTRAP_ADDRESS))) {
		//40Mhz
		ath_reg_wr(SWITCH_CLOCK_SPARE_ADDRESS, 0x45500);
	} else {
		//25Mhz
		ath_reg_wr(SWITCH_CLOCK_SPARE_ADDRESS, 0xc5200);
	}

	if (is_s27() && (mac->mac_unit == 0)) {
		printf("Dragonfly----> S27 PHY *\n");
	
		ath_reg_wr(ETH_XMII_ADDRESS, ETH_XMII_TX_INVERT_SET(1) |
						ETH_XMII_RX_DELAY_SET(2) |
						ETH_XMII_TX_DELAY_SET(1) |
						ETH_XMII_GIGE_SET(1));

       	mgmt_cfg_val = 7;
		udelay(1000);
		ath_gmac_reg_wr(mac, ATH_MAC_MII_MGMT_CFG, mgmt_cfg_val | (1 << 31));
		udelay(1000);
		ath_gmac_reg_wr(mac, ATH_MAC_MII_MGMT_CFG, mgmt_cfg_val);

		//GMAC1 need to set for MDC/MDIO Works
		udelay(1000);
		ath_gmac_reg_wr(ath_gmac_macs[1], ATH_MAC_MII_MGMT_CFG, mgmt_cfg_val | (1 << 31));
		udelay(1000);
		ath_gmac_reg_wr(ath_gmac_macs[1], ATH_MAC_MII_MGMT_CFG, mgmt_cfg_val);
		
		return;
	}

	if ( CFG_ATH_GMAC_NMACS == 1){
		printf("Dragonfly  ----> S17 PHY *\n");
		mgmt_cfg_val = 7;

		ath_reg_wr(ATH_ETH_CFG, ETH_CFG_ETH_RXDV_DELAY_SET(3) |
					ETH_CFG_ETH_RXD_DELAY_SET(3)|
					ETH_CFG_RGMII_GE0_SET(1) |
					ETH_CFG_GE0_SGMII_SET(1) );

		ath_reg_wr(ETH_XMII_ADDRESS, ETH_XMII_TX_INVERT_SET(1) |
                			     ETH_XMII_RX_DELAY_SET(2)  |
                			     ETH_XMII_TX_DELAY_SET(1)  |
					     ETH_XMII_GIGE_SET(1));

		udelay(1000);
		ath_gmac_reg_wr(mac, ATH_MAC_MII_MGMT_CFG, mgmt_cfg_val | (1 << 31));
		ath_gmac_reg_wr(mac, ATH_MAC_MII_MGMT_CFG, mgmt_cfg_val);
		return;		
	}

}

void
athrs_sgmii_res_cal(void)
{
	unsigned int read_data;
	unsigned int reversed_sgmii_value;
	unsigned int i=0;
	unsigned int vco_fast,vco_slow;
	unsigned int startValue=0, endValue=0;

	ath_reg_wr(ETH_SGMII_SERDES_ADDRESS,
			ETH_SGMII_SERDES_EN_LOCK_DETECT_MASK |
			ETH_SGMII_SERDES_EN_PLL_MASK);

	read_data = ath_reg_rd(SGMII_SERDES_ADDRESS);

	vco_fast = SGMII_SERDES_VCO_FAST_GET(read_data);
	vco_slow = SGMII_SERDES_VCO_SLOW_GET(read_data);
	/* set resistor Calibration from 0000 -> 1111 */
	for (i=0; i < 0x10; i++)
	{
		read_data = (ath_reg_rd(SGMII_SERDES_ADDRESS) &
					~SGMII_SERDES_RES_CALIBRATION_MASK) |
				SGMII_SERDES_RES_CALIBRATION_SET(i);	
		ath_reg_wr(SGMII_SERDES_ADDRESS, read_data);

		udelay(50);

		read_data = ath_reg_rd(SGMII_SERDES_ADDRESS);
		if ((vco_fast != SGMII_SERDES_VCO_FAST_GET(read_data)) ||
			(vco_slow != SGMII_SERDES_VCO_SLOW_GET(read_data)) ){
			if (startValue == 0){
				startValue=endValue=i;
			}else{
				endValue=i;
			}
		}
		vco_fast = SGMII_SERDES_VCO_FAST_GET(read_data);
		vco_slow = SGMII_SERDES_VCO_SLOW_GET(read_data);		
	}
	
	if (startValue == 0){
		/* No boundary found, use middle value for resistor calibration value */
		reversed_sgmii_value = 0x7;
	}else{
		/* get resistor calibration from the middle of boundary */
		reversed_sgmii_value = (startValue + endValue)/2; 
	}

	read_data = (ath_reg_rd(SGMII_SERDES_ADDRESS) &
				~SGMII_SERDES_RES_CALIBRATION_MASK) |
			SGMII_SERDES_RES_CALIBRATION_SET(reversed_sgmii_value);

	ath_reg_wr(SGMII_SERDES_ADDRESS, read_data);


	ath_reg_wr(ETH_SGMII_SERDES_ADDRESS,
			ETH_SGMII_SERDES_EN_LOCK_DETECT_MASK |
			/*ETH_SGMII_SERDES_PLL_REFCLK_SEL_MASK |*/
			ETH_SGMII_SERDES_EN_PLL_MASK);

	ath_reg_rmw_set(SGMII_SERDES_ADDRESS,
			SGMII_SERDES_CDR_BW_SET(3) |
			SGMII_SERDES_TX_DR_CTRL_SET(1) |
			SGMII_SERDES_PLL_BW_SET(1) |
			SGMII_SERDES_EN_SIGNAL_DETECT_SET(1) |
			SGMII_SERDES_FIBER_SDO_SET(1) |
			SGMII_SERDES_VCO_REG_SET(3));

	ath_reg_rmw_clear(RST_RESET_ADDRESS, RST_RESET_ETH_SGMII_ARESET_MASK);
	udelay(25);
	ath_reg_rmw_clear(RST_RESET_ADDRESS, RST_RESET_ETH_SGMII_RESET_MASK);

	while (!(ath_reg_rd(SGMII_SERDES_ADDRESS) & SGMII_SERDES_LOCK_DETECT_STATUS_MASK));
}


static void athr_gmac_sgmii_setup()
{
	int status = 0, count = 0;

#ifdef ATH_SGMII_FORCED_MODE
        ath_reg_wr(MR_AN_CONTROL_ADDRESS, MR_AN_CONTROL_SPEED_SEL1_SET(1) |
                                           MR_AN_CONTROL_PHY_RESET_SET(1)  |
                                           MR_AN_CONTROL_DUPLEX_MODE_SET(1));
        udelay(10);

        ath_reg_wr(SGMII_CONFIG_ADDRESS, SGMII_CONFIG_MODE_CTRL_SET(2)   |
                                          SGMII_CONFIG_FORCE_SPEED_SET(1) |
                                          SGMII_CONFIG_SPEED_SET(2));

        printf ("SGMII in forced mode\n");
#else

	ath_reg_wr(SGMII_CONFIG_ADDRESS, SGMII_CONFIG_MODE_CTRL_SET(2));

	ath_reg_wr(MR_AN_CONTROL_ADDRESS, MR_AN_CONTROL_AN_ENABLE_SET(1)
                                      |MR_AN_CONTROL_PHY_RESET_SET(1));

	ath_reg_wr(MR_AN_CONTROL_ADDRESS, MR_AN_CONTROL_AN_ENABLE_SET(1));
#endif
/*
 * SGMII reset sequence suggested by systems team.
 */

	ath_reg_wr(SGMII_RESET_ADDRESS, SGMII_RESET_RX_CLK_N_RESET);

	ath_reg_wr(SGMII_RESET_ADDRESS, SGMII_RESET_HW_RX_125M_N_SET(1));

	ath_reg_wr(SGMII_RESET_ADDRESS, SGMII_RESET_HW_RX_125M_N_SET(1)
                                    |SGMII_RESET_RX_125M_N_SET(1));

	ath_reg_wr(SGMII_RESET_ADDRESS, SGMII_RESET_HW_RX_125M_N_SET(1)
                                    |SGMII_RESET_TX_125M_N_SET(1)
                                    |SGMII_RESET_RX_125M_N_SET(1));

	ath_reg_wr(SGMII_RESET_ADDRESS, SGMII_RESET_HW_RX_125M_N_SET(1)
                                    |SGMII_RESET_TX_125M_N_SET(1)
                                    |SGMII_RESET_RX_125M_N_SET(1)
                                    |SGMII_RESET_RX_CLK_N_SET(1));

	ath_reg_wr(SGMII_RESET_ADDRESS, SGMII_RESET_HW_RX_125M_N_SET(1)
                                    |SGMII_RESET_TX_125M_N_SET(1)
                                    |SGMII_RESET_RX_125M_N_SET(1)
                                    |SGMII_RESET_RX_CLK_N_SET(1)
                                    |SGMII_RESET_TX_CLK_N_SET(1));

        ath_reg_rmw_clear(MR_AN_CONTROL_ADDRESS, MR_AN_CONTROL_PHY_RESET_SET(1));
	/*
	 * WAR::Across resets SGMII link status goes to weird
	 * state.
	 * if 0xb8070058 (SGMII_DEBUG register) reads other then 0x1f or 0x10
	 * for sure we are in bad  state.
	 * Issue a PHY reset in MR_AN_CONTROL_ADDRESS to keep going.
	 */
	status = (ath_reg_rd(SGMII_DEBUG_ADDRESS) & 0xff);
	while (!(status == 0xf || status == 0x10)) {

		ath_reg_rmw_set(MR_AN_CONTROL_ADDRESS, MR_AN_CONTROL_PHY_RESET_SET(1));
		udelay(100);
		ath_reg_rmw_clear(MR_AN_CONTROL_ADDRESS, MR_AN_CONTROL_PHY_RESET_SET(1));
		if (count++ == SGMII_LINK_WAR_MAX_TRY) {
			printf ("Max resets limit reached exiting...\n");
			break;
	    	}
		status = (ath_reg_rd(SGMII_DEBUG_ADDRESS) & 0xff);
	}

	printf("%s SGMII done\n",__func__);

}

static void ath_gmac_hw_start(ath_gmac_mac_t *mac)
{


#ifndef ATH_RGMII_CAL /* Moved after mii_setup since these registers are touched in RGMII cal code */
	if(mac->mac_unit)
	{
		ath_gmac_reg_rmw_set(mac, ATH_MAC_CFG2, (ATH_MAC_CFG2_PAD_CRC_EN |
					ATH_MAC_CFG2_LEN_CHECK | ATH_MAC_CFG2_IF_1000));
	} else {


		ath_gmac_reg_rmw_set(mac, ATH_MAC_CFG2, (ATH_MAC_CFG2_PAD_CRC_EN |
					ATH_MAC_CFG2_LEN_CHECK | ATH_MAC_CFG2_IF_10_100));
	}
	ath_gmac_reg_wr(mac, ATH_MAC_FIFO_CFG_0, 0x1f00);
#endif


#ifdef ATH_RGMII_CAL
	if(mac->mac_unit)
	{
		ath_gmac_reg_rmw_set(mac, ATH_MAC_CFG2, (ATH_MAC_CFG2_PAD_CRC_EN |
					ATH_MAC_CFG2_LEN_CHECK | ATH_MAC_CFG2_IF_1000));
	} else {


		ath_gmac_reg_rmw_set(mac, ATH_MAC_CFG2, (ATH_MAC_CFG2_PAD_CRC_EN |
					ATH_MAC_CFG2_LEN_CHECK | ATH_MAC_CFG2_IF_10_100));
	}
	ath_gmac_reg_wr(mac, ATH_MAC_FIFO_CFG_0, 0x1f00);
#endif

	ath_gmac_reg_wr(mac, ATH_MAC_FIFO_CFG_1, 0x10ffff);
	ath_gmac_reg_wr(mac, ATH_MAC_FIFO_CFG_2, 0xAAA0555);

	ath_gmac_reg_rmw_set(mac, ATH_MAC_FIFO_CFG_4, 0x3ffff);
	/*
	 * Setting Drop CRC Errors, Pause Frames,Length Error frames
	 * and Multi/Broad cast frames.
	 */

/* when httpd enabled, need broadcast package passed 
 * to cpu for visiting web page.setting soc register 
 * 0x1900005c broad and multi
 */
#if defined(CONFIG_CMD_HTTPD)
    ath_gmac_reg_wr(mac, ATH_MAC_FIFO_CFG_5, 0x7efcf);
#else
    ath_gmac_reg_wr(mac, ATH_MAC_FIFO_CFG_5, 0x7eccf);
#endif

	ath_gmac_reg_wr(mac, ATH_MAC_FIFO_CFG_3, 0x1f00140);

	printf(": cfg1 %#x cfg2 %#x\n", ath_gmac_reg_rd(mac, ATH_MAC_CFG1),
			ath_gmac_reg_rd(mac, ATH_MAC_CFG2));


}

static int ath_gmac_check_link(ath_gmac_mac_t *mac)
{
	int link, duplex, speed;

	ath_gmac_phy_link(mac->mac_unit, &link);
	ath_gmac_phy_duplex(mac->mac_unit, &duplex);
	ath_gmac_phy_speed(mac->mac_unit, &speed);

	mac->link = link;

	if(!mac->link) {
		printf("%s link down\n",mac->dev->name);
		return 0;
	}

	switch (speed)
	{
		case _1000BASET:
			ath_gmac_set_mac_if(mac, 1);
			ath_gmac_reg_rmw_set(mac, ATH_MAC_FIFO_CFG_5, (1 << 19));

			if (is_ar8033() && mac->mac_unit == 1) {
				ath_reg_wr(ETH_SGMII_ADDRESS, ETH_SGMII_GIGE_SET(1) |
                                           ETH_SGMII_CLK_SEL_SET(1));
			}
	
			break;

		case _100BASET:
			ath_gmac_set_mac_if(mac, 0);
			ath_gmac_set_mac_speed(mac, 1);
			ath_gmac_reg_rmw_clear(mac, ATH_MAC_FIFO_CFG_5, (1 << 19));

                        if (is_ar8033() && mac->mac_unit == 1) {
                        	ath_reg_wr(ETH_SGMII_ADDRESS, ETH_SGMII_PHASE0_COUNT_SET(1) |
                                           ETH_SGMII_PHASE1_COUNT_SET(1));
			}

			break;

		case _10BASET:
			ath_gmac_set_mac_if(mac, 0);
			ath_gmac_set_mac_speed(mac, 0);
			ath_gmac_reg_rmw_clear(mac, ATH_MAC_FIFO_CFG_5, (1 << 19));


			break;

		default:
			printf("Invalid speed detected\n");
			return 0;
	}

	if (mac->link && (duplex == mac->duplex) && (speed == mac->speed))
		return 1;

	mac->duplex = duplex;
	mac->speed = speed;

	printf("dup %d speed %d\n", duplex, speed);

	ath_gmac_set_mac_duplex(mac,duplex);

	return 1;
}

/*
 * For every command we re-setup the ring and start with clean h/w rx state
 */
static int ath_gmac_clean_rx(struct eth_device *dev, bd_t * bd)
{

	int i;
	ath_gmac_desc_t *fr;
	ath_gmac_mac_t *mac = (ath_gmac_mac_t*)dev->priv;

	if (!ath_gmac_check_link(mac))
		return 0;

	mac->next_rx = 0;

        ath_gmac_reg_wr(mac, ATH_MAC_FIFO_CFG_0, 0x1f00); 
        ath_gmac_reg_wr(mac, ATH_MAC_CFG1, (ATH_MAC_CFG1_RX_EN | ATH_MAC_CFG1_TX_EN));

	for (i = 0; i < NO_OF_RX_FIFOS; i++) {
		fr = mac->fifo_rx[i];
		fr->pkt_start_addr = virt_to_phys(NetRxPackets[i]);
		flush_cache((u32) NetRxPackets[i], PKTSIZE_ALIGN);
		ath_gmac_rx_give_to_dma(fr);
	}

	ath_gmac_reg_wr(mac, ATH_DMA_RX_DESC, virt_to_phys(mac->fifo_rx[0]));
	ath_gmac_reg_wr(mac, ATH_DMA_RX_CTRL, ATH_RXE);	/* rx start */
	udelay(1000 * 1000);


	return 1;

}

static int ath_gmac_alloc_fifo(int ndesc, ath_gmac_desc_t ** fifo)
{
	int i;
	u32 size;
	uchar *p = NULL;

	size = sizeof(ath_gmac_desc_t) * ndesc;
	size += CFG_CACHELINE_SIZE - 1;

	if ((p = malloc(size)) == NULL) {
		printf("Cant allocate fifos\n");
		return -1;
	}

	p = (uchar *) (((u32) p + CFG_CACHELINE_SIZE - 1) &
			~(CFG_CACHELINE_SIZE - 1));
	p = UNCACHED_SDRAM(p);

	for (i = 0; i < ndesc; i++)
		fifo[i] = (ath_gmac_desc_t *) p + i;

	return 0;
}

static int ath_gmac_setup_fifos(ath_gmac_mac_t *mac)
{
	int i;

	if (ath_gmac_alloc_fifo(NO_OF_TX_FIFOS, mac->fifo_tx))
		return 1;

	for (i = 0; i < NO_OF_TX_FIFOS; i++) {
		mac->fifo_tx[i]->next_desc = (i == NO_OF_TX_FIFOS - 1) ?
			virt_to_phys(mac->fifo_tx[0]) : virt_to_phys(mac->fifo_tx[i + 1]);
		ath_gmac_tx_own(mac->fifo_tx[i]);
	}

	if (ath_gmac_alloc_fifo(NO_OF_RX_FIFOS, mac->fifo_rx))
		return 1;

	for (i = 0; i < NO_OF_RX_FIFOS; i++) {
		mac->fifo_rx[i]->next_desc = (i == NO_OF_RX_FIFOS - 1) ?
			virt_to_phys(mac->fifo_rx[0]) : virt_to_phys(mac->fifo_rx[i + 1]);
	}

	return (1);
}

static void ath_gmac_halt(struct eth_device *dev)
{
	ath_gmac_mac_t *mac = (ath_gmac_mac_t *)dev->priv;
        ath_gmac_reg_rmw_clear(mac, ATH_MAC_CFG1,(ATH_MAC_CFG1_RX_EN | ATH_MAC_CFG1_TX_EN));
        ath_gmac_reg_wr(mac,ATH_MAC_FIFO_CFG_0,0x1f1f);
	ath_gmac_reg_wr(mac,ATH_DMA_RX_CTRL, 0);
	while (ath_gmac_reg_rd(mac, ATH_DMA_RX_CTRL));
}

#ifdef CONFIG_ATH_NAND_BR

unsigned char *
ath_eth_mac_addr(unsigned char *sectorBuff)
{
	ulong   off, size;
	nand_info_t *nand;
	unsigned char ret;

	/*
	 * caldata partition is of 128k
	 */
	nand = &nand_info[nand_curr_device];
	size = ATH_ETH_MAC_READ_SIZE; /* To read 4k setting size as 4k */

	/*
	 * Get the Offset of Caldata partition
	 */
	off = ath_nand_get_cal_offset(getenv("bootargs"));
	if(off == ATH_CAL_OFF_INVAL) {
		printf("Invalid CAL offset \n");
		return NULL;
	}
	/*
	 * Get the values from flash, and program into the MAC address
	 * registers
	 */
	ret = nand_read(nand, (loff_t)off, &size, (u_char *)sectorBuff);
	printf(" %d bytes %s: %s\n", size,
			"read", ret ? "ERROR" : "OK");
	if(ret != 0 ) {
		return NULL;
	}

	return sectorBuff;
}

#else  /* CONFIG_ATH_NAND_BR */

unsigned char *
ath_gmac_mac_addr_loc(void)
{
	extern flash_info_t flash_info[];

#ifdef BOARDCAL
	/*
	 ** BOARDCAL environmental variable has the address of the cal sector
	 */

	return ((unsigned char *)BOARDCAL);

#else
	/* MAC address is store in the 2nd 4k of last sector */
	return ((unsigned char *)
			(KSEG1ADDR(ATH_SPI_BASE) + (4 * 1024) +
			 flash_info[0].size - (64 * 1024) /* sector_size */ ));
#endif
}

#endif  /* CONFIG_ATH_NAND_BR */

static void ath_gmac_get_ethaddr(struct eth_device *dev)
{
	unsigned char *eeprom;
	unsigned char *mac = dev->enetaddr;
#ifndef CONFIG_ATH_EMULATION

#ifdef CONFIG_ATH_NAND_BR
	unsigned char sectorBuff[ATH_ETH_MAC_READ_SIZE];

	eeprom = ath_eth_mac_addr(sectorBuff);
	if(eeprom == NULL) {
		/* mac address will be set to default mac address */
		mac[0] = 0xff;
	}
	else {
#else  /* CONFIG_ATH_NAND_BR */
		eeprom = ath_gmac_mac_addr_loc();
#endif  /* CONFIG_ATH_NAND_BR */

		if (strcmp(dev->name, "eth0") == 0) {
			memcpy(mac, eeprom, 6);
		} else if (strcmp(dev->name, "eth1") == 0) {
			eeprom += 6;
			memcpy(mac, eeprom, 6);
		} else {
			printf("%s: unknown ethernet device %s\n", __func__, dev->name);
			return;
		}
#ifdef CONFIG_ATH_NAND_BR
	}
#endif  /* CONFIG_ATH_NAND_BR */
	/* Use fixed address if the above address is invalid */
	if (mac[0] != 0x00 || (mac[0] == 0xff && mac[5] == 0xff))
#else
	if (1)
#endif
	{
			mac[0] = 0x00;
			mac[1] = 0x03;
			mac[2] = 0x7f;
			mac[3] = 0x09;
			mac[4] = 0x0b;
			mac[5] = 0xad;
			printf("No valid address in Flash. Using fixed address\n");
		} else {
			printf("%s: Fetching MAC Address from 0x%p\n", __func__, eeprom);
		}
}

void
athr_mgmt_init(void)
{
#if defined (CONFIG_ATHRS17_PHY)
uint32_t rddata;

// init MDI/ MDO/ MDC
if (CFG_ATH_GMAC_NMACS == 1){
    /*
     * GPIO 10 as MDI
     */
    rddata = ath_reg_rd(GPIO_IN_ENABLE3_ADDRESS)&
             ~GPIO_IN_ENABLE3_MII_GE1_MDI_MASK;
    rddata |= GPIO_IN_ENABLE3_MII_GE1_MDI_SET(10);
    ath_reg_wr(GPIO_IN_ENABLE3_ADDRESS, rddata);

    /*
     * GPIO 10 as MDO
     */
    rddata = ath_reg_rd(GPIO_OUT_FUNCTION2_ADDRESS) &
             ~ (GPIO_OUT_FUNCTION2_ENABLE_GPIO_10_MASK);
    rddata |= (GPIO_OUT_FUNCTION2_ENABLE_GPIO_10_SET(0x20));
    ath_reg_wr(GPIO_OUT_FUNCTION2_ADDRESS, rddata);             
                
    /*
     * GPIO 10 as MDO
     */
    rddata = ath_reg_rd(GPIO_OE_ADDRESS);
    rddata &= ~(1<<10);
    ath_reg_wr(GPIO_OE_ADDRESS, rddata);

    /*
     * GPIO 8 as MDC
     */
    rddata = ath_reg_rd(GPIO_OE_ADDRESS);
    rddata &= ~(1<<8);
    ath_reg_wr(GPIO_OE_ADDRESS, rddata);

    rddata = ath_reg_rd(GPIO_OUT_FUNCTION2_ADDRESS) &
           ~ (GPIO_OUT_FUNCTION2_ENABLE_GPIO_8_MASK);
    rddata |= GPIO_OUT_FUNCTION2_ENABLE_GPIO_8_SET(0x21);
    ath_reg_wr(GPIO_OUT_FUNCTION2_ADDRESS, rddata);


}
#endif /* CONFIG_ATHRS17_PHY */

	printf ("%s ::done\n",__func__);
}


int ath_gmac_enet_initialize(bd_t * bis)
{
	struct eth_device *dev[CFG_ATH_GMAC_NMACS];
	u32 mask, mac_h, mac_l;
	int i;
	u32 val;
	
	/* printf("%s...\n", __func__); */

	if ( CFG_ATH_GMAC_NMACS == 1){
		athrs_sgmii_res_cal();
	}
	
	for (i = 0;i < CFG_ATH_GMAC_NMACS;i++) {

		if ((dev[i] = (struct eth_device *) malloc(sizeof (struct eth_device))) == NULL) {
			puts("malloc failed\n");
			return 0;
		}

		if ((ath_gmac_macs[i] = (ath_gmac_mac_t *) malloc(sizeof (ath_gmac_mac_t))) == NULL) {
			puts("malloc failed\n");
			return 0;
		}

		memset(ath_gmac_macs[i], 0, sizeof(ath_gmac_macs[i]));
		memset(dev[i], 0, sizeof(dev[i]));

		snprintf(dev[i]->name, sizeof(dev[i]->name), "eth%d", i);
		ath_gmac_get_ethaddr(dev[i]);

		ath_gmac_macs[i]->mac_unit = i;
		ath_gmac_macs[i]->mac_base = i ? ATH_GE1_BASE : ATH_GE0_BASE ;
		ath_gmac_macs[i]->dev = dev[i];

		dev[i]->iobase = 0;
		dev[i]->init = ath_gmac_clean_rx;
		dev[i]->halt = ath_gmac_halt;
		dev[i]->send = ath_gmac_send;
		dev[i]->recv = ath_gmac_recv;
		dev[i]->priv = (void *)ath_gmac_macs[i];
	}

#if !defined(CONFIG_ATH_NAND_BR)
	ath_reg_rmw_set(RST_RESET_ADDRESS,  RST_RESET_ETH_SGMII_ARESET_SET(1));
	udelay(1000 * 100);
	ath_reg_rmw_clear(RST_RESET_ADDRESS, RST_RESET_ETH_SGMII_ARESET_SET(1));
	udelay(100);
#endif
	if ( CFG_ATH_GMAC_NMACS == 1){
	mask =	RST_RESET_ETH_SGMII_RESET_SET(1) | RST_RESET_ETH_SGMII_ARESET_SET(1) | RST_RESET_EXTERNAL_RESET_SET(1) | 
				RST_RESET_ETH_SWITCH_ANALOG_RESET_SET(1) | RST_RESET_ETH_SWITCH_RESET_SET(1);
	}else{
		mask =  RST_RESET_ETH_SGMII_RESET_SET(1) | RST_RESET_EXTERNAL_RESET_SET(1) | 
				RST_RESET_ETH_SWITCH_ANALOG_RESET_SET(1) | RST_RESET_ETH_SWITCH_RESET_SET(1);
	}
	ath_reg_rmw_set(RST_RESET_ADDRESS, mask);
	udelay(1000 * 100);
	if ( CFG_ATH_GMAC_NMACS == 1){
			mask =	RST_RESET_ETH_SGMII_RESET_SET(1) | RST_RESET_ETH_SGMII_ARESET_SET(1)  | RST_RESET_EXTERNAL_RESET_SET(1);
	}
	
	ath_reg_rmw_clear(RST_RESET_ADDRESS, mask);
	udelay(1000 * 100);

#if defined(CONFIG_ATHRS17_PHY)
	if ( CFG_ATH_GMAC_NMACS == 1) {
		//   S17 SWITCH RESET
		val = ath_reg_rd(GPIO_OE_ADDRESS) & ~(1 << 11);
		ath_reg_wr(GPIO_OE_ADDRESS, val);
		udelay(1000 * 100);
		ath_reg_rmw_set(GPIO_OUT_ADDRESS, ( 1 << 11));
		udelay(1000 * 100);
		ath_reg_rmw_clear(GPIO_OUT_ADDRESS, ( 1 << 11));
		udelay(1000 * 100);
		ath_reg_rmw_set(GPIO_OUT_ADDRESS, ( 1 << 11));
	}
#endif
	for (i = 0;i < CFG_ATH_GMAC_NMACS;i++) {

		ath_gmac_reg_rmw_set(ath_gmac_macs[i], ATH_MAC_CFG1, ATH_MAC_CFG1_SOFT_RST
				| ATH_MAC_CFG1_RX_RST | ATH_MAC_CFG1_TX_RST);

		if(!i) {
			mask = (ATH_RESET_GE0_MAC | ATH_RESET_GE1_MAC);

			mask = mask | ATH_RESET_GE0_MDIO | ATH_RESET_GE1_MDIO;

			/* printf("%s: reset mask:%x \n", __func__, mask); */

			ath_reg_rmw_set(RST_RESET_ADDRESS, mask);
			udelay(1000 * 100);

			ath_reg_rmw_clear(RST_RESET_ADDRESS, mask);
			udelay(1000 * 100);

			udelay(10 * 1000);
		}
#if defined(CONFIG_MGMT_INIT) && defined (CONFIG_ATHR_SWITCH_ONLY_MODE) || defined ATH_MDC_GPIO
		if (!i)
			athr_mgmt_init();

		if (ath_gmac_macs[i]->mac_unit == 0)
                        continue;
#endif
		if (CFG_ATH_GMAC_NMACS == 1){
			athr_mgmt_init();
		}
		eth_register(dev[i]);
#if(CONFIG_COMMANDS & CFG_CMD_MII)
		miiphy_register(dev[i]->name, ath_gmac_miiphy_read, ath_gmac_miiphy_write);
#endif
		ath_gmac_mii_setup(ath_gmac_macs[i]);

		/* if using header for register configuration, we have to     */
		/* configure s26 register after frame transmission is enabled */

		if (ath_gmac_macs[i]->mac_unit == 0) { /* WAN Phy */
#ifdef  CONFIG_ATHRS17_PHY
			athrs17_reg_init();
#endif

#ifdef CFG_ATHRS26_PHY
                	athrs26_reg_init();
#endif

#ifdef CFG_ATHRS27_PHY
                	athrs27_reg_init();
#endif


		} else {

#if defined(CONFIG_MGMT_INIT) && defined (CONFIG_ATHR_SWITCH_ONLY_MODE)
			athrs17_reg_init();
#elif defined (CONFIG_ATHRS17_PHY) && !defined(CFG_DUAL_PHY_SUPPORT)
			athrs17_reg_init_wan();
#endif

#ifdef CFG_ATHRS27_PHY
                	athrs27_reg_init_lan();
#endif

		}
#ifdef CONFIG_ATHRS_GMAC_SGMII
	/*
         * MAC unit 1 or drqfn package call sgmii setup.
	 */
	if (i == 0 && CFG_ATH_GMAC_NMACS == 1)
		athr_gmac_sgmii_setup();
#endif
		ath_gmac_hw_start(ath_gmac_macs[i]);
		ath_gmac_setup_fifos(ath_gmac_macs[i]);



		udelay(100 * 1000);

		{
			unsigned char *mac = dev[i]->enetaddr;

			printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", dev[i]->name,
					mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff,
					mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff);
		}
		mac_l = (dev[i]->enetaddr[4] << 8) | (dev[i]->enetaddr[5]);
		mac_h = (dev[i]->enetaddr[0] << 24) | (dev[i]->enetaddr[1] << 16) |
			(dev[i]->enetaddr[2] << 8) | (dev[i]->enetaddr[3] << 0);

		ath_gmac_reg_wr(ath_gmac_macs[i], ATH_GE_MAC_ADDR1, mac_l);
		ath_gmac_reg_wr(ath_gmac_macs[i], ATH_GE_MAC_ADDR2, mac_h);


	ath_gmac_phy_setup(ath_gmac_macs[i]->mac_unit);
		printf("%s up\n",dev[i]->name);
	}


	return 1;
}

void uboot_phy_down()
{

#ifdef  CONFIG_ATHRS17_PHY
    athrs17_phy_down();
#endif

}


#if (CONFIG_COMMANDS & CFG_CMD_MII)
int
ath_gmac_miiphy_read(char *devname, uint32_t phy_addr, uint8_t reg, uint16_t *data)
{
	ath_gmac_mac_t *mac   = ath_gmac_name2mac(devname);
	uint16_t      addr  = (phy_addr << ATH_ADDR_SHIFT) | reg, val;
	volatile int           rddata;
	uint16_t      ii = 0xFFFF;




	/*
	 * Check for previous transactions are complete. Added to avoid
	 * race condition while running at higher frequencies.
	 */
	do
	{
		udelay(5);
		rddata = ath_gmac_reg_rd(mac, ATH_MII_MGMT_IND) & 0x1;
	}while(rddata && --ii);

	if (ii == 0)
		printf("ERROR:%s:%d transaction failed\n",__func__,__LINE__);


	ath_gmac_reg_wr(mac, ATH_MII_MGMT_CMD, 0x0);
	ath_gmac_reg_wr(mac, ATH_MII_MGMT_ADDRESS, addr);
	ath_gmac_reg_wr(mac, ATH_MII_MGMT_CMD, ATH_MGMT_CMD_READ);

	do
	{
		udelay(5);
		rddata = ath_gmac_reg_rd(mac, ATH_MII_MGMT_IND) & 0x1;
	}while(rddata && --ii);

	if(ii==0)
		printf("Error!!! Leave ath_gmac_miiphy_read without polling correct status!\n");

	val = ath_gmac_reg_rd(mac, ATH_MII_MGMT_STATUS);
	ath_gmac_reg_wr(mac, ATH_MII_MGMT_CMD, 0x0);

        if (data != NULL)
	    *data = val; 
	return val;
}

int
ath_gmac_miiphy_write(char *devname, uint32_t phy_addr, uint8_t reg, uint16_t data)
{
	ath_gmac_mac_t *mac   = ath_gmac_name2mac(devname);
	uint16_t      addr  = (phy_addr << ATH_ADDR_SHIFT) | reg;
	volatile int rddata;
	uint16_t      ii = 0xFFFF;


	/*
	 * Check for previous transactions are complete. Added to avoid
	 * race condition while running at higher frequencies.
	 */
	do {
		udelay(5);
		rddata = ath_gmac_reg_rd(mac, ATH_MII_MGMT_IND) & 0x1;
	} while (rddata && --ii);

	if (ii == 0)
		printf("ERROR:%s:%d transaction failed\n",__func__,__LINE__);

	ath_gmac_reg_wr(mac, ATH_MII_MGMT_ADDRESS, addr);
	ath_gmac_reg_wr(mac, ATH_MII_MGMT_CTRL, data);

	do {
		rddata = ath_gmac_reg_rd(mac, ATH_MII_MGMT_IND) & 0x1;
	} while (rddata && --ii);

	if (ii == 0)
		printf("Error!!! Leave ath_gmac_miiphy_write without polling correct status!\n");
	return 0; 
}
#endif		/* CONFIG_COMMANDS & CFG_CMD_MII */
