#include <common.h>
#include "config.h"

static int l_FWRecoveryFlag = 0;

int isFWRecoveryStarted(void)
{
    return l_FWRecoveryFlag;
}

void perform_tpFwRecovery(void)
{
    #define MAX_CMD_LEN       (128)
    #define FW_DOWNLOAD_ADDR  "0x80800000"
    int  ret = 0;
    char *s;
    char cmdBuff[MAX_CMD_LEN] = {0};
    int  file_size = 0;

    fwrecovery_gpio_init();
    fwrecovery_led_off();

    ret = fwrecovery_rst_btn_pressed();
    if (ret)
    {
#ifdef CFG_ATHRS27_PHY
        //enable_phy_ports_all();
#endif
        fwrecovery_led_on();
        l_FWRecoveryFlag = 1;        

        /* wait for ethernet config done. by HouXB, 28Apr11 */
        udelay(2000*1000);
	/*
        memset(cmdBuff, 0, MAX_CMD_LEN);
        sprintf(cmdBuff, "setenv serverip %s", FIRMWARE_RECOVERY_SERVER_IP);      
        run_command(cmdBuff, 0);
        
        memset(cmdBuff, 0, MAX_CMD_LEN);
        sprintf(cmdBuff, "setenv ipaddr %s", FIRMWARE_RECOVERY_IP_ADDR);  
        run_command(cmdBuff, 0);

        memset(cmdBuff, 0, MAX_CMD_LEN);
        sprintf(cmdBuff, "tftp %s %s", FW_DOWNLOAD_ADDR, FIRMWARE_RECOVERY_NAME); 
        run_command(cmdBuff, 0);

        s = getenv("filesize");
        if (s)
        {
            file_size = simple_strtoul(s, NULL, 16);
        }

        printf("Firmware recovery: FLASH_SIZE = %d filesize = 0x%x.\n", FLASH_SIZE, file_size);
        memset(cmdBuff, 0, MAX_CMD_LEN);
        sprintf(cmdBuff, "fwrecov %s 0x%08x", FW_DOWNLOAD_ADDR, file_size); 
        run_command(cmdBuff, 0);

        do_reset (NULL, 0, 0, NULL);
	*/
	phy_delay_init();
	memset(cmdBuff, 0, MAX_CMD_LEN);
	sprintf(cmdBuff, "setenv ipaddr %s; httpd\0", WEBFAILSAFE_SERVER_IP_ADDR);
	run_command(cmdBuff, 0);
    }
    else
    {
        fwrecovery_led_off();
    }
}

