#include <common.h>
#include <command.h>

#include "../nvram_mngr/nm_lib.h"
#include "../nvram_mngr/nm_fwup.h"

#define IMAGE_SIZE_LEN  (0x04)
#define IMAGE_SIZE_MD5  (0x10)
#define IMAGE_SIZE_PRODUCT  (0x1000)
#define IMAGE_SIZE_BASE (IMAGE_SIZE_LEN + IMAGE_SIZE_MD5 + IMAGE_SIZE_PRODUCT)

#define IMAGE_SIZE_MAX  (IMAGE_SIZE_BASE + 0x800 + 0x1000000)
#define IMAGE_SIZE_MIN  (IMAGE_SIZE_BASE + 0x800)

int do_fwrecovery( cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
    int ret = 0;
    int fileLen = 0;
    int bufLen  = 0;
#if !defined(CONFIG_DOUBLE_UBOOT_SECOND) && !defined(CONFIG_DOUBLE_UBOOT_FACTORY)
    uint8_t *pBuf = NULL;
#endif
    unsigned char *addr = NULL;

        if (argc < 2) {
                printf ("Usage:\n%s\n", cmdtp->usage);
                return -1;
        }

    addr   = simple_strtoul(argv[1], NULL, 0);
    bufLen = simple_strtoul(argv[2], NULL, 0);

    if (!addr || !bufLen)
    {
                printf ("Usage:\n%s\n", cmdtp->usage);
                return -2;
    }

    ret = nm_init();
    if (OK != ret)
    {
        printf("Partition table initiating failed.\n");
        return -3;
    }

    memcpy(&fileLen, addr, sizeof(int));
    fileLen = ntohl(fileLen);

    if(fileLen < IMAGE_SIZE_MIN || fileLen > IMAGE_SIZE_MAX || bufLen < fileLen)
    {
        printf("Bad file length(Buffer Length:%d File Length:%d)\n", bufLen, fileLen);
        return -1;
    }
    printf("File Length:%d\n", fileLen);

#if !defined(CONFIG_DOUBLE_UBOOT_SECOND) && !defined(CONFIG_DOUBLE_UBOOT_FACTORY)
    pBuf = addr + IMAGE_SIZE_BASE;
    ret = nm_buildUpgradeStruct((char *)pBuf, bufLen - IMAGE_SIZE_BASE);
#else
    ret = nm_tpFirmwareCheck((char *)addr, bufLen);
#endif
    if (0 != ret)
    {
        printf("Firmware Invalid!\n");
        return -1;
    }
    printf("Firmware Checking Passed.\n");

    ret = nm_upgradeFwupFile((char *)addr + IMAGE_SIZE_BASE, bufLen - IMAGE_SIZE_BASE);
    if (ret != OK)
    {
        printf("Firmware Upgrading Failed!\n");
        return -1;
    }

    printf("All Done!\n");
    return 0;

}

U_BOOT_CMD(fwrecovery, 3, 0, do_fwrecovery,
           "Firmware recovery",
           "loadAddress firmwareName");
