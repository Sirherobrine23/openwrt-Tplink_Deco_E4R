
/*! Copyright(c) 1996-2009 Shenzhen TP-LINK Technologies Co. Ltd.
 * \file    ipifcfg_cfg.h
 * \brief   Protos for ipnet ifconfig's config mod.
 * \author  Meng Qing
 * \version 1.0
 * \date    21/1/2009
 */

#ifndef NM_FWUP_H
#define NM_FWUP_H


#ifdef __cplusplus
extern "C"{
#endif


/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/
#define NM_FWUP_FRAGMENT_SIZE 0x10000

#define MD5_DIGEST_LEN  16
#define IMAGE_SIZE_LEN  (0x04)
#define IMAGE_SIZE_MD5  (0x10)
#define IMAGE_SIZE_PRODUCT  (0x1000)
#define IMAGE_SIZE_BASE (IMAGE_SIZE_LEN + IMAGE_SIZE_MD5 + IMAGE_SIZE_PRODUCT)
#define IMAGE_SIZE_FWTYPE       (IMAGE_SIZE_LEN + IMAGE_SIZE_MD5)

#define IMAGE_SIZE_RSA_SIG      (IMAGE_SIZE_FWTYPE + 0x11C)
#define IMAGE_LEN_RSA_SIG       (0x80)

#define FW_TYPE_NAME_LEN_MAX    0x100
#define IMAGE_SIZE_MAX  (IMAGE_SIZE_BASE + 0x800 + NM_FLASH_SIZE)
#define IMAGE_SIZE_MIN  (IMAGE_SIZE_BASE + 0x800)
/*
#define IMAGE_CLOUD_HEAD_OFFSET (252)

#define NM_FWUP_SUPPORT_LIST_NUM_MAX 16

#define NM_FWUP_SOFTWARE_VERSION_LEN    (256)
*/
/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/
typedef int STATUS;

typedef enum _FWUP_ERROR_TYPE
{
	NM_FWUP_ERROR_NONE 				 =  0,
    NM_FWUP_ERROR_NORMAL			 = -1,	/* inner error */
    NM_FWUP_ERROR_INVALID_FILE		 = -2,	/* invalid firmware file */
    NM_FWUP_ERROR_INCORRECT_MODEL	 = -3,	/* the firmware is not for this model */
    NM_FWUP_ERROR_BAD_FILE			 = -4,	/* an valid firmware, but something wrong in file */
    NM_FWUP_ERROR_UNSUPPORT_VER		 = -5,	/* firmware file not compatible with current version */
    NM_FWUP_ERROR_UNSUPPORT_BOOT_MOD = -6,	/* firmware file not compatible with boot mode */
} FWUP_ERROR_TYPE;

enum fw_type
{
    FW_TYPE_INVALID = 0x0,
    FW_TYPE_COMMON = 0x1,
    FW_TYPE_CLOUD = 0x2,
    FW_TYPE_MAX = 0xff
};

struct fw_type_option
{
	char *name;
	enum fw_type type;
	int (*func)(unsigned char *buf, int buf_len);
};

/**************************************************************************************************/
/*                                      FUNCTIONS                                                 */
/**************************************************************************************************/


STATUS nm_initFwupPtnStruct(void);
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
STATUS nm_tpFirmwareRecovery(unsigned char *ptr,int bufsize);
#endif
extern STATUS nm_upgradeFwupFile(char *pAppBuf, int nFileBytes);
extern int nm_buildUpgradeStruct(char *pAppBuf, int nFileBytes);

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

extern int g_nmCountFwupAllWriteBytes;
extern int g_nmCountFwupCurrWriteBytes;
extern int g_nmUpgradeResult;

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
extern int g_fwupPercent;
#endif



#ifdef __cplusplus 
}
#endif

#endif


