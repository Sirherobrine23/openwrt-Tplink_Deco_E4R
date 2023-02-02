
/*! Copyright(c) 1996-2009 Shenzhen TP-LINK Technologies Co. Ltd.
 * \file    nm_lib.h
 * \brief   Protos for NVRAM manager's api functions.
 * \author  Meng Qing
 * \version 1.0
 * \date    25/04/2009
 */

#ifndef NM_API_H
#define NM_API_H

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

#define NM_PTN_NAME_FS_UBOOT "fs-uboot"
	
#define NM_PTN_NAME_PTN_TABLE "partition-table"

#define NM_PTN_NAME_DEFAULT_MAC "default-mac"
#define NM_PTN_NAME_PIN	"pin"
#define NM_PTN_NAME_PRODUCT_INFO "product-info"
#define NM_PTN_NAME_SOFT_VERSION "soft-version"

#define NM_PTN_NAME_SUPPORT_LIST "support-list"
	
#define NM_PTN_NAME_OS_IMAGE "os-image"

#define NM_PTN_NAME_FILE_SYSTEM "file-system"

#define NM_PTN_NAME_USER_CFG "user-config"

#define NM_PTN_NAME_DEFAULT_CFG "default-config"
	
#define NM_PTN_NAME_RADIO "radio"

#define NM_PTN_NAME_LOG "log"

#define NM_PTN_NAME_PROFILE "profile"

#define NM_PTN_NAME_QOS_DB "qos-db"

#define NM_PTN_NAME_FACTORY_BOOT "factory-boot"

#define NM_PTN_NAME_EXTRA_PARA		"extra-para"

#define NM_PTN_NAME_DEVID		"device-id"

#define SPECTIAL_SUPPORT_LIST "TP_PharOS_Special_Ver"


#ifndef OK
#define OK 0
#endif

#ifndef ERROR
#define ERROR -1
#endif

#define _STR(a) 	#a
#define STR(a) 		_STR(a)

/**************************************************************************************************/
/*                                      FUNCTIONS                                                 */
/**************************************************************************************************/

extern int nm_api_writePtnToNvram(char *name, char *buf, int len);
extern int nm_api_readPtnFromNvram(char *name, char *buf, int len);

extern int nm_api_writeToNvram(char *base, char *buf, int len);
extern int nm_api_readFromNvram(char *base, char *buf, int len);

extern int nm_api_checkKernel(void);
extern int nm_api_checkDefaultMac(void);

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
extern int nm_api_erasePtn(char *name);
extern int  nm_api_readPtnUsedSize(char *name);
extern int nm_api_checkInteger(void);
extern int nm_api_setIntegerFlag(unsigned char flag);
#endif
/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

#ifdef __cplusplus 
}
#endif

#endif /* NM_API_H */

