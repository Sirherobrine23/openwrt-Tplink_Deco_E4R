/*! Copyright(c) 2008-2011 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     sysmgr_cfg_productinfo.h
 *\brief    Implements for product information manager.
 *\details  
 *
 *\author   Meng Qing
 *\version  1.0.0
 *\date     02May09
 *
 *\warning  
 *
 *\history  \arg    1.0.0, 02May09, Meng Qing, Create the file.
 */

#ifndef __SYSMGR_CFG_PRODUCTINFO_H__
#define __SYSMGR_CFG_PRODUCTINFO_H__
/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/


#ifdef __cplusplus
extern "C"
{
#endif  /* __cplusplus */

/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/

#define PRODUCTINFO_DEBUG_L1(fmt, args...) \
    printf("[Debug1]%s():%5d @ "fmt, __FUNCTION__, __LINE__, ##args)
#define PRODUCTINFO_DEBUG_L2(fmt, args...) \
    printf("[Debug2]%s():%5d @ "fmt, __FUNCTION__, __LINE__, ##args) 
#define PRODUCTINFO_ERROR(fmt, args...) \
    printf("[Error]%s():%5d @ "fmt, __FUNCTION__, __LINE__, ##args)

#define SYSMGR_PROINFO_CONTENT_MAX_LEN          (0x400)     /* 1024Byte */
#define SYSMGR_SUPPORTLIST_CONTENT_MAX_LEN      (0x10000)


#define PRODUCTINFO_VENDOR_NAME_LEN         (32)
#define PRODUCTINFO_VENDOR_URL_LEN          (64)
#define PRODUCTINFO_PRODUCT_NAME_LEN        (32)
#define PRODUCTINFO_PRODUCT_ID_LEN          ( 8)
#define PRODUCTINFO_PRODUCT_VER_LEN         ( 8)
#define PRODUCTINFO_HW_ID_LEN         		( 48)
#define PRODUCTINFO_OEM_ID_LEN         		( 48)
#define PRODUCTINFO_SPECIAL_ID_LEN          ( 8)
#define PRODUCTINFO_LANGUAGE_LEN            ( 8)


/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/

typedef struct _PRODUCT_INFO_STRUCT
{
    unsigned char   vendorName[PRODUCTINFO_VENDOR_NAME_LEN];
    unsigned char   vendorUrl[PRODUCTINFO_VENDOR_URL_LEN];
    unsigned char   productName[PRODUCTINFO_PRODUCT_NAME_LEN];
    unsigned char   productLanguage[PRODUCTINFO_LANGUAGE_LEN];
    unsigned char   hwId[PRODUCTINFO_HW_ID_LEN];
    unsigned char   oemId[PRODUCTINFO_OEM_ID_LEN];

    unsigned long   productId;
    unsigned long   productVer;
    unsigned long   specialId;
}PRODUCT_INFO_STRUCT;

#ifndef OK
#define OK (0)
#endif
#ifndef ERROR
#define ERROR (-1)
#endif

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      FUNCTIONS                                                 */
/**************************************************************************************************/
int  sysmgr_cfg_checkSupportList(PRODUCT_INFO_STRUCT *pProductInfo, const char* listContent, int fileLen);
PRODUCT_INFO_STRUCT *sysmgr_getProductInfo(void);
int  sysmgr_cfg_getProductInfoFromNvram(PRODUCT_INFO_STRUCT *productInfo);
void sysmgr_proinfo_show(void);


#ifdef __cplusplus
}
#endif  /* __cplusplus */


#endif  /* __SYSMGR_CFG_PRODUCTINFO_H__ */
