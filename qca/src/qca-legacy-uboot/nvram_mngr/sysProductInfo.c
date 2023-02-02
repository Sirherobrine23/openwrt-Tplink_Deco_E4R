/*! Copyright(c) 2008-2011 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     sysmgr_cfg_productinfo.c
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

/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/
#if 0
#include "lib_types.h"
#include "lib_string.h"
#include "lib_printf.h"
#include "lib_scanf.h"
#endif
#include <common.h>
 
#include "sysProductInfo.h"
#include "nm_api.h"

/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/


/* Porting... */
//#define printf              xprintf
//#define strcasecmp          strcmpi
extern unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base);
#define strtoul(a,b,c)                    simple_strtoul(a, b, c)
//#define memmove(x,y,z)      bcopy(x,y,z)
/* Sorry, I ported a snprintf to a sprintf. */
#define snprintf(buf, size, fmt, args...) sprintf(buf, fmt, ##args)

#define SYSMGR_PROINFO_INFO_MAX_CNT             (32)
#define SYSMGR_SUPPORTLIST_MAX_CNT              (32)
#define SYSMGR_PROINFO_CHAR_INFO_SEPERATOR      (0x03)

#define LEAVE(retVal)       do{ret = retVal;goto leave;}while(0)

/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/
typedef struct _SYSMGR_PROINFO_STR_MAP
{
    int             key;
    char*           str;
} SYSMGR_PROINFO_STR_MAP;


typedef enum _SYSMGR_PROINFO_ID
{
    PRODCUTINFO_ID_VOID = -1,

    PRODUCTINFO_VENDOR_NAME,
    PRODUCTINFO_VENDOR_URL,
    PRODUCTINFO_PRODUCT_NAME,
    PRODUCTINFO_PRODUCT_ID,
    PRODUCTINFO_PRODUCT_VER,
    PRODUCTINFO_SPECIAL_ID,
    PRODUCTINFO_HW_ID,
    PRODUCTINFO_OEM_ID,
    PRODUCTINFO_LANGUAGE, 

    SYSMGR_PROINFO_ID_NUM,
} SYSMGR_PROINFO_ID;


/**************************************************************************************************/
/*                                      EXTERN_PROTOTYPES                                         */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      LOCAL_PROTOTYPES                                          */
/**************************************************************************************************/
/* Those clean freak and their compliers are really annoying ... J. Wang */
static char * _keyToStr(const SYSMGR_PROINFO_STR_MAP *pMap, int key) __attribute__ ((unused));
static int _ProductVerToStr(char* str, unsigned long *modelVer) __attribute__ ((unused));


/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/
static SYSMGR_PROINFO_STR_MAP l_mapProductInfoId[] = {
    {PRODUCTINFO_VENDOR_NAME,         "vendor_name"},
    {PRODUCTINFO_VENDOR_URL,          "vendor_url"},
    {PRODUCTINFO_PRODUCT_NAME,        "product_name"},
    {PRODUCTINFO_PRODUCT_ID,          "product_id"},

    {PRODUCTINFO_PRODUCT_VER,         "product_ver"},
    {PRODUCTINFO_SPECIAL_ID,          "special_id"},
    {PRODUCTINFO_HW_ID,               "hw_id"},
    {PRODUCTINFO_OEM_ID,              "oem_id"},
    {PRODUCTINFO_LANGUAGE,            "language"},

    {PRODCUTINFO_ID_VOID,                NULL}
};

static PRODUCT_INFO_STRUCT g_sysProductInfo;
static char productInfoBuf[SYSMGR_PROINFO_CONTENT_MAX_LEN];
static char supportListBuf[SYSMGR_SUPPORTLIST_CONTENT_MAX_LEN];

/**************************************************************************************************/
/*                                      LOCAL_FUNCTIONS                                           */
/**************************************************************************************************/

static int 
_makeSubStrByChar(char *string, char delimit, int maxNum, char *subStrArr[])
{
	char ws[8];
	char *pChar = NULL;
    char *pLast = NULL;
	int 	cnt    = 0;

	if ((NULL == string) || (NULL == subStrArr))
	{
		PRODUCTINFO_ERROR("Some parameter is null.\r\n");
		return -1;
	}

    if (maxNum <= 0)
    {
		PRODUCTINFO_ERROR("Maximum number is invalid. maxNum = %d\r\n", maxNum);
		return -1;
    }

	memset(ws, 0, sizeof(ws));

	ws[0] = delimit;
	ws[1] = '\0';
	strncat(ws, "\t\r\n", strlen("\t\r\n")+1);

	for (pChar=strtok_r(string,ws,&pLast); pChar; pChar=strtok_r(NULL,ws,&pLast))
	{
        subStrArr[cnt++] = pChar;

        #if 1
		if (cnt >= maxNum)
		{
			PRODUCTINFO_ERROR("Too many substrings to string.\r\n");
            
			return -1;
		}
        #endif
	}
    
	subStrArr[cnt] = NULL;

	return cnt;
}


static char* 
_delLeadingSpace(char *str)
{
    int     i;
    int     len;
    char    *tmpStart = NULL;

    if(NULL == str)
    {
        return NULL;
    }
    
    len = strlen(str);
    
    for (i = 0; i < len; ++i)
    {
        if(*(str + i) != ' ')
        {
            tmpStart = (str+i);
            break;
        }
        
    }
    if(NULL == tmpStart)
    {
        (*str) =  '\0';
        return str;
    }
    
    if(tmpStart > str)
    {
        memmove(str, tmpStart, strlen(tmpStart)+1);
    }
    
    return str;
}

static char* 
_delTailSpace(char *str)
{
    int     i;
    int     len;
    int    bAllBlank = 1;

    if(NULL == str)
    {
        return NULL;
    }
    
    len = strlen(str);
    
    bAllBlank = 1; 
    for (i = (len-1); i >= 0; --i)
    {
        if(*(str + i) != ' ')
        {
            bAllBlank = 0;
            break;
        }
    }
    if(0 == bAllBlank)
    {
    *(str + i + 1) = '\0';
    }
    else
    {
        (*str) = '\0';
    }
    
    return str;
}


static char* 
_delSpace(char* str)
{
    _delLeadingSpace(str);
    _delTailSpace(str);
    return str;
}

/* replace the srcchar with dstchar */
static char* 
_charReplace(char* string, const char srcchar, const char dstchar)
{
    int i;
    int len;
    if((NULL == string) || ('\0' == string[0]))
    {
        return NULL;
    }
    len = strlen(string);
    for (i = 0; i < len; ++i)
    {
        if (*(string + i) == srcchar)
        {
            *(string + i) = dstchar;
        }
    }
    
    return string;
}

static char * 
_keyToStr(const SYSMGR_PROINFO_STR_MAP *pMap, int key)
{
    int i = 0;
    
    while(pMap[i].str != NULL)
    {
        if (pMap[i].key == key)
            return pMap[i].str;

        i++;
    }

    return NULL;
}

static int
_strToKey(const SYSMGR_PROINFO_STR_MAP *pMap, const char *str)
{
    int i = 0;
    
    while(pMap[i].str != NULL)
    {
        if (0 == strcmp(pMap[i].str, str))
            return pMap[i].key;

        i++;
    }

    return -1;
}

static int 
_strToStr(char* outStr, int outStrSize, const char* inStr)
{
    int len  = 0;

    if ((NULL == inStr) || ('\0' == inStr[0]))
    {
        return ERROR;
    }

    if (NULL == outStr)
    {
        return ERROR;
    }

    if (strlen(inStr) > (outStrSize - 1))
    {
        return ERROR;
    }

    len = snprintf(outStr, outStrSize, "%s", inStr);
    if ((len < 0) || (len != strlen(inStr)))
    {
        return ERROR;
    }
    outStr[len] = '\0';

    return OK;
}

static int
_hexStrToUL(unsigned long *u32, const char* hexStr)
{
    char tmpStr[16] = {0};

    if (8 != strlen(hexStr))
    {
        return ERROR;
    }

    snprintf(tmpStr, sizeof(tmpStr), "0x%s", hexStr);

    
    (*u32) = strtoul(tmpStr, NULL, 16);

    return OK;
}

static int
_strToVendorName(char* vendorName, const char* str)
{
    return _strToStr(vendorName, PRODUCTINFO_VENDOR_NAME_LEN, str);
}

static int
_strToVendorUrl(char* vendorUrl, const char* str)
{
    return _strToStr(vendorUrl, PRODUCTINFO_VENDOR_URL_LEN, str);
}

static int
_strToProductName(char* modelName, const char* str)
{
    return _strToStr(modelName, PRODUCTINFO_PRODUCT_NAME_LEN, str);
}

static int
_strToProductId(unsigned long *modelId, const char* str)
{
    return _hexStrToUL(modelId, str);
}

static int
_strToSpecialId(unsigned long *specialId,const char *str)
{
    return _hexStrToUL(specialId,str);
}

static int
_strToProductVer(unsigned long *modelVer, const char* str)
{
    
    unsigned long ver = 0;
    int cnt = 0;
    unsigned long val[3] = {0};
    
    if (NULL == modelVer)
    {
        return ERROR;
    }

    if ((NULL == str) || ('\0' == str[0]))
    {
        return ERROR;
    }

    /* ProductVer:1.0.0 or 1.0 */
    /* 1.0.0 */
    if(strlen(str) == 5)
    {
        cnt = sscanf(str, "%u.%u.%u", &(val[0]), &(val[1]), &(val[2]));
    	if (3 != cnt)
    	{
	        return ERROR;
	}
	if ((val[0] > 0xff) || (val[1] > 0xff) || (val[2] > 0xff))
    	{
        	return ERROR;
    	}

	ver  = 0xff000000;
    	ver |= ((unsigned char)val[0]) << 16;
    	ver |= ((unsigned char)val[1]) <<  8;
    	ver |= (unsigned char)val[2];
    }
    /* 1.0 */
    else
    {
        cnt = sscanf(str, "%u.%u", &(val[0]), &(val[1]));
        if (2 != cnt)
        {
            return ERROR;
        }
        if ((val[0] > 0xff) || (val[1] > 0xff))
        {
            return ERROR;
        }

        ver  = 0xffff0000;
        ver |= ((unsigned char)val[0]) << 8;
        ver |= (unsigned char)val[1];
    }

    *modelVer = ver;

    return OK;
}

static int
_ProductVerToStr(char* str, unsigned long *modelVer)
{
    union 
    {
        unsigned long u32;
        unsigned char ch[4];
    } ver;

    if (NULL == modelVer)
    {
        return ERROR;
    }

    if (NULL == str)
    {
        return ERROR;
    }

    ver.u32 = *modelVer;

    sprintf(str, "%u.%u.%u", ver.ch[1], ver.ch[2], ver.ch[3]);

    return OK;
}
static int
_strToHwId(char *hwId, const char* str)
{
    return _strToStr(hwId, PRODUCTINFO_HW_ID_LEN, str);
}

static int
_strToOemId(char *oemId, const char* str)
{
    return _strToStr(oemId, PRODUCTINFO_OEM_ID_LEN, str);
}

static int
_strToProductLanguage(char *language, const char* str)
{
    return _strToStr(language, PRODUCTINFO_LANGUAGE_LEN, str);
}

int 
sysmgr_proinfo_buildStruct(PRODUCT_INFO_STRUCT *productInfo, const char* file, int fileLen)
{
    int     ret         = ERROR;
    
    char*   infoVal[SYSMGR_PROINFO_INFO_MAX_CNT] = {0};
    int     infoCnt     = 0;
    int     infoIndex   = 0;

    char*   buf         = NULL;

    if ((NULL == file) || (fileLen <= 0))
    {
        PRODUCTINFO_ERROR("Invalid file.\n");
        LEAVE(ERROR);
    }
#if 0
    /* memset(productInfo, 0, sizeof(*productInfo)); */
    buf = malloc(fileLen + 1);
    if (NULL == buf)
    {
        PRODUCTINFO_ERROR("No memory.\n");
        LEAVE(ERROR);
    }

    memcpy(buf, file, fileLen + 1);
#endif
    buf = file;

    _charReplace(buf, '\r', '\n');
    _charReplace(buf, '\n', SYSMGR_PROINFO_CHAR_INFO_SEPERATOR);

    //hexdump((const unsigned char *)buf, SYSMGR_PROINFO_CONTENT_MAX_LEN, 0);

    infoCnt = _makeSubStrByChar(buf, SYSMGR_PROINFO_CHAR_INFO_SEPERATOR, 
                                          SYSMGR_PROINFO_INFO_MAX_CNT, infoVal);
    if (infoCnt <= 0)
    {
        PRODUCTINFO_ERROR("ucm_string_makeSubStrByChar() failed.\n");
        LEAVE(ERROR);
    }

    for (infoIndex = 0; infoIndex < infoCnt; ++infoIndex)
    {    
        char*   argv[32] = {NULL};
        int     argc     = 0;
        int     argIndex = 0;
        int     id    = 0;

        PRODUCTINFO_DEBUG_L1("infoVal[%d] = (%s).\n", infoIndex, infoVal[infoIndex]);

        argc = _makeSubStrByChar(infoVal[infoIndex], ':', 32, argv);

        if (2 != argc)
        {
            PRODUCTINFO_ERROR("should be 2 args (%d).\n", argc);
            continue;
        }

        for (argIndex = 0; argIndex < argc; ++argIndex)
        {
            PRODUCTINFO_DEBUG_L1("argv[%d] = (%s).\n", argIndex, argv[argIndex]);
            _delSpace(argv[argIndex]);
            PRODUCTINFO_DEBUG_L1("argv[%d] = (%s).\n", argIndex, argv[argIndex]);
        }

        id = _strToKey(l_mapProductInfoId, argv[0]);
        switch (id)
        {
        case PRODUCTINFO_VENDOR_NAME:
            {
                ret = _strToVendorName((char*)productInfo->vendorName, argv[1]);
                if (ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToVendorName(%s) failed.\n", argv[1]);
                    LEAVE(ERROR);
                }
                break;
            }
        case PRODUCTINFO_VENDOR_URL:
            {
                ret = _strToVendorUrl((char*)productInfo->vendorUrl, argv[1]);
                if (ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToVendorUrl(%s) failed.\n", argv[1]);
                    LEAVE(ERROR);
                }
                break;
            }
        case PRODUCTINFO_PRODUCT_NAME:
            {
                ret = _strToProductName((char*)productInfo->productName, argv[1]);
                if (ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToModelName(%s) failed.\n", argv[1]);
                    LEAVE(ERROR);
                }
                break;
            }
        case PRODUCTINFO_PRODUCT_ID:
            {
                ret = _strToProductId(&(productInfo->productId), argv[1]);
                if (ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToModelId(%s) failed.\n", argv[1]);
                    LEAVE(ERROR);
                }
                break;
            }
         case PRODUCTINFO_SPECIAL_ID:
            {
                ret = _strToSpecialId(&(productInfo->specialId),argv[1]);
                if(ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToSpecialId(%s) failed.\n",argv[1]);
                    LEAVE(ERROR);
                }
                break;
            }
         case PRODUCTINFO_PRODUCT_VER:
            {
                ret = _strToProductVer(&(productInfo->productVer), argv[1]);
                if (ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToProductVer(%s) failed.\n", argv[1]);
                    LEAVE(ERROR);
                }
                break;
            }
         case PRODUCTINFO_HW_ID:
            {
				ret = _strToHwId((char *)productInfo->hwId, argv[1]);
                if (ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToHwId(%s) failed.\n", argv[1]);
                    LEAVE(ERROR);
                }
                break;
            }
         case PRODUCTINFO_OEM_ID:
            {
				ret = _strToOemId((char *)productInfo->oemId, argv[1]);
                if (ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToOemId(%s) failed.\n", argv[1]);
                    LEAVE(ERROR);
                }
                break;
            }
        case PRODUCTINFO_LANGUAGE:
            {
                ret = _strToProductLanguage((char *)productInfo->productLanguage, argv[1]);
                if (ERROR == ret)
                {
                    PRODUCTINFO_ERROR("_strToModelVer(%s) failed.\n", argv[1]);
                    LEAVE(ERROR);
                }
                break;

            }
        default:
            {
                PRODUCTINFO_ERROR("unknown id(%s), skip it.\n", argv[0]);
                break;
            }
        } /* end of switch() */
    }

    ret = OK;

leave:
#if 0
    if (NULL != buf)
    {
        free(buf);
    }
#endif
    return ret;
}

void sysmgr_proinfo_structShow(PRODUCT_INFO_STRUCT* productInfo)
{
    if (NULL == productInfo)
    {
        printf("productInfo param is null.\n");
        return;
    }
    printf("--------------------------------------------------------------------\r\n");
    printf("%16s : %s\n", "vendorName", productInfo->vendorName);
    printf("%16s : %s\n", "vendorUrl", productInfo->vendorUrl);
    printf("%16s : %s\n", "productName", productInfo->productName);
    printf("%16s : %s\n", "productLanguage", productInfo->productLanguage);


    printf("%16s : %08x\n", "productId", productInfo->productId);
    printf("%16s : %08x\n", "productVer", productInfo->productVer);
    printf("%16s : %08x\n", "specialId", productInfo->specialId);
    printf("%16s : %s\n", "hwId", productInfo->hwId);
    printf("%16s : %s\n", "oemId", productInfo->oemId);
    printf("--------------------------------------------------------------------\r\n");
}

/**************************************************************************************************/
/*                                      PUBLIC_FUNCTIONS                                          */
/**************************************************************************************************/
PRODUCT_INFO_STRUCT *sysmgr_getProductInfo(void)
{
    int ret = 0;

    ret = sysmgr_cfg_getProductInfoFromNvram(&g_sysProductInfo);
    if(OK != ret)
    {
        PRODUCTINFO_ERROR("Failed to read system Product Info.\r\n");
        return NULL;
    }
    //sysmgr_proinfo_structShow(&g_sysProductInfo);

    return &g_sysProductInfo;
}

/*!
 *\fn       void sysmgr_proinfo_show(void)
 *\brief    Show the product info of NVRAM.   
 *  
 *
 *\return   ERROR/OK       
 *
 */
void sysmgr_proinfo_show(void)
{
    PRODUCT_INFO_STRUCT proInfo;

    memset(&proInfo, 0, sizeof(proInfo));

    if(ERROR == sysmgr_cfg_getProductInfoFromNvram(&proInfo))
    {
        printf("failed to get product info from nvram.\n");
        return;
    }

    sysmgr_proinfo_structShow(&proInfo);
}


/*!
 *\fn       STATUS sysmgr_cfg_getProductInfoFromNvram(PRODUCT_INFO_STRUCT *productInfo) 
 *\brief    Get the product information from NVRAM.
 *\details  
 *
 *\param[in]    N/A
 *\param[out]   productInfo     The struct of the product information.
 *
 *\return   The result of the operation.
 *\retval   OK      Operation succeeded.
 *\retval   ERROR   Operation failed.
 *
 *\note     
 */
int 
sysmgr_cfg_getProductInfoFromNvram(PRODUCT_INFO_STRUCT *productInfo)
{
    char* buf = NULL;
    int   ret = ERROR;
    int   cnt = 0;

    buf = productInfoBuf;

    memset(buf, 0, SYSMGR_PROINFO_CONTENT_MAX_LEN);
    cnt = nm_api_readPtnFromNvram(NM_PTN_NAME_PRODUCT_INFO, buf, SYSMGR_PROINFO_CONTENT_MAX_LEN);
    if (cnt < 0)
    {
        PRODUCTINFO_ERROR("ucm_nvram_proInfoRead() failed.\n");
        LEAVE(ERROR);
    }
    buf[SYSMGR_PROINFO_CONTENT_MAX_LEN-1] = '\0';

    //PRODUCTINFO_DEBUG_L1("productinfo from NVRAM is\r\n%s\r\n", buf);

    if (ERROR == sysmgr_proinfo_buildStruct(productInfo, buf, strlen(buf)))
    {
        PRODUCTINFO_ERROR("sysmgr_proinfo_buildStruct() failed.\n");
        LEAVE(ERROR);
    }
    
    ret = OK;

leave:
    return OK;
}

int 
sysmgr_cfg_checkSupportList(PRODUCT_INFO_STRUCT *pProductInfo, const char* listContent, int fileLen)
{
    int     ret         = OK;

    char*   entryInfoVal[SYSMGR_PROINFO_INFO_MAX_CNT] = {0};
    char*   itemInfoVal [SYSMGR_SUPPORTLIST_MAX_CNT]  = {0};
    
    int     entryInfoCnt     = 0;
    int     itemInfoCnt      = 0;
    int     entryInfoIndex   = 0;
    int     itemInfoIndex    = 0;

    int isProductNameFound   = 0;
    int isProductVerFound    = 0;
    PRODUCT_INFO_STRUCT supportList;

    char*   buf         = NULL;

    if (NULL == pProductInfo)
    {
        LEAVE(ERROR);
    }

    if ((NULL == listContent) || (fileLen <= 0))
    {
        PRODUCTINFO_ERROR("Invalid file.\n");
        LEAVE(ERROR);
    }

#if 0
    buf = malloc(fileLen + 1);
    if (NULL == buf)
    {
        PRODUCTINFO_ERROR("No memory.\n");
        LEAVE(ERROR);
    }
#else
    if (fileLen > SYSMGR_SUPPORTLIST_CONTENT_MAX_LEN - 1)
    {
        PRODUCTINFO_ERROR("Support list size out of range.\n");
        LEAVE(ERROR);
    }

    buf = supportListBuf;
    memset(buf, 0, SYSMGR_SUPPORTLIST_CONTENT_MAX_LEN);
#endif
    memcpy(buf, listContent, fileLen);

    _charReplace(buf, '\r', '\n');
    _charReplace(buf, '{',  '\n');
    _charReplace(buf, '}',  '\n');
    _charReplace(buf, '\n', SYSMGR_PROINFO_CHAR_INFO_SEPERATOR);

    entryInfoCnt = _makeSubStrByChar(buf, SYSMGR_PROINFO_CHAR_INFO_SEPERATOR, 
                                          SYSMGR_SUPPORTLIST_MAX_CNT, entryInfoVal);
    if (entryInfoCnt <= 0)
    {
        PRODUCTINFO_ERROR("ucm_string_makeSubStrByChar() failed.\n");
        LEAVE(ERROR);
    }
    
    PRODUCTINFO_DEBUG_L1("%d support-list entries found.\r\n");
    for (entryInfoIndex = 0; entryInfoIndex < entryInfoCnt; ++entryInfoIndex)
    {
        int forbidden = 0;  
    
        isProductNameFound   = 0;
        isProductVerFound    = 0;
        PRODUCTINFO_DEBUG_L1("Checking entry:%d ...\r\n", entryInfoIndex);
        _charReplace(entryInfoVal[entryInfoIndex], ',', SYSMGR_PROINFO_CHAR_INFO_SEPERATOR);
        itemInfoCnt = _makeSubStrByChar(entryInfoVal[entryInfoIndex], 
                                        SYSMGR_PROINFO_CHAR_INFO_SEPERATOR, 
                                        SYSMGR_PROINFO_INFO_MAX_CNT, itemInfoVal);
        for(itemInfoIndex = 0; itemInfoIndex < itemInfoCnt; ++itemInfoIndex)
        {
            char*   argv[32] = {NULL};
            int     argc     = 0;
            int     argIndex = 0;
            int     id    = 0;

            if (forbidden)
            {
                PRODUCTINFO_DEBUG_L1("Entry %d NOT Match.\r\n", entryInfoIndex);
                break;
            }

            PRODUCTINFO_DEBUG_L1("itemInfoValue[%d] = (%s).\n", itemInfoIndex, itemInfoVal[itemInfoIndex]);
            argc = _makeSubStrByChar(itemInfoVal[itemInfoIndex], ':', 32, argv);        

            if (2 != argc)
            {
                PRODUCTINFO_ERROR("should be 2 args (%d).\n", argc);
                continue;
            }
            
            for (argIndex = 0; argIndex < argc; ++argIndex)
            {
                PRODUCTINFO_DEBUG_L1("argv[%d] = (%s).\n", argIndex, argv[argIndex]);
                _delSpace(argv[argIndex]);
                PRODUCTINFO_DEBUG_L1("argv[%d] = (%s).\n", argIndex, argv[argIndex]);
            }
            
            id = _strToKey(l_mapProductInfoId, argv[0]);

            switch (id)
            {
                case PRODUCTINFO_VENDOR_NAME:
                {
                    ret = _strToVendorName((char*)supportList.vendorName, argv[1]);
                    if (ERROR == ret)
                    {
                        PRODUCTINFO_ERROR("_strToVendorName(%s) failed.\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    
                    if (0 != strcasecmp((const char*)pProductInfo->vendorName, (const char*)supportList.vendorName))
                    {
                        PRODUCTINFO_ERROR("%s NOT Match.\r\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
                    break;
                }
                case PRODUCTINFO_VENDOR_URL:
                {
                    ret = _strToVendorUrl((char*)supportList.vendorUrl, argv[1]);
                    if (ERROR == ret)
                    {
                        PRODUCTINFO_ERROR("_strToVendorUrl(%s) failed.\n", argv[1]);
                        forbidden = 1;
                        break;
                    }

                    if (0 != strcasecmp((const char*)pProductInfo->vendorUrl, (const char*)supportList.vendorUrl))
                    {
                        PRODUCTINFO_ERROR("%s NOT Match.\r\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
                    break;
                }
                case PRODUCTINFO_PRODUCT_NAME:
                {
                    ret = _strToProductName((char*)supportList.productName, argv[1]);
                    if (ERROR == ret)
                    {
                        PRODUCTINFO_ERROR("_strToModelName(%s) failed.\n", argv[1]);
                        forbidden = 1;
                        break;
                    }

                    if (0 != strcasecmp((const char*)pProductInfo->productName, (const char*)supportList.productName))
                    {
                        PRODUCTINFO_ERROR("%s NOT Match.\r\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
                    isProductNameFound = 1;
                    break;
                }
                case PRODUCTINFO_PRODUCT_ID:
                {
                    ret = _strToProductId(&(supportList.productId), argv[1]);
                    if (ERROR == ret)
                    {
                        PRODUCTINFO_ERROR("_strToModelId(%s) failed.\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    
                    if (pProductInfo->productId != supportList.productId)
                    {
                        PRODUCTINFO_ERROR("%s NOT Match.\r\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
                    break;
                }
                case PRODUCTINFO_SPECIAL_ID:
                {
                    ret = _strToSpecialId(&(supportList.specialId),argv[1]);
                    if(ERROR == ret)
                    {
                        PRODUCTINFO_ERROR("_strToSpecialId(%s) failed.\n",argv[1]);
                        forbidden = 1;
                        break;
                    }

                    if (pProductInfo->specialId != supportList.specialId)
                    {
                        PRODUCTINFO_ERROR("%s NOT Match.\r\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
                    break;
                }
                case PRODUCTINFO_PRODUCT_VER:
                {
                    ret = _strToProductVer(&(supportList.productVer), argv[1]);
                    if (ERROR == ret)
                    {
                        PRODUCTINFO_ERROR("_strToModelVer(%s) failed.\n", argv[1]);
                        forbidden = 1;
                        break;
                    }

                    if (pProductInfo->productVer != supportList.productVer)
                    {
                        PRODUCTINFO_ERROR("%s NOT Match.\r\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
                    isProductVerFound = 1;
                    break;
                }
				case PRODUCTINFO_HW_ID:
				{
                    ret = _strToHwId((char *)supportList.hwId, argv[1]);
					if (ERROR == ret)
					{
						PRODUCTINFO_ERROR("_strToHwId(%s) failed.\n", argv[1]);
						forbidden = 1;
						break;
					}

					if (0 != strcasecmp((const char*)pProductInfo->hwId, (const char*)supportList.hwId))
					{
						PRODUCTINFO_ERROR("hwId %s NOT Match.\r\n", argv[1]);
						forbidden = 1;
						break;
					}
					PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
					break;

				}
				case PRODUCTINFO_OEM_ID:
				{
                    ret = _strToOemId((char *)supportList.oemId, argv[1]);
					if (ERROR == ret)
					{
						PRODUCTINFO_ERROR("_strToOemId(%s) failed.\n", argv[1]);
						forbidden = 1;
						break;
					}

					if (0 != strcasecmp((const char*)pProductInfo->oemId, (const char*)supportList.oemId))
					{
						PRODUCTINFO_ERROR("oemId %s NOT Match.\r\n", argv[1]);
						forbidden = 1;
						break;
					}
					PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
					break;

				}
                case PRODUCTINFO_LANGUAGE:
                {
                    ret = _strToProductLanguage((char *)supportList.productLanguage, argv[1]);
                    if (ERROR == ret)
                    {
                        PRODUCTINFO_ERROR("_strToModelVer(%s) failed.\n", argv[1]);
                        forbidden = 1;
                        break;
                    }

                    if (0 != strcasecmp((const char*)pProductInfo->productLanguage, (const char*)supportList.productLanguage))
                    {
                        PRODUCTINFO_ERROR("%s NOT Match.\r\n", argv[1]);
                        forbidden = 1;
                        break;
                    }
                    PRODUCTINFO_DEBUG_L1("%s Matched!!!\r\n", argv[1]);
                    break;

                }
                default:
                {
                    PRODUCTINFO_ERROR("unknown id(%s), skip it.\n", argv[0]);
                    break;
                }
            } /* end of switch() */
        } /* item parcing loops */
        
        /* We got here because an entry matched or forbidden */
        /* It is COMPULSORY that 'product_name' and 'product_ver' be written to every entry
         * of firmware's support-list. If this is not satified, we will consider this entry
         * as invalid. */
        if (!isProductNameFound || !isProductVerFound)
        {
            /* This entry regarded as invalid, try next entry. */
            PRODUCTINFO_DEBUG_L1("ProductName or ProductVersion not Found. "
                                 "Invalid support-list entry.\r\n");
            continue;
        }
        if (!forbidden)
        {
            /* Matched */       
            ret = OK;
            goto leave;
        }
        /* if forbidden, then we try next entry. */

    } /* entry parcing loops */

    /* All entries tried. NOT SUPPORTED */
    ret = ERROR;

leave:
#if 0
    if (NULL != buf)
    {
        free(buf);
    }
#endif
    return ret;

}

/**************************************************************************************************/
/*                                      GLOBAL_FUNCTIONS                                          */
/**************************************************************************************************/


