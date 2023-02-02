/*! Copyright(c) 1996-2009 Shenzhen TP-LINK Technologies Co. Ltd.
 * \file    nm_fwup.c
 * \brief   Implements for upgrade firmware to NVRAM.
 * \author  Meng Qing
 * \version 1.0
 * \date    21/05/2009
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
#include "lib_malloc.h"
#endif
#include <common.h>

#include "nm_lib.h"
#include "nm_fwup.h"
#include "nm_api.h"

#include "sysProductInfo.h"

/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/
/* Porting memory managing utils. */
extern void *malloc(unsigned int size);
extern void free(void *src);
#define fflush(stdout) 

/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      EXTERN_PROTOTYPES                                         */
/**************************************************************************************************/
STATUS nm_initFwupPtnStruct(void);
STATUS nm_getDataFromFwupFile(NM_PTN_STRUCT *ptnStruct, char *fwupPtnIndex, char *fwupFileBase);
STATUS nm_getDataFromNvram(NM_PTN_STRUCT *ptnStruct, NM_PTN_STRUCT *runtimePtnStruct);
STATUS nm_updateDataToNvram(NM_PTN_STRUCT *ptnStruct);
STATUS nm_updateRuntimePtnTable(NM_PTN_STRUCT *ptnStruct, NM_PTN_STRUCT *runtimePtnStruct);
static int nm_checkSupportList(char *support_list, int len);
STATUS nm_checkUpdateContent(NM_PTN_STRUCT *ptnStruct, char *pAppBuf, int nFileBytes, int *errorCode);
STATUS nm_cleanupPtnContentCache(void);
int nm_buildUpgradeStruct(char *pAppBuf, int nFileBytes);
STATUS nm_upgradeFwupFile(char *pAppBuf, int nFileBytes);

int handle_fw_cloud(unsigned char*, int);

/**************************************************************************************************/
/*                                      LOCAL_PROTOTYPES                                          */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

NM_STR_MAP nm_fwupPtnIndexFileParaStrMap[] =
{
    {NM_FWUP_PTN_INDEX_PARA_ID_NAME,    "fwup-ptn"},
    {NM_FWUP_PTN_INDEX_PARA_ID_BASE,    "base"},
    {NM_FWUP_PTN_INDEX_PARA_ID_SIZE,    "size"},

    {-1,                                NULL}
};

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
static unsigned char md5Key[IMAGE_SIZE_MD5] = 
{
	0x7a, 0x2b, 0x15, 0xed,  0x9b, 0x98, 0x59, 0x6d,
	0xe5, 0x04, 0xab, 0x44,  0xac, 0x2a, 0x9f, 0x4e
};
#endif
static unsigned char rsaPubKey[] = "BgIAAACkAABSU0ExAAQAAAEAAQD9lxDCQ5DFNSYJBriTmTmZlEMYVgGcZTO+AIwm" \
				"dVjhaeJI6wWtN7DqCaHQlOqJ2xvKNrLB+wA1NxUh7VDViymotq/+9QDf7qEtJHmesji" \
				"rvPN6Hfrf+FO4/hmjbVXgytHORxGta5KW4QHVIwyMSVPOvMC4A5lFIh+D1kJW5GXWtA==";

static struct fw_type_option fw_type_array[] =
{
	{	"Cloud",	FW_TYPE_CLOUD,		handle_fw_cloud},
	{	NULL,	FW_TYPE_INVALID,	NULL}	/* end entry of  fw_type_array */
};

NM_PTN_STRUCT *g_nmFwupPtnStruct;
NM_PTN_STRUCT g_nmFwupPtnStructEntity;
int g_nmCountFwupCurrWriteBytes;
int g_nmCountFwupAllWriteBytes;

STATUS g_nmUpgradeResult;


char *ptnContentCache[NM_PTN_NUM_MAX];

/**************************************************************************************************/
/*                                      LOCAL_FUNCTIONS                                           */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      PUBLIC_FUNCTIONS                                          */
/**************************************************************************************************/
//#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
enum fw_type gset_fw_type(enum fw_type type)
{
	static enum fw_type curr_fw_type = FW_TYPE_COMMON;

	if (FW_TYPE_INVALID < type && type < FW_TYPE_MAX)
		curr_fw_type = type;

	return curr_fw_type;
}
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
STATUS nm_tpFirmwareMd5Check(unsigned char *ptr,int bufsize)
{
	unsigned char fileMd5Checksum[IMAGE_SIZE_MD5];
	unsigned char digst[IMAGE_SIZE_MD5];
	
	memcpy(fileMd5Checksum, ptr + IMAGE_SIZE_LEN, IMAGE_SIZE_MD5);
	memcpy(ptr + IMAGE_SIZE_LEN, md5Key, IMAGE_SIZE_MD5);

	md5_make_digest(digst, ptr + IMAGE_SIZE_LEN, bufsize - IMAGE_SIZE_LEN);

	if (0 != memcmp(digst, fileMd5Checksum, IMAGE_SIZE_MD5))
	{
		NM_ERROR("Check md5 error.\n");
		return -1;
	}

	memcpy(ptr + IMAGE_SIZE_LEN, fileMd5Checksum, IMAGE_SIZE_MD5);

	return 0;
}
#endif
int handle_fw_cloud(unsigned char *buf, int buf_len)
{
	unsigned char md5_dig[MD5_DIGEST_LEN];
	unsigned char sig_buf[IMAGE_LEN_RSA_SIG];
	unsigned char tmp_rsa_sig[IMAGE_LEN_RSA_SIG];
	int ret = 0;

	/*backup data*/
	memcpy(tmp_rsa_sig,buf + IMAGE_SIZE_RSA_SIG,IMAGE_LEN_RSA_SIG);

	memcpy(sig_buf, buf + IMAGE_SIZE_RSA_SIG, IMAGE_LEN_RSA_SIG);

	/* fill with 0x0 */
	memset(buf + IMAGE_SIZE_RSA_SIG, 0x0, IMAGE_LEN_RSA_SIG);

	md5_make_digest(md5_dig, buf + IMAGE_SIZE_FWTYPE, buf_len - IMAGE_SIZE_FWTYPE);

	ret = rsaVerifySignByBase64EncodePublicKeyBlob(rsaPubKey, strlen((char *)rsaPubKey),
                md5_dig, MD5_DIGEST_LEN, sig_buf, IMAGE_LEN_RSA_SIG);

	memcpy(buf + IMAGE_SIZE_RSA_SIG,tmp_rsa_sig,IMAGE_LEN_RSA_SIG);

	if (NULL == ret)
	{
		NM_ERROR("Check rsa error.\n");
		return -1;
	}
	else
	{
		return 0;
	}
}
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
STATUS nm_tpFirmwareFindType(char *ptr, int len, char *buf, int buf_len)
{
	int end = 0;
	int begin = 0;
	char *pBuf = NULL;
	char *type = "fw-type:"; //the fw type stored as "fw-type:cloud\n"

	if (buf_len < IMAGE_CLOUD_HEAD_OFFSET || 
		len < (IMAGE_SIZE_FWTYPE + IMAGE_CLOUD_HEAD_OFFSET))
	{
		return -1;
	}
	
	pBuf = ptr + IMAGE_SIZE_FWTYPE;

	//find the fw type name begin and end
	while (*(pBuf + end) != '\n' && end < IMAGE_CLOUD_HEAD_OFFSET)
	{
		if (begin < strlen(type))
		{			
			if (*(pBuf + end) != type[begin])
			{
				return -1;
			}

			begin++;
		}

		end++;
	}

	if (end >= IMAGE_CLOUD_HEAD_OFFSET || begin != strlen(type) || end <= begin) 
		return -1;

	//copy to the fw type name buffer
	memcpy(buf, pBuf + begin, end - begin);

	return 0;
}
#endif
STATUS nm_tpFirmwareVerify(unsigned char *ptr,int len)
{
	int ret;
	char fw_type_name[FW_TYPE_NAME_LEN_MAX];
	struct fw_type_option *ptr_fw_type = NULL;
	char *pBuf = NULL;

	/* check fw_type for cloud */
        pBuf = ptr + IMAGE_SIZE_FWTYPE;

        memset(fw_type_name, 0x0, sizeof(fw_type_name));
        sscanf(pBuf, "fw-type:%[^\"\t\r\n]", fw_type_name);
        printf("fw_type_name : %s \n", fw_type_name);
//	nm_tpFirmwareFindType((char *)ptr, len, fw_type_name, FW_TYPE_NAME_LEN_MAX);
//	NM_INFO("fw type name : %s.\n", fw_type_name);

	//get firmware type
	for (ptr_fw_type = fw_type_array; ; ++ptr_fw_type)
	{
		if (!ptr_fw_type || !ptr_fw_type->name)
		{
			gset_fw_type(FW_TYPE_COMMON);
			break;
		}
		
		if (!strcmp(ptr_fw_type->name, fw_type_name))
		{
			gset_fw_type(ptr_fw_type->type);
			break;
		}
	}
#if 0
#ifdef CONFIG_FIRMWARE_NOCHECK
	NM_INFO("Firmware process common.\r\n");
	ret = nm_tpFirmwareMd5Check(ptr, len);
#else
	if (gset_fw_type(FW_TYPE_INVALID) == FW_TYPE_COMMON)
	{
		//common firmware MD5 check
		NM_INFO("Firmware process common.\r\n");
		ret = nm_tpFirmwareMd5Check(ptr, len);
	}
	else
	{
		NM_INFO("Firmware process id %d.\r\n", gset_fw_type(FW_TYPE_INVALID));
		//ret = ptr_fw_type->func(ptr, len);
		ret = handle_fw_cloud(ptr, len);
	}
#endif
	if ( ret < 0 )
	{
		return NM_FWUP_ERROR_INVALID_FILE;
	}
#endif

	printf("cloud %s : %d\n", __func__, __LINE__);

	ret = handle_fw_cloud(ptr, len);
	if ( ret < 0 )
        {
                return NM_FWUP_ERROR_INVALID_FILE;
        }

	NM_INFO("Image verify OK!\r\n");

	return OK;
}
//#endif
/*******************************************************************
 * Name		: nm_initFwupPtnStruct
 * Abstract	: Initialize partition-struct.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
STATUS nm_initFwupPtnStruct()
{
    memset(&g_nmFwupPtnStructEntity, 0, sizeof(g_nmFwupPtnStructEntity));
    g_nmFwupPtnStruct = &g_nmFwupPtnStructEntity;

    int index = 0;

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {           
        if (ptnContentCache[index] != NULL)
        {
            ptnContentCache[index] = NULL;
        }   
    }

    return OK;
}


/*******************************************************************
 * Name		: nm_getDataFromFwupFile
 * Abstract	: 
 * Input	: fwupFileBase: start addr of FwupPtnTable
 * Output	: 
 * Return	: OK/ERROR.
 */
STATUS nm_getDataFromFwupFile(NM_PTN_STRUCT *ptnStruct, char *fwupPtnIndex, char *fwupFileBase)
{   
    int index = 0;
    int paraId = -1;
    int argc;
    char *argv[NM_FWUP_PTN_INDEX_ARG_NUM_MAX];
    NM_PTN_ENTRY *currPtnEntry = NULL;

    argc = nm_lib_makeArgs(fwupPtnIndex, argv, NM_FWUP_PTN_INDEX_ARG_NUM_MAX);
    
    while (index < argc)
    {
        if ((paraId = nm_lib_strToKey(nm_fwupPtnIndexFileParaStrMap, argv[index])) < 0)
        {
            NM_ERROR("invalid partition-index-file para id.\r\n");
            goto error;
        }

        index++;

        switch (paraId)
        {
        case NM_FWUP_PTN_INDEX_PARA_ID_NAME:
            /* we only update upgrade-info to partitions exist in partition-table */
            currPtnEntry = nm_lib_ptnNameToEntry(ptnStruct, argv[index]);

            if (currPtnEntry == NULL)
            {
                NM_DEBUG("partition name not found.");
                continue;           
            }

            if (currPtnEntry->upgradeInfo.dataType == NM_FWUP_UPGRADE_DATA_TYPE_BLANK)
            {
                currPtnEntry->upgradeInfo.dataType = NM_FWUP_UPGRADE_DATA_FROM_FWUP_FILE;
            }
            index++;
            break;
            
        case NM_FWUP_PTN_INDEX_PARA_ID_BASE:
            /* get data-offset in fwupFile */
            if (nm_lib_parseU32((NM_UINT32 *)&currPtnEntry->upgradeInfo.dataStart, argv[index]) < 0)
            {
                NM_ERROR("parse upgradeInfo start value failed.");
                goto error;
            }
            
            currPtnEntry->upgradeInfo.dataStart += (unsigned int)fwupFileBase;
            index++;
            break;

        case NM_FWUP_PTN_INDEX_PARA_ID_SIZE:
            if (nm_lib_parseU32((NM_UINT32 *)&currPtnEntry->upgradeInfo.dataLen, argv[index]) < 0)
            {
                NM_ERROR("parse upgradeInfo len value failed.");
                goto error;
            }
            index++;
            break;

        default:
            NM_ERROR("invalid para id.");
            goto error;
            break;
        }
        
    }

    /* force get partition-table from fwup-file */
    currPtnEntry = nm_lib_ptnNameToEntry(ptnStruct, NM_PTN_NAME_PTN_TABLE); 
    if (currPtnEntry == NULL)
    {
        NM_ERROR("no partition-table in fwup-file.\r\n");
        goto error; 
    }

    currPtnEntry->upgradeInfo.dataType = NM_FWUP_UPGRADE_DATA_FROM_FWUP_FILE;
    currPtnEntry->upgradeInfo.dataStart = (unsigned int)fwupFileBase + NM_FWUP_PTN_INDEX_SIZE;
    /* length of partition-table is "probe to os-image"(4 bytes) and ptn-index-file(string) */
    currPtnEntry->upgradeInfo.dataLen = sizeof(int) + strlen((char*)(currPtnEntry->upgradeInfo.dataStart + sizeof(int)));
    
    return OK;
error:
    return ERROR;
}



/*******************************************************************
 * Name		: nm_getDataFromNvram
 * Abstract	: 
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR.
 */
STATUS nm_getDataFromNvram(NM_PTN_STRUCT *ptnStruct, NM_PTN_STRUCT *runtimePtnStruct)
{   
    int index = 0;
    NM_PTN_ENTRY *currPtnEntry = NULL;
    NM_UINT32 readSize = 0;
    

    NM_PTN_ENTRY *tmpPtnEntry = NULL;
	if (ptnStruct == NULL)
	{
        NM_ERROR("invalid input ptnStruct.");
        goto error;		
	}

    nm_cleanupPtnContentCache();   

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {       
#if 0
        currPtnEntry = nm_lib_ptnNameToEntry(ptnStruct, runtimePtnStruct->entries[index].name);

        if (currPtnEntry == NULL)
        {
            continue;           
        }

        if (currPtnEntry->upgradeInfo.dataType == NM_FWUP_UPGRADE_DATA_TYPE_BLANK)
        {
			/* if base not changed, do nothing */
			if (currPtnEntry->base == runtimePtnStruct->entries[index].base)
			{
				currPtnEntry->upgradeInfo.dataType = NM_FWUP_UPGRADE_DATA_TYPE_NO_CHANGE;
				continue;
			}
            /* read content from NVRAM to a memory cache */
            readSize = 0;
            if(currPtnEntry->size <= runtimePtnStruct->entries[index].size)
            {
                readSize = currPtnEntry->size;
            }
            else
            {
                readSize = runtimePtnStruct->entries[index].size;
            }
            //ptnContentCache[index] = malloc(runtimePtnStruct->entries[index].size);
            ptnContentCache[index] = malloc(readSize);

            if (ptnContentCache[index] == NULL)
            {
                NM_ERROR("memory malloc failed.");
                goto error;
            }
            
            //memset(ptnContentCache[index], 0, runtimePtnStruct->entries[index].size);
            memset(ptnContentCache[index], 0, readSize);

            if (nm_lib_readHeadlessPtnFromNvram((char *)runtimePtnStruct->entries[index].base, 
                                                ptnContentCache[index], readSize) < 0)
            {               
                NM_ERROR("get data from NVRAM failed.");
                goto error;
            }

            currPtnEntry->upgradeInfo.dataStart = (unsigned int)ptnContentCache[index];
            currPtnEntry->upgradeInfo.dataLen = readSize;
            currPtnEntry->upgradeInfo.dataType = NM_FWUP_UPGRADE_DATA_FROM_NVRAM;
        }
#else
		tmpPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
		if (tmpPtnEntry->upgradeInfo.dataType == NM_FWUP_UPGRADE_DATA_TYPE_BLANK)
		{
			/* if not in nvram */
			//currPtnEntry = nm_lib_ptnNameToEntry(runtimePtnStruct, tmpPtnEntry->name);
			currPtnEntry = nm_lib_ptnNameToEntry(runtimePtnStruct, tmpPtnEntry->fullname);
			if (currPtnEntry == NULL)
			{
				continue;			
			}
		
			/* if base not changed, do nothing */
			if (currPtnEntry->base == tmpPtnEntry->base)
			{
				tmpPtnEntry->upgradeInfo.dataType = NM_FWUP_UPGRADE_DATA_TYPE_NO_CHANGE;
				continue;
			}
			/* read content from NVRAM to a memory cache */
			readSize = 0;
			if(currPtnEntry->size <= tmpPtnEntry->size)
			{
				readSize = currPtnEntry->size;
			}
			else
			{
				readSize = tmpPtnEntry->size;
			}

			ptnContentCache[index] = malloc(readSize);
		
			if (ptnContentCache[index] == NULL)
			{
				NM_ERROR("memory malloc failed.");
				goto error;
			}
			
			memset(ptnContentCache[index], 0, readSize);
		
			if (nm_lib_readHeadlessPtnFromNvram((char *)currPtnEntry->base, 
												ptnContentCache[index], readSize) < 0)
			{				
				NM_ERROR("get data from NVRAM failed.");
				goto error;
			}
		
			tmpPtnEntry->upgradeInfo.dataStart = (unsigned int)ptnContentCache[index];
			tmpPtnEntry->upgradeInfo.dataLen = readSize;
			tmpPtnEntry->upgradeInfo.dataType = NM_FWUP_UPGRADE_DATA_FROM_NVRAM;
		}
#endif
    }

    return OK;
error:
    return ERROR;
}
    
STATUS nm_updatePartitionDataToNvram(NM_PTN_ENTRY *currPtnEntry, int index)
{
        int numBlookUpdate = 0;
        int  firstFragmentSize = 0;
        int firstFragment = TRUE;
        unsigned long int fragmentBase = 0;
        int  fragmentDataStart = 0;
        int  fwupDataLen = 0;

	NM_DEBUG("PTN %02d: name = %-16s, base = 0x%08x, size = 0x%08x Bytes, upDataType = %d, upDataStart = %08x, upDataLen = %08x",
        index+1, 
        currPtnEntry->fullname,
        currPtnEntry->base,
        currPtnEntry->size,
        currPtnEntry->upgradeInfo.dataType,
        currPtnEntry->upgradeInfo.dataStart,
        currPtnEntry->upgradeInfo.dataLen);

        if (currPtnEntry->upgradeInfo.dataLen > NM_FWUP_FRAGMENT_SIZE)
        {
            fwupDataLen = currPtnEntry->upgradeInfo.dataLen;
            firstFragment = TRUE;

            firstFragmentSize = NM_FWUP_FRAGMENT_SIZE - (currPtnEntry->base % NM_FWUP_FRAGMENT_SIZE);
            fragmentBase = 0;
            fragmentDataStart = 0;

            while (fwupDataLen > 0)
            {
                if (firstFragment)
                {
                    fragmentBase = currPtnEntry->base;
                    fragmentDataStart = currPtnEntry->upgradeInfo.dataStart;

                    NM_DEBUG("PTN f %02d: fragmentBase = %08x, FragmentStart = %08x, FragmentLen = %08x, datalen = %08x", index+1, fragmentBase, fragmentDataStart, firstFragmentSize, fwupDataLen);

                    if (nm_lib_writeHeadlessPtnToNvram((char *)fragmentBase, 
                                                            (char *)fragmentDataStart,
                                                            firstFragmentSize) < 0)
                    {
                        NM_ERROR("WRITE TO NVRAM FAILED!!!!!!!!.");
                        return ERROR;
                    }

                    fragmentBase += firstFragmentSize;
                    fragmentDataStart += firstFragmentSize;
                    g_nmCountFwupCurrWriteBytes += firstFragmentSize;
                    fwupDataLen -= firstFragmentSize;
                    NM_DEBUG("PTN f %02d: write bytes = %08x", index+1, g_nmCountFwupCurrWriteBytes);
                    firstFragment = FALSE;
                }
                    /* last block */
                else if (fwupDataLen < NM_FWUP_FRAGMENT_SIZE)
                {
                    NM_DEBUG("PTN l %02d: fragmentBase = %08x, FragmentStart = %08x, FragmentLen = %08x, datalen = %08x", index+1, fragmentBase, fragmentDataStart, fwupDataLen, fwupDataLen);

                    if (nm_lib_writeHeadlessPtnToNvram((char *)fragmentBase, 
                                                            (char *)fragmentDataStart,
                                                            fwupDataLen) < 0)
                    {
                        NM_ERROR("WRITE TO NVRAM FAILED!!!!!!!!.");
                        return ERROR;
                    }

                    fragmentBase += fwupDataLen;
                    fragmentDataStart += fwupDataLen;
                    g_nmCountFwupCurrWriteBytes += fwupDataLen;
                    fwupDataLen -= fwupDataLen;
                    NM_DEBUG("PTN l %02d: write bytes = %08x", index+1, g_nmCountFwupCurrWriteBytes);
                }
                else
                {
                    NM_DEBUG("PTN n %02d: fragmentBase = %08x, FragmentStart = %08x, FragmentLen = %08x, datalen = %08x", index+1, fragmentBase, fragmentDataStart, NM_FWUP_FRAGMENT_SIZE, fwupDataLen);

                    if (nm_lib_writeHeadlessPtnToNvram((char *)fragmentBase, 
                                                            (char *)fragmentDataStart,
                                                            NM_FWUP_FRAGMENT_SIZE) < 0)
                    {
                        NM_ERROR("WRITE TO NVRAM FAILED!!!!!!!!.");
                        return ERROR;
                    }
                 
                    fragmentBase += NM_FWUP_FRAGMENT_SIZE;
                    fragmentDataStart += NM_FWUP_FRAGMENT_SIZE;
                    g_nmCountFwupCurrWriteBytes += NM_FWUP_FRAGMENT_SIZE;
                    fwupDataLen -= NM_FWUP_FRAGMENT_SIZE;
                    NM_DEBUG("PTN n %02d: write bytes = %08x", index+1, g_nmCountFwupCurrWriteBytes);
                }

                if(numBlookUpdate >= 70)
                {
                        numBlookUpdate = 0;
                        printf("\r\n");
                }
                numBlookUpdate ++;
                printf("#");
                fflush(stdout);
            }

        }
        else
        {           
            /* we should add head to ptn-table partition */
            if (strncmp(currPtnEntry->name, NM_PTN_NAME_PTN_TABLE, NM_PTN_NAME_LEN) == 0)
            {
                if (nm_lib_writePtnToNvram((char *)currPtnEntry->base, 
                                                    (char *)currPtnEntry->upgradeInfo.dataStart,
                                                    currPtnEntry->upgradeInfo.dataLen) < 0)
                {
                    NM_ERROR("WRITE TO NVRAM FAILED!!!!!!!!.");
                    return ERROR;
                }
            }
            /* head of other partitions can be found in fwup-file or NVRAM */
            else
            {
            	if (nm_lib_writeHeadlessPtnToNvram((char *)currPtnEntry->base, 
                                                    (char *)currPtnEntry->upgradeInfo.dataStart,
                                                    currPtnEntry->upgradeInfo.dataLen) < 0)                             
                {
                   NM_ERROR("WRITE TO NVRAM FAILED!!!!!!!!.");
                    return ERROR;
               	}
	    }
            g_nmCountFwupCurrWriteBytes += currPtnEntry->upgradeInfo.dataLen;
            NM_DEBUG("PTN %02d: write bytes = %08x", index+1, g_nmCountFwupCurrWriteBytes);

            if(numBlookUpdate >= 70)
            {
                numBlookUpdate = 0;
                printf("\r\n");
            }

	    numBlookUpdate ++;
	    printf("#");
	    fflush(stdout);
    }

	return OK;
}

int nm_isLeaderPartition(NM_PTN_ENTRY *entry)
{
    if (entry->usedFlag != TRUE)
    {
        return FALSE;
    }

    if (entry->upgradeInfo.dataType == NM_FWUP_UPGRADE_DATA_TYPE_NO_CHANGE)
    {
        return FALSE;
    }

    if (strncmp(entry->name, NM_PTN_NAME_OS_IMAGE, NM_PTN_NAME_LEN) != 0)
    {
        return FALSE;
    }

    return TRUE;
}

/*******************************************************************
 * Name		: nm_updateDataToNvram
 * Abstract	: write to NARAM
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR.
 */
STATUS nm_updateDataToNvram(NM_PTN_STRUCT *ptnStruct)
{   
    int index = 0;
    NM_PTN_ENTRY *currPtnEntry = NULL;

    /* clear write bytes counter first */
    g_nmCountFwupAllWriteBytes = 0;

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);

        switch (currPtnEntry->upgradeInfo.dataType)
        {
        case NM_FWUP_UPGRADE_DATA_TYPE_BLANK:
            /* if a partition is "blank", means it's a new partition
             * without content, we set content of this partition to all zero */
            if (ptnContentCache[index] != NULL)
            {
                free(ptnContentCache[index]);
                ptnContentCache[index] = NULL;
            }

            ptnContentCache[index] = malloc(currPtnEntry->size);            

            if (ptnContentCache[index] == NULL)
            {
                NM_ERROR("memory malloc failed.");
                goto error;
            }
            
            memset(ptnContentCache[index], 0, currPtnEntry->size);

            currPtnEntry->upgradeInfo.dataStart = (unsigned int)ptnContentCache[index];
            currPtnEntry->upgradeInfo.dataLen = currPtnEntry->size;
            break;
		case NM_FWUP_UPGRADE_DATA_TYPE_NO_CHANGE:
			NM_DEBUG("PTN %s no need to update.", currPtnEntry->fullname);
			break;

        case NM_FWUP_UPGRADE_DATA_FROM_FWUP_FILE:
        case NM_FWUP_UPGRADE_DATA_FROM_NVRAM:
            /* Do Nothing */
            break;

        default:
            NM_ERROR("invalid upgradeInfo dataType found.");
            goto error;
            break;  
        }
        
    }

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);

        if (currPtnEntry->usedFlag != TRUE)
        {
            continue;
        }
        
        g_nmCountFwupAllWriteBytes += currPtnEntry->upgradeInfo.dataLen;
        
        NM_DEBUG("PTN %02d: dataLen = %08x, g_nmCountFwupAllWriteBytes = %08x", 
                        index+1, currPtnEntry->upgradeInfo.dataLen, g_nmCountFwupAllWriteBytes);
    }

    //Erase first block of Kernel partition.
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
        if (currPtnEntry->usedFlag != TRUE)
        {
            continue;
        }

        if (nm_isLeaderPartition(currPtnEntry))
        {
            char eraseBuf[NM_FWUP_FRAGMENT_SIZE];
            memset(eraseBuf, 0xff, NM_FWUP_FRAGMENT_SIZE);
            NM_INFO("erase %s first", currPtnEntry->fullname);
            currPtnEntry = nm_lib_ptnNameToEntry(g_nmPtnStruct, currPtnEntry->fullname);
            if (nm_lib_writeHeadlessPtnToNvram((char *)currPtnEntry->base,
                                               eraseBuf, NM_FWUP_FRAGMENT_SIZE) < 0)
            {
                NM_ERROR("erase failed");
                /* Ignore it. */
                continue;
            }
        }
    }



#if defined(CONFIG_PRODUCT_E4)
		ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 1));//e4 red
		ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 21));//e4 green
		ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 2));//e4 blue
		ath_reg_rmw_clear(GPIO_OUT_ADDRESS, (1 << 1) + (1 << 21));//e4 red
		ath_reg_rmw_set(GPIO_OUT_ADDRESS, (1 << 2));//e4 red
#else
		ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 1));//red
    	ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 7));//green
#endif

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);

        switch (currPtnEntry->upgradeInfo.dataType)
        {
		case NM_FWUP_UPGRADE_DATA_TYPE_NO_CHANGE:
			NM_DEBUG("PTN %s no need to update.\r\n", currPtnEntry->fullname);
			break;
        case NM_FWUP_UPGRADE_DATA_TYPE_BLANK:       
        case NM_FWUP_UPGRADE_DATA_FROM_FWUP_FILE:   
        case NM_FWUP_UPGRADE_DATA_FROM_NVRAM:
            if (currPtnEntry->usedFlag != TRUE)
            {
                NM_DEBUG("PTN %02d: usedFlag = FALSE", index+1);
                continue;
            }

            if (nm_isLeaderPartition(currPtnEntry))
            {
                NM_INFO("skip %s for a second", currPtnEntry->fullname);
                continue;
            }

            if(nm_updatePartitionDataToNvram(currPtnEntry, index) == ERROR)
            {
                goto error;
            }

            break;

        default:
            NM_ERROR("invalid upgradeInfo dataType found.");
            goto error;
            break;  
        }       
    }

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
        if (nm_isLeaderPartition(currPtnEntry))
        {
            if (nm_updatePartitionDataToNvram(currPtnEntry, index) == ERROR)
            {
                goto error;
            }
        }
    }

    printf("\r\nDone.\r\n");
    return OK;
error:
    return ERROR;
}


/*******************************************************************
 * Name		: nm_updateRuntimePtnTable
 * Abstract	: update the runtimePtnTable.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
STATUS nm_updateRuntimePtnTable(NM_PTN_STRUCT *ptnStruct, NM_PTN_STRUCT *runtimePtnStruct)
{   
    int index = 0;
    NM_PTN_ENTRY *currPtnEntry = NULL;
    NM_PTN_ENTRY *currRuntimePtnEntry = NULL;

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
        currRuntimePtnEntry = (NM_PTN_ENTRY *)&(runtimePtnStruct->entries[index]);

        strncmp(currRuntimePtnEntry->name, currPtnEntry->name, NM_PTN_NAME_LEN);
	strncmp(currRuntimePtnEntry->fullname, currPtnEntry->fullname, NM_PTN_NAME_LEN);
        currRuntimePtnEntry->base = currPtnEntry->base;
        currRuntimePtnEntry->tail = currPtnEntry->tail;
        currRuntimePtnEntry->size = currPtnEntry->size;
        currRuntimePtnEntry->usedFlag = currPtnEntry->usedFlag;
    }   

    return OK;
}



int nm_checkSupportList(char *support_list, int len)
{
    int ret = 0;
    
    PRODUCT_INFO_STRUCT *pProductInfo = NULL;

    /* skip partition header */
    len -= 8;
    support_list += 8;
 
    /* check list prefix string */
    if (len < 12 || strncmp(support_list, "SupportList:", 12) != 0)
        return 0;

    len -= 12;
    support_list += 12;

    pProductInfo = sysmgr_getProductInfo();
    ret = sysmgr_cfg_checkSupportList(pProductInfo, support_list, len);
    if (0 == ret)
    {
        NM_INFO("Firmware supports, check OK.\r\n");
        return 1;
    }
    
    NM_INFO("Firmware not supports, check failed.\r\n");
    return 0;
}

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
/*******************************************************************
 * Name		: nm_checkUpgradeMode
 * Abstract	: check the boot mode
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_checkUpgradeMode(NM_PTN_STRUCT *ptnStruct)
{
    NM_PTN_ENTRY *ptnEntry = NULL;
    int upDbootFound = FALSE;
    int flashDbootFound = FALSE;
	NM_PTN_EXTRA_PARA *ptnSysParaData = NULL;
	
	/* not allowed to upgrade between double boot version 
	 * and single boot version, "extra-para" all exist or 
	 * not and double boot flag must equal
	 */

	/* check partition-table partition base address is equal or not*/
	if ((ptnEntry = nm_lib_ptnNameToEntry(ptnStruct, NM_PTN_NAME_PTN_TABLE)) == NULL)
	{
		NM_ERROR("Up file partition-table not found!\n");
		return ERROR;
		
	}

	if (ptnEntry->base != NM_PTN_TABLE_BASE)
	{
		NM_ERROR("Up file partition-table base address changed up(0x%08x) flash(0x%08x)!\n",
			ptnEntry->base, NM_PTN_TABLE_BASE);
		return ERROR;		
	}

	/* do not allow double boot upgrade to single boot or single to double */
	if ((ptnEntry = nm_lib_ptnNameToEntry(ptnStruct, NM_PTN_NAME_EXTRA_PARA)) != NULL)
	{
		/* double boot up file must have extra-para partition for boot mode check */
		if (ptnEntry->upgradeInfo.dataType == NM_FWUP_UPGRADE_DATA_FROM_FWUP_FILE)
		{
			ptnSysParaData = (NM_PTN_EXTRA_PARA *)((char*)ptnEntry->upgradeInfo.dataStart + 8);

			if (ptnSysParaData->dbootFlag == NM_FWUP_IS_DOUBLE_BOOT)
			{
				upDbootFound = TRUE;
			}
		}
	}

	flashDbootFound = TRUE;

	if (upDbootFound != flashDbootFound)
	{
		NM_ERROR("Double boot flag up %d flash %d not ok!",
			upDbootFound, flashDbootFound);
		return ERROR;
	}
	
	return OK;
}

/*******************************************************************
 * Name		: nm_checkSoftVer
 * Abstract	: check the software version.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_checkSoftVer(char *sw_ver, int len)
{
	int ret = 0;
	int cnt = 0;

	char tmpbuff[NM_FWUP_SOFTWARE_VERSION_LEN] = {0};
	int buflen = NM_FWUP_SOFTWARE_VERSION_LEN;
	int curFw_x = 0, curFw_y = 0;
	int newFw_x = 0, newFw_y = 0;

	/* skip partition header */
	len -= 8;
	sw_ver += 8;

	/* check list prefix string */
	if (strncmp(sw_ver, "soft_ver:", 9) != 0)
		return ERROR;

	len -= 9;
	sw_ver += 9;

	cnt = sscanf(sw_ver, "%d.%d.%*s", &newFw_x, &newFw_y);
	if (cnt != 2)
	{
		NM_ERROR("Input get soft version digit failed!");		
		return ERROR;
	}

	/* read partition from nvram */
	ret = nm_api_readPtnFromNvram(NM_PTN_NAME_SOFT_VERSION, tmpbuff, buflen);
	if (ret < 0)
	{
		NM_ERROR("failed to read partition from flash!");
		return ERROR;
	}
	
	if (strncmp(tmpbuff, "soft_ver:", 9) != 0)
		return ERROR;
			
	cnt = sscanf(tmpbuff+9, "%d.%d.%*s", &curFw_x, &curFw_y);
	if (cnt != 2)
	{
		NM_ERROR("Flash get soft version digit failed!");		
		return ERROR;
	}

	NM_INFO(" (curFw_ver, newFw_ver) == (%d.%d, %d.%d) \r\n", curFw_x,curFw_y, newFw_x,newFw_y);

	if ((curFw_x > newFw_x) || 
	    ((curFw_x == newFw_x) && (curFw_y > newFw_y)))
	{
		NM_ERROR("Firmware not supports, check failed.");
		return ERROR;
	}

	return OK;
}
#endif

/*******************************************************************
 * Name		: nm_checkUpdateContent
 * Abstract	: check the updata content.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
STATUS nm_checkUpdateContent(NM_PTN_STRUCT *ptnStruct, char *pAppBuf, int nFileBytes, int *errorCode)
{   
    int index = 0;
    NM_PTN_ENTRY *currPtnEntry = NULL;
    int ptnFound = FALSE;
	int suppportListIndex = 0;
	int softVersionIndex = 0;

    /* check update content */
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);

        if (currPtnEntry->upgradeInfo.dataType == NM_FWUP_UPGRADE_DATA_FROM_FWUP_FILE)
        {       
            if ((currPtnEntry->upgradeInfo.dataStart + currPtnEntry->upgradeInfo.dataLen)
                > (unsigned int)(pAppBuf + nFileBytes))
            {
                NM_ERROR("ptn \"%s\": update data end out of fwup-file.", currPtnEntry->fullname);
                *errorCode = NM_FWUP_ERROR_BAD_FILE;
                goto error;
            }
        }
    }

    /* check important partitions */
    ptnFound = FALSE;

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
		currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);

       	if (strncmp(currPtnEntry->name, NM_PTN_NAME_FS_UBOOT, NM_PTN_NAME_LEN) == 0)
        {
            ptnFound = TRUE;
            break;
        }
    }
    if (ptnFound == FALSE)
    {               
        NM_ERROR("ptn \"%s\" not found whether in fwup-file or NVRAM.", NM_PTN_NAME_FS_UBOOT);
        *errorCode = NM_FWUP_ERROR_BAD_FILE;
        goto error;
    }


	ptnFound = FALSE;
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
        
        if (strncmp(currPtnEntry->name, NM_PTN_NAME_PTN_TABLE, NM_PTN_NAME_LEN) == 0)
        {
            ptnFound = TRUE;
            break;
        }
    }
    if (ptnFound == FALSE)
    {               
        NM_ERROR("ptn \"%s\" not found whether in fwup-file or NVRAM.", NM_PTN_NAME_PTN_TABLE);
        *errorCode = NM_FWUP_ERROR_BAD_FILE;
        goto error;
    }

//#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
    ptnFound = FALSE;
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
        
        if (strncmp(currPtnEntry->name, NM_PTN_NAME_DEFAULT_MAC, NM_PTN_NAME_LEN) == 0)
        {
            ptnFound = TRUE;
            break;
        }
    }
    if (ptnFound == FALSE)
    {               
        NM_ERROR("ptn \"%s\" not found whether in fwup-file or NVRAM.", NM_PTN_NAME_DEFAULT_MAC);
        *errorCode = NM_FWUP_ERROR_BAD_FILE;
        goto error;
    }


	ptnFound = FALSE;
	for (index=0; index<NM_PTN_NUM_MAX; index++)
	{
		currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
		
		if (strncmp(currPtnEntry->name, NM_PTN_NAME_PRODUCT_INFO, NM_PTN_NAME_LEN) == 0)
		{
			ptnFound = TRUE;
			break;
		}
	}
	if (ptnFound == FALSE)
	{				
		NM_ERROR("ptn \"%s\" not found whether in fwup-file or NVRAM.", NM_PTN_NAME_PRODUCT_INFO);
		*errorCode = NM_FWUP_ERROR_BAD_FILE;
        goto error;
    }
//#endif
	ptnFound = FALSE;
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
        
        if (strncmp(currPtnEntry->name, NM_PTN_NAME_SUPPORT_LIST, NM_PTN_NAME_LEN) == 0)
        {
			suppportListIndex = index;
            ptnFound = TRUE;
			//currPtnEntry->upgradeInfo.dataType = NM_FWUP_UPGRADE_DATA_TYPE_NO_CHANGE;
            break;
        }
    }
    if (ptnFound == FALSE)
    {               
        NM_ERROR("ptn \"%s\" not found whether in fwup-file or NVRAM.", NM_PTN_NAME_SUPPORT_LIST);
        *errorCode = NM_FWUP_ERROR_BAD_FILE;
        goto error;
    }

	
	ptnFound = FALSE;
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
        
        if (strncmp(currPtnEntry->name, NM_PTN_NAME_SOFT_VERSION, NM_PTN_NAME_LEN) == 0)
        {
			softVersionIndex = index;
            ptnFound = TRUE;
            break;
        }
    }
    if (ptnFound == FALSE)
    {               
        NM_ERROR("ptn \"%s\" not found whether in fwup-file or NVRAM.", NM_PTN_NAME_SOFT_VERSION);
        *errorCode = NM_FWUP_ERROR_BAD_FILE;
        goto error;
    }
	

    ptnFound = FALSE;
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
        
        if (strncmp(currPtnEntry->name, NM_PTN_NAME_OS_IMAGE, NM_PTN_NAME_LEN) == 0)
        {
            ptnFound = TRUE;
            break;
        }
    }
    if (ptnFound == FALSE)
    {               
        NM_ERROR("ptn \"%s\" not found whether in fwup-file or NVRAM.", NM_PTN_NAME_OS_IMAGE);
        *errorCode = NM_FWUP_ERROR_BAD_FILE;
        goto error;
    }


	ptnFound = FALSE;
	for (index=0; index<NM_PTN_NUM_MAX; index++)
	{
		currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[index]);
		
		if (strncmp(currPtnEntry->name, NM_PTN_NAME_FILE_SYSTEM, NM_PTN_NAME_LEN) == 0)
		{
			ptnFound = TRUE;
			break;
		}
	}
	if (ptnFound == FALSE)
	{				
		NM_ERROR("ptn \"%s\" not found whether in fwup-file or NVRAM.", NM_PTN_NAME_FILE_SYSTEM);
		*errorCode = NM_FWUP_ERROR_BAD_FILE;
		goto error;
	}

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
	if (OK != nm_checkUpgradeMode(ptnStruct))
	{
		NM_ERROR("upgrade boot mode check fail.");
		*errorCode = NM_FWUP_ERROR_UNSUPPORT_BOOT_MOD;
		goto error;	
	}
#endif	
	//check the hardware version support list
	currPtnEntry = (NM_PTN_ENTRY *)&(ptnStruct->entries[suppportListIndex]);

	if(
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
	   	NM_FWUP_UPGRADE_DATA_FROM_FWUP_FILE != currPtnEntry->upgradeInfo.dataType ||
#endif
        !nm_checkSupportList((char*)currPtnEntry->upgradeInfo.dataStart, currPtnEntry->upgradeInfo.dataLen))
	{
		NM_ERROR("the firmware is not for this model");
		*errorCode = NM_FWUP_ERROR_INCORRECT_MODEL;
		goto error;
	}

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)	
	currPtnEntry = (NM_PTN_ENTRY *) & (ptnStruct->entries[softVersionIndex]);
	if (gset_fw_type(FW_TYPE_INVALID) == FW_TYPE_CLOUD &&
	        OK != nm_checkSoftVer((char *)currPtnEntry->upgradeInfo.dataStart, currPtnEntry->upgradeInfo.dataLen))
	{
		NM_ERROR("the firmware software version dismatched");
		*errorCode = NM_FWUP_ERROR_UNSUPPORT_VER;
		goto error;
	}
#endif

    return OK;
error:
    return ERROR;
}



/*******************************************************************
 * Name		: nm_cleanupPtnContentCache
 * Abstract	: free the memmory of ptnContentCache.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR.
 */

STATUS nm_cleanupPtnContentCache()
{   
    int index = 0;


    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {           
        if (ptnContentCache[index] != NULL)
        {
            free(ptnContentCache[index]);
            ptnContentCache[index] = NULL;
        }   
    }
    
    return OK;
}


/*******************************************************************
 * Name		: nm_buildUpgradeStruct
 * Abstract	: Generate an upgrade file from NVRAM and firmware file.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR.
 */
int nm_buildUpgradeStruct(char *pAppBuf, int nFileBytes)
{
    char fwupPtnIndex[NM_FWUP_PTN_INDEX_SIZE+1] = {0};
    char *fwupFileBase = NULL;
    int index;
    int ret = 0;

    memset(g_nmFwupPtnStruct, 0, sizeof(NM_PTN_STRUCT));
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        g_nmFwupPtnStruct->entries[index].usedFlag = FALSE;
    }
    g_nmCountFwupAllWriteBytes = 0;
    g_nmCountFwupCurrWriteBytes = 0;
    nm_cleanupPtnContentCache();

    /* backup "fwup-partition-index" */
    fwupFileBase = pAppBuf;
    strncpy(fwupPtnIndex, pAppBuf, NM_FWUP_PTN_INDEX_SIZE+1); 
    pAppBuf += NM_FWUP_PTN_INDEX_SIZE;
    pAppBuf += sizeof(int);

    NM_DEBUG("nFileBytes = %d",  nFileBytes);
    if (nm_lib_parsePtnIndexFile(g_nmFwupPtnStruct, pAppBuf) != OK)
    {
        NM_ERROR("parse new ptn-index failed.");
        ret = NM_FWUP_ERROR_BAD_FILE;
        goto cleanup;
    }

    if (nm_getDataFromFwupFile(g_nmFwupPtnStruct, (char *)&fwupPtnIndex, fwupFileBase) != OK)
    {
        NM_ERROR("getDataFromFwupFile failed.");
        ret = NM_FWUP_ERROR_BAD_FILE;
        goto cleanup;
    }

    if (nm_getDataFromNvram(g_nmFwupPtnStruct, g_nmPtnStruct) != OK)
    {
        NM_ERROR("getDataFromNvram failed.");
        ret = NM_FWUP_ERROR_BAD_FILE;
        goto cleanup;
    }

    if (nm_checkUpdateContent(g_nmFwupPtnStruct, fwupFileBase, nFileBytes, &ret) != OK)
    {
        NM_ERROR("checkUpdateContent failed.");
        goto cleanup;
    }

    return 0;
    
cleanup:
    memset(g_nmFwupPtnStruct, 0, sizeof(NM_PTN_STRUCT));
    g_nmCountFwupAllWriteBytes = 0;
    g_nmCountFwupCurrWriteBytes = 0;
    nm_cleanupPtnContentCache();
    g_nmUpgradeResult = FALSE;
    return ret;
}


/*******************************************************************
 * Name		: nm_upgradeFwupFile
 * Abstract	: upgrade the FwupFile to NVRAM
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR.
 */
STATUS nm_upgradeFwupFile(char *pAppBuf, int nFileBytes)
{   
    g_nmUpgradeResult = FALSE;
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
	if (OK != nm_api_setIntegerFlag(NM_FWUP_NOT_INTEGER))
	{
		NM_ERROR("set not integer failed!");
		goto cleanup;
	}
#endif

    if (nm_updateDataToNvram(g_nmFwupPtnStruct) != OK)
    {
        NM_ERROR("updateDataToNvram failed.");
        goto cleanup;
    }

    /* update run-time partition-table, active new partition-table without restart */
    if (nm_updateRuntimePtnTable(g_nmFwupPtnStruct, g_nmPtnStruct) != OK)
    {
        NM_ERROR("updateDataToNvram failed.");
        goto cleanup;
    }
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
	if (OK != nm_api_setIntegerFlag(NM_FWUP_IS_INTEGER))
	{
		NM_ERROR("set integer failed!");
		goto cleanup;
	}
#endif

    memset(g_nmFwupPtnStruct, 0, sizeof(NM_PTN_STRUCT));
    g_nmCountFwupAllWriteBytes = 0;
    g_nmCountFwupCurrWriteBytes = 0;
    nm_cleanupPtnContentCache();
    g_nmUpgradeResult = TRUE;
    return OK;
    
cleanup:
    memset(g_nmFwupPtnStruct, 0, sizeof(NM_PTN_STRUCT));
    g_nmCountFwupAllWriteBytes = 0;
    g_nmCountFwupCurrWriteBytes = 0;
    nm_cleanupPtnContentCache();
    g_nmUpgradeResult = FALSE;
    return ERROR;
}

/*  *********************************************************************
    *  nm_tpFirmwareCheck()
    *  
    *  firmware check
    *  
    *  Input parameters: 
    *  	   ptr     : buffer pointer
    *	   bufsize : buffer size
    *  	   
    *  Return value:
    *  	   0 if set ok
    *  	   other is error
    ********************************************************************* */
STATUS nm_tpFirmwareCheck(unsigned char *ptr,int bufsize)
{
    int ret = 0;
    int fileLen = 0;
    unsigned char *pBuf = NULL;

    ret = nm_init();
    if (OK != ret)
    {
        NM_ERROR("Init failed.");
        return NM_FWUP_ERROR_NORMAL;
    }
    
    memcpy(&fileLen, ptr, sizeof(int));
	fileLen = ntohl(fileLen);

	if(fileLen < IMAGE_SIZE_MIN || fileLen > IMAGE_SIZE_MAX || bufsize < fileLen)
	{
		NM_ERROR("The file's length is bad(buf:%d fileLen%d)", bufsize, fileLen);
		return NM_FWUP_ERROR_INVALID_FILE;
	}

	NM_INFO("Firmware Recovery file length : %d\r\n", fileLen);

	ret = nm_tpFirmwareVerify(ptr, bufsize);
	if (0 != ret)
	{
		return ret;
	}
	
	NM_INFO("Firmware file Verify ok!\r\n");

	pBuf = ptr + IMAGE_SIZE_BASE;
	ret = nm_buildUpgradeStruct((char *)pBuf, bufsize - IMAGE_SIZE_BASE);
	if (0 != ret)
	{
		return ret;
	}

	NM_INFO("Firmware Recovery check ok!\r\n");
	
    return OK;
}

/*  *********************************************************************
    *  nm_tpFirmwareRecovery()
    *  
    *  firmware recovery process
    *  
    *  Input parameters: 
    *  	   ptr     : buffer pointer
    *	   bufsize : buffer size
    *  	   
    *  Return value:
    *  	   0 if set ok
    *  	   other is error
    ********************************************************************* */
STATUS nm_tpFirmwareRecovery(unsigned char *ptr,int bufsize)
{
    int ret = 0;
    
	ret = nm_tpFirmwareCheck(ptr, bufsize);
    if (OK != ret)
    {
		return ret;
	}
	ret = nm_upgradeFwupFile((char *)ptr + IMAGE_SIZE_BASE, bufsize - IMAGE_SIZE_BASE);
    if (OK != ret)
    {
        NM_ERROR("upgrade firmware failed!");
		return NM_FWUP_ERROR_NORMAL;
    }

	NM_INFO("Firmware Recovery Success!\r\n");
    return OK;
}
/**************************************************************************************************/
/*                                      GLOBAL_FUNCTIONS                                          */
/**************************************************************************************************/

