
/*! Copyright(c) 1996-2009 Shenzhen TP-LINK Technologies Co. Ltd.
 * \file	nm_lib.c
 * \brief	api functions for NVRAM manager.
 * \author	Meng Qing
 * \version	1.0
 * \date	24/04/2009
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
#endif
#include <common.h>

#include "nm_lib.h"
#include "nm_api.h"


/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      EXTERN_PROTOTYPES                                         */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      LOCAL_PROTOTYPES                                          */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      LOCAL_FUNCTIONS                                           */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      PUBLIC_FUNCTIONS                                          */
/**************************************************************************************************/

/*******************************************************************
 * Name		: nm_api_writePtnToNvram
 * Abstract	: write the value of a partition to NVRAM.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_api_writePtnToNvram(char *name, char *buf, int len)
{
	int ret;
	char *ptr = buf;
	NM_PTN_ENTRY *ptnEntry;

	NM_SEM_TAKE(g_nmReadWriteLock, WAIT_FOREVER);
	
	/* get runtime-partition-entry by name */
	if ((ptnEntry = nm_lib_ptnNameToEntry(g_nmPtnStruct, name)) == NULL)
	{
		NM_ERROR("partition name not found.\r\n");
		goto error;
	}

	/* some partitions don't have partition head(partition-length & checksum) */
	if ((strncmp(NM_PTN_NAME_FS_UBOOT, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
		|| (strncmp(NM_PTN_NAME_FACTORY_BOOT, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
#endif
		|| (strncmp(NM_PTN_NAME_OS_IMAGE, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_FILE_SYSTEM, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_QOS_DB, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_RADIO, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_LOG, ptnEntry->name, NM_PTN_NAME_LEN) == 0))
	{
		if (len > ptnEntry->size)
		{
			NM_ERROR("no enough space in this partition.");
			goto error;
		}

		ret = nm_lib_writeHeadlessPtnToNvram((char *)ptnEntry->base, ptr, len);
	}
	else
	{
		if (len > (ptnEntry->size - sizeof(int) - sizeof(int)))
		{
			NM_ERROR("no enough space in this partition.");
			goto error;
		}
		
		ret = nm_lib_writePtnToNvram((char *)ptnEntry->base, ptr, len);
	}

	NM_SEM_GIVE(g_nmReadWriteLock);
	return ret;
	
error:
	NM_SEM_GIVE(g_nmReadWriteLock);
	return -1;
}



/*******************************************************************
 * Name		: nm_api_readPtnFromNvram
 * Abstract	: read value of a partition from NVRAM.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_api_readPtnFromNvram(char *name, char *buf, int len)
{
	int ret;
	char *ptr = buf;
	NM_PTN_ENTRY *ptnEntry;

	NM_SEM_TAKE(g_nmReadWriteLock, WAIT_FOREVER);
		
	/* get runtime-partition-entry by name */
	if ((ptnEntry = nm_lib_ptnNameToEntry(g_nmPtnStruct, name)) == NULL)
	{
		NM_ERROR("partition name not found.\r\n");
		goto error;
	}

	/* some partitions don't have partition head(partition-length & checksum) */
	if ((strncmp(NM_PTN_NAME_FS_UBOOT, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
		|| (strncmp(NM_PTN_NAME_FACTORY_BOOT, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
#endif
		|| (strncmp(NM_PTN_NAME_OS_IMAGE, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_FILE_SYSTEM, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_QOS_DB, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_RADIO, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_LOG, ptnEntry->name, NM_PTN_NAME_LEN) == 0))
	{
		ret = nm_lib_readHeadlessPtnFromNvram((char *)ptnEntry->base, ptr, len);
	}
	else
	{
		ret = nm_lib_readPtnFromNvram((char *)ptnEntry->base, ptr, len);
	}

	NM_SEM_GIVE(g_nmReadWriteLock);
	return ret;
	
error:
	NM_SEM_GIVE(g_nmReadWriteLock);
	return -1;
}




/*******************************************************************
 * Name		: nm_api_writeToNvram
 * Abstract	: write value from a buffer to NVRAM.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_api_writeToNvram(char *base, char *buf, int len)
{
	int ret;
	
	NM_SEM_TAKE(g_nmReadWriteLock, WAIT_FOREVER);
	ret = nm_lib_writeHeadlessPtnToNvram(base, buf, len);
	NM_SEM_GIVE(g_nmReadWriteLock);

	return ret;
}



/*******************************************************************
 * Name		: nm_api_readFromNvram
 * Abstract	: read value from NVRAM to a buffer.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_api_readFromNvram(char *base, char *buf, int len)
{
	int ret;
	
	NM_SEM_TAKE(g_nmReadWriteLock, WAIT_FOREVER);
	ret = nm_lib_readHeadlessPtnFromNvram(base, buf, len);
	NM_SEM_GIVE(g_nmReadWriteLock);

	return ret;
}

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
/*******************************************************************
 * Name		: nm_api_erasePtn
 * Abstract	: erase a partition.
 * Input	: partition name
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_api_erasePtn(char *name)
{
	char *eraseBuf = NULL;
	NM_PTN_ENTRY *ptnEntry;

	/* get runtime-partition-entry by name */
	if ((ptnEntry = nm_lib_ptnNameToEntry(g_nmPtnStruct, name)) == NULL)
	{
		NM_ERROR("partition name not found.\r\n");
		return ERROR;
	}
    
    eraseBuf = (char *)malloc(ptnEntry->size);
    NM_DEBUG("eraseBuf size = %x \n", ptnEntry->size);
    if (eraseBuf == NULL)
    {
        NM_ERROR("malloc failed! \n");
        return ERROR;
    }

    /* reset partition content to 0xff */
    memset(eraseBuf, 0xff, ptnEntry->size);

    
	if(nm_lib_writeHeadlessPtnToNvram((char *)ptnEntry->base, eraseBuf, ptnEntry->size) < 0)
    {
        NM_ERROR("erase failed! \n");
        free(eraseBuf);
        return ERROR;
    }

    free(eraseBuf);
	return OK;

}



/*******************************************************************
 * Name		: nm_api_readPtnUsedSize
 * Abstract	: read used size of a partition with header.
 * Input	: partition name 
 * Output	: 
 * Return	: used size
 */
int  nm_api_readPtnUsedSize(char *name)
{
    int size;
	NM_PTN_ENTRY *ptnEntry;
    
	/* get runtime-partition-entry by name */
	if ((ptnEntry = nm_lib_ptnNameToEntry(g_nmPtnStruct, name)) == NULL)
	{
		NM_ERROR("partition name not found.\r\n");
	    return -1;
	}

	/* some partitions don't have partition head(partition-length & checksum) */

	if ((strncmp(NM_PTN_NAME_USER_CFG, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_PROFILE, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_DEFAULT_MAC, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_DEFAULT_CFG, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_SOFT_VERSION, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_PRODUCT_INFO, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_PIN, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_PTN_TABLE, ptnEntry->name, NM_PTN_NAME_LEN) == 0)
		|| (strncmp(NM_PTN_NAME_SUPPORT_LIST, ptnEntry->name, NM_PTN_NAME_LEN) == 0))

	{
		size = nm_lib_readPtnUsedSize((char *)ptnEntry->base);
	}
	else
	{
		NM_ERROR("partition with header not found.\r\n");
	    return -1;
	}

	return size;
}

/*******************************************************************
 * Name		: nm_api_setIntegerFlag
 * Abstract	: set image integer flag.
 * Input	: N/A 
 * Output	: 
 * Return	: 0 if check ok, -1 if check fail
 */
int nm_api_setIntegerFlag(unsigned char flag)
{
	int len = -1;
	NM_PTN_EXTRA_PARA sysParaData;

	memset(&sysParaData, 0, sizeof(NM_PTN_EXTRA_PARA));
	
	NM_INFO("set integer flag to %d.\r\n", flag);

	//get partition table
    if (0 != nm_init())   
    {
		NM_ERROR("set integer flag partition init fail.");
	    return ERROR;
    }

	//get the sys para data stored in flash
	len = nm_api_readPtnFromNvram(NM_PTN_NAME_EXTRA_PARA, 
					(char *)&sysParaData, sizeof(NM_PTN_EXTRA_PARA));
    if (len < 0)   
    {
		NM_ERROR("read integer flag from partition failed.");
		return ERROR;
    }

	//set the integer flag
	sysParaData.integerFlag = flag;
	len = nm_api_writePtnToNvram(NM_PTN_NAME_EXTRA_PARA, 
					(char *)&sysParaData, sizeof(NM_PTN_EXTRA_PARA));

    if (len < 0)   
    {
		NM_ERROR("write integer flag to partition failed.");
	    return ERROR;
    }

	return OK;
}
#endif

/*******************************************************************
 * Name		: nm_api_checkInteger
 * Abstract	: Process image integer check.
 * Input	: N/A 
 * Output	: 
 * Return	: 0 if check ok, -1 if check fail
 */
int nm_api_checkInteger(void)
{
#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
	int len = -1;
	NM_PTN_EXTRA_PARA sysParaData;

	//get partition table
    if (0 != nm_init())   
    {
	NM_ERROR("factory boot check integer partition init fail.");
    return ERROR;
    }

	//get the md5 value stored in flash
	len = nm_api_readPtnFromNvram(NM_PTN_NAME_EXTRA_PARA, 
							(char *)&sysParaData, sizeof(NM_PTN_EXTRA_PARA));
    if (len < 0)   
    {
	NM_ERROR("factory boot check integer read flag partition fail.");
    return ERROR;
    }

	//if integer flag is 1, mean upgrade no error
	if (sysParaData.integerFlag != NM_FWUP_IS_INTEGER)
	{
		NM_ERROR("factory boot check integer flag is not 1.");
		return ERROR;
	}
	NM_INFO("factory boot check integer ok.\r\n");
#endif
	return OK;
}
/*******************************************************************
 * Name         : nm_api_checkDefaultMac
 * Abstract     : Process default mac check.
 * Input        : N/A 
 * Output       : 
 * Return       : 0 if has default-mac , or -1 
 */
#define MAC_BUFF_SIZE 6
int nm_api_checkDefaultMac(void)
{
	int len = -1;
	unsigned char match_buff[6] = {0xff, 0xff, 0xff, 0xff,0xff,0xff};
	unsigned char mac[MAC_BUFF_SIZE] = {0};
	if (0 == nm_init())
	{
		len = nm_api_readPtnFromNvram(NM_PTN_NAME_DEFAULT_MAC, mac, MAC_BUFF_SIZE);
		if (len < 0)
		{
			return -1;
		}
		if (0 == memcmp(mac, match_buff, sizeof(match_buff)))
		{
			return -1;
		}
		else
		{
			return 0;
		}
	}
	return -1;
}

/*******************************************************************
 * Name         : nm_api_checkKernel
 * Abstract     : Process image kernel check.
 * Input        : N/A 
 * Output       : 
 * Return       : 0 if check ok, -1 if check fail
 */
#define BLOCK_SIZE 0x10000
int isCheckKernel = TRUE;
int nm_api_checkKernel(void)
{
	isCheckKernel = TRUE;

        int len = -1;
	unsigned char buf[BLOCK_SIZE];
	unsigned char matchPattern[16] = {0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF
					};

        //get partition table
        if (0 != nm_init())
        {
            NM_ERROR("factory boot check kernel partition init fail.");
	    isCheckKernel = FALSE;
            return ERROR;
        }

        //get the value stored in flash
        len = nm_api_readPtnFromNvram(NM_PTN_NAME_OS_IMAGE, buf, BLOCK_SIZE);
        if (len < 0)
        {
            NM_ERROR("factory boot check kernel partition fail.");
	    isCheckKernel = FALSE;
            return ERROR;
        }

	//hexdump(buf, 1024, buf);	

	if(memcmp(matchPattern, buf, sizeof(matchPattern)) == 0
		&& memcmp(matchPattern, buf + 320, sizeof(matchPattern)) == 0
		&& memcmp(matchPattern, buf + 480, sizeof(matchPattern)) == 0
		)
        {
		isCheckKernel = FALSE;
                return ERROR;
        }

        NM_INFO("factory boot check kernel ok.\r\n");
        return OK;	
}

/**************************************************************************************************/
/*                                      GLOBAL_FUNCTIONS                                          */
/**************************************************************************************************/


