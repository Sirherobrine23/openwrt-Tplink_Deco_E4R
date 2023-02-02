
/*! Copyright(c) 1996-2009 Shenzhen TP-LINK Technologies Co. Ltd.
 * \file    nm_lib.c
 * \brief   library functions for NVRAM manager.
 * \author  Meng Qing
 * \version 1.0
 * \date    24/04/2009
 */

/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/
#if 0
#include "cfe_iocb.h"
#include "cfe_devfuncs.h"

#include "lib_types.h"
#include "lib_string.h"
#include "lib_printf.h"
#endif
#include <common.h>

#include "nm_lib.h"
#include "nm_fwup.h"
#include "nm_api.h"



/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/
#define FLASH_SECTOR_SIZE      (64*1024)
#define FLASH_DEV_NAME         "flash0"

#define copy_from_user(kernel, user, len) memcpy(kernel, user, len)
#define copy_to_user(user, kernel, len)   memcpy(user, kernel, len)
extern unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base);
#define strtoul(a,b,c)                    simple_strtoul(a, b, c)
/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      EXTERN_PROTOTYPES                                         */
/**************************************************************************************************/
//extern unsigned long bcm_strtoul(const char *cp, char **endp, unsigned int base);
extern int nvrammngr_flashOpPortErase(unsigned int off, unsigned int len);
extern int nvrammngr_flashOpPortWrite(unsigned int off, unsigned int len, unsigned char *in);
extern int isCheckKernel;

/**************************************************************************************************/
/*                                      LOCAL_PROTOTYPES                                          */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/
static int  l_nminited = FALSE;
NM_PTN_STRUCT *g_nmPtnStruct;
NM_PTN_STRUCT g_nmPtnStructEntity;

#if USE_LOCK
SEM_ID g_nmReadWriteLock;
#endif

NM_STR_MAP nm_ptnIndexFileParaStrMap[] =
{
    {NM_PTN_INDEX_PARA_ID_NAME,         "partition"},
    {NM_PTN_INDEX_PARA_ID_BASE,         "base"},
    {NM_PTN_INDEX_PARA_ID_TAIL,         "tail"},
    {NM_PTN_INDEX_PARA_ID_SIZE,         "size"},

    {-1,                                NULL}
};

static unsigned char nvrammngr_rwBuf[FLASH_SECTOR_SIZE];
static unsigned char orignData[FLASH_SECTOR_SIZE];
/**************************************************************************************************/
/*                                      LOCAL_FUNCTIONS                                           */
/**************************************************************************************************/
static int _nvrammng_flash_erase(unsigned int off)
{
    nvrammngr_flashOpPortErase(off|0x9f000000, FLASH_SECTOR_SIZE);
    return 0;
}

static int flag = 1;
static int count = 1;
static int _nvrammngr_flash_read(unsigned char *in, unsigned int off, unsigned int len)
{
    if(isCheckKernel == FALSE){
        if(count < 2)
        {
            count++;
        }
        else
        {
            if(flag == 1)
            {
                
#if defined(CONFIG_PRODUCT_E4)
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 1));//e4 red
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 21));//e4 green
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 2));//e4 blue
				ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 1) + (1 << 21));//e4 red
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 2));//e4 blue
#else
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 1));//red
                ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 7));//green
#endif
                flag = 0;
            }
            else
            {
#if defined(CONFIG_PRODUCT_E4)
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 1));//e4 red
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 21));//e4 green
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 2));//e4 blue
				ath_reg_rmw_clear(GPIO_OE_ADDRESS, (1 << 1) + (1 << 21));//e4 red
#else
				ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 1));//red
                ath_reg_rmw_set(GPIO_OE_ADDRESS, (1 << 7));//green
#endif
                flag = 1;
            }
            count = 1;
    	}
    }
    //nvrammngr_flashOpPortRead(in, off, len);
    NM_DEBUG("Read flash from address: %x\n", (const void *)(off|0x9f000000));
    memcpy(in, (const void *)(off|0x9f000000), len);
    //printk("[NVRAM-MNGR] read after port api\n");
    //hexdump(in, 64, off);
    return 0;
}

static int _nvrammngr_flash_write(unsigned int off, unsigned int len, unsigned char *in)
{
    //nvrammngr_flashOpPortWrite(off, len, in);
    nvrammngr_flashOpPortWrite(off|0x9f000000, len, in);
    //printf("*");
    return 0;
}
int nm_lib_writePtntoNvram_unify(uint32_t hasHead, uint32_t offset, uint8_t *data, uint32_t len)
{
	uint32_t address = 0;
	uint32_t headLen = 0;
	uint32_t endAddr = 0, startAddr = 0;
	//uint8_t *orignData = NULL;
	uint32_t headData[2] = {len, 0};
	uint32_t frontLen = 0, tailLen = 0;
	uint32_t retLen = 0;

	headData[0] = htonl(len);	

	if (hasHead != 0)
	{
		headLen = 2 * sizeof(uint32_t);
		len += headLen;
	}

	frontLen = offset % FLASH_SECTOR_SIZE;
	tailLen  = (offset + len) % FLASH_SECTOR_SIZE;
	address = offset - frontLen;
	endAddr = offset + len - tailLen;

	NM_DEBUG("\n*****\n frontLen is %08x.\n tailLen is %08x.\n address is %08x.\n endAddr is %08x.",
		frontLen, tailLen, address, endAddr);

	//orignData = (uint8_t *)(nvrammngr_rwBuf + FLASH_SECTOR_SIZE);

	if (frontLen > 0 || headLen > 0)
	{
		retLen = _nvrammngr_flash_read(orignData, address, FLASH_SECTOR_SIZE);
		memcpy(nvrammngr_rwBuf, orignData, frontLen);
		//hexdump(orignData, 1024, orignData);
		if (FLASH_SECTOR_SIZE < frontLen + headLen) 
		{
			headLen = FLASH_SECTOR_SIZE - frontLen;
			memcpy(nvrammngr_rwBuf + frontLen, headData, headLen);

			/***************************************************/
			if (memcmp(orignData, nvrammngr_rwBuf, FLASH_SECTOR_SIZE) != 0)
			{
				_nvrammng_flash_erase(address);
				retLen = _nvrammngr_flash_write(address, FLASH_SECTOR_SIZE, nvrammngr_rwBuf);
			}
			address += FLASH_SECTOR_SIZE;
			/***************************************************/
			retLen = _nvrammngr_flash_read(orignData, address, FLASH_SECTOR_SIZE);
			memcpy(nvrammngr_rwBuf, (uint8_t*)(headData) + headLen, 8 - headLen);

			if (len - headLen < FLASH_SECTOR_SIZE) 
			{
				headLen = 8 - headLen;
				copy_from_user(nvrammngr_rwBuf + headLen, data, tailLen - headLen);
				memcpy(nvrammngr_rwBuf + tailLen, orignData + tailLen, FLASH_SECTOR_SIZE - tailLen);
				data += tailLen - headLen;
			}
			else
			{
				headLen = 8 - headLen;
				copy_from_user(nvrammngr_rwBuf + headLen, data, FLASH_SECTOR_SIZE - headLen);
				data += FLASH_SECTOR_SIZE - headLen;
			}
		}
		else
		{
			memcpy(nvrammngr_rwBuf + frontLen, headData, headLen);
			
			if (len + frontLen < FLASH_SECTOR_SIZE)
			{
				copy_from_user(nvrammngr_rwBuf + frontLen + headLen, data, len - headLen);
				data += len - headLen;
				memcpy(nvrammngr_rwBuf + frontLen + len,
						orignData + frontLen + len,
						FLASH_SECTOR_SIZE - (frontLen + len));
			}
			else
			{
				copy_from_user(nvrammngr_rwBuf + frontLen + headLen, data, FLASH_SECTOR_SIZE - frontLen - headLen);
				data += FLASH_SECTOR_SIZE - frontLen - headLen;
			}
		}

		/***************************************************/
		if (memcmp(orignData, nvrammngr_rwBuf, FLASH_SECTOR_SIZE) != 0)
		{
			_nvrammng_flash_erase(address);
			retLen = _nvrammngr_flash_write(address, FLASH_SECTOR_SIZE, nvrammngr_rwBuf);
		}
		address += FLASH_SECTOR_SIZE;
		/***************************************************/
	}

	if (address < endAddr)
	{
		startAddr = address;
		while (address < endAddr)
		{
			retLen = _nvrammngr_flash_read(orignData, address, FLASH_SECTOR_SIZE);
			//hexdump(orignData, 1024, orignData);
			copy_from_user(nvrammngr_rwBuf, data, FLASH_SECTOR_SIZE);
			/***************************************************/
			if (memcmp(orignData, nvrammngr_rwBuf, FLASH_SECTOR_SIZE) != 0)
			{
				_nvrammng_flash_erase(address);
				retLen = _nvrammngr_flash_write(address, FLASH_SECTOR_SIZE, nvrammngr_rwBuf);
			}
			address += FLASH_SECTOR_SIZE;
			/***************************************************/
			data += FLASH_SECTOR_SIZE;
		}
	}

	if (address < offset + len) 
	{
		retLen = _nvrammngr_flash_read(orignData, address, FLASH_SECTOR_SIZE);
		copy_from_user(nvrammngr_rwBuf, data, tailLen);
		memcpy(nvrammngr_rwBuf + tailLen, orignData + tailLen, FLASH_SECTOR_SIZE - tailLen);
		/***************************************************/
		if (memcmp(orignData, nvrammngr_rwBuf, FLASH_SECTOR_SIZE) != 0) 
		{
			_nvrammng_flash_erase(address);
			retLen = _nvrammngr_flash_write(address, FLASH_SECTOR_SIZE, nvrammngr_rwBuf);
		}
		address += FLASH_SECTOR_SIZE;
		/***************************************************/
	}

	return 0;
}

static int nm_lib_readFlash_unify(uint32_t offset, uint8_t *usr_buf, uint32_t len)
{
	uint32_t startBlkAddr = 0, endBlkAddr = 0;
	uint32_t frontLen = 0, tailLen = 0;
    uint32_t readAddr = 0;
	uint32_t retLen = 0;

    uint8_t *pUsrBufCur = usr_buf;

	frontLen     = offset % FLASH_SECTOR_SIZE;
	tailLen      = (offset + len) % FLASH_SECTOR_SIZE;
	startBlkAddr = offset - frontLen;
	endBlkAddr   = offset + len - tailLen;
    readAddr     = startBlkAddr;

    //printk("[NVRAM-MNGR] read frontLen %d \n", frontLen);
    //printk("[NVRAM-MNGR] read tailLen %d \n",  tailLen);
    //printk("[NVRAM-MNGR] read startBlkAddr %d \n", startBlkAddr);
    //printk("[NVRAM-MNGR] read endBlkAddr %d \n", endBlkAddr);
    //printk("[NVRAM-MNGR] read frontreadAddrLen %d \n", readAddr);
    //printk("[NVRAM-MNGR] read user_buf addr %08x \n", usr_buf);
	if (frontLen > 0)
	{
        retLen = _nvrammngr_flash_read(nvrammngr_rwBuf, readAddr, FLASH_SECTOR_SIZE);
        if (startBlkAddr == endBlkAddr)  /* read in one block */
        {
            copy_to_user(pUsrBufCur, nvrammngr_rwBuf+frontLen, len);
        }
        else /* read across a block */
        {
    		copy_to_user(pUsrBufCur, nvrammngr_rwBuf+frontLen, FLASH_SECTOR_SIZE-frontLen);
            pUsrBufCur = pUsrBufCur + FLASH_SECTOR_SIZE - frontLen;
        }   
        readAddr += FLASH_SECTOR_SIZE;         
    }
		
	if (startBlkAddr < endBlkAddr) /* blocks in middle */
	{
		while (readAddr < endBlkAddr)
		{
			retLen = _nvrammngr_flash_read(nvrammngr_rwBuf, readAddr, FLASH_SECTOR_SIZE);
			copy_to_user(pUsrBufCur, nvrammngr_rwBuf, FLASH_SECTOR_SIZE);
            pUsrBufCur += FLASH_SECTOR_SIZE;
			readAddr += FLASH_SECTOR_SIZE;
		}
	}

	if (readAddr < offset + len) 
	{
		retLen = _nvrammngr_flash_read(nvrammngr_rwBuf, readAddr, FLASH_SECTOR_SIZE);
        //printk("[NVRAM-MNGR] Dumping nvrammngr_rwBuf before copy to user\n");        
        //hexdump(nvrammngr_rwBuf, 64, (int)nvrammngr_rwBuf);
        //printk("[NVRAM-MNGR] copy to user space addr %08x, data len %d \n", pUsrBufCur, tailLen);
		copy_to_user(pUsrBufCur, nvrammngr_rwBuf, tailLen);
	}

	return 0;
}


/**************************************************************************************************/
/*                                      PUBLIC_FUNCTIONS                                          */
/**************************************************************************************************/

/*******************************************************************
 * Name		: nm_lib_parseU32
 * Abstract	: Converts the string in arg to numeric value.
 * Input	: 
 * Output	: 
 * Return	: success:    0.
 *            fail:       -1
 */
int nm_lib_parseU32(NM_UINT32 *val, const char *arg)
{
    unsigned long res;
    char *ptr = NULL;

    if (!arg || !*arg)
    {
        return -1;
    }

    res = strtoul(arg, &ptr, 0);
    if (!ptr || ptr == arg || *ptr || res > 0xFFFFFFFFUL)
    {
        return -1;
    }
    *val = res;

    
    return 0;
}



/*******************************************************************
 * Name		: nm_lib_makeArgs
 * Abstract	: parse the string of partition-table.
 * Input	: 
 * Output	: 
 * Return	: 
 */
int nm_lib_makeArgs(char *string, char *argv[], int maxArgs)
{
    static const char ws[] = " \t\r\n";
    char *cp;
    int argc = 0;
    char *p_last = NULL;
    
    if (string == NULL)
    {
        return -1;
    }

    for (cp = strtok_r(string, ws, &p_last); cp; cp = strtok_r(NULL, ws, &p_last)) 
    {
        if (argc >= (maxArgs - 1)) 
        {
            NM_ERROR("Too many arguments.");
            return -1;
        }
        argv[argc++] = cp;
    }
    argv[argc] = NULL;

    return argc;
}



/*******************************************************************
 * Name		: nm_lib_strToKey
 * Abstract	: Converts the string in map to numeric value.
 * Input	: map:    The int to string map to use.
 *			  str:    The string representation.
 * Output	: 
 * Return	: success:    The key representation.
 *            fail:       -1
 */
int nm_lib_strToKey(NM_STR_MAP *map, char *str)
{
    int index;

    if (str)
    {
        for (index=0; map[index].str != NULL; index++)
        {
            NM_DEBUG("str(%s) ?= map(%s)", str, map[index].str);
            if (strcmp(str, map[index].str) == 0)
            {
                return map[index].key;
            }
        }
    }
    
    return -1;
}


/*******************************************************************
 * Name		: nm_lib_ptnNameToEntry
 * Abstract	: get partition-entry match the input name.
 * Input	: 
 * Output	: 
 * Return	: point to the partition-entry if match successful.
 *            NULL if match failed.
 */
NM_PTN_ENTRY *nm_lib_ptnNameToEntry(NM_PTN_STRUCT *ptnStruct, char *name)
{
    int index;

    if ((ptnStruct == NULL) || (name == NULL))
    {
        NM_ERROR("invalid input param.");
        return NULL;
    }

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {       
        if (strcmp(ptnStruct->entries[index].fullname, name) == 0)
	{
	    NM_DEBUG("select partition %s",ptnStruct->entries[index].fullname);
            return &(ptnStruct->entries[index]);
	}
    }
    
    return NULL;
}


/*******************************************************************
 * Name		: nm_lib_fetchUnusedPtnEntry
 * Abstract	: get an unused partition-entry from partition-struct.
 * Input	: 
 * Output	: 
 * Return	: point to the partition-entry if match successful.
 *            NULL if match failed.
 */
NM_PTN_ENTRY *nm_lib_fetchUnusedPtnEntry(NM_PTN_STRUCT *ptnStruct)
{
    int index;

    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {       
        if (ptnStruct->entries[index].usedFlag != TRUE)
        {
            ptnStruct->entries[index].usedFlag = TRUE;
            return &(ptnStruct->entries[index]);
        }
    }
    
    return NULL;
}


/*******************************************************************
 * Name		: nm_lib_writeHeadlessPtnToNvram
 * Abstract	: write the value of a partition in NVRAM.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_lib_writeHeadlessPtnToNvram(char *base, char *buf, int len)
{
    NM_DEBUG("ptnEntry->base = %08x, buf = %08x, len = %d", base + NM_NVRAM_BASE, buf, len);

    if (nm_lib_writePtntoNvram_unify(0, (uint32_t)base + NM_NVRAM_BASE, (uint8_t*)buf, len) < 0)
    {
        return -1;
    }
    
    return len;
}


/*******************************************************************
 * Name		: nm_lib_writePtnToNvram
 * Abstract	: write the value of a partition in NVRAM.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_lib_writePtnToNvram(char *base, char *buf, int len)
{
    NM_DEBUG("ptnEntry->base = %08x, buf = %08x, len = %d", base + NM_NVRAM_BASE, buf, len);
	
    if (nm_lib_writePtntoNvram_unify(1, (uint32_t)base + NM_NVRAM_BASE, (uint8_t*)buf, len) < 0)
    {
        return -1;
    }

    return len;
}


/*******************************************************************
 * Name		: nm_lib_readHeadlessPtnFromNvram
 * Abstract	: read the value of a partition in NVRAM.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_lib_readHeadlessPtnFromNvram(char *base, char *buf, int len)
{
    
    if (nm_lib_readFlash_unify((uint32_t)base + NM_NVRAM_BASE, (uint8_t*)buf, len) < 0)
    {
        return -1;
    }
    
    return len;
}



/*******************************************************************
 * Name		: nm_lib_readPtnFromNvram
 * Abstract	: read the value of a partition in NVRAM.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_lib_readPtnFromNvram(char *base, char *buf, int len)
{
    int ret = OK;
	uint32_t partition_used_len = 0;
    uint32_t read_len = 0;

    uint32_t offset = (uint32_t)base;

	ret = nm_lib_readFlash_unify(offset, (unsigned char*)&partition_used_len, sizeof(uint32_t));
    if (ret < 0)
    {
        NM_ERROR("Read Partition used size failed(%d).", ret);
        ret = -1;
        goto leave;
    }

	partition_used_len = ntohl(partition_used_len);
	read_len = (len > partition_used_len) ? partition_used_len : len;

    NM_DEBUG("partition_used_len = %d, requried len = %d", partition_used_len, len);

	/* jump over partition length and checksum */
    ret = nm_lib_readFlash_unify(offset + sizeof(int) + sizeof(int), (unsigned char*)buf, read_len);
	if (ret < 0)
	{
        NM_ERROR("Read Partition data failed(%d).", ret);
        ret = -2;
        goto leave;
	}

leave:
    return ret;
}


/*******************************************************************
 * Name		: nm_lib_initPtnStruct
 * Abstract	: init runtime-partition-struct.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
STATUS nm_lib_initPtnStruct(void)
{
    memset(&g_nmPtnStructEntity, 0, sizeof(g_nmPtnStructEntity));
    g_nmPtnStruct = &g_nmPtnStructEntity;
    
    return OK;
}




/*******************************************************************
 * Name		: nm_lib_parsePtnIndexFile
 * Abstract	: parse partition-index-file to runtime-partition-struct.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
STATUS nm_lib_parsePtnIndexFile(NM_PTN_STRUCT *ptnStruct, char *ptr)
{   
    int index = 0;
    int paraId = -1;
	
    int argc;
    char *argv[NM_PTN_INDEX_ARG_NUM_MAX];
	
    char buf[NM_PTN_INDEX_SIZE+1] = {0};
    NM_PTN_ENTRY *currPtnEntry = NULL;

    /* reset partition-table param */
    memset(ptnStruct, 0, sizeof(NM_PTN_STRUCT));
    for (index=0; index<NM_PTN_NUM_MAX; index++)
    {
        ptnStruct->entries[index].usedFlag = FALSE;
    }

    strncpy((char *)buf, (char *)ptr, NM_PTN_INDEX_SIZE+1);

    argc = nm_lib_makeArgs(buf, argv, NM_PTN_INDEX_ARG_NUM_MAX);
    
    index = 0;

    while (index < argc)
    {
        NM_DEBUG("parsing %d args:%s", index, argv[index]);
        //printf("Addr of nm_ptnIndexFileParaStrMap:%08x\n", (int)nm_ptnIndexFileParaStrMap);
        //hexdump(nm_ptnIndexFileParaStrMap, 64, (int)nm_ptnIndexFileParaStrMap);
        if ((paraId = nm_lib_strToKey(nm_ptnIndexFileParaStrMap, argv[index])) < 0)
        {
            NM_ERROR("invalid partition-index-file para id.");
            goto error;
        }

        index++;

        switch (paraId)
        {
        case NM_PTN_INDEX_PARA_ID_NAME:
            /* check if this partition-name already be used */
            if (nm_lib_ptnNameToEntry(ptnStruct, argv[index]) != NULL)
            {
                NM_ERROR("duplicate partition name found.");
                goto error;
            }
            
            /* get a new partition-entry */
            if ((currPtnEntry = nm_lib_fetchUnusedPtnEntry(ptnStruct)) == NULL)
            {
                NM_ERROR("too many partitions.");
                goto error;
            }
            strncpy(currPtnEntry->name, argv[index], NM_PTN_NAME_LEN);
	    strncpy(currPtnEntry->fullname, argv[index], NM_PTN_NAME_LEN);
            currPtnEntry->usedFlag = TRUE;
            index++;
            break;
            
        case NM_PTN_INDEX_PARA_ID_BASE:
            if (nm_lib_parseU32((NM_UINT32 *)&currPtnEntry->base, argv[index]) < 0)
            {
                NM_ERROR("parse base-addr value failed.");
                goto error;
            }
            index++;
            break;

        case NM_PTN_INDEX_PARA_ID_TAIL:
            if (nm_lib_parseU32((NM_UINT32 *)&currPtnEntry->tail, argv[index]) < 0)
            {
                NM_ERROR("parse tail-addr value failed.");
                goto error;
            }
            index++;
            break;

        case NM_PTN_INDEX_PARA_ID_SIZE:
            if (nm_lib_parseU32((NM_UINT32 *)&currPtnEntry->size, argv[index]) < 0)
            {
                NM_ERROR("parse size value failed.");
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
    
    return OK;
error:
    return ERROR;
}



/*******************************************************************
 * Name		: nm_lib_parsePtnTable
 * Abstract	: parse partition-table.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
STATUS nm_lib_parsePtnTable(char *ptr)
{
    /* jump over "probe to os-image" */
    ptr += sizeof(int);
    
    //hexdump((const unsigned char*)ptr, 1024, 0);
    return nm_lib_parsePtnIndexFile(g_nmPtnStruct, ptr);
}



/*******************************************************************
 * Name		: nm_lib_parsePtnTable
 * Abstract	: read and parse partition-table from NVRAM
 * Input	: 
 * Output	: 
 * Return	: 
 */
int nm_lib_readPtnTable(void)
{
    char ptnTable[NM_PTN_TABLE_SIZE];
    int ret = OK;

    nm_lib_initPtnStruct();
    memset(&ptnTable, 0, sizeof(ptnTable));

    NM_DEBUG("NM_PTN_TABLE_BASE = 0x%x",  NM_PTN_TABLE_BASE);
    
    NM_INFO("Reading Partition Table from NVRAM ... ");
    ret = nm_lib_readPtnFromNvram((char *)NM_PTN_TABLE_BASE, (char *)&ptnTable, NM_PTN_TABLE_SIZE);
    if (ret < 0)
    {
        NM_INFO("FAILED\r\n");
        goto failed;
    }
    NM_INFO("OK\r\n");

    NM_INFO("Parsing Partition Table ... ");
    ret = nm_lib_parsePtnTable((char *)&ptnTable);
    if (OK != ret)
    {
        NM_INFO("FAILED\r\n");
        goto failed;
    }
    NM_INFO("OK\r\n");

    return OK;

failed:
    nm_lib_initPtnStruct();
    return ERROR;
}

void nm_lib_showPtn()
{
    int i;

    if (!l_nminited)
    {
        NM_INFO("Nvrammngr not Initialize, now initializing...");
        if (OK != nm_init())
        {
            NM_INFO("failed.\r\n");
            return;
        }
        
        NM_INFO("done.\r\n");
    }
    
    for (i=0; i<NM_PTN_NUM_MAX; i++)
    {
        NM_INFO("partition %02d: name = %-16s, base = 0x%08x, size = 0x%08x Bytes, usedFlag = %d\r\n",
            i+1, g_nmPtnStruct->entries[i].fullname, g_nmPtnStruct->entries[i].base,
            g_nmPtnStruct->entries[i].size, g_nmPtnStruct->entries[i].usedFlag);
    }
}
/*******************************************************************
 * Name		: nm_init
 * Abstract	: Initialize partition-struct and fwup PTN-struct.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
STATUS nm_init()
{
    int ret = OK;

    if (l_nminited)
        return OK;

#if USE_LOCK	
	g_nmReadWriteLock = semBCreate(0, 1);

    if (g_nmReadWriteLock == (SEM_ID)NULL)
    {
        NM_ERROR("creating binary semaphore failed.");
        return ERROR;
    }
#endif
	
    nm_initFwupPtnStruct();

    ret = nm_lib_readPtnTable();
    if (OK != ret)   
    {
        return ERROR;
    }

    l_nminited = TRUE;
	//nm_lib_showPtn();

    return OK;
}

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
/*******************************************************************
 * Name		: NM_UINT32 nm_lib_readPtnUsedSize
 * Abstract	: read the used size of partition with header.
 * Input	: 
 * Output	: 
 * Return	: OK/ERROR
 */
int nm_lib_readPtnUsedSize(char *base)
{
    uint32_t partition_used_len;
    uint32_t read_len;

	nm_lib_readFlash_unify(base, (unsigned char*)&partition_used_len, sizeof(uint32_t));

	NM_DEBUG("partition_used_len = %d\r\n", partition_used_len);
	partition_used_len = ntohl(partition_used_len);
    NM_DEBUG("partition_used_len = %d\r\n", partition_used_len);

    if(partition_used_len == 0xffffffff)
    {
        NM_ERROR("partition not written\n");
        return -1;
    }
    
	return partition_used_len;
  
}
#endif

/**************************************************************************************************/
/*                                      GLOBAL_FUNCTIONS                                          */
/**************************************************************************************************/

