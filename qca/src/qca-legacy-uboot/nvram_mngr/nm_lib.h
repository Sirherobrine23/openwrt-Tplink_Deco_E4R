
/*! Copyright(c) 1996-2009 Shenzhen TP-LINK Technologies Co. Ltd.
 * \file    nm_lib.h
 * \brief   Protos for NVRAM manager's library functions.
 * \author  Meng Qing
 * \version 1.0
 * \date    25/04/2009
 */

#ifndef __NM_LIB_H__
#define __NM_LIB_H__

#ifdef __cplusplus
extern "C"{
#endif

#include "config.h"

/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/

#ifndef OK
#define OK (0)
#endif
#ifndef ERROR
#define ERROR (-1)
#endif

#ifndef	NULL
#define NULL            0
#endif
#ifndef	TRUE
#define TRUE            1
#endif
#ifndef FALSE
#define FALSE           0
#endif


/* ========= Global Configure Parameters ================== */
#ifndef NM_FLASH_SIZE
#define NM_FLASH_SIZE 0x1000000
#endif

#ifndef NM_PTN_TABLE_BASE
#define NM_PTN_TABLE_BASE 0xed7000
#elif NM_PTN_TABLE_BASE<0 || NM_PTN_TABLE_BASE>0x1000000
	#error "NM_PTN_TABLE_BASE IS INVALID!"
#endif

#define NM_PTN_TABLE_SIZE 0x002000

#define NM_OS_IMAGE_BASE 0x40000

#define NM_NVRAM_BASE 	0x000000  //0x9F000000

#define NM_PTN_NUM_MAX 32
#define NM_PTN_INDEX_SIZE 2000
#define NM_FWUP_PTN_INDEX_SIZE 2048 /* 0x800 */

#define USE_LOCK      0

#if USE_LOCK 
#define NM_SEM_TAKE semTake
#define NM_SEM_GIVE semGive
#else
#define NM_SEM_TAKE(lock, until)
#define NM_SEM_GIVE(lock)
#endif

#define WAIT_FOREVER	(-1)

/* ========= Generic Defines ============================== */
#define NM_UINT32 unsigned long int
#define NM_PTN_NAME_LEN 32
#define NM_PTN_INDEX_ARG_NUM_MAX (NM_PTN_NUM_MAX*8)
#define NM_FWUP_PTN_INDEX_ARG_NUM_MAX (NM_PTN_NUM_MAX*8)

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
#define NM_FWUP_IS_INTEGER	(1)
#define NM_FWUP_NOT_INTEGER	(0)
#define NM_FWUP_IS_DOUBLE_BOOT	(1)
#define NM_FWUP_NOT_DOUBLE_BOOT	(0)
#endif
/* ========= Debug Info =================================== */
#define NM_DEBUG(fmt, args...) \
	//printf("[NM_Debug](%s) %05d: "fmt"\r\n", __FUNCTION__, __LINE__, ##args)
#define NM_ERROR(fmt, args...)  \
	printf("[NM_Error](%s) %05d: "fmt"\r\n", __FUNCTION__, __LINE__, ##args)
#define NM_INFO(fmt, args...)  \
    printf(fmt, ##args)


/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/

/* --------- Enum Defines ---------------- */
typedef enum nm_partition_index_para_id
{
    NM_PTN_INDEX_FILE_ID_VOID = -1, 
    NM_PTN_INDEX_PARA_ID_NAME, 
    NM_PTN_INDEX_PARA_ID_BASE, 
    NM_PTN_INDEX_PARA_ID_TAIL, 
    NM_PTN_INDEX_PARA_ID_SIZE, 
    NM_PTN_INDEX_PARA_ID_MAX,
} NM_PTN_INDEX_PARA_ID;

typedef enum nm_fwup_partition_index_para_id
{
    NM_FWUP_PTN_INDEX_FILE_ID_VOID = -1, 
    NM_FWUP_PTN_INDEX_PARA_ID_NAME, 
    NM_FWUP_PTN_INDEX_PARA_ID_BASE, 
    NM_FWUP_PTN_INDEX_PARA_ID_SIZE, 
    NM_FWUP_PTN_INDEX_PARA_ID_MAX,
} NM_FWUP_PTN_INDEX_PARA_ID;

typedef enum nm_fwup_upgrade_date_type
{
    NM_FWUP_UPGRADE_DATA_TYPE_VOID = -1, 
    NM_FWUP_UPGRADE_DATA_TYPE_BLANK, 
    NM_FWUP_UPGRADE_DATA_FROM_FWUP_FILE, 
    NM_FWUP_UPGRADE_DATA_FROM_NVRAM, 
	NM_FWUP_UPGRADE_DATA_TYPE_NO_CHANGE, 
    NM_FWUP_UPGRADE_DATA_TYPE_MAX,
} NM_FWUP_UPGRADE_DATA_TYPE;


/* --------- Data Structure ---------------- */
typedef struct nm_str_map
{
    int key;
    char *str;
}NM_STR_MAP;

typedef struct nm_upgrade_info
{
    NM_UINT32 dataStart;
    NM_UINT32 dataLen;
    int dataType;
} NM_UPGRADE_INFO;

typedef struct nm_partition_entry
{
    char name[NM_PTN_NAME_LEN];
    char fullname[NM_PTN_NAME_LEN];
    NM_UINT32 base;
    NM_UINT32 tail;
    NM_UINT32 size;
    unsigned int usedFlag;
    NM_UINT32 usedSize;
    NM_UPGRADE_INFO upgradeInfo;
} NM_PTN_ENTRY;

typedef struct nm_partition_list
{
    NM_PTN_ENTRY entries[NM_PTN_NUM_MAX];
} NM_PTN_STRUCT;


#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
typedef struct nm_ptn_extra_para
{
	unsigned char dbootFlag;
	unsigned char integerFlag;	
} NM_PTN_EXTRA_PARA;
#endif

/**************************************************************************************************/
/*                                      FUNCTIONS                                                 */
/**************************************************************************************************/
int nm_init(void);

int nm_lib_parseU32(NM_UINT32 *val, const char *arg);
int nm_lib_makeArgs(char *string, char *argv[], int maxArgs);
int nm_lib_strToKey(NM_STR_MAP *map, char *str);
NM_PTN_ENTRY *nm_lib_ptnNameToEntry(NM_PTN_STRUCT *ptnStruct, char *name);
int nm_lib_parsePtnIndexFile(NM_PTN_STRUCT *ptnStruct, char *ptr);


NM_PTN_ENTRY *nm_lib_ptnNameToEntry(NM_PTN_STRUCT *ptnStruct, char *name);
int nm_lib_readPtnFromNvram(char *base, char *buf, int len);
int nm_lib_readHeadlessPtnFromNvram(char *base, char *buf, int len);
int nm_lib_writePtnToNvram(char *base, char *buf, int len);
int nm_lib_writeHeadlessPtnToNvram(char *base, char *buf, int len);
void nm_lib_showPtn(void);

#if defined(CONFIG_DOUBLE_UBOOT_FACTORY) || defined(CONFIG_DOUBLE_UBOOT_SECOND)
int nm_lib_readPtnUsedSize(char *base);
#endif

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

extern NM_PTN_STRUCT *g_nmPtnStruct;
#if USE_LOCK
extern SEM_ID g_nmReadWriteLock;
#endif



#ifdef __cplusplus 
}
#endif

#endif /* __NM_LIB_H__ */

