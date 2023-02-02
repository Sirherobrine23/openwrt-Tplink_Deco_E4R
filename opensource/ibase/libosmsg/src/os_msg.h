/*  Copyright(c) 2010-2011 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 * file	os_msg.h
 * brief	The msg lib declarations. 
 *
 * author	Yang Xv
 * version	1.0.0
 * date	28Apr11
 *
 * history 	\arg 1.0.0, 28Apr11, Yang Xv, Create the file.
 */

#ifndef __OS_MSG_H__
#define __OS_MSG_H__

/* 注意这个头文件不要引用<cstd.h>头文件 */
#include <unistd.h>

/* do not include <netinet/in.h> */

/**************************************************************************************************/
/*                                           DEFINES                                              */
/**************************************************************************************************/
#if 0
#define DEBUG_PRINT(_fmt, arg...) printf(_fmt, ##arg)
#else
#define DEBUG_PRINT(_fmt, arg...)
#endif

/* 
 * brief Message content size	
 */
#define MSG_CONTENT_SIZE	143352


/* 
 * brief Message size	
 */
#define MSG_SIZE			143360 /* 140k */


/**************************************************************************************************/
/*                                           TYPES                                                */
/**************************************************************************************************/


#include <sys/un.h>

typedef struct
{
	int fd;
	struct sockaddr_un _localAddr;
	struct sockaddr_un _remoteAddr;
}CMSG_FD;


/* 
 * brief 	Enumeration message type
 * 			Convention:
 *			System message types - 1000 ~ 1999
 *			Common application message types - 2000 ~ 2999
 */
typedef enum
/* 如果一个消息只有一个UINT32的数据，那么可以省略该message type对应的结构体，
 * 只使用CMSG_BUFF结构中的priv成员即可
 */
{
	CMSG_NULL = 0,
	CMSG_REPLY = 1,
	CMSG_IOT_MSG = 2000,
	CMSG_IOT_INNER_MSG = 2001,
	CMSG_IOT_MODULE_REG = 2002,
	CMSG_ZIGBEE_INPUT_MSG = 2003,
	CMSG_IOT_MODULE_UNREG = 2004,
	CMSG_ZIGBEE_EVENT_MSG = 2005,
	CMSG_ZIGBEE_MFG_MSG = 2006,
	CMSG_ZIGBEE_UPGRADE_MSG = 2007,
	CMSG_IOT_REQUEST_MSG = 2008,
	CMSG_IOT_REQUEST_REPLY_MSG = 2009,
	CMSG_ZIGBEE_MERGE_CFG_MSG = 2010,
	CMSG_ZIGBEE_OPEN_LOG_MSG = 2011,
	CMSG_ZIGBEE_CLOSE_LOG_MSG = 2012,
	CMSG_ZIGBEE_NWKFORM_MSG = 2013,
	CMSG_ZIGBEE_GET_COEXIST_GPIO_MSG = 2014,
	CMSG_ZIGBEE_SET_COEXIST_GPIO_MSG = 2015
}CMSG_TYPE;


/* 
 * brief	Message struct
 */
typedef struct
{
	CMSG_TYPE type;		/* specifies what message this is */
	unsigned int priv;		/* private data, one word of user data etc. */
	unsigned char content[MSG_CONTENT_SIZE];
}CMSG_BUFF;


/* 
 * brief	Message type identification	
 */
typedef enum
{
	CMSG_ID_NULL = 5,	/* start from 5 */
	CMSG_ID_IOT_CENTER = 6,
	CMSG_ID_IOT_AUTOMATION = 7,
	CMSG_ID_IOT_ACCESS = 8,
	CMSG_ID_ZIGBEE = 9,
	CMSG_ID_BLE = 10,
	CMSG_ID_TPRA = 11,
	CMSG_ID_NEST = 12,
	CMSG_ID_HUE = 13,
	CMSG_ID_ZIGBEE_INPUT = 14,
	CMSG_ID_ZIGBEE_MFG = 15,
	CMSG_ID_NETDEV = 16,
	CMSG_ID_MAX,	
}CMSG_ID;


/**************************************************************************************************/
/*                                           FUNCTIONS                                            */
/**************************************************************************************************/

/* 
 * fn		int msg_init(CMSG_FD *pMsgFd)
 * brief	Create an endpoint for msg
 *	
 * param[out]	pMsgFd - return msg descriptor that has been create	
 *
 * return	-1 is returned if an error occurs, otherwise is 0
 *
 * note 	Need call msg_cleanup() when you no longer use this msg which is created by msg_init()
 */
int msg_init(CMSG_FD *pMsgFd);


/* 
 * fn		int msg_srvInit(CMSG_ID msgId, CMSG_FD *pMsgFd)
 * brief	Init an endpoint as a server and bind a name to this endpoint msg	
 *
 * param[in]	msgId - server name	
 * param[in]	pMsgFd - server endpoint msg fd
 *
 * return	-1 is returned if an error occurs, otherwise is 0	
 */
int msg_srvInit(CMSG_ID msgId, CMSG_FD *pMsgFd);



/* 
 * fn		int msg_connSrv(CMSG_ID msgId, CMSG_FD *pMsgFd)
 * brief	Init an endpoint as a client and specify a server name	
 *
 * param[in]		msgId - server name that we want to connect	
 * param[in/out]	pMsgFd - client endpoint msg fd	
 *
 * return	-1 is returned if an error occurs, otherwise is 0
 */
int msg_connSrv(CMSG_ID msgId, CMSG_FD *pMsgFd);


/* 
 * fn		int msg_recv(const CMSG_FD *pMsgFd, CMSG_BUFF *pMsgBuff)
 * brief	Receive a message form a msg	
 *
 * param[in]	pMsgFd - msg fd that we want to receive message
 * param[out]	pMsgBuff - return recived message
 *
 * return	-1 is returned if an error occurs, otherwise is 0
 *
 * note		we will clear msg buffer before recv
 */
int msg_recv(const CMSG_FD *pMsgFd, CMSG_BUFF *pMsgBuff);


/* 
 * fn		int msg_send(const CMSG_FD *pMsgFd, const CMSG_BUFF *pMsgBuff)
 * brief	Send a message from a msg	
 *
 * param[in]	pMsgFd - msg fd that we want to send message	
 * param[in]	pMsgBuff - msg that we wnat to send
 *
 * return	-1 is returned if an error occurs, otherwise is 0
 *
 * note 	This function will while call sendto() if sendto() return ENOENT error
 */
int msg_send(const CMSG_FD *pMsgFd, const CMSG_BUFF *pMsgBuff);


/* 
 * fn		int msg_cleanup(CMSG_FD *pMsgFd)
 * brief	Close a message fd
 * details	
 *
 * param[in]	pMsgFd - message fd that we want to close		
 *
 * return	-1 is returned if an error occurs, otherwise is 0		
 */
int msg_cleanup(CMSG_FD *pMsgFd);


/* 
 * fn		int msg_connCliAndSend(CMSG_ID msgId, CMSG_FD *pMsgFd, CMSG_BUFF *pMsgBuff)
 * brief	init a client msg and send msg to server which is specified by msgId	
 *
 * param[in]	msgId -	server ID that we want to send
 * param[in]	pMsgFd - message fd that we want to send
 * param[in]	pMsgBuff - msg that we wnat to send
 *
 * return	-1 is returned if an error occurs, otherwise is 0	
 */
int msg_connCliAndSend(CMSG_ID msgId, CMSG_FD *pMsgFd, CMSG_BUFF *pMsgBuff);


/* 
 * fn		int msg_sendAndGetReply(CMSG_FD *pMsgFd, CMSG_BUFF *pMsgBuff)
 * brief	
 *
 * param[in]	pMsgFd - msg fd that we want to use
 * param[in/out]pMsgBuff - send msg and get reply
 * param[in]	timeSeconds - timeout in second
 *
 * return	-1 is returned if an error occurs, otherwise is 0	
 */
int msg_sendAndGetReplyWithTimeout(CMSG_FD *pMsgFd, CMSG_BUFF *pMsgBuff, int timeSeconds);


#endif /* __OS_MSG_H__ */

