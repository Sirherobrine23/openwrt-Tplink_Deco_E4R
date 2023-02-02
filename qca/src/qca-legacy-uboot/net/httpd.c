/*
 *	Copyright 1994, 1995, 2000 Neil Russell.
 *	(See License)
 *	Copyright 2000, 2001 DENX Software Engineering, Wolfgang Denk, wd@denx.de
 */

#include <common.h>
#include <command.h>
#include <net.h>
#include <asm/byteorder.h>
#include "httpd.h"

#include "../httpd/uipopt.h"
#include "../httpd/uip.h"
#include "../httpd/uip_arp.h"

static int arptimer = 0;

int upgrade_filecheck(unsigned char * ptr, int size){
	int len = 0;
	int ret;

	if (NULL == ptr || 0 == size){ 
		printf("## Error: input ptr or size error!\n");
		return(-2);
	}
	
	memcpy(&len, ptr, sizeof(int));
	len = ntohl(len);
	
	if(len > size){
		printf("## Error: file size error!\n");
		return(-2);
	}

	ret = nm_tpFirmwareCheck(ptr, size);
	if ( ret != 0)
	{
		return ret;
	}
	printf("upgrade_filecheck ok\n");
	
	return(0);
}

void HttpdHandler(void){
	int i;

	for(i = 0; i < UIP_CONNS; i++){
		uip_periodic(i);

		if(uip_len > 0){
			uip_arp_out();
			NetSendHttpd();
		}
	}

	if(++arptimer == 20){
		uip_arp_timer();
		arptimer = 0;
	}
}

// start http daemon
void HttpdStart(void){
	uip_init();
	httpd_init(upgrade_filecheck);
}

int do_http_upgrade(const ulong size, const int upgrade_type){
	int ret;
	printf("do http upgrade\n");
	if(upgrade_type == WEBFAILSAFE_UPGRADE_TYPE_FIRMWARE){
		
		ret = nm_tpFirmwareRecovery((unsigned char *)WEBFAILSAFE_UPLOAD_RAM_ADDRESS, (int)size);
		if (ret == 0)
		{
			return(0);
		}
	}

	printf("Web recovery failed type %d.\n", upgrade_type);

	return(-1);
}

// info about current progress of failsafe mode
int do_http_progress(const int state){
	/* toggle LED's here */
	switch(state){
		case WEBFAILSAFE_PROGRESS_START:
			printf("HTTP server is ready!\n\n");
			break;

		case WEBFAILSAFE_PROGRESS_TIMEOUT:
			//printf("Waiting for request...\n");
			break;

		case WEBFAILSAFE_PROGRESS_UPLOAD_READY:
			printf("HTTP upload is done! Upgrading...\n");
			break;

		case WEBFAILSAFE_PROGRESS_UPGRADE_READY:
			printf("HTTP ugrade is done! Rebooting...\n\n");
			break;

		case WEBFAILSAFE_PROGRESS_UPGRADE_FAILED:
			printf("## Error: HTTP ugrade failed!\n\n");
			break;

		case WEBFAILSAFE_PROGRESS_CHECK_FAILED:
			printf("## Error: HTTP upgrade file check failed!\n\n");
			break;
			
		default:
			printf("## Error: Wrong state!\n\n");
			break;
	}

	return(0);
}
