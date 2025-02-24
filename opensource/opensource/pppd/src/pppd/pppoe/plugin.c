/***********************************************************************
*
* plugin.c
*
* pppd plugin for kernel-mode PPPoE on Linux
*
* Copyright (C) 2001 by Roaring Penguin Software Inc., Michal Ostrowski
* and Jamal Hadi Salim.
*
* Much code and many ideas derived from pppoe plugin by Michal
* Ostrowski and Jamal Hadi Salim, which carries this copyright:
*
* Copyright 2000 Michal Ostrowski <mostrows@styx.uwaterloo.ca>,
*                Jamal Hadi Salim <hadi@cyberus.ca>
* Borrows heavily from the PPPoATM plugin by Mitchell Blank Jr.,
* which is based in part on work from Jens Axboe and Paul Mackerras.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version
* 2 of the License, or (at your option) any later version.
***********************************************************************/

static char const RCSID[] =
"$Id: plugin.c,v 1.12 2004/11/04 10:07:37 paulus Exp $";

#define _GNU_SOURCE 1
#include "pppoe.h"

#include "pppd.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#include "ccp.h"
#include "pathnames.h"

#include <linux/types.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include "ppp_defs.h"
#include "if_ppp.h"
#include "if_pppox.h"

#define _PATH_ETHOPT         _ROOT_PATH "/etc/ppp/options."

char pppd_version[] = VERSION;

/* From sys-linux.c in pppd -- MUST FIX THIS! */
extern int new_style_driver;

char *pppd_pppoe_service = NULL;
static char *acName = NULL;
static char *existingSession = NULL;
static int printACNames = 0;

int pppoe_enable = 0;

static int PPPoEDevnameHook(char *cmd, char **argv, int doit);
static option_t Options[] = {
    { "device name", o_wild, (void *) &PPPoEDevnameHook,
      "PPPoE device name",
      OPT_DEVNAM | OPT_PRIVFIX | OPT_NOARG  | OPT_A2STRVAL | OPT_STATIC,
      devnam},
    { "rp_pppoe_service", o_string, &pppd_pppoe_service,
      "Desired PPPoE service name" },
    { "rp_pppoe_ac",      o_string, &acName,
      "Desired PPPoE access concentrator name" },
    { "rp_pppoe_sess",    o_string, &existingSession,
      "Attach to existing session (sessid:macaddr)" },
    { "rp_pppoe_verbose", o_int, &printACNames,
      "Be verbose about discovered access concentrators"},
    { NULL }
};

static PPPoEConnection *conn = NULL;

/**********************************************************************
 * %FUNCTION: PPPOEInitDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 *
 * %DESCRIPTION:
 * Initializes PPPoE device.
 ***********************************************************************/
static int
PPPOEInitDevice(void)
{
    conn = malloc(sizeof(PPPoEConnection));
    if (!conn) {
	fatal("Could not allocate memory for PPPoE session");
    }
    memset(conn, 0, sizeof(PPPoEConnection));
    if (acName) {
	SET_STRING(conn->acName, acName);
    }
    if (pppd_pppoe_service) {
	SET_STRING(conn->serviceName, pppd_pppoe_service);
    }
    SET_STRING(conn->ifName, devnam);
    conn->discoverySocket = -1;
    conn->sessionSocket = -1;
    conn->useHostUniq = 1;
    conn->printACNames = printACNames;

    return 1;
}

/**********************************************************************
 * %FUNCTION: PPPOEConnectDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Non-negative if all goes well; -1 otherwise
 * %DESCRIPTION:
 * Connects PPPoE device.
 ***********************************************************************/
 
static int
PPPOEConnectDevice(void)
{
    struct sockaddr_pppox sp;
	
#ifdef MODULE_HWNAT
	char buf[256] = {0};
	extern bool hwnat;
#endif

	//add by yangxv, 2007.12.10
	notice("PPPoE Connect Device");

    strlcpy(ppp_devnam, devnam, sizeof(ppp_devnam));
	if (existingSession) {
		unsigned int mac[ETH_ALEN];
		int i, ses;
		if (sscanf(existingSession, "%d:%x:%x:%x:%x:%x:%x",
			   &ses, &mac[0], &mac[1], &mac[2],
			   &mac[3], &mac[4], &mac[5]) != 7) {
		    fatal("Illegal value for rp_pppoe_sess option");
		}
		conn->session = htons(ses);
		for (i=0; i<ETH_ALEN; i++) {
		    conn->peerEth[i] = (unsigned char) mac[i];
		}
    } else {
		discovery(conn);
		if (conn->discoveryState != STATE_SESSION) {
		    error("Unable to complete PPPoE Discovery");
		    return -1;
		}
    }

    /* Set PPPoE session-number for further consumption */
    ppp_session_number = ntohs(conn->session);
    

#ifdef MODULE_HWNAT
	/* For HW NAT, normol operation hav not this operation */
	if(hwnat)
	{
		memset(buf, 0 , 256);
	/* session id by lyj, 21Sep11 */
	sprintf(buf,"[ -f '/proc/qca_switch/nf_athrs17_hnat' ] && echo %d > /proc/qca_switch/nf_athrs17_hnat_ppp_id", conn->session);
	system(buf);
	}
	
#endif

    /* Make the session socket */
    conn->sessionSocket = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
    if (conn->sessionSocket < 0) {
	fatal("Failed to create PPPoE socket: %m");
    }
	
    sp.sa_family = AF_PPPOX;
    sp.sa_protocol = PX_PROTO_OE;
    sp.sa_addr.pppoe.sid = conn->session;
    memcpy(sp.sa_addr.pppoe.dev, conn->ifName, IFNAMSIZ);
    memcpy(sp.sa_addr.pppoe.remote, conn->peerEth, ETH_ALEN);

    /* Set remote_number for ServPoET */
	//the MAC of peer
    sprintf(remote_number, "%02X:%02X:%02X:%02X:%02X:%02X",
	    (unsigned) conn->peerEth[0],
	    (unsigned) conn->peerEth[1],
	    (unsigned) conn->peerEth[2],
	    (unsigned) conn->peerEth[3],
	    (unsigned) conn->peerEth[4],
	    (unsigned) conn->peerEth[5]);
	
#ifdef MODULE_HWNAT	
	/* For HW NAT, normol operation hav not this operation */
	if(hwnat)
	{
		memset(buf, 0 , 256);
	/* Peer Mac by lyj, 21Sep11 */
	sprintf(buf,"[ -f '/proc/qca_switch/nf_athrs17_hnat' ] && echo %02x%02x%02x%02x%02x%02x > /proc/qca_switch/nf_athrs17_hnat_ppp_peer_mac",
		conn->peerEth[0], conn->peerEth[1],
		conn->peerEth[2], conn->peerEth[3],
		conn->peerEth[4], conn->peerEth[5]);
	system(buf);
	
	memset(buf, 0 , 256);
	/* Our Mac by lyj, 21Sep11 */
	sprintf(buf,"[ -f '/proc/qca_switch/nf_athrs17_hnat' ] && echo %02x%02x%02x%02x%02x%02x > /proc/qca_switch/nf_athrs17_hnat_wan_mac",
		conn->myEth[0], conn->myEth[1],
		conn->myEth[2], conn->myEth[3],
		conn->myEth[4], conn->myEth[5]);
	system(buf);
	}
	
#endif

    if (connect(conn->sessionSocket, (struct sockaddr *) &sp,
		sizeof(struct sockaddr_pppox)) < 0) {
	fatal("Failed to connect PPPoE socket: %d %m", errno);
	return -1;
    }
    #ifdef MODULE_HWNAT
    if(hwnat)
    {
    	system("[ -f '/proc/qca_switch/nf_athrs17_hnat' ] && echo 1 > /proc/qca_switch/nf_athrs17_hnat_wan_type");
    }
    
    #endif

    return conn->sessionSocket;
}

static void
PPPOESendConfig(int mtu,
		u_int32_t asyncmap,
		int pcomp,
		int accomp)
{
    int sock;
    struct ifreq ifr;

    if (mtu > MAX_PPPOE_MTU) {
	warn("Couldn't increase MTU to %d", mtu);
	mtu = MAX_PPPOE_MTU;
    }
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	error("Couldn't create IP socket: %m");
	return;
    }

    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    ifr.ifr_mtu = mtu;
    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
	error("Couldn't set interface MTU to %d: %m", mtu);
	close(sock);
	return;
    }
    (void) close (sock);
}


static void
PPPOERecvConfig(int mru,
		u_int32_t asyncmap,
		int pcomp,
		int accomp)
{
    if (mru > MAX_PPPOE_MTU)
	warn("Couldn't increase MRU to %d", mru);
}

/**********************************************************************
 * %FUNCTION: PPPOEDisconnectDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Disconnects PPPoE device
 ***********************************************************************/
static void
PPPOEDisconnectDevice(void)
{
    struct sockaddr_pppox sp;

    sp.sa_family = AF_PPPOX;
    sp.sa_protocol = PX_PROTO_OE;
    sp.sa_addr.pppoe.sid = 0;
    memcpy(sp.sa_addr.pppoe.dev, conn->ifName, IFNAMSIZ);
    memcpy(sp.sa_addr.pppoe.remote, conn->peerEth, ETH_ALEN);
    if (connect(conn->sessionSocket, (struct sockaddr *) &sp,
		sizeof(struct sockaddr_pppox)) < 0) {
	fatal("Failed to disconnect PPPoE socket: %d %m", errno);
	return;
    }
    close(conn->sessionSocket);

	/* modified by kuangguiming, fix bug 50443, send PADT before we close the socket. */
#if 0
    /* don't send PADT?? */
    close(conn->discoverySocket);
#endif
	
	if (conn->discoverySocket >= 0) 
	{
		sendPADT(conn, NULL);
		close(conn->discoverySocket);
	}

	/* end modify */
}

static void
PPPOEDeviceOptions(void)
{
    char buf[256];
    snprintf(buf, 256, _PATH_ETHOPT "%s",devnam);
    if(!options_from_file(buf, 0, 0, 1))
	exit(EXIT_OPTION_ERROR);

}

struct channel pppoe_channel;

/**********************************************************************
 * %FUNCTION: PPPoEDevnameHook
 * %ARGUMENTS:
 * cmd -- the command (actually, the device name
 * argv -- argument vector
 * doit -- if non-zero, set device name.  Otherwise, just check if possible
 * %RETURNS:
 * 1 if we will handle this device; 0 otherwise.
 * %DESCRIPTION:
 * Checks if name is a valid interface name; if so, returns 1.  Also
 * sets up devnam (string representation of device).
 ***********************************************************************/
static int
PPPoEDevnameHook(char *cmd, char **argv, int doit)
{
    int r = 1;
    int fd;
    struct ifreq ifr;

    //add by yangxv, 2007.12.10
    notice("PPPoE DevName Hook, the name is %s", cmd);

    /* Only do it if name is "ethXXX", "nasXXX", "tapXXX" or "nic-XXXX.
       In latter case strip off the "nic-" */
    /* Thanks to Russ Couturier for this fix */
    if (strlen(cmd) > 4 && !strncmp(cmd, "nic-", 4)) {
	/* Strip off "nic-" */
	cmd += 4;
    } else if (strlen(cmd) < 3
	       || (strncmp(cmd, "eth", 3) && strncmp(cmd, "nas", 3)
		   && strncmp(cmd, "tap", 3) && strncmp(cmd, "br", 2) 
		   && strncmp(cmd, "ath", 3))) {
	return 0;
    }

    /* Open a socket */
    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
	r = 0;
    }

    /* Try getting interface index */
    if (r) {
	strncpy(ifr.ifr_name, cmd, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	    r = 0;
	} else {
	    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		r = 0;
	    } else {
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		    error("Interface %s not Ethernet", cmd);
		    r=0;
		}
	    }
	}
    }

    /* Close socket */
    close(fd);
    if (r) {
	strncpy(devnam, cmd, sizeof(devnam));
	if (the_channel != &pppoe_channel) {

			notice("make the channel with pppoe_channel");
				
	    the_channel = &pppoe_channel;
	    modem = 0;

	    lcp_allowoptions[0].neg_accompression = 0;
	    lcp_wantoptions[0].neg_accompression = 0;

	    lcp_allowoptions[0].neg_asyncmap = 0;
	    lcp_wantoptions[0].neg_asyncmap = 0;

	    lcp_allowoptions[0].neg_pcompression = 0;
	    lcp_wantoptions[0].neg_pcompression = 0;

	    ccp_allowoptions[0].deflate = 0 ;
	    ccp_wantoptions[0].deflate = 0 ;

	    ipcp_allowoptions[0].neg_vj=0;
	    ipcp_wantoptions[0].neg_vj=0;

	    ccp_allowoptions[0].bsd_compress = 0;
	    ccp_wantoptions[0].bsd_compress = 0;

	    PPPOEInitDevice();
	}
	return 1;
    }

    return r;
}

/**********************************************************************
 * %old FUNCTION: plugin_init
 * %now FUNCTION: pppoe_init
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Initializes hooks for pppd plugin
 * changed function name by yangxv:from plugin_init() to pppoe_init()2007.11.15
 ***********************************************************************/
int
pppoe_init(void)
{
	pppoe_enable = 1;
	if (!ppp_available() && !new_style_driver) {
		fatal("Linux kernel does not support PPPoE -- are you running 2.4.x?");
	}

	add_options(Options);
	info("pppoe_init() success");

	return 1;
}

/**********************************************************************
*%FUNCTION: fatalSys
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to stderr and syslog and exits.
***********************************************************************/
void
fatalSys(char const *str)
{
    char buf[1024];
    int i = errno;
    sprintf(buf, "%.256s: %.256s", str, strerror(i));
    printErr(buf);
    sprintf(buf, "RP-PPPoE: %.256s: %.256s", str, strerror(i));
    sendPADT(conn, buf);
    exit(1);
}

/**********************************************************************
*%FUNCTION: rp_fatal
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog and exits.
***********************************************************************/
void
rp_fatal(char const *str)
{
    char buf[1024];
    printErr(str);
    sprintf(buf, "RP-PPPoE: %.256s", str);
    sendPADT(conn, buf);
    exit(1);
}
/**********************************************************************
*%FUNCTION: sysErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to syslog.
***********************************************************************/
void
sysErr(char const *str)
{
    rp_fatal(str);
}


struct channel pppoe_channel = {
    options: Options,
    //changed by yangxv
    process_extra_options: NULL,
    //process_extra_options: &PPPOEDeviceOptions,
    check_options: NULL,
    connect: &PPPOEConnectDevice,
    disconnect: &PPPOEDisconnectDevice,
    establish_ppp: &generic_establish_ppp,
    disestablish_ppp: &generic_disestablish_ppp,
	/* no need, just set mtu, it had set in lcp_up */
    //send_config: &PPPOESendConfig,
    //recv_config: &PPPOERecvConfig,
    close: NULL,
    cleanup: NULL
};
