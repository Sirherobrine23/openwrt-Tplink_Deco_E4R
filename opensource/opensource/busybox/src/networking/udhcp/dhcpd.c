/* vi: set sw=4 ts=4: */
/*
 * udhcp server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@moreton.com.au>
 *			Chris Trew <ctrew@moreton.com.au>
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

//usage:#define udhcpd_trivial_usage
//usage:       "[-fS] [-I ADDR]" IF_FEATURE_UDHCP_PORT(" [-P N]") " [CONFFILE]"
//usage:#define udhcpd_full_usage "\n\n"
//usage:       "DHCP server\n"
//usage:     "\n	-f	Run in foreground"
//usage:     "\n	-S	Log to syslog too"
//usage:     "\n	-I ADDR	Local address"
//usage:	IF_FEATURE_UDHCP_PORT(
//usage:     "\n	-P N	Use port N (default 67)"
//usage:	)

#include <syslog.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include "common.h"
#include "dhcpc.h"
#include "dhcpd.h"

#include "deco.h"

static char model_name[32] = {0};
static char wan_host_name[32] = {0};

static int get_product_name()
{
	char result[32] = {0};
	unsigned int len = 0;
	FILE *fp = NULL;

	memset(result, 0, 32);

	strncpy(model_name, "M6", 32);

	fp = popen("getfirm MODEL", "r");
	if (NULL == fp)
	{
		bb_error_msg("Failed to get model name");
		return -1;
	}

	fgets(result, sizeof(result), fp);
	if (result[0] != 0 && ((len = strlen(result)) > 0))
	{
		if (result[len - 1] == '\n')
		{
			if (len >= 2 && result[len - 2] == '\r')
				result[len - 2] = '\0';
			else
				result[len - 1] = '\0';
		}

		strncpy(model_name, result, 32);
	}

	pclose(fp);
	return 0;
}

static int get_wan_hostname()
{
	snprintf(wan_host_name, 32, "deco_%s", model_name);
	return 0;
}

/* Send a packet to a specific mac address and ip address by creating our own ip packet */
static void send_packet_to_client(struct dhcp_packet *dhcp_pkt, int force_broadcast)
{
	const uint8_t *chaddr;
	uint32_t ciaddr;

	// Was:
	//if (force_broadcast) { /* broadcast */ }
	//else if (dhcp_pkt->ciaddr) { /* unicast to dhcp_pkt->ciaddr */ }
	//else if (dhcp_pkt->flags & htons(BROADCAST_FLAG)) { /* broadcast */ }
	//else { /* unicast to dhcp_pkt->yiaddr */ }
	// But this is wrong: yiaddr is _our_ idea what client's IP is
	// (for example, from lease file). Client may not know that,
	// and may not have UDP socket listening on that IP!
	// We should never unicast to dhcp_pkt->yiaddr!
	// dhcp_pkt->ciaddr, OTOH, comes from client's request packet,
	// and can be used.
	if (force_broadcast) {
		log1("broadcasting packet to client");
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else if (dhcp_pkt->ciaddr) {
		log1("unicasting packet to client ciaddr");
		ciaddr = dhcp_pkt->ciaddr;
		chaddr = dhcp_pkt->chaddr;
	 
	} else if (ntohs(dhcp_pkt->flags) & BROADCAST_FLAG) {
		log1("broadcasting packet to client (requested)");
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else {
		log1("unicasting packet to client yiaddr");
		ciaddr = dhcp_pkt->yiaddr;
		chaddr = dhcp_pkt->chaddr;
	}
	
#if 0

	if (force_broadcast
	 || (dhcp_pkt->flags & htons(BROADCAST_FLAG))
	 || dhcp_pkt->ciaddr == 0
	) {
		log1("Broadcasting packet to client");
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else {
		log1("Unicasting packet to client ciaddr");
		ciaddr = dhcp_pkt->ciaddr;
		chaddr = dhcp_pkt->chaddr;
	}
#endif	

	udhcp_send_raw_packet(dhcp_pkt,
		/*src*/ server_config.server_nip, SERVER_PORT,
		/*dst*/ ciaddr, CLIENT_PORT, chaddr,
		server_config.ifindex);
}

/* Send a packet to gateway_nip using the kernel ip stack */
static void send_packet_to_relay(struct dhcp_packet *dhcp_pkt)
{
	log1("Forwarding packet to relay");

	udhcp_send_kernel_packet(dhcp_pkt,
			server_config.server_nip, SERVER_PORT,
			dhcp_pkt->gateway_nip, SERVER_PORT);
}

static void send_packet(struct dhcp_packet *dhcp_pkt, int force_broadcast)
{
	if (dhcp_pkt->gateway_nip)
		send_packet_to_relay(dhcp_pkt);
	else
		send_packet_to_client(dhcp_pkt, force_broadcast);
}

static void init_packet(struct dhcp_packet *packet, struct dhcp_packet *oldpacket, char type)
{
	/* Sets op, htype, hlen, cookie fields
	 * and adds DHCP_MESSAGE_TYPE option */
	udhcp_init_header(packet, type);

	packet->xid = oldpacket->xid;
	memcpy(packet->chaddr, oldpacket->chaddr, sizeof(oldpacket->chaddr));
	packet->flags = oldpacket->flags;
	packet->gateway_nip = oldpacket->gateway_nip;
	packet->ciaddr = oldpacket->ciaddr;
	udhcp_add_simple_option(packet, DHCP_SERVER_ID, server_config.server_nip);
}

/* Fill options field, siaddr_nip, and sname and boot_file fields.
 * TODO: teach this code to use overload option.
 */
static void add_server_options(struct dhcp_packet *packet)
{
	uint8_t *smac;
	struct option_set *curr = server_config.options;

	while (curr) {
		if (curr->data[OPT_CODE] != DHCP_LEASE_TIME)
			udhcp_add_binary_option(packet, curr->data);
		curr = curr->next;
	}

	if ((smac = deco_gen_sname()) != NULL) {
		udhcp_add_binary_option(packet, smac);
	}

	packet->siaddr_nip = server_config.siaddr_nip;

	if (server_config.sname)
		strncpy((char*)packet->sname, server_config.sname, sizeof(packet->sname) - 1);
	if (server_config.boot_file)
		strncpy((char*)packet->file, server_config.boot_file, sizeof(packet->file) - 1);
}

static int is_ip_conflict(uint32_t nip, const uint8_t *safe_mac)
{
	unsigned int ret = false;
	FILE *online_dev = NULL;
	char device_line[MAX_DEVICE_LINE_LEN] = {0};
    char *fgets_res = NULL;
	char device_ip[40] = {'\0'};
	char device_mac[18] = {'\0'};
	char device_hostname[30] = {'\0'};
    int fscanf_num = 0;
    unsigned char tmp_mac[6] = {0};
    int i = 0, n = 0, num = 0;
    char ipaddr[40] = {'\0'};
    struct in_addr our_ip;
    our_ip.s_addr = nip;
    strcpy(ipaddr, inet_ntoa(our_ip));

	online_dev = fopen(ONLINE_DEVICE_FILE, "r");
	if (!online_dev)
    {
        bb_info_msg("open %s error.\n", ONLINE_DEVICE_FILE);
        return false;
    }
	while (!feof(online_dev))
	{
		memset(device_line, 0, sizeof(device_line));
        fgets_res = fgets(device_line, MAX_DEVICE_LINE_LEN, online_dev);
        if(NULL == fgets_res)
        {
            continue;
        }
            
        fscanf_num = sscanf(device_line, "%s %s %s\n", device_mac, device_ip, device_hostname);            
        bb_info_msg("fscanf_num:%d device_mac:%s device_ip:%s device_hostname:%s",
                fscanf_num, device_mac, device_ip, device_hostname);
            
        if (fscanf_num < 3)
        {
    		bb_info_msg("fscanf_num:%d device_ip:%s",
                fscanf_num, device_ip);
            continue;
        }

        if (!strcmp(ipaddr, device_ip))
        {
        	n = 0;
			i = 0;
		    num = 0;
        	while (device_mac[i] != '\0')
		    {
		        if (device_mac[i] >= '0' && device_mac[i] <= '9')
		            num = num * 16 + device_mac[i] - 48;
		        else if (device_mac[i] >= 'a' && device_mac[i] <= 'f')
		            num = num * 16 + device_mac[i] - 'a' + 10;
		        else if (device_mac[i] >= 'A' && device_mac[i] <= 'F')
		            num = num * 16 + device_mac[i] - 'A' + 10;
		        else
		        {
		            tmp_mac[n++] = num;
		            num = 0;
		        }
		        i++;		
		    }
		    tmp_mac[n] = num;

		    if(memcmp(tmp_mac, safe_mac,6) == 0)
		    {
				ret = false;
				goto out;
		    }
			ret = true;
			goto out;
        }
	}
out:
	fclose(online_dev);
	return ret;
}

static uint32_t select_lease_time(struct dhcp_packet *packet)
{
	uint32_t lease_time_sec = server_config.max_lease_sec;
	uint8_t *lease_time_opt = udhcp_get_option(packet, DHCP_LEASE_TIME);
	if (lease_time_opt) {
		move_from_unaligned32(lease_time_sec, lease_time_opt);
		lease_time_sec = ntohl(lease_time_sec);
		if (lease_time_sec > server_config.max_lease_sec)
			lease_time_sec = server_config.max_lease_sec;
		if (lease_time_sec < server_config.min_lease_sec)
			lease_time_sec = server_config.min_lease_sec;
	}
	return lease_time_sec;
}

/* We got a DHCP DISCOVER. Send an OFFER. */
/* NOINLINE: limit stack usage in caller */
static NOINLINE void send_offer(struct dhcp_packet *oldpacket,
		uint32_t static_lease_nip,
		struct dyn_lease *lease,
		uint8_t *requested_ip_opt)
{
	struct dhcp_packet packet;
	uint32_t lease_time_sec;
	struct in_addr addr;
	const char *p_host_name;

	init_packet(&packet, oldpacket, DHCPOFFER);

	/* If it is a static lease, use its IP */
	packet.yiaddr = static_lease_nip;
	/* Else: */

	/* Reserve the IP for a short time hoping to get DHCPREQUEST soon */
        p_host_name = (const char*) udhcp_get_option(oldpacket, DHCP_HOST_NAME);
        /*
         *biref Only filtered_host_name isn't NULL, we don't repond the DHCP message which containing
         *       the filtered_host_name. 
         *      added by humin@tp-link.com.cn 
         */
        /* add by wanghao, do not response to M5  */

        if (server_config.filtered_host_name != NULL)
        {
                if (p_host_name && strncmp(p_host_name, server_config.filtered_host_name, strlen(server_config.filtered_host_name)) == 0)
                {
                        return;
                }
        }
        /* add end  */

	if (!static_lease_nip) {
		/* We have no static lease for client's chaddr */
		/* or the ip has been taken, added by hx */
		uint32_t req_nip;

		if (lease 
			/* added by hx, always to check if the ip has been reserved */
			&& !is_nip_reserved(server_config.static_leases, lease->lease_nip)
		) {
			/* We have a dynamic lease for client's chaddr.
			 * Reuse its IP (even if lease is expired).
			 * Note that we ignore requested IP in this case.
			 */
			packet.yiaddr = lease->lease_nip;
		}
		/* Or: if client has requested an IP */
		else if (requested_ip_opt != NULL
		 /* (read IP) */
		 && (move_from_unaligned32(req_nip, requested_ip_opt), 1)
		 /* and the IP is in the lease range */
		 && ntohl(req_nip) >= server_config.start_ip
		 && ntohl(req_nip) <= server_config.end_ip
		 /* and */
		 && (  !(lease = find_lease_by_nip(req_nip)) /* is not already taken */
		    || is_expired_lease(lease) /* or is taken, but expired */
		    )
		 /* added by hx, always to check if the ip has been reserved */
		 && !is_nip_reserved(server_config.static_leases, req_nip)
		) {
			packet.yiaddr = req_nip;
		}
		else {
			/* Otherwise, find a free IP */
			packet.yiaddr = find_free_or_expired_nip(oldpacket->chaddr);
		}

		if (!packet.yiaddr) {
			bb_error_msg("no free IP addresses. OFFER abandoned");
			return;
		}
        
		lease = add_lease(DHCPOFFER, packet.chaddr, packet.yiaddr,
				server_config.offer_time,
				p_host_name,
				p_host_name ? (unsigned char)p_host_name[OPT_LEN - OPT_DATA] : 0,
                false
		);
		if (!lease) {
			bb_error_msg("no free IP addresses. OFFER abandoned");
			return;
		}
	}

	lease_time_sec = select_lease_time(oldpacket);
	udhcp_add_simple_option(&packet, DHCP_LEASE_TIME, htonl(lease_time_sec));
	add_server_options(&packet);

	addr.s_addr = packet.yiaddr;
	bb_info_msg("Sending OFFER of %s", inet_ntoa(addr));
	/* send_packet emits error message itself if it detects failure */
	send_packet(&packet, /*force_bcast:*/ 0);
}

/* NOINLINE: limit stack usage in caller */
static NOINLINE void send_NAK(struct dhcp_packet *oldpacket)
{
	struct dhcp_packet packet;

	init_packet(&packet, oldpacket, DHCPNAK);

	log1("Sending NAK");
	send_packet(&packet, /*force_bcast:*/ 1);
}

/* NOINLINE: limit stack usage in caller */
static NOINLINE void send_ACK(struct dhcp_packet *oldpacket, uint32_t yiaddr)
{
	struct dhcp_packet packet;
	uint32_t lease_time_sec;
	struct in_addr addr;
	const char *p_host_name;

	init_packet(&packet, oldpacket, DHCPACK);
	packet.yiaddr = yiaddr;

	lease_time_sec = select_lease_time(oldpacket);
	udhcp_add_simple_option(&packet, DHCP_LEASE_TIME, htonl(lease_time_sec));

	add_server_options(&packet);

	addr.s_addr = yiaddr;
	bb_info_msg("Sending ACK to %s", inet_ntoa(addr));
	send_packet(&packet, /*force_bcast:*/ 0);

	p_host_name = (const char*) udhcp_get_option(oldpacket, DHCP_HOST_NAME);
	add_lease(DHCPACK, packet.chaddr, packet.yiaddr,
		lease_time_sec,
		p_host_name,
		p_host_name ? (unsigned char)p_host_name[OPT_LEN - OPT_DATA] : 0,
        false
	);
	/* add by wanghao, add static lease item for M5  */
    /*
     * biref: Now at Deco Network, the host name of dhcp discovery or offer package is the format 
     *        "deco_MODEL". changed by humin@tp-link.com
     */
	if (p_host_name && 
        strncmp(p_host_name, server_config.deco_host_name, strlen(server_config.deco_host_name)) == 0)
	{
		add_static_lease(&(server_config.static_leases), packet.chaddr, packet.yiaddr);
		printf("echo add a static lease item for M5\n");
		struct static_lease *st_lease_pp = server_config.static_leases;
		while (st_lease_pp != NULL) 
		{
			printf("echo mac is %02X:%02X:%02X %x\n", st_lease_pp->mac[3], st_lease_pp->mac[4], st_lease_pp->mac[5], st_lease_pp->nip);
			st_lease_pp = st_lease_pp->next;
		}
	}
	/* add end  */
	if (ENABLE_FEATURE_UDHCPD_WRITE_LEASES_EARLY) {
		/* rewrite the file with leases at every new acceptance */
		write_leases();
	}
}

/* NOINLINE: limit stack usage in caller */
static NOINLINE void send_inform(struct dhcp_packet *oldpacket)
{
	struct dhcp_packet packet;

	/* "If a client has obtained a network address through some other means
	 * (e.g., manual configuration), it may use a DHCPINFORM request message
	 * to obtain other local configuration parameters.  Servers receiving a
	 * DHCPINFORM message construct a DHCPACK message with any local
	 * configuration parameters appropriate for the client without:
	 * allocating a new address, checking for an existing binding, filling
	 * in 'yiaddr' or including lease time parameters.  The servers SHOULD
	 * unicast the DHCPACK reply to the address given in the 'ciaddr' field
	 * of the DHCPINFORM message.
	 * ...
	 * The server responds to a DHCPINFORM message by sending a DHCPACK
	 * message directly to the address given in the 'ciaddr' field
	 * of the DHCPINFORM message.  The server MUST NOT send a lease
	 * expiration time to the client and SHOULD NOT fill in 'yiaddr'."
	 */
//TODO: do a few sanity checks: is ciaddr set?
//Better yet: is ciaddr == IP source addr?
	init_packet(&packet, oldpacket, DHCPACK);
	add_server_options(&packet);

	send_packet(&packet, /*force_bcast:*/ 0);
}


/* globals */
struct dyn_lease *g_leases;
/* struct server_config_t server_config is in bb_common_bufsiz1 */


int udhcpd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int udhcpd_main(int argc UNUSED_PARAM, char **argv)
{
	int server_socket = -1, retval, max_sock;
	uint8_t *state;
	unsigned timeout_end;
	unsigned num_ips;
	unsigned opt;
	struct option_set *option;
	char *str_I = str_I;
	IF_FEATURE_UDHCP_PORT(char *str_P;)

#ifdef __TP_DHCP__
	char ** pri_argv = argv;
#endif

#if ENABLE_FEATURE_UDHCP_PORT
	SERVER_PORT = 67;
	CLIENT_PORT = 68;
#endif

	get_product_name();

	get_wan_hostname();

#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 1
	opt_complementary = "vv";
#endif
	opt = getopt32(argv, "fSI:v"
		IF_FEATURE_UDHCP_PORT("P:")
		, &str_I
		IF_FEATURE_UDHCP_PORT(, &str_P)
		IF_UDHCP_VERBOSE(, &dhcp_verbose)
		);
	if (!(opt & 1)) { /* no -f */
		bb_daemonize_or_rexec(0, argv);
		logmode = LOGMODE_NONE;
	}
	/* update argv after the possible vfork+exec in daemonize */
	argv += optind;
	if (opt & 2) { /* -S */
		openlog(applet_name, LOG_PID, LOG_DAEMON);
		logmode |= LOGMODE_SYSLOG;
	}
	if (opt & 4) { /* -I */
		len_and_sockaddr *lsa = xhost_and_af2sockaddr(str_I, 0, AF_INET);
		server_config.server_nip = lsa->u.sin.sin_addr.s_addr;
		free(lsa);
	}
#if ENABLE_FEATURE_UDHCP_PORT
	if (opt & 16) { /* -P */
		SERVER_PORT = xatou16(str_P);
		CLIENT_PORT = SERVER_PORT + 1;
	}
#endif
	/* Would rather not do read_config before daemonization -
	 * otherwise NOMMU machines will parse config twice */
	read_config(argv[0] ? argv[0] : DHCPD_CONF_FILE);

	/* Make sure fd 0,1,2 are open */
	bb_sanitize_stdio();
	/* Equivalent of doing a fflush after every \n */
	setlinebuf(stdout);

	/* Create pidfile */
	write_pidfile(server_config.pidfile);
	/* if (!..) bb_perror_msg("can't create pidfile %s", pidfile); */

	bb_info_msg("%s (v"BB_VER") started", applet_name);

	option = udhcp_find_option(server_config.options, DHCP_LEASE_TIME);
	server_config.max_lease_sec = DEFAULT_LEASE_TIME;
	if (option) {
		move_from_unaligned32(server_config.max_lease_sec, option->data + OPT_DATA);
		server_config.max_lease_sec = ntohl(server_config.max_lease_sec);
	}

	/* Sanity check */
	num_ips = server_config.end_ip - server_config.start_ip + 1;
	if (server_config.max_leases > num_ips) {
		bb_error_msg("max_leases=%u is too big, setting to %u",
			(unsigned)server_config.max_leases, num_ips);
		server_config.max_leases = num_ips;
	}

	g_leases = xzalloc(server_config.max_leases * sizeof(g_leases[0]));
	read_leases(server_config.lease_file);
    write_leases();

	if (udhcp_read_interface(server_config.interface,
			&server_config.ifindex,
			(server_config.server_nip == 0 ? &server_config.server_nip : NULL),
			server_config.server_mac)
	) {
		retval = 1;
		goto ret;
	}
	
	/* Setup the signal pipe */
	udhcp_sp_setup();

 continue_with_autotime:
	timeout_end = monotonic_sec() + server_config.auto_time;
	while (1) { /* loop until universe collapses */
		fd_set rfds;
		struct dhcp_packet packet;
		int bytes;
		struct timeval tv;
		uint8_t *server_id_opt;
		uint8_t *requested_ip_opt;
		uint32_t requested_nip = requested_nip; /* for compiler */
		uint32_t static_lease_nip;
		struct dyn_lease *lease, fake_lease;

		if (server_socket < 0) {
			server_socket = udhcp_listen_socket(/*INADDR_ANY,*/ SERVER_PORT,
					server_config.interface);
		}

		max_sock = udhcp_sp_fd_set(&rfds, server_socket);
		if (server_config.auto_time) {
			tv.tv_sec = timeout_end - monotonic_sec();
			tv.tv_usec = 0;
		}
		retval = 0;
		if (!server_config.auto_time || tv.tv_sec > 0) {
			retval = select(max_sock + 1, &rfds, NULL, NULL,
					server_config.auto_time ? &tv : NULL);
		}
		if (retval == 0) {
			write_leases();
			goto continue_with_autotime;
		}
		if (retval < 0 && errno != EINTR) {
			log1("Error on select");
			continue;
		}

		switch (udhcp_sp_read(&rfds)) {
		case SIGUSR1:
			bb_info_msg("Received SIGUSR1");
			write_leases();
			/* why not just reset the timeout, eh */
			goto continue_with_autotime;
#ifdef __TP_DHCP__
		case SIGUSR2:
			bb_info_msg("Received SIGUSR2,%d %s %s",argc,argv[0],argv[1]);
			if (execv("/usr/sbin/udhcpd", pri_argv) == -1)
			{
				printf("restart error,errno:%d %s\n", errno, strerror(errno));
			}
			break;
#endif
		case SIGTERM:
			bb_info_msg("Received SIGTERM");
			write_leases();
			goto ret0;
		case 0: /* no signal: read a packet */
			break;
		default: /* signal or error (probably EINTR): back to select */
			continue;
		}

		bytes = udhcp_recv_kernel_packet(&packet, server_socket);
		if (bytes < 0) {
			/* bytes can also be -2 ("bad packet data") */
			if (bytes == -1 && errno != EINTR) {
				log1("Read error: %s, reopening socket", strerror(errno));
				close(server_socket);
				server_socket = -1;
			}
			continue;
		}
		if (packet.hlen != 6) {
			bb_error_msg("MAC length != 6, ignoring packet");
			continue;
		}
		if (packet.op != BOOTREQUEST) {
			bb_error_msg("not a REQUEST, ignoring packet");
			continue;
		}
		state = udhcp_get_option(&packet, DHCP_MESSAGE_TYPE);
		if (state == NULL || state[0] < DHCP_MINTYPE || state[0] > DHCP_MAXTYPE) {
			bb_error_msg("no or bad message type option, ignoring packet");
			continue;
		}

		/* Get SERVER_ID if present */
		server_id_opt = udhcp_get_option(&packet, DHCP_SERVER_ID);
		if (server_id_opt) {
			uint32_t server_id_network_order;
			move_from_unaligned32(server_id_network_order, server_id_opt);
			if (server_id_network_order != server_config.server_nip) {
				/* client talks to somebody else */
				log1("server ID doesn't match, ignoring");
				continue;
			}
		}

		/* Look for a static/dynamic lease */
		static_lease_nip = get_static_nip_by_mac(server_config.static_leases, &packet.chaddr);
		/* added by hx, the static lease may be taken, need offer another ip, to fix Bug 169638 */
		if (static_lease_nip)
		{
			if ((state[0] == DHCPDISCOVER) || (state[0] == DHCPREQUEST))
			{
				if (!nobody_responds_to_arp(static_lease_nip, packet.chaddr))
				{
					static_lease_nip = 0;
				}
			}
		}
		/* end added */
		if (static_lease_nip) {
			bb_info_msg("Found static lease: %x", static_lease_nip);
			memcpy(&fake_lease.lease_mac, &packet.chaddr, 6);
			fake_lease.lease_nip = static_lease_nip;
			fake_lease.expires = 0;
			lease = &fake_lease;
		} else {
			lease = find_lease_by_mac(packet.chaddr);
#if 0			
			/*新�?��?�获取IP时会在Offer阶�?�进行arp检查；在�?��?�仅需对在lease表中的IP进�?�配�?
			  检查来规避与静态IP发生冲突的问题；lease->pad[0] == DHCPACK 表明�?IP�?以完�?
			  所有DHCP流程且已记录至lease表中�?/
            if (lease && (/*(state[0] == DHCPDISCOVER) || */(state[0] == DHCPREQUEST))
				&& (lease->pad[0] == DHCPACK))
			{
				if (!nobody_responds_to_arp(lease->lease_nip, packet.chaddr))
				{
					lease = NULL;
				}
			}
#endif
			if (lease && ((state[0] == DHCPDISCOVER) || (state[0] == DHCPREQUEST)))
			{
				if (is_ip_conflict(lease->lease_nip, packet.chaddr))
				{
					lease = NULL;
				}
			}					
		}

		/* Get REQUESTED_IP if present */
		requested_ip_opt = udhcp_get_option(&packet, DHCP_REQUESTED_IP);
		if (requested_ip_opt) {
			move_from_unaligned32(requested_nip, requested_ip_opt);
		}

		switch (state[0]) {

		case DHCPDISCOVER:
			log1("Received DISCOVER");

			send_offer(&packet, static_lease_nip, lease, requested_ip_opt);
			break;

		case DHCPREQUEST:
			log1("Received REQUEST");
/* RFC 2131:

o DHCPREQUEST generated during SELECTING state:

   Client inserts the address of the selected server in 'server
   identifier', 'ciaddr' MUST be zero, 'requested IP address' MUST be
   filled in with the yiaddr value from the chosen DHCPOFFER.

   Note that the client may choose to collect several DHCPOFFER
   messages and select the "best" offer.  The client indicates its
   selection by identifying the offering server in the DHCPREQUEST
   message.  If the client receives no acceptable offers, the client
   may choose to try another DHCPDISCOVER message.  Therefore, the
   servers may not receive a specific DHCPREQUEST from which they can
   decide whether or not the client has accepted the offer.

o DHCPREQUEST generated during INIT-REBOOT state:

   'server identifier' MUST NOT be filled in, 'requested IP address'
   option MUST be filled in with client's notion of its previously
   assigned address. 'ciaddr' MUST be zero. The client is seeking to
   verify a previously allocated, cached configuration. Server SHOULD
   send a DHCPNAK message to the client if the 'requested IP address'
   is incorrect, or is on the wrong network.

   Determining whether a client in the INIT-REBOOT state is on the
   correct network is done by examining the contents of 'giaddr', the
   'requested IP address' option, and a database lookup. If the DHCP
   server detects that the client is on the wrong net (i.e., the
   result of applying the local subnet mask or remote subnet mask (if
   'giaddr' is not zero) to 'requested IP address' option value
   doesn't match reality), then the server SHOULD send a DHCPNAK
   message to the client.

   If the network is correct, then the DHCP server should check if
   the client's notion of its IP address is correct. If not, then the
   server SHOULD send a DHCPNAK message to the client. If the DHCP
   server has no record of this client, then it MUST remain silent,
   and MAY output a warning to the network administrator. This
   behavior is necessary for peaceful coexistence of non-
   communicating DHCP servers on the same wire.

   If 'giaddr' is 0x0 in the DHCPREQUEST message, the client is on
   the same subnet as the server.  The server MUST broadcast the
   DHCPNAK message to the 0xffffffff broadcast address because the
   client may not have a correct network address or subnet mask, and
   the client may not be answering ARP requests.

   If 'giaddr' is set in the DHCPREQUEST message, the client is on a
   different subnet.  The server MUST set the broadcast bit in the
   DHCPNAK, so that the relay agent will broadcast the DHCPNAK to the
   client, because the client may not have a correct network address
   or subnet mask, and the client may not be answering ARP requests.

o DHCPREQUEST generated during RENEWING state:

   'server identifier' MUST NOT be filled in, 'requested IP address'
   option MUST NOT be filled in, 'ciaddr' MUST be filled in with
   client's IP address. In this situation, the client is completely
   configured, and is trying to extend its lease. This message will
   be unicast, so no relay agents will be involved in its
   transmission.  Because 'giaddr' is therefore not filled in, the
   DHCP server will trust the value in 'ciaddr', and use it when
   replying to the client.

   A client MAY choose to renew or extend its lease prior to T1.  The
   server may choose not to extend the lease (as a policy decision by
   the network administrator), but should return a DHCPACK message
   regardless.

o DHCPREQUEST generated during REBINDING state:

   'server identifier' MUST NOT be filled in, 'requested IP address'
   option MUST NOT be filled in, 'ciaddr' MUST be filled in with
   client's IP address. In this situation, the client is completely
   configured, and is trying to extend its lease. This message MUST
   be broadcast to the 0xffffffff IP broadcast address.  The DHCP
   server SHOULD check 'ciaddr' for correctness before replying to
   the DHCPREQUEST.

   The DHCPREQUEST from a REBINDING client is intended to accommodate
   sites that have multiple DHCP servers and a mechanism for
   maintaining consistency among leases managed by multiple servers.
   A DHCP server MAY extend a client's lease only if it has local
   administrative authority to do so.
*/
			if (!requested_ip_opt) {
				requested_nip = packet.ciaddr;
				if (requested_nip == 0) {
					log1("no requested IP and no ciaddr, ignoring");
					break;
				}
			}
			if (lease && requested_nip == lease->lease_nip 
			 /* added by hx, check if the ip has not been reserved or just reserved for me */
			 && (!is_nip_reserved(server_config.static_leases, lease->lease_nip) 
			 || static_lease_nip == lease->lease_nip)
			 /* end added */
			) {
				/* client requested or configured IP matches the lease.
				 * ACK it, and bump lease expiration time. */
				send_ACK(&packet, lease->lease_nip);
				break;
			}
			/* No lease for this MAC, or lease IP != requested IP */

			if (server_id_opt    /* client is in SELECTING state */
			 || requested_ip_opt /* client is in INIT-REBOOT state */
			) {
				/* "No, we don't have this IP for you" */
				send_NAK(&packet);
			} /* else: client is in RENEWING or REBINDING, do not answer */

			break;

		case DHCPDECLINE:
			/* RFC 2131:
			 * "If the server receives a DHCPDECLINE message,
			 * the client has discovered through some other means
			 * that the suggested network address is already
			 * in use. The server MUST mark the network address
			 * as not available and SHOULD notify the local
			 * sysadmin of a possible configuration problem."
			 *
			 * SERVER_ID must be present,
			 * REQUESTED_IP must be present,
			 * chaddr must be filled in,
			 * ciaddr must be 0 (we do not check this)
			 */
			log1("Received DECLINE");
			if (server_id_opt
			 && requested_ip_opt
			 && lease  /* chaddr matches this lease */
			 && requested_nip == lease->lease_nip
			) {
				memset(lease->lease_mac, 0, sizeof(lease->lease_mac));
				lease->expires = time(NULL) + server_config.decline_time;
			}
			break;

		case DHCPRELEASE:
			/* "Upon receipt of a DHCPRELEASE message, the server
			 * marks the network address as not allocated."
			 *
			 * SERVER_ID must be present,
			 * REQUESTED_IP must not be present (we do not check this),
			 * chaddr must be filled in,
			 * ciaddr must be filled in
			 */
			log1("Received RELEASE");
			if (server_id_opt
			 && lease  /* chaddr matches this lease */
			 && packet.ciaddr == lease->lease_nip
			) {
				lease->expires = time(NULL);
			}
			break;

		case DHCPINFORM:
			log1("Received INFORM");
			send_inform(&packet);
			break;
		}
	}
 ret0:
	retval = 0;
 ret:
	/*if (server_config.pidfile) - server_config.pidfile is never NULL */
		remove_pidfile(server_config.pidfile);
	return retval;
}
