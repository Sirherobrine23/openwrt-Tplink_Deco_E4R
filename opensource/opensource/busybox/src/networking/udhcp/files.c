/* vi: set sw=4 ts=4: */
/*
 * DHCP server config and lease file manipulation
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#include <netinet/ether.h>

#include "common.h"
#include "dhcpd.h"

/* on these functions, make sure your datatype matches */
static int FAST_FUNC read_str(const char *line, void *arg)
{
	char **dest = arg;

	free(*dest);
	*dest = xstrdup(line);
	return 1;
}

static int FAST_FUNC read_u32(const char *line, void *arg)
{
	*(uint32_t*)arg = bb_strtou32(line, NULL, 10);
	return errno == 0;
}

static int FAST_FUNC read_staticlease(const char *const_line, void *arg)
{
	char *line;
	char *mac_string;
	char *ip_string;
	struct ether_addr mac_bytes; /* it's "struct { uint8_t mac[6]; }" */
	uint32_t nip;

	/* Read mac */
	line = (char *) const_line;
	mac_string = strtok_r(line, " \t", &line);
	if (!mac_string || !ether_aton_r(mac_string, &mac_bytes))
		return 0;

	/* Read ip */
	ip_string = strtok_r(NULL, " \t", &line);
	if (!ip_string || !udhcp_str2nip(ip_string, &nip))
		return 0;

	add_static_lease(arg, (uint8_t*) &mac_bytes, nip);

	log_static_leases(arg);

	return 1;
}


struct config_keyword {
	const char *keyword;
	int (*handler)(const char *line, void *var) FAST_FUNC;
	void *var;
	const char *def;
};

static const struct config_keyword keywords[] = {
	/* keyword        handler           variable address               default */
	{"start"        , udhcp_str2nip   , &server_config.start_ip     , "192.168.0.20"},
	{"end"          , udhcp_str2nip   , &server_config.end_ip       , "192.168.0.254"},
	{"interface"    , read_str        , &server_config.interface    , "eth0"},
	/* Avoid "max_leases value not sane" warning by setting default
	 * to default_end_ip - default_start_ip + 1: */
	{"max_leases"   , read_u32        , &server_config.max_leases   , "235"},
	{"auto_time"    , read_u32        , &server_config.auto_time    , "7200"},
	{"decline_time" , read_u32        , &server_config.decline_time , "3600"},
	{"conflict_time", read_u32        , &server_config.conflict_time, "3600"},
	{"offer_time"   , read_u32        , &server_config.offer_time   , "60"},
	{"min_lease"    , read_u32        , &server_config.min_lease_sec, "60"},
	{"lease_file"   , read_str        , &server_config.lease_file   , LEASES_FILE},
	{"pidfile"      , read_str        , &server_config.pidfile      , "/var/run/udhcpd.pid"},
	{"deco_host_name" , read_str      , &server_config.deco_host_name , "DECO_M5"},
	{"siaddr"       , udhcp_str2nip   , &server_config.siaddr_nip   , "0.0.0.0"},
	/* keywords with no defaults must be last! */
	{"option"       , udhcp_str2optset, &server_config.options      , ""},
	{"opt"          , udhcp_str2optset, &server_config.options      , ""},
	{"notify_file"  , read_str        , &server_config.notify_file  , NULL},
	{"sname"        , read_str        , &server_config.sname        , NULL},
	{"boot_file"    , read_str        , &server_config.boot_file    , NULL},
	{"static_lease" , read_staticlease, &server_config.static_leases, ""},
	{"filtered_host_name" , read_str  , &server_config.filtered_host_name, NULL},
};
enum { KWS_WITH_DEFAULTS = ARRAY_SIZE(keywords) - 6 };

void FAST_FUNC read_config(const char *file)
{
	parser_t *parser;
	const struct config_keyword *k;
	unsigned i;
	char *token[2];

	for (i = 0; i < KWS_WITH_DEFAULTS; i++)
		keywords[i].handler(keywords[i].def, keywords[i].var);

	parser = config_open(file);
	while (config_read(parser, token, 2, 2, "# \t", PARSE_NORMAL)) {
		for (k = keywords, i = 0; i < ARRAY_SIZE(keywords); k++, i++) {
			if (strcasecmp(token[0], k->keyword) == 0) {
				if (!k->handler(token[1], k->var)) {
					bb_error_msg("can't parse line %u in %s",
							parser->lineno, file);
					/* reset back to the default value */
					k->handler(k->def, k->var);
				}
				break;
			}
		}
	}
	config_close(parser);

	server_config.start_ip = ntohl(server_config.start_ip);
	server_config.end_ip = ntohl(server_config.end_ip);
}

void FAST_FUNC write_leases(void)
{
	int fd;
	unsigned i;
	leasetime_t curr;
	int64_t written_at;

#ifdef __TP_DHCP__
	FILE * fp;
	char cli_info_buf[256];
	char mac_str[18];
	uint32_t ip;
	char ip_str[16];
	char leasetime_str[10];
	
	fp = fopen(server_config.lease_file, "w");
	if (NULL == fp)
	{
		return;
	}
	curr = time(NULL);
#else
	fd = open_or_warn(server_config.lease_file, O_WRONLY|O_CREAT|O_TRUNC);
	if (fd < 0)
		return;

	curr = written_at = time(NULL);

	written_at = SWAP_BE64(written_at);

	full_write(fd, &written_at, sizeof(written_at));
#endif	

	for (i = 0; i < server_config.max_leases; i++) {
		leasetime_t tmp_time;

		if (g_leases[i].lease_nip == 0)
			continue;

#ifdef __TP_DHCP__
		if(g_leases[i].lease_mac[0] == 0 &&
		    g_leases[i].lease_mac[1] == 0 &&
		    g_leases[i].lease_mac[2] == 0 &&
		    g_leases[i].lease_mac[3] == 0 &&
		    g_leases[i].lease_mac[4] == 0 &&
		    g_leases[i].lease_mac[5] == 0)
		{
			continue;
		}

		if(g_leases[i].pad[0] != DHCPACK)
			continue;
#endif

		/* Screw with the time in the struct, for easier writing */
		tmp_time = g_leases[i].expires;

#ifdef __TP_DHCP__
		tmp_time -= curr;
            
		/* Modify by zengdongbiao to solve the problem: g_leases[i].expires (e.g. now time is 
		 * 2017.07.10 07:0:0, lease time is 2 hours, then expires would point to 09:0:0) 
		 * may expire after ntp success (e.g. time is 15:0:0 after ntp success, so expires expired),
		 * then lease file would be empty, 2017.07.10.  
		 */
#if 0            
        if((signed_leasetime_t)tmp_time <= 0)
        {
			g_leases[i].expires = 0;
			continue;
		}
#else
		if (g_leases[i].expires <= 0)
		{
			continue;
		}
#endif

		memset(cli_info_buf, 0, 256);
		memset(mac_str, 0, 18);
		memset(ip_str, 0, 16);
		memset(leasetime_str, 0, 10);
		sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", 
				g_leases[i].lease_mac[0], 
				g_leases[i].lease_mac[1], 
				g_leases[i].lease_mac[2], 
				g_leases[i].lease_mac[3], 
				g_leases[i].lease_mac[4], 
				g_leases[i].lease_mac[5]);

		ip = ntohl(g_leases[i].lease_nip);
		sprintf(ip_str, "%d.%d.%d.%d", 
				ip >> 24, 
				(ip & 0xff0000) >> 16,  
				(ip & 0xff00) >> 8, 
				ip & 0xff);
		if (0XFFFFFFFF == tmp_time)
		{
			sprintf(leasetime_str, "%s", "Permanent");
		}
		else
		{
			sprintf(leasetime_str, "%d", g_leases[i].expires);
		}
		//sprintf(cli_info_buf, "\n{\"key\": %d, macaddr: \"%s\", leasetime: \"%s\", name: \"%s\", ipaddr: \"%s\", state: %d},", 

		sprintf(cli_info_buf, "%s %s %s %s %d\n",
				leasetime_str, mac_str, ip_str, g_leases[i].hostname, DHCPACK);
		//		i, mac_str, leasetime_str, g_leases[i].hostname, 
		//		ip_str, DHCPACK);
		fwrite(cli_info_buf, strlen(cli_info_buf), 1, fp);
#else

		g_leases[i].expires -= curr;
		if ((signed_leasetime_t) g_leases[i].expires < 0)
			g_leases[i].expires = 0;
		g_leases[i].expires = htonl(g_leases[i].expires);

		/* No error check. If the file gets truncated,
		 * we lose some leases on restart. Oh well. */
		full_write(fd, &g_leases[i], sizeof(g_leases[i]));

		/* Then restore it when done */
		g_leases[i].expires = tmp_time;
#endif		
	}
#ifdef __TP_DHCP__
	fclose(fp);
	fp = NULL;
#else
	close(fd);
#endif

	if (server_config.notify_file) {
		char *argv[3];
		argv[0] = server_config.notify_file;
		argv[1] = server_config.lease_file;
		argv[2] = NULL;
		spawn_and_wait(argv);
	}
}

void FAST_FUNC read_leases(const char *file)
{
	struct dyn_lease lease;
	int64_t written_at, time_passed;
	int fd;
#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 1
	unsigned i = 0;
#endif

#ifdef __TP_DHCP__
	FILE * fp;
	char mac_str[18] = {0};
	char ip_str[16] = {0};
	char hostname[32] = {0};
	char *pLine = NULL, *pStr = NULL, *pMac = NULL, *pIp = NULL, *pHostname = NULL;
	char buffer[256] = {0};
	int64_t expire = 0;
	int64_t curr, time_left;
	struct ether_addr mac_bytes; /* it's "struct { uint8_t mac[6]; }" */
	uint32_t nip;
    uint32_t tmp_ip = 0;
	struct option_set *option;
    uint32_t subnet = 0;

	option = udhcp_find_option(server_config.options, DHCP_SUBNET);
	if (option) {
		move_from_unaligned32(subnet, option->data + OPT_DATA);
        subnet = ntohl(subnet);
	}

	fp = fopen(server_config.lease_file, "r");
	if (NULL == fp)
	{
		return;
	}
    
    bb_error_msg("start ip 0x%x, end ip 0x%x, subnet:0x%x", 
        server_config.start_ip, server_config.end_ip, subnet);

	while (fgets(buffer, 256, fp))
	{
		
		if ((pStr = strchr(buffer, '\n')) != NULL)
		{
			*pStr = '\0';
		}		
		pLine = buffer + strspn(buffer, " \t");

		pStr = strchr(pLine, ' ');
		if (pStr == NULL)
		{
			continue;
		}
		else
		{
			*pStr = '\0';
		}
		
		expire = (int64_t)atol(pLine);
		curr = (int64_t)time(NULL);
		
		if (curr - expire >= 0)
		{
			continue;
		}

		time_left = expire - curr;

		pMac = strchr(++pStr, ' ');
		if (pMac == NULL)
		{
			continue;
		}
		else
		{
			*pMac = '\0';
			strncpy(mac_str, pStr, 18);
			pStr = pMac;
		}

		if (mac_str[0] == '\0' || !ether_aton_r(mac_str, &mac_bytes))
		{
			continue;
		}

		pIp = strchr(++pStr, ' ');
		if (pIp == NULL)
		{
			continue;
		}
		else
		{
			*pIp = '\0';
			strncpy(ip_str, pStr, 16);
			pStr = pIp;
		}

		if (ip_str[0] == '\0' || !udhcp_str2nip(ip_str, &nip))
		{
			continue;
		}

		pHostname = strrchr(++pStr, ' ');
		if (pHostname == NULL)
		{
			strncpy(hostname, "UNKNOWN", 32);
		}
		else
		{
			*pHostname = '\0';
			strncpy(hostname, pStr, 32);
		}

        tmp_ip = ntohl(nip);
        bb_error_msg("lease ip: 0x%x", tmp_ip);
		if (tmp_ip >= server_config.start_ip && tmp_ip <= server_config.end_ip) {
    		if (add_lease(DHCPACK, (uint8_t*) &mac_bytes, nip,
    					  time_left, hostname, strlen(hostname), false) == 0) 
    		{
    			bb_error_msg("too many leases while loading %s", file);
    			break;
    		}		
        }
        else if (subnet && ((server_config.start_ip & subnet) == (tmp_ip & subnet)))
        {
            if (add_lease(DHCPACK, (uint8_t*) &mac_bytes, nip,
    					  time_left, hostname, strlen(hostname), true) == 0) 
    		{
    			bb_error_msg("too many leases while loading %s #", file);
    			break;
    		}	
        }
	}

	fclose(fp);
	return;

#else

	fd = open_or_warn(file, O_RDONLY);
	if (fd < 0)
		return;

	if (full_read(fd, &written_at, sizeof(written_at)) != sizeof(written_at))
		goto ret;
	written_at = SWAP_BE64(written_at);

	time_passed = time(NULL) - written_at;
	/* Strange written_at, or lease file from old version of udhcpd
	 * which had no "written_at" field? */
	if ((uint64_t)time_passed > 12 * 60 * 60)
		goto ret;

	while (full_read(fd, &lease, sizeof(lease)) == sizeof(lease)) {
//FIXME: what if it matches some static lease?
		uint32_t y = ntohl(lease.lease_nip);
		if (y >= server_config.start_ip && y <= server_config.end_ip) {
			signed_leasetime_t expires = ntohl(lease.expires) - (signed_leasetime_t)time_passed;
			if (expires <= 0)
				continue;
			/* NB: add_lease takes "relative time", IOW,
			 * lease duration, not lease deadline. */
			if (add_lease(DHCPNULL, lease.lease_mac, lease.lease_nip,
					expires,
					lease.hostname, sizeof(lease.hostname), false
				) == 0
			) {
				bb_error_msg("too many leases while loading %s", file);
				break;
			}
#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 1
			i++;
#endif
		}
	}
	log1("Read %d leases", i);
 ret:
	close(fd);
#endif	/* __TP_DHCP__ */
}
