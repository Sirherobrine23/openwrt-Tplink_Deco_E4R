/* vi: set sw=4 ts=4: */
/*
 * udhcp client
 *
 * Russ Dill <Russ.Dill@asu.edu> July 2001
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
#include <syslog.h>
/* Override ENABLE_FEATURE_PIDFILE - ifupdown needs our pidfile to always exist */
#define WANT_PIDFILE 1

#include "common.h"
#include "dhcpd.h"
#include "dhcpc.h"

#include <netinet/if_ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>

#include "deco.h"
//#include "ibus.h"

#if (CONFIG_IBUS_METHOD == IBUS_USE_UBUS)

#include "libubox/blobmsg_json.h"

#endif

/* "struct client_config_t client_config" is in bb_common_bufsiz1 */


#if ENABLE_LONG_OPTS
static const char udhcpc_longopts[] ALIGN1 =
		"clientid-none\0"  No_argument       "C"
				"vendorclass\0"    Required_argument "V"
				"hostname\0"       Required_argument "H"
				"fqdn\0"           Required_argument "F"
				"interface\0"      Required_argument "i"
				"unbound\0"        No_argument       "u"
				"now\0"            No_argument       "n"
				"pidfile\0"        Required_argument "p"
				"quit\0"           No_argument       "q"
				"release\0"        No_argument       "R"
				"request\0"        Required_argument "r"
				"script\0"         Required_argument "s"
				"timeout\0"        Required_argument "T"
				"retries\0"        Required_argument "t"
				"tryagain\0"       Required_argument "A"
				"syslog\0"         No_argument       "S"
				"request-option\0" Required_argument "O"
				"no-default-options\0" No_argument   "o"
				"foreground\0"     No_argument       "f"
				"background\0"     No_argument       "b"
				"broadcast\0"      No_argument       "B"
				"gap\0"            Required_argument "g"
				"mode\0"           Required_argument "m"
IF_FEATURE_UDHCPC_ARPING("arping\0"    No_argument       "a")
IF_FEATURE_UDHCP_PORT("client-port\0"    Required_argument "P");
#endif
/* Must match getopt32 option string order */
enum {
	OPT_C = 1 << 0,
	OPT_V = 1 << 1,
	OPT_H = 1 << 2,
	OPT_h = 1 << 3,
	OPT_F = 1 << 4,
	OPT_i = 1 << 5,
	OPT_u = 1 << 6,
	OPT_n = 1 << 7,
	OPT_p = 1 << 8,
	OPT_q = 1 << 9,
	OPT_Q = 1 << 10,     /* Exit after receiving DHCP Offer */
	OPT_R = 1 << 11,
	OPT_r = 1 << 12,
	OPT_s = 1 << 13,
	OPT_T = 1 << 14,
	OPT_t = 1 << 15,
	OPT_S = 1 << 16,
	OPT_A = 1 << 17,
	OPT_O = 1 << 18,
	OPT_o = 1 << 19,
	OPT_x = 1 << 20,
	OPT_f = 1 << 21,
	OPT_B = 1 << 22,
	OPT_g = 1 << 23,
	OPT_m = 1 << 24,
/* The rest has variable bit positions, need to be clever */
			OPTBIT_NOT_CLEVER_MAX = 24,
	USE_FOR_MMU(OPTBIT_b,)
	IF_FEATURE_UDHCPC_ARPING(OPTBIT_a, )
	IF_FEATURE_UDHCP_PORT(   OPTBIT_P, )
	USE_FOR_MMU(OPT_b = 1 << OPTBIT_b,)
	IF_FEATURE_UDHCPC_ARPING(OPT_a = 1 << OPTBIT_a, )
	IF_FEATURE_UDHCP_PORT(   OPT_P = 1 << OPTBIT_P, )
};


/*** Script execution code ***/

/* get a rough idea of how long an option will be (rounding up...) */
static const uint8_t len_of_option_as_string[] = {
		[OPTION_IP] = sizeof("255.255.255.255 "),
		[OPTION_IP_PAIR] = sizeof("255.255.255.255 ") * 2,
		[OPTION_STATIC_ROUTES] = sizeof("255.255.255.255/32 255.255.255.255 "),
		[OPTION_6RD] = sizeof("32 128 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 255.255.255.255 "),
		[OPTION_STRING] = 1,
		[OPTION_STRING_HOST] = 1,
#if ENABLE_FEATURE_UDHCP_RFC3397
[OPTION_DNS_STRING      ] = 1, /* unused */
/* Hmmm, this severely overestimates size if SIP_SERVERS option
 * is in domain name form: N-byte option in binary form
 * mallocs ~16*N bytes. But it is freed almost at once.
 */
[OPTION_SIP_SERVERS     ] = sizeof("255.255.255.255 "),
#endif
//	[OPTION_BOOLEAN         ] = sizeof("yes "),
		[OPTION_U8] = sizeof("255 "),
		[OPTION_U16] = sizeof("65535 "),
//	[OPTION_S16             ] = sizeof("-32768 "),
		[OPTION_U32] = sizeof("4294967295 "),
		[OPTION_S32] = sizeof("-2147483684 "),
};

/* note: ip is a pointer to an IP in network order, possibly misaliged */
static int sprint_nip(char *dest, const char *pre, const uint8_t *ip)
{
	return sprintf(dest, "%s%u.%u.%u.%u", pre, ip[0], ip[1], ip[2], ip[3]);
}

/* really simple implementation, just count the bits */
static int mton(uint32_t mask)
{
	int i = 0;
	mask = ntohl(mask); /* 111110000-like bit pattern */
	while (mask) {
		i++;
		mask <<= 1;
	}
	return i;
}

/* Check if a given label represents a valid DNS label
 * Return pointer to the first character after the label upon success,
 * NULL otherwise.
 * See RFC1035, 2.3.1
 */
/* We don't need to be particularly anal. For example, allowing _, hyphen
 * at the end, or leading and trailing dots would be ok, since it
 * can't be used for attacks. (Leading hyphen can be, if someone uses
 * cmd "$hostname"
 * in the script: then hostname may be treated as an option)
 */
static const char *valid_domain_label(const char *label)
{
	unsigned char ch;
	unsigned pos = 0;

	for (;;) {
		ch = *label;
		if ((ch | 0x20) < 'a' || (ch | 0x20) > 'z') {
			if (pos == 0) {
				/* label must begin with letter */
				return NULL;
			}
			if (ch < '0' || ch > '9') {
				if (ch == '\0' || ch == '.') {
					return label;
				}
				/* DNS allows only '-', but we are more permissive */
				if (ch != '-' && ch != '_') {
					return NULL;
				}
			}
		}
		label++;
		pos++;
		//Do we want this?
		//if (pos > 63) /* NS_MAXLABEL; labels must be 63 chars or less */
		//	return NULL;
	}
}

/* Check if a given name represents a valid DNS name */
/* See RFC1035, 2.3.1 */
static int good_hostname(const char *name)
{
	//const char *start = name;

	for (;;) {
		name = valid_domain_label(name);
		if (!name) {
			return 0;
		}
		if (!name[0]) {
			return 1;
		}
		//Do we want this?
		//return ((name - start) < 1025); /* NS_MAXDNAME */
		name++;
	}
}

/* Create "opt_name=opt_value" string */
static NOINLINE char *
xmalloc_optname_optval(uint8_t *option, const struct dhcp_optflag *optflag, const char *opt_name)
{
	unsigned upper_length;
	int len, type, optlen;
	char *dest, *ret;

	/* option points to OPT_DATA, need to go back to get OPT_LEN */
	len = option[-OPT_DATA + OPT_LEN];

	type = optflag->flags & OPTION_TYPE_MASK;
	optlen = dhcp_option_lengths[type];
	upper_length = len_of_option_as_string[type]
	               * ((unsigned) (len + optlen - 1) / (unsigned) optlen);

	dest = ret = xmalloc(upper_length + strlen(opt_name) + 2);
	dest += sprintf(ret, "%s=", opt_name);

	while (len >= optlen) {
		switch (type) {
		case OPTION_IP:
		case OPTION_IP_PAIR:
			dest += sprint_nip(dest, "", option);
			if (type == OPTION_IP) {
				break;
			}
			dest += sprint_nip(dest, "/", option + 4);
			break;
//		case OPTION_BOOLEAN:
//			dest += sprintf(dest, *option ? "yes" : "no");
//			break;
		case OPTION_U8:
			dest += sprintf(dest, "%u", *option);
			break;
//		case OPTION_S16:
		case OPTION_U16: {
			uint16_t val_u16;
			move_from_unaligned16(val_u16, option);
			dest += sprintf(dest, "%u", ntohs(val_u16));
			break;
		}
		case OPTION_S32:
		case OPTION_U32: {
			uint32_t val_u32;
			move_from_unaligned32(val_u32, option);
			dest += sprintf(dest, type == OPTION_U32 ? "%lu" : "%ld",
			                (unsigned long) ntohl(val_u32));
			break;
		}
			/* Note: options which use 'return' instead of 'break'
			 * (for example, OPTION_STRING) skip the code which handles
			 * the case of list of options.
			 */
		case OPTION_STRING:
		case OPTION_STRING_HOST:
			memcpy(dest, option, len);
			dest[len] = '\0';
			if (type == OPTION_STRING_HOST && !good_hostname(dest)) {
				safe_strncpy(dest, "bad", len);
			}
			return ret;
		case OPTION_STATIC_ROUTES: {
			/* Option binary format:
			 * mask [one byte, 0..32]
			 * ip [big endian, 0..4 bytes depending on mask]
			 * router [big endian, 4 bytes]
			 * may be repeated
			 *
			 * We convert it to a string "IP/MASK ROUTER IP2/MASK2 ROUTER2"
			 */
			const char *pfx = "";
			while (len >= 1 + 4) { /* mask + 0-byte ip + router */
				uint32_t nip;
				uint8_t *p;
				unsigned mask;
				int bytes;

				mask = *option++;
				if (mask > 32) {
					break;
				}
				len--;

				nip = 0;
				p = (void *) &nip;
				bytes = (mask + 7) / 8; /* 0 -> 0, 1..8 -> 1, 9..16 -> 2 etc */
				while (--bytes >= 0) {
					*p++ = *option++;
					len--;
				}
				if (len < 4) {
					break;
				}
				if ( 0 != mask)
				{
					/* print ip/mask */
					dest += sprint_nip(dest, pfx, (void *) &nip);
					pfx = " ";
					dest += sprintf(dest, "/%u ", mask);
					/* print router */
					dest += sprint_nip(dest, "", option);
				}
				option += 4;
				len -= 4;
			}

			return ret;
		}
		case OPTION_6RD:
			/* Option binary format (see RFC 5969):
			 *  0                   1                   2                   3
			 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * |  OPTION_6RD   | option-length |  IPv4MaskLen  |  6rdPrefixLen |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * |                           6rdPrefix                           |
			 * ...                        (16 octets)                        ...
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * ...                   6rdBRIPv4Address(es)                    ...
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * We convert it to a string
			 * "IPv4MaskLen 6rdPrefixLen 6rdPrefix 6rdBRIPv4Address..."
			 *
			 * Sanity check: ensure that our length is at least 22 bytes, that
			 * IPv4MaskLen <= 32,
			 * 6rdPrefixLen <= 128,
			 * 6rdPrefixLen + (32 - IPv4MaskLen) <= 128
			 * (2nd condition need no check - it follows from 1st and 3rd).
			 * Else, return envvar with empty value ("optname=")
			 */
			if (len >= (1 + 1 + 16 + 4)
			    && option[0] <= 32
			    && (option[1] + 32 - option[0]) <= 128
					) {
				/* IPv4MaskLen */
				dest += sprintf(dest, "%u ", *option++);
				/* 6rdPrefixLen */
				dest += sprintf(dest, "%u ", *option++);
				/* 6rdPrefix */
				dest += sprint_nip6(dest, /* "", */ option);
				option += 16;
				len -= 1 + 1 + 16 + 4;
				/* "+ 4" above corresponds to the length of IPv4 addr
				 * we consume in the loop below */
				while (1) {
					/* 6rdBRIPv4Address(es) */
					dest += sprint_nip(dest, " ", option);
					option += 4;
					len -= 4; /* do we have yet another 4+ bytes? */
					if (len < 0) {
						break;
					} /* no */
				}
			}

			return ret;
#if ENABLE_FEATURE_UDHCP_RFC3397
			case OPTION_DNS_STRING:
				/* unpack option into dest; use ret for prefix (i.e., "optname=") */
				dest = dname_dec(option, len, ret);
				if (dest) {
					free(ret);
					return dest;
				}
				/* error. return "optname=" string */
				return ret;
			case OPTION_SIP_SERVERS:
				/* Option binary format:
				 * type: byte
				 * type=0: domain names, dns-compressed
				 * type=1: IP addrs
				 */
				option++;
				len--;
				if (option[-1] == 0) {
					dest = dname_dec(option, len, ret);
					if (dest) {
						free(ret);
						return dest;
					}
				} else
				if (option[-1] == 1) {
					const char *pfx = "";
					while (1) {
						len -= 4;
						if (len < 0)
							break;
						dest += sprint_nip(dest, pfx, option);
						pfx = " ";
						option += 4;
					}
				}
				return ret;
#endif
		} /* switch */

		/* If we are here, try to format any remaining data
		 * in the option as another, similarly-formatted option
		 */
		option += optlen;
		len -= optlen;
// TODO: it can be a list only if (optflag->flags & OPTION_LIST).
// Should we bail out/warn if we see multi-ip option which is
// not allowed to be such (for example, DHCP_BROADCAST)? -
		if (len < optlen /* || !(optflag->flags & OPTION_LIST) */) {
			break;
		}
		*dest++ = ' ';
		*dest = '\0';
	} /* while */

	return ret;
}

/* put all the parameters into the environment */
static char **fill_envp(struct dhcp_packet *packet)
{
	int envc;
	int i;
	char **envp, **curr;
	const char *opt_name;
	uint8_t *temp;
	uint8_t overload = 0;

#define BITMAP unsigned
#define BBITS (sizeof(BITMAP) * 8)
#define BMASK(i) (1 << (i & (sizeof(BITMAP) * 8 - 1)))
#define FOUND_OPTS(i) (found_opts[(unsigned)i / BBITS])
	BITMAP found_opts[256 / BBITS];

	memset(found_opts, 0, sizeof(found_opts));

	/* We need 6 elements for:
	 * "interface=IFACE"
	 * "ip=N.N.N.N" from packet->yiaddr
	 * "siaddr=IP" from packet->siaddr_nip (unless 0)
	 * "boot_file=FILE" from packet->file (unless overloaded)
	 * "sname=SERVER_HOSTNAME" from packet->sname (unless overloaded)
	 * terminating NULL
	 */
	envc = 6;
	/* +1 element for each option, +2 for subnet option: */
	if (packet) {
		/* note: do not search for "pad" (0) and "end" (255) options */
//TODO: change logic to scan packet _once_
		for (i = 1; i < 255; i++) {
			temp = udhcp_get_option(packet, i);
			if (temp) {
				if (i == DHCP_OPTION_OVERLOAD) {
					overload = *temp;
				}
				else if (i == DHCP_SUBNET) {
					envc++;
				} /* for $mask */
				envc++;
				/*if (i != DHCP_MESSAGE_TYPE)*/
				FOUND_OPTS(i) |= BMASK(i);
			}
		}
	}
	curr = envp = xzalloc(sizeof(envp[0]) * envc);

	*curr = xasprintf("interface=%s", client_config.interface);
	putenv(*curr++);

	if (!packet) {
		return envp;
	}

	/* Export BOOTP fields. Fields we don't (yet?) export:
	 * uint8_t op;      // always BOOTREPLY
	 * uint8_t htype;   // hardware address type. 1 = 10mb ethernet
	 * uint8_t hlen;    // hardware address length
	 * uint8_t hops;    // used by relay agents only
	 * uint32_t xid;
	 * uint16_t secs;   // elapsed since client began acquisition/renewal
	 * uint16_t flags;  // only one flag so far: bcast. Never set by server
	 * uint32_t ciaddr; // client IP (usually == yiaddr. can it be different
	 *                  // if during renew server wants to give us differn IP?)
	 * uint32_t gateway_nip; // relay agent IP address
	 * uint8_t chaddr[16]; // link-layer client hardware address (MAC)
	 * TODO: export gateway_nip as $giaddr?
	 */
	/* Most important one: yiaddr as $ip */
	*curr = xmalloc(sizeof("ip=255.255.255.255"));
	sprint_nip(*curr, "ip=", (uint8_t *) &packet->yiaddr);
	putenv(*curr++);
	if (packet->siaddr_nip) {
		/* IP address of next server to use in bootstrap */
		*curr = xmalloc(sizeof("siaddr=255.255.255.255"));
		sprint_nip(*curr, "siaddr=", (uint8_t *) &packet->siaddr_nip);
		putenv(*curr++);
	}
	if (!(overload & FILE_FIELD) && packet->file[0]) {
		/* watch out for invalid packets */
		*curr = xasprintf("boot_file=%."DHCP_PKT_FILE_LEN_STR"s", packet->file);
		putenv(*curr++);
	}
	if (!(overload & SNAME_FIELD) && packet->sname[0]) {
		/* watch out for invalid packets */
		*curr = xasprintf("sname=%."DHCP_PKT_SNAME_LEN_STR"s", packet->sname);
		putenv(*curr++);
	}

	/* Export known DHCP options */
	opt_name = dhcp_option_strings;
	i = 0;
	while (*opt_name) {
		uint8_t code = dhcp_optflags[i].code;
		BITMAP *found_ptr = &FOUND_OPTS(code);
		BITMAP found_mask = BMASK(code);
		if (!(*found_ptr & found_mask)) {
			goto next;
		}
		*found_ptr &= ~found_mask; /* leave only unknown options */
		temp = udhcp_get_option(packet, code);
		*curr = xmalloc_optname_optval(temp, &dhcp_optflags[i], opt_name);
		putenv(*curr++);
		if (code == DHCP_SUBNET) {
			/* Subnet option: make things like "$ip/$mask" possible */
			uint32_t subnet;
			move_from_unaligned32(subnet, temp);
			*curr = xasprintf("mask=%u", mton(subnet));
			putenv(*curr++);
		}
next:
		opt_name += strlen(opt_name) + 1;
		i++;
	}
	/* Export unknown options */
	for (i = 0; i < 256;) {
		BITMAP bitmap = FOUND_OPTS(i);
		if (!bitmap) {
			i += BBITS;
			continue;
		}
		if (bitmap & BMASK(i)) {
			unsigned len, ofs;

			temp = udhcp_get_option(packet, i);
			/* udhcp_get_option returns ptr to data portion,
			 * need to go back to get len
			 */
			len = temp[-OPT_DATA + OPT_LEN];
			*curr = xmalloc(sizeof("optNNN=") + 1 + len * 2);
			ofs = sprintf(*curr, "opt%u=", i);
			*bin2hex(*curr + ofs, (void *) temp, len) = '\0';
			putenv(*curr++);
		}
		i++;
	}

	return envp;
}

/* Call a script with a par file and env vars */
static void udhcp_run_script(struct dhcp_packet *packet, const char *name)
{
	char **envp, **curr;
	char *argv[3];

	if (client_config.script == NULL) {
		return;
	}

	/* add by wanghao  */
	if (strncmp(client_config.interface, "br-lan", strlen("br-lan")) == 0 ||
	    strncmp(client_config.interface, "br-guest", strlen("br-guest")) == 0) {
		//smartip will handle this.
		return;
	}
	/* add end  */

	envp = fill_envp(packet);

	/* call script */
	log1("Executing %s %s", client_config.script, name);
	argv[0] = (char *) client_config.script;
	argv[1] = (char *) name;
	argv[2] = NULL;
	spawn_and_wait(argv);

	for (curr = envp; *curr; curr++) {
		log2(" %s", *curr);
		bb_unsetenv_and_free(*curr);
	}
	free(envp);
}


/*** Sending/receiving packets ***/

static ALWAYS_INLINE uint32_t random_xid(void)
{
	return rand();
}

/* Initialize the packet with the proper defaults */
static void init_packet(struct dhcp_packet *packet, char type)
{
	uint16_t secs;

	/* Fill in: op, htype, hlen, cookie fields; message type option: */
	udhcp_init_header(packet, type);

	packet->xid = random_xid();

	client_config.last_secs = monotonic_sec();
	if (client_config.first_secs == 0)
		client_config.first_secs = client_config.last_secs;
	secs = client_config.last_secs - client_config.first_secs;
	packet->secs = htons(secs);

	memcpy(packet->chaddr, client_config.client_mac, 6);
	if (client_config.clientid) {
		udhcp_add_binary_option(packet, client_config.clientid);
	}
}

static void add_client_options(struct dhcp_packet *packet)
{
	int i, end, len;

	udhcp_add_simple_option(packet, DHCP_MAX_SIZE, htons(IP_UDP_DHCP_SIZE));

	/* Add a "param req" option with the list of options we'd like to have
	 * from stubborn DHCP servers. Pull the data from the struct in common.c.
	 * No bounds checking because it goes towards the head of the packet. */
	end = udhcp_end_option(packet->options);
	len = 0;
	for (i = 1; i < DHCP_END; i++) {
		if (client_config.opt_mask[i >> 3] & (1 << (i & 7))) {
			packet->options[end + OPT_DATA + len] = i;
			len++;
		}
	}
	if (len) {
		packet->options[end + OPT_CODE] = DHCP_PARAM_REQ;
		packet->options[end + OPT_LEN] = len;
		packet->options[end + OPT_DATA + len] = DHCP_END;
	}

	if (client_config.vendorclass) {
		udhcp_add_binary_option(packet, client_config.vendorclass);
	}
	if (client_config.hostname) {
		udhcp_add_binary_option(packet, client_config.hostname);
	}
	if (client_config.fqdn) {
		udhcp_add_binary_option(packet, client_config.fqdn);
	}

	/* Request broadcast replies if we have no IP addr */
	if ((option_mask32 & OPT_B) && packet->ciaddr == 0) {
		packet->flags |= htons(BROADCAST_FLAG);
	}

	/* Add -x options if any */
	{
		struct option_set *curr = client_config.options;
		while (curr) {
			udhcp_add_binary_option(packet, curr->data);
			curr = curr->next;
		}
//		if (client_config.sname)
//			strncpy((char*)packet->sname, client_config.sname, sizeof(packet->sname) - 1);
//		if (client_config.boot_file)
//			strncpy((char*)packet->file, client_config.boot_file, sizeof(packet->file) - 1);
	}

	// This will be needed if we remove -V VENDOR_STR in favor of
	// -x vendor:VENDOR_STR
	//if (!udhcp_find_option(packet.options, DHCP_VENDOR))
	//	/* not set, set the default vendor ID */
	//	...add (DHCP_VENDOR, "udhcp "BB_VER) opt...
}

/* RFC 2131
 * 4.4.4 Use of broadcast and unicast
 *
 * The DHCP client broadcasts DHCPDISCOVER, DHCPREQUEST and DHCPINFORM
 * messages, unless the client knows the address of a DHCP server.
 * The client unicasts DHCPRELEASE messages to the server. Because
 * the client is declining the use of the IP address supplied by the server,
 * the client broadcasts DHCPDECLINE messages.
 *
 * When the DHCP client knows the address of a DHCP server, in either
 * INIT or REBOOTING state, the client may use that address
 * in the DHCPDISCOVER or DHCPREQUEST rather than the IP broadcast address.
 * The client may also use unicast to send DHCPINFORM messages
 * to a known DHCP server. If the client receives no response to DHCP
 * messages sent to the IP address of a known DHCP server, the DHCP
 * client reverts to using the IP broadcast address.
 */

static int raw_bcast_from_client_config_ifindex(struct dhcp_packet *packet, uint32_t src_nip)
{
	return udhcp_send_raw_packet(packet,
			/*src*/ src_nip, CLIENT_PORT,
			/*dst*/ INADDR_BROADCAST, SERVER_PORT, MAC_BCAST_ADDR,
			                     client_config.ifindex);
}

static int bcast_or_ucast(struct dhcp_packet *packet, uint32_t ciaddr, uint32_t server)
{
	if (server) {
		return udhcp_send_kernel_packet(packet,
		                                ciaddr, CLIENT_PORT,
		                                server, SERVER_PORT);
	}
	return raw_bcast_from_client_config_ifindex(packet, ciaddr);
}

/* Broadcast a DHCP discover packet to the network, with an optionally requested IP */
/* NOINLINE: limit stack usage in caller */
static NOINLINE int send_discover(uint32_t xid, uint32_t requested)
{
	struct dhcp_packet packet;
	static int msgs = 0;

	/* Fill in: op, htype, hlen, cookie, chaddr fields,
	 * random xid field (we override it below),
	 * client-id option (unless -C), message type option:
	 */
	init_packet(&packet, DHCPDISCOVER);

	packet.xid = xid;
	if (requested) {
		udhcp_add_simple_option(&packet, DHCP_REQUESTED_IP, requested);
	}

	/* Add options: maxsize,
	 * optionally: hostname, fqdn, vendorclass,
	 * "param req" option according to -O, options specified with -x
	 */
	add_client_options(&packet);

	if (msgs++ < 3) {
		bb_info_msg("Sending discover...");
	}
	return raw_bcast_from_client_config_ifindex(&packet, INADDR_ANY);
}

/* Broadcast a DHCP request message */
/* RFC 2131 3.1 paragraph 3:
 * "The client _broadcasts_ a DHCPREQUEST message..."
 */
/* NOINLINE: limit stack usage in caller */
static NOINLINE int send_select(uint32_t xid, uint32_t server, uint32_t requested)
{
	struct dhcp_packet packet;
	struct in_addr addr;

/*
 * RFC 2131 4.3.2 DHCPREQUEST message
 * ...
 * If the DHCPREQUEST message contains a 'server identifier'
 * option, the message is in response to a DHCPOFFER message.
 * Otherwise, the message is a request to verify or extend an
 * existing lease. If the client uses a 'client identifier'
 * in a DHCPREQUEST message, it MUST use that same 'client identifier'
 * in all subsequent messages. If the client included a list
 * of requested parameters in a DHCPDISCOVER message, it MUST
 * include that list in all subsequent messages.
 */
	/* Fill in: op, htype, hlen, cookie, chaddr fields,
	 * random xid field (we override it below),
	 * client-id option (unless -C), message type option:
	 */
	init_packet(&packet, DHCPREQUEST);

	packet.xid = xid;
	udhcp_add_simple_option(&packet, DHCP_REQUESTED_IP, requested);

	udhcp_add_simple_option(&packet, DHCP_SERVER_ID, server);

	/* Add options: maxsize,
	 * optionally: hostname, fqdn, vendorclass,
	 * "param req" option according to -O, and options specified with -x
	 */
	add_client_options(&packet);

	addr.s_addr = requested;
	bb_info_msg("Sending select for %s...", inet_ntoa(addr));
	return raw_bcast_from_client_config_ifindex(&packet, INADDR_ANY);
}

/* Unicast or broadcast a DHCP renew message */
/* NOINLINE: limit stack usage in caller */
static NOINLINE int send_renew(uint32_t xid, uint32_t server, uint32_t ciaddr)
{
	struct dhcp_packet packet;

/*
 * RFC 2131 4.3.2 DHCPREQUEST message
 * ...
 * DHCPREQUEST generated during RENEWING state:
 *
 * 'server identifier' MUST NOT be filled in, 'requested IP address'
 * option MUST NOT be filled in, 'ciaddr' MUST be filled in with
 * client's IP address. In this situation, the client is completely
 * configured, and is trying to extend its lease. This message will
 * be unicast, so no relay agents will be involved in its
 * transmission.  Because 'giaddr' is therefore not filled in, the
 * DHCP server will trust the value in 'ciaddr', and use it when
 * replying to the client.
 */
	/* Fill in: op, htype, hlen, cookie, chaddr fields,
	 * random xid field (we override it below),
	 * client-id option (unless -C), message type option:
	 */
	init_packet(&packet, DHCPREQUEST);

	packet.xid = xid;
	packet.ciaddr = ciaddr;

	/* Add options: maxsize,
	 * optionally: hostname, fqdn, vendorclass,
	 * "param req" option according to -O, and options specified with -x
	 */
	add_client_options(&packet);

	bb_info_msg("Sending renew...");
	return bcast_or_ucast(&packet, ciaddr, server);
}

#if ENABLE_FEATURE_UDHCPC_ARPING
/* Broadcast a DHCP decline message */
/* NOINLINE: limit stack usage in caller */
static NOINLINE int send_decline(/*uint32_t xid,*/ uint32_t server, uint32_t requested)
{
	struct dhcp_packet packet;

	/* Fill in: op, htype, hlen, cookie, chaddr, random xid fields,
	 * client-id option (unless -C), message type option:
	 */
	init_packet(&packet, DHCPDECLINE);

#if 0
	/* RFC 2131 says DHCPDECLINE's xid is randomly selected by client,
	 * but in case the server is buggy and wants DHCPDECLINE's xid
	 * to match the xid which started entire handshake,
	 * we use the same xid we used in initial DHCPDISCOVER:
	 */
	packet.xid = xid;
#endif
	/* DHCPDECLINE uses "requested ip", not ciaddr, to store offered IP */
	udhcp_add_simple_option(&packet, DHCP_REQUESTED_IP, requested);

	udhcp_add_simple_option(&packet, DHCP_SERVER_ID, server);

	bb_info_msg("Sending decline...");
	return raw_bcast_from_client_config_ifindex(&packet, INADDR_ANY);
}
#endif

/* Unicast a DHCP release message */
static int send_release(uint32_t server, uint32_t ciaddr)
{
	struct dhcp_packet packet;

	/* Fill in: op, htype, hlen, cookie, chaddr, random xid fields,
	 * client-id option (unless -C), message type option:
	 */
	init_packet(&packet, DHCPRELEASE);

	/* DHCPRELEASE uses ciaddr, not "requested ip", to store IP being released */
	packet.ciaddr = ciaddr;

	udhcp_add_simple_option(&packet, DHCP_SERVER_ID, server);

	bb_info_msg("Sending release...");
	/* Note: normally we unicast here since "server" is not zero.
	 * However, there _are_ people who run "address-less" DHCP servers,
	 * and reportedly ISC dhcp client and Windows allow that.
	 */
	return bcast_or_ucast(&packet, ciaddr, server);
}

/* Returns -1 on errors that are fatal for the socket, -2 for those that aren't */
/* NOINLINE: limit stack usage in caller */
static NOINLINE int udhcp_recv_raw_packet(struct dhcp_packet *dhcp_pkt, int fd)
{
	int bytes;
	struct ip_udp_dhcp_packet packet;
	uint16_t check;
	unsigned char cmsgbuf[CMSG_LEN(sizeof(struct tpacket_auxdata))];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;

	/* used to use just safe_read(fd, &packet, sizeof(packet))
	 * but we need to check for TP_STATUS_CSUMNOTREADY :(
	 */
	iov.iov_base = &packet;
	iov.iov_len = sizeof(packet);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	for (;;) {
		bytes = recvmsg(fd, &msg, 0);
		if (bytes < 0) {
			if (errno == EINTR) {
				continue;
			}
			log1("Packet read error, ignoring");
			/* NB: possible down interface, etc. Caller should pause. */
			return bytes; /* returns -1 */
		}
		break;
	}

	if (bytes < (int) (sizeof(packet.ip) + sizeof(packet.udp))) {
		log1("Packet is too short, ignoring");
		return -2;
	}

	if (bytes < ntohs(packet.ip.tot_len)) {
		/* packet is bigger than sizeof(packet), we did partial read */
		log1("Oversized packet, ignoring");
		return -2;
	}

	/* ignore any extra garbage bytes */
	bytes = ntohs(packet.ip.tot_len);

	/* make sure its the right packet for us, and that it passes sanity checks */
	if (packet.ip.protocol != IPPROTO_UDP
	    || packet.ip.version != IPVERSION
	    || packet.ip.ihl != (sizeof(packet.ip) >> 2)
	    || packet.udp.dest != htons(CLIENT_PORT)
	    /* || bytes > (int) sizeof(packet) - can't happen */
	    || ntohs(packet.udp.len) != (uint16_t) (bytes - sizeof(packet.ip))
			) {
		log1("Unrelated/bogus packet, ignoring");
		return -2;
	}

	/* verify IP checksum */
	check = packet.ip.check;
	packet.ip.check = 0;
	if (check != inet_cksum((uint16_t *) &packet.ip, sizeof(packet.ip))) {
		log1("Bad IP header checksum, ignoring");
		return -2;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_PACKET
		    && cmsg->cmsg_type == PACKET_AUXDATA
				) {
			/* some VMs don't checksum UDP and TCP data
			 * they send to the same physical machine,
			 * here we detect this case:
			 */
			struct tpacket_auxdata *aux = (void *) CMSG_DATA(cmsg);
			if (aux->tp_status & TP_STATUS_CSUMNOTREADY) {
				goto skip_udp_sum_check;
			}
		}
	}

	/* verify UDP checksum. IP header has to be modified for this */
	memset(&packet.ip, 0, offsetof(struct iphdr, protocol));
	/* ip.xx fields which are not memset: protocol, check, saddr, daddr */
	packet.ip.tot_len = packet.udp.len; /* yes, this is needed */
	check = packet.udp.check;
	packet.udp.check = 0;
	if (check && check != inet_cksum((uint16_t *) &packet, bytes)) {
		log1("Packet with bad UDP checksum received, ignoring");
		return -2;
	}
skip_udp_sum_check:

	if (packet.data.cookie != htonl(DHCP_MAGIC)) {
		bb_info_msg("Packet with bad magic, ignoring");
		return -2;
	}

	/*
	 * check if the packet is from expected servers
	 */
	if (client_config.mode[0] == 'i' || client_config.mode[0] == 'e') {
		void *sname =  udhcp_get_option(&packet.data, DHCP_HOST_NAME);
		const char *mac = deco_get_mac_from_sname(sname);

		if (mac == NULL) {
			if (client_config.mode[0] == 'i') {
				bb_info_msg("Packet UNEXPECTEDLY NOT from group devices, ignoring");
				return -2;
			}
		}
		else {
			struct kvlist *macs = deco_get_mac_list();
			void *res = kvlist_get(macs, mac);
			if (res == NULL) {
				if (client_config.mode[0] == 'i') {
					bb_info_msg("Packet UNEXPECTEDLY NOT from group devices, ignoring");
					return -2;
				}
			}
			else {
				if (client_config.mode[0] == 'e') {
					bb_info_msg("Packet UNEXPECTEDLY from group devices, ignoring");
					return -2;
				}
			}
		}
	}

	log1("Received a packet");
	udhcp_dump_packet(&packet.data);

	bytes -= sizeof(packet.ip) + sizeof(packet.udp);
	memcpy(dhcp_pkt, &packet.data, bytes);
	return bytes;
}


/*** Main ***/

static int sockfd = -1;

#define LISTEN_NONE   0
#define LISTEN_KERNEL 1
#define LISTEN_RAW    2
static smallint listen_mode;

/* initial state: (re)start DHCP negotiation */
#define INIT_SELECTING  0
/* discover was sent, DHCPOFFER reply received */
#define REQUESTING      1
/* select/renew was sent, DHCPACK reply received */
#define BOUND           2
/* half of lease passed, want to renew it by sending unicast renew requests */
#define RENEWING        3
/* renew requests were not answered, lease is almost over, send broadcast renew */
#define REBINDING       4
/* manually requested renew (SIGUSR1) */
#define RENEW_REQUESTED 5
/* release, possibly manually requested (SIGUSR2) */
#define RELEASED        6
static smallint state;

#if defined CONFIG_PACKAGE_smartip
#define DETECT_SUCCESS 0
#define DETECT_FAIL 1
#endif

static int udhcp_raw_socket(int ifindex)
{
	int fd;
	struct sockaddr_ll sock;

	/*
	 * Comment:
	 *
	 *	I've selected not to see LL header, so BPF doesn't see it, too.
	 *	The filter may also pass non-IP and non-ARP packets, but we do
	 *	a more complete check when receiving the message in userspace.
	 *
	 * and filter shamelessly stolen from:
	 *
	 *	http://www.flamewarmaster.de/software/dhcpclient/
	 *
	 * There are a few other interesting ideas on that page (look under
	 * "Motivation").  Use of netlink events is most interesting.  Think
	 * of various network servers listening for events and reconfiguring.
	 * That would obsolete sending HUP signals and/or make use of restarts.
	 *
	 * Copyright: 2006, 2007 Stefan Rompf <sux@loplof.de>.
	 * License: GPL v2.
	 *
	 * TODO: make conditional?
	 */
	static const struct sock_filter filter_instr[] = {
			/* load 9th byte (protocol) */
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
			/* jump to L1 if it is IPPROTO_UDP, else to L4 */
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 6),
			/* L1: load halfword from offset 6 (flags and frag offset) */
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 6),
			/* jump to L4 if any bits in frag offset field are set, else to L2 */
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, 4, 0),
			/* L2: skip IP header (load index reg with header len) */
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
			/* load udp destination port from halfword[header_len + 2] */
			BPF_STMT(BPF_LD | BPF_H | BPF_IND, 2),
			/* jump to L3 if udp dport is CLIENT_PORT, else to L4 */
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 68, 0, 1),
			/* L3: accept packet */
			BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
			/* L4: discard packet */
			BPF_STMT(BPF_RET | BPF_K, 0),
	};
	static const struct sock_fprog filter_prog = {
			.len = sizeof(filter_instr) / sizeof(filter_instr[0]),
			/* casting const away: */
			.filter = (struct sock_filter *) filter_instr,
	};

	log1("Opening raw socket on ifindex %d", ifindex); //log2?

	fd = xsocket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	log1("Got raw socket fd"); //log2?


	if (!client_config.unbound) {
		sock.sll_family = AF_PACKET;
		sock.sll_protocol = htons(ETH_P_IP);
		sock.sll_ifindex = ifindex;
		xbind(fd, (struct sockaddr *) &sock, sizeof(sock));
	}

	if (CLIENT_PORT == 68) {
		/* Use only if standard port is in use */
		/* Ignoring error (kernel may lack support for this) */
		if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog,
		               sizeof(filter_prog)) >= 0)
			log1("Attached filter to raw socket fd"); // log?
	}

	if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA,
	               &const_int_1, sizeof(int)) < 0
			) {
		if (errno != ENOPROTOOPT)
			log1("Can't set PACKET_AUXDATA on raw socket");
	}

	log1("Created raw socket");

	return fd;
}

static void change_listen_mode(int new_mode)
{
	log1("Entering listen mode: %s",
	     new_mode != LISTEN_NONE
	     ? (new_mode == LISTEN_KERNEL ? "kernel" : "raw")
	     : "none"
	);

	listen_mode = new_mode;
	if (sockfd >= 0) {
		close(sockfd);
		sockfd = -1;
	}
	if (new_mode == LISTEN_KERNEL) {
		sockfd = udhcp_listen_socket(/*INADDR_ANY,*/ CLIENT_PORT, client_config.interface);
	}
	else if (new_mode != LISTEN_NONE) {
		sockfd = udhcp_raw_socket(client_config.ifindex);
	}
	/* else LISTEN_NONE: sockfd stays closed */
}

/* Called only on SIGUSR1 */
static void perform_renew(void)
{
	bb_info_msg("Performing a DHCP renew");
	switch (state) {
	case BOUND:
		change_listen_mode(LISTEN_KERNEL);
	case RENEWING:
	case REBINDING:
		state = RENEW_REQUESTED;
		break;
	case RENEW_REQUESTED: /* impatient are we? fine, square 1 */
	case REQUESTING:
	case RELEASED:
		change_listen_mode(LISTEN_RAW);
		state = INIT_SELECTING;
		break;
	case INIT_SELECTING:
		break;
	}
}

static void perform_release(uint32_t server_addr, uint32_t requested_ip)
{
	char buffer[sizeof("255.255.255.255")];
	struct in_addr temp_addr;

	/* send release packet */
	if (state == BOUND || state == RENEWING || state == REBINDING) {
		temp_addr.s_addr = server_addr;
		strcpy(buffer, inet_ntoa(temp_addr));
		temp_addr.s_addr = requested_ip;
		bb_info_msg("Unicasting a release of %s to %s",
		            inet_ntoa(temp_addr), buffer);
		send_release(server_addr, requested_ip); /* unicast */
		udhcp_run_script(NULL, "deconfig");
	}
	bb_info_msg("Entering released state");

	change_listen_mode(LISTEN_NONE);
	state = RELEASED;
}

static uint8_t *alloc_dhcp_option(int code, const char *str, int extra)
{
	uint8_t *storage;
	int len = strnlen(str, 255);
	storage = xzalloc(len + extra + OPT_DATA);
	storage[OPT_CODE] = code;
	storage[OPT_LEN] = len + extra;
	memcpy(storage + extra + OPT_DATA, str, len);
	return storage;
}

#if BB_MMU

static void client_background(void)
{
	bb_daemonize(0);
	logmode &= ~LOGMODE_STDIO;
	/* rewrite pidfile, as our pid is different now */
	write_pidfile(client_config.pidfile);
}

#endif

#if defined CONFIG_PACKAGE_smartip
#define MAX_DNS_NUM             (3)
#if (CONFIG_IBUS_METHOD == IBUS_USE_UBUS)
static int
udhcpc_send_event(uint16_t detect_result, const char *client_if, struct dhcp_packet *packet)
{
	uint32_t dns[MAX_DNS_NUM];
	uint32_t dns_num, i;
	uint32_t *temp;
	static struct blob_buf blob;
	char *jtok = NULL;
	char cmd[256];

    /* init dns info */
	for (i = 0; i < MAX_DNS_NUM; i++) {
		dns[i] = 0;
	}

	blob_buf_init(&blob, 0);

	blobmsg_add_u16(&blob, UBUS_SMARTIP_ACTION, IBUS_SMARTIP_ACTION_DHCP);
	blobmsg_add_u16(&blob, UBUS_SMARTIP_STATUS, detect_result);

	if (NULL != client_if) {
		blobmsg_add_string(&blob, UBUS_SMARTIP_DHCPC_IFACE, client_if);
	}

	if (NULL != packet) {
		blobmsg_add_u32(&blob, UBUS_SMARTIP_DHCPC_IP, ntohl(packet->yiaddr));

		temp = (uint32_t *) udhcp_get_option(packet, DHCP_SUBNET);
		if (temp) {
			blobmsg_add_u32(&blob, UBUS_SMARTIP_DHCPC_MASK, ntohl(*temp));
		}

		temp = (uint32_t *) udhcp_get_option(packet, DHCP_ROUTER);
		if (temp) {
			blobmsg_add_u32(&blob, UBUS_SMARTIP_DHCPC_GW, ntohl(*temp));
		}

		temp = (uint32_t *) udhcp_get_option(packet, DHCP_DNS_SERVER);
		if (temp) {
			dns_num = (*((uint8_t *) temp - 1)) >> 2;
			dns_num = dns_num > MAX_DNS_NUM ? MAX_DNS_NUM : dns_num;
			for (i = 0; i < dns_num; i++) {
				dns[i] = ntohl(*(temp + i));
			}
		}

		blobmsg_add_u32(&blob, UBUS_SMARTIP_DHCPC_DNS1, dns[0]);
		blobmsg_add_u32(&blob, UBUS_SMARTIP_DHCPC_DNS2, dns[1]);
		blobmsg_add_u32(&blob, UBUS_SMARTIP_DHCPC_DNS3, dns[2]);

		blobmsg_add_u32(&blob, UBUS_SMARTIP_DHCPC_XID, packet->xid);
	}

	jtok = blobmsg_format_json(blob.head, true);
	if (NULL == jtok) {
		return 0;
	}

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "ubus send %s '%s'", UBUS_OBJ_SMARTIP, jtok);
	system(cmd);

	free(jtok);
	return 0;
}

#endif /* CONFIG_IBUS_METHOD == IBUS_USE_UBUS */
#endif /* CONFIG_PACKAGE_smartip */

/* add by wanghao  */
struct routeEntry {
	char dstStr[16];
	char netmaskStr[16];
};

struct routeEntry staticRoute[64];
unsigned char routeIndex = 0;

void printDebugInfo(const char *fmt, ...)
{
#if 0
	char buff[170];
	char cmd[170];
	va_list args;

	va_start(args, fmt);
	vsprintf(buff, fmt, args);
	va_end(args);

	sprintf(cmd, "echo %s > /dev/console", buff);
	system(cmd);
#endif
}

int udhcp_addrNumToStr(unsigned int numAddr, char *pStrAddr)
{
	int a = 0, b = 0, c = 0, d = 0;

	if (pStrAddr == NULL) {
		return 0;
	}

	a = ((unsigned char *) &numAddr)[0];
	b = ((unsigned char *) &numAddr)[1];
	c = ((unsigned char *) &numAddr)[2];
	d = ((unsigned char *) &numAddr)[3];

	if (a > 255 || b > 255 || c > 255 || d > 255 ||
	    a < 0 || b < 0 || c < 0 || d < 0) {
		return -1;
	}

	sprintf(pStrAddr, "%d.%d.%d.%d", a, b, c, d);

	return 0;
}

void handleRouteOption(struct dhcp_packet *packet, char *pWanIf)
{
	int len = 0;
	uint8_t *pData = NULL;
	int pos = 0;
	uint32_t dst = 0, router = 0, netmask = 0;
	char dstStr[16] = {0}, routerStr[16] = {0}, netmaskStr[16] = {0};
	char cmd[256] = {0};
	char sleepd = 0;

	/* clear static route entry before add  */
	uint8_t index = 0;
	for (index = 0; index < routeIndex; index++) {
		sprintf(cmd, "route del -net %s netmask %s", staticRoute[index].dstStr,
		        staticRoute[index].netmaskStr);
		system(cmd);
	}
	routeIndex = 0;

	/* option 33 */
	if (pData = udhcp_get_option(packet, DHCP_ROUTES)) {
		if (!sleepd) {
			sleepd = 1;
			sleep(2);
		}

		len = *(pData - 1);
		while (pos + 7 < len) /* at least 8 len */
		{
			dst = *(int *) (pData + pos);
			udhcp_addrNumToStr(dst, dstStr);
			pos += 4;
			udhcp_addrNumToStr(*(int *) (pData + pos), routerStr);
			pos += 4;
			netmask = 0xffffffff;
			dst = ntohl(dst);
			while ((dst != 0) && ((dst & 0xff) == 0)) {
				netmask = netmask << 8;
				dst = dst >> 8;
			}
			udhcp_addrNumToStr(htonl(netmask), netmaskStr);
			dst = 0;
			strncpy(staticRoute[routeIndex].dstStr, dstStr, 16);
			strncpy(staticRoute[routeIndex].netmaskStr, netmaskStr, 16);
			routeIndex++;
			sprintf(cmd, "route add -net %s netmask %s gw %s", dstStr, netmaskStr, routerStr);
			printDebugInfo("dhcp option 33: %s", cmd);
			system(cmd);
		}
	}

	/* option 121 */
	pos = 0;
	if (pData = udhcp_get_option(packet, DHCP_STATIC_ROUTES)) {
		if (!sleepd) {
			sleepd = 1;
			sleep(2);
		}
		len = *(pData - 1);
		while (pos + 4 < len) /* at least 5 len */
		{
			if (0 == *(pData + pos)) /* default route */
			{
				pos += 1;
				udhcp_addrNumToStr(*(int *) (pData + pos), routerStr);
				pos += 4;
				sprintf(cmd, "route add default gw %s dev %s", routerStr, pWanIf);
				printDebugInfo("dhcp option 121 default route: %s", cmd);
				system(cmd);
			}
			else {
				/* netmask */
				int netLen = *(pData + pos);
				netmask = 0xffffffff;
				netmask = (netmask << (32 - netLen));
				udhcp_addrNumToStr(htonl(netmask), netmaskStr);
				pos += 1;    /* dst */
				memcpy(&dst, pData + pos, (netLen + 7) / 8);
				udhcp_addrNumToStr(dst, dstStr);
				pos += ((netLen + 7) / 8);    /* router */
				udhcp_addrNumToStr(*(int *) (pData + pos), routerStr);
				pos += 4;
				strncpy(staticRoute[routeIndex].dstStr, dstStr, 16);
				strncpy(staticRoute[routeIndex].netmaskStr, netmaskStr, 16);
				routeIndex++;
				sprintf(cmd, "route add -net %s netmask %s gw %s", dstStr, netmaskStr, routerStr);
				printDebugInfo("dhcp option 121: %s", cmd);
				system(cmd);
			}
			dst = 0;
		}
	}

	/* option 249 */
	pos = 0;
	if (pData = udhcp_get_option(packet, DHCP_MS_STATIC_ROUTES)) {
		if (!sleepd) {
			sleepd = 1;
			sleep(2);
		}
		len = *(pData - 1);
		while (pos + 4 < len) /* at least 5 len */
		{
			if (0 == *(pData + pos)) /* default route */
			{
				pos += 1;
				udhcp_addrNumToStr(*(int *) (pData + pos), routerStr);
				pos += 4;
				sprintf(cmd, "route add default gw %s dev %s", routerStr, pWanIf);
				printDebugInfo("dhcp option 249 default route: %s", cmd);
				system(cmd);
			}
			else {    /* netmask */
				int netLen = *(pData + pos);
				netmask = 0xffffffff;
				netmask = (netmask << (32 - netLen));
				udhcp_addrNumToStr(htonl(netmask), netmaskStr);
				pos += 1;    /* dst */
				memcpy(&dst, pData + pos, (netLen + 7) / 8);
				udhcp_addrNumToStr(dst, dstStr);
				pos += ((netLen + 7) / 8);    /* router */
				udhcp_addrNumToStr(*(int *) (pData + pos), routerStr);
				pos += 4;
				strncpy(staticRoute[routeIndex].dstStr, dstStr, 16);
				strncpy(staticRoute[routeIndex].netmaskStr, netmaskStr, 16);
				routeIndex++;
				sprintf(cmd, "route add -net %s netmask %s gw %s", dstStr, netmaskStr, routerStr);
				printDebugInfo("dhcp option 249: %s", cmd);
				system(cmd);
			}
			dst = 0;
		}
	}
}
/* add end  */

//usage:#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 1
//usage:# define IF_UDHCP_VERBOSE(...) __VA_ARGS__
//usage:#else
//usage:# define IF_UDHCP_VERBOSE(...)
//usage:#endif
//usage:#define udhcpc_trivial_usage
//usage:       "[-fbq"IF_UDHCP_VERBOSE("v")IF_FEATURE_UDHCPC_ARPING("a")"RB] [-t N] [-T SEC] [-A SEC/-n]\n"
//usage:       "	[-i IFACE]"IF_FEATURE_UDHCP_PORT(" [-P PORT]")" [-s PROG] [-p PIDFILE]\n"
//usage:       "	[-oC] [-r IP] [-V VENDOR] [-F NAME] [-x OPT:VAL]... [-O OPT]..."
//usage:#define udhcpc_full_usage "\n"
//usage:	IF_LONG_OPTS(
//usage:     "\n	-i,--interface IFACE	Interface to use (default eth0)"
//usage:     "\n	-u,--unbound		Do not bind listening socket to interface"
//usage:	IF_FEATURE_UDHCP_PORT(
//usage:     "\n	-P,--client-port PORT	Use PORT (default 68)"
//usage:	)
//usage:     "\n	-s,--script PROG	Run PROG at DHCP events (default "CONFIG_UDHCPC_DEFAULT_SCRIPT")"
//usage:     "\n	-p,--pidfile FILE	Create pidfile"
//usage:     "\n	-B,--broadcast		Request broadcast replies"
//usage:     "\n	-t,--retries N		Send up to N discover packets (default 3)"
//usage:     "\n	-T,--timeout SEC	Pause between packets (default 3)"
//usage:     "\n	-A,--tryagain SEC	Wait if lease is not obtained (default 20)"
//usage:     "\n	-n,--now		Exit if lease is not obtained"
//usage:     "\n	-q,--quit		Exit after obtaining lease"
//usage:     "\n	-Q,--Quit		Exit after receiving offer"
//usage:     "\n	-R,--release		Release IP on exit"
//usage:     "\n	-f,--foreground		Run in foreground"
//usage:     "\n	-m MODE		Filter servers (default normal)"
//usage:     "\n			-m interior - servers in Deco group only"
//usage:     "\n			-m exterior - servers NOT in Deco group only"
//usage:     "\n			-m normal   - both above"
//usage:	USE_FOR_MMU(
//usage:     "\n	-b,--background		Background if lease is not obtained"
//usage:	)
//usage:     "\n	-S,--syslog		Log to syslog too"
//usage:	IF_FEATURE_UDHCPC_ARPING(
//usage:     "\n	-a,--arping		Use arping to validate offered address"
//usage:	)
//usage:     "\n	-r,--request IP		Request this IP address"
//usage:     "\n	-o,--no-default-options	Don't request any options (unless -O is given)"
//usage:     "\n	-O,--request-option OPT	Request option OPT from server (cumulative)"
//usage:     "\n	-x OPT:VAL		Include option OPT in sent packets (cumulative)"
//usage:     "\n				Examples of string, numeric, and hex byte opts:"
//usage:     "\n				-x hostname:bbox - option 12"
//usage:     "\n				-x lease:3600 - option 51 (lease time)"
//usage:     "\n				-x 0x3d:0100BEEFC0FFEE - option 61 (client id)"
//usage:     "\n	-F,--fqdn NAME		Ask server to update DNS mapping for NAME"
//usage:     "\n	-V,--vendorclass VENDOR	Vendor identifier (default 'udhcp VERSION')"
//usage:     "\n	-C,--clientid-none	Don't send MAC as client identifier"
//usage:	IF_UDHCP_VERBOSE(
//usage:     "\n	-v			Verbose"
//usage:	)
//usage:	)
//usage:	IF_NOT_LONG_OPTS(
//usage:     "\n	-i IFACE	Interface to use (default eth0)"
//usage:     "\n	-u		Do not bind listening socket to interface"
//usage:	IF_FEATURE_UDHCP_PORT(
//usage:     "\n	-P PORT		Use PORT (default 68)"
//usage:	)
//usage:     "\n	-s PROG		Run PROG at DHCP events (default "CONFIG_UDHCPC_DEFAULT_SCRIPT")"
//usage:     "\n	-p FILE		Create pidfile"
//usage:     "\n	-B		Request broadcast replies"
//usage:     "\n	-t N		Send up to N discover packets (default 3)"
//usage:     "\n	-T SEC		Pause between packets (default 3)"
//usage:     "\n	-A SEC		Wait if lease is not obtained (default 20)"
//usage:     "\n	-n		Exit if lease is not obtained"
//usage:     "\n	-Q		Exit after receiving offer"
//usage:     "\n	-q		Exit after obtaining lease"
//usage:     "\n	-R		Release IP on exit"
//usage:     "\n	-f		Run in foreground"
//usage:     "\n	-m MODE		Filter servers (default normal)"
//usage:     "\n			-m interior - servers in Deco group only"
//usage:     "\n			-m exterior - servers NOT in Deco group only"
//usage:     "\n			-m normal   - both above"
//usage:	USE_FOR_MMU(
//usage:     "\n	-b		Background if lease is not obtained"
//usage:	)
//usage:     "\n	-S		Log to syslog too"
//usage:	IF_FEATURE_UDHCPC_ARPING(
//usage:     "\n	-a		Use arping to validate offered address"
//usage:	)
//usage:     "\n	-r IP		Request this IP address"
//usage:     "\n	-o		Don't request any options (unless -O is given)"
//usage:     "\n	-O OPT		Request option OPT from server (cumulative)"
//usage:     "\n	-x OPT:VAL	Include option OPT in sent packets (cumulative)"
//usage:     "\n			Examples of string, numeric, and hex byte opts:"
//usage:     "\n			-x hostname:bbox - option 12"
//usage:     "\n			-x lease:3600 - option 51 (lease time)"
//usage:     "\n			-x 0x3d:0100BEEFC0FFEE - option 61 (client id)"
//usage:     "\n	-F NAME		Ask server to update DNS mapping for NAME"
//usage:     "\n	-V VENDOR	Vendor identifier (default 'udhcp VERSION')"
//usage:     "\n	-C		Don't send MAC as client identifier"
//usage:	IF_UDHCP_VERBOSE(
//usage:     "\n	-v		Verbose"
//usage:	)
//usage:	)
//usage:     "\nSignals:"
//usage:     "\n	USR1	Renew lease"
//usage:     "\n	USR2	Release lease"


int udhcpc_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;

int udhcpc_main(int argc UNUSED_PARAM, char **argv)
{
	uint8_t *temp, *message;
	const char *str_V, *str_h, *str_F, *str_r;
	IF_FEATURE_UDHCP_PORT(
	char *str_P;)
	void *clientid_mac_ptr;
	llist_t *list_O = NULL;
	llist_t *list_x = NULL;
	int tryagain_timeout = 20;
	int discover_timeout = 3;
	int discover_retries = 3;
	uint32_t server_addr = server_addr; /* for compiler */
	uint32_t requested_ip = 0;
	uint32_t xid = xid; /* for compiler */
	int packet_num;
	int timeout; /* must be signed */
	unsigned already_waited_sec;
	unsigned opt;
	int max_fd;
	int retval;
	fd_set rfds;
	uint32_t renew_gap = 0;

#if defined CONFIG_PACKAGE_smartip
	char default_type[8] = "dynamic";
	const char *lan_type = default_type;
	struct timeval now, last_send_time;
	int first_discover_packet;
	int first_detect;
	int discover_send_interval;
#endif

	/* Default options */
	IF_FEATURE_UDHCP_PORT(SERVER_PORT = 67;)
	IF_FEATURE_UDHCP_PORT(CLIENT_PORT = 68;)
	client_config.interface = "eth0";
	client_config.script = CONFIG_UDHCPC_DEFAULT_SCRIPT;
	str_V = "udhcp " BB_VER;

	client_config.mode = "normal";

	/* Parse command line */
	/* O,x: list; -T,-t,-A take numeric param */
	opt_complementary = "O::x::T+:t+:A+:g+" IF_UDHCP_VERBOSE(":vv");
	IF_LONG_OPTS(applet_long_options = udhcpc_longopts;)
	opt = getopt32(argv, "CV:H:h:F:i:unp:qQRr:s:T:t:SA:O:ox:fBg:m:"
			USE_FOR_MMU("b")
	IF_FEATURE_UDHCPC_ARPING("a")
	IF_FEATURE_UDHCP_PORT("P:")
	"v"
			, &str_V, &str_h, &str_h, &str_F
			, &client_config.interface, &client_config.pidfile, &str_r /* i,p */
			, &client_config.script /* s */
			, &discover_timeout, &discover_retries, &tryagain_timeout /* T,t,A */
			, &list_O
			, &list_x
			, &renew_gap
			, &client_config.mode /* m */
	IF_FEATURE_UDHCP_PORT(, &str_P)
	IF_UDHCP_VERBOSE(, &dhcp_verbose)
	);

#if defined CONFIG_PACKAGE_smartip
	lan_type = default_type;

	/* we assume that only "smartip" set script option to 'dynamic' or 'static' */
	if (client_config.script != NULL &&(
			strcmp(client_config.script, "dynamic") == 0 ||
			strcmp(client_config.script, "static") == 0)) {
		lan_type = client_config.script;
		client_config.script = NULL;
	}
#endif
	client_config.unbound = (opt & OPT_u);

	if (opt & (OPT_h | OPT_H)) {
		//msg added 2011-11
		bb_error_msg("option -h NAME is deprecated, use -x hostname:NAME");
		client_config.hostname = alloc_dhcp_option(DHCP_HOST_NAME, str_h, 0);
	}
	if (opt & OPT_F) {
		/* FQDN option format: [0x51][len][flags][0][0]<fqdn> */
		client_config.fqdn = alloc_dhcp_option(DHCP_FQDN, str_F, 3);
		/* Flag bits: 0000NEOS
		 * S: 1 = Client requests server to update A RR in DNS as well as PTR
		 * O: 1 = Server indicates to client that DNS has been updated regardless
		 * E: 1 = Name is in DNS format, i.e. <4>host<6>domain<3>com<0>,
		 *    not "host.domain.com". Format 0 is obsolete.
		 * N: 1 = Client requests server to not update DNS (S must be 0 then)
		 * Two [0] bytes which follow are deprecated and must be 0.
		 */
		client_config.fqdn[OPT_DATA + 0] = 0x1;
		/*client_config.fqdn[OPT_DATA + 1] = 0; - xzalloc did it */
		/*client_config.fqdn[OPT_DATA + 2] = 0; */
	}
	if (opt & OPT_r) {
		requested_ip = inet_addr(str_r);
	}
#if ENABLE_FEATURE_UDHCP_PORT
	if (opt & OPT_P) {
		CLIENT_PORT = xatou16(str_P);
		SERVER_PORT = CLIENT_PORT - 1;
	}
#endif
	while (list_O) {
		char *optstr = llist_pop(&list_O);
		unsigned n = bb_strtou(optstr, NULL, 0);
		if (errno || n > 254) {
			n = udhcp_option_idx(optstr);
			n = dhcp_optflags[n].code;
		}
		client_config.opt_mask[n >> 3] |= 1 << (n & 7);
	}
	if (!(opt & OPT_o)) {
		unsigned i, n;
		for (i = 0; (n = dhcp_optflags[i].code) != 0; i++) {
			if (dhcp_optflags[i].flags & OPTION_REQ) {
				client_config.opt_mask[n >> 3] |= 1 << (n & 7);
			}
		}
	}
	while (list_x) {
		char *optstr = llist_pop(&list_x);
		char *colon = strchr(optstr, ':');
		if (colon) {
			*colon = ' ';
		}
		/* now it looks similar to udhcpd's config file line:
		 * "optname optval", using the common routine: */
		udhcp_str2optset(optstr, &client_config.options);
	}

	if (udhcp_read_interface(client_config.interface,
	                         &client_config.ifindex,
	                         NULL,
	                         client_config.client_mac)
			) {
		return 1;
	}

	clientid_mac_ptr = NULL;
	if (!(opt & OPT_C) && !udhcp_find_option(client_config.options, DHCP_CLIENT_ID)) {
		/* not suppressed and not set, set the default client ID */
		client_config.clientid = alloc_dhcp_option(DHCP_CLIENT_ID, "", 7);
		client_config.clientid[OPT_DATA] = 1; /* type: ethernet */
		clientid_mac_ptr = client_config.clientid + OPT_DATA + 1;
		memcpy(clientid_mac_ptr, client_config.client_mac, 6);
	}
	if (str_V[0] != '\0') {
		// can drop -V, str_V, client_config.vendorclass,
		// but need to add "vendor" to the list of recognized
		// string opts for this to work;
		// and need to tweak add_client_options() too...
		// ...so the question is, should we?
		//bb_error_msg("option -V VENDOR is deprecated, use -x vendor:VENDOR");
		client_config.vendorclass = alloc_dhcp_option(DHCP_VENDOR, str_V, 0);
	}

#if !BB_MMU
	/* on NOMMU reexec (i.e., background) early */
	if (!(opt & OPT_f)) {
		bb_daemonize_or_rexec(0 /* flags */, argv);
		logmode = LOGMODE_NONE;
	}
#endif
	if (opt & OPT_S) {
		openlog(applet_name, LOG_PID, LOG_DAEMON);
		logmode |= LOGMODE_SYSLOG;
	}

	/* Make sure fd 0,1,2 are open */
	bb_sanitize_stdio();
	/* Equivalent of doing a fflush after every \n */
	setlinebuf(stdout);
	/* Create pidfile */
	if (NULL == client_config.pidfile) {
		client_config.pidfile = "/tmp/udhcpc.pid";
	}
	write_pidfile(client_config.pidfile);
	/* Goes to stdout (unless NOMMU) and possibly syslog */
	bb_info_msg("%s (v"
	BB_VER
	") started", applet_name);
	/* Set up the signal pipe */
	udhcp_sp_setup();
	/* We want random_xid to be random... */
	srand(monotonic_us());

	state = INIT_SELECTING;
	udhcp_run_script(NULL, "deconfig");
	change_listen_mode(LISTEN_RAW);
	packet_num = 0;
	timeout = 0;
	already_waited_sec = 0;

#if defined CONFIG_PACKAGE_smartip
	first_discover_packet = 1;
	first_detect = 1;
	if (0 == strcmp(lan_type, "static")) {
		gettimeofday(&now, NULL);
		gettimeofday(&last_send_time, NULL);
	}
#endif

	/* Main event loop. select() waits on signal pipe and possibly
	 * on sockfd.
	 * "continue" statements in code below jump to the top of the loop.
	 */
	for (;;) {
		struct timeval tv;
		struct dhcp_packet packet;
		/* silence "uninitialized!" warning */
		unsigned timestamp_before_wait = timestamp_before_wait;

		/* When running on a bridge, the ifindex may have changed (e.g. if
		 * member interfaces were added/removed or if the status of the
		 * bridge changed).
		 * Workaround: refresh it here before processing the next packet */
		udhcp_read_interface(client_config.interface, &client_config.ifindex, NULL,
		                     client_config.client_mac);

		//bb_error_msg("sockfd:%d, listen_mode:%d", sockfd, listen_mode);

		/* Was opening raw or udp socket here
		 * if (listen_mode != LISTEN_NONE && sockfd < 0),
		 * but on fast network renew responses return faster
		 * than we open sockets. Thus this code is moved
		 * to change_listen_mode(). Thus we open listen socket
		 * BEFORE we send renew request (see "case BOUND:"). */

		max_fd = udhcp_sp_fd_set(&rfds, sockfd);

//		bb_info_msg("enter loop, state=%d listen_mode=%d", state, listen_mode);

		tv.tv_sec = timeout - already_waited_sec;
		tv.tv_usec = 0;
		retval = 0;
		/* If we already timed out, fall through with retval = 0, else... */
		if ((int) tv.tv_sec > 0) {
			log1("Waiting on select %u seconds", (int) tv.tv_sec);
			timestamp_before_wait = (unsigned) monotonic_sec();
			retval = select(max_fd + 1, &rfds, NULL, NULL, &tv);
			if (retval < 0) {
				/* EINTR? A signal was caught, don't panic */
				if (errno == EINTR) {
					already_waited_sec += (unsigned) monotonic_sec() - timestamp_before_wait;
					continue;
				}
				/* Else: an error occured, panic! */
				bb_perror_msg_and_die("select");
			}
		}

		/* If timeout dropped to zero, time to become active:
		 * resend discover/renew/whatever
		 */
		if (retval == 0) {
			/* When running on a bridge, the ifindex may have changed
			 * (e.g. if member interfaces were added/removed
			 * or if the status of the bridge changed).
			 * Refresh ifindex and client_mac:
			 */
			if (udhcp_read_interface(client_config.interface,
			                         &client_config.ifindex,
			                         NULL,
			                         client_config.client_mac)
					) {
				goto ret0; /* iface is gone? */
			}
			if (clientid_mac_ptr) {
				memcpy(clientid_mac_ptr, client_config.client_mac, 6);
			}

			/* We will restart the wait in any case */
			already_waited_sec = 0;

			switch (state) {
			case INIT_SELECTING:
				if (!discover_retries || packet_num < discover_retries) {
					if (packet_num == 0) {
						xid = random_xid();
					}

#if defined CONFIG_PACKAGE_smartip
					if (0 != strcmp(lan_type, "static")) {
#endif
						/* broadcast */
						send_discover(xid, requested_ip);
						timeout = discover_timeout;
						packet_num++;

#if defined CONFIG_PACKAGE_smartip
					}
					else {
						gettimeofday(&now, NULL);
						if (0 != first_detect) {
							discover_send_interval = 10;
						}
						else {
							discover_send_interval = 20;
						}

						if ((0 != first_discover_packet) ||
						    ((now.tv_sec - last_send_time.tv_sec) > discover_send_interval)) {
							send_discover(xid, requested_ip);
							timeout = discover_timeout;
							packet_num++;
							gettimeofday(&last_send_time, NULL);
							if (0 != first_discover_packet) {
								first_discover_packet = 0;
							}
							else {
								timeout = discover_timeout;
							}
						}
					}
#endif
					continue;
				}
			leasefail:
				udhcp_run_script(NULL, "leasefail");

#if defined CONFIG_PACKAGE_smartip
#if (CONFIG_IBUS_METHOD == IBUS_USE_UBUS)
				udhcpc_send_event(DETECT_FAIL, client_config.interface, NULL);
#endif
				if ((0 == strcmp(lan_type, "static")) && (0 != first_detect)) {
					first_detect = 0;
				}
#endif

#if BB_MMU /* -b is not supported on NOMMU */
				if (opt & OPT_b) { /* background if no lease */
					bb_info_msg("No lease, forking to background");
					client_background();
					/* do not background again! */
					opt = ((opt & ~OPT_b) | OPT_f);
				}
				else
#endif
				if (opt & OPT_n) { /* abort if no lease */
					bb_info_msg("No lease, failing");
					retval = 1;
					goto ret;
				}
				/* wait before trying again */
				timeout = tryagain_timeout;
				packet_num = 0;
				continue;
			case REQUESTING:
				if (opt & OPT_Q) {
					/* quit when DHCP offer received */
					bb_info_msg("DHCP offer received, exit");
					goto ret0;
				}

				if (!discover_retries || packet_num < discover_retries) {
					/* send broadcast select packet */
					send_select(xid, server_addr, requested_ip);
					timeout = discover_timeout;
					packet_num++;
					continue;
				}
				/* Timed out, go back to init state.
				 * "discover...select...discover..." loops
				 * were seen in the wild. Treat them similarly
				 * to "no response to discover" case */
				change_listen_mode(LISTEN_RAW);
				state = INIT_SELECTING;
				goto leasefail;
			case BOUND:
				/* 1/2 lease passed, enter renewing state */
				state = RENEWING;
				client_config.first_secs = 0; /* make secs field count from 0 */
				change_listen_mode(LISTEN_KERNEL);
				log1("Entering renew state");
				/* fall right through */
			case RENEW_REQUESTED: /* manual (SIGUSR1) renew */
			case_RENEW_REQUESTED:
			case RENEWING:
				if (timeout >= 30) {
					/* send an unicast renew request */
					/* Sometimes observed to fail (EADDRNOTAVAIL) to bind
					 * a new UDP socket for sending inside send_renew.
					 * I hazard to guess existing listening socket
					 * is somehow conflicting with it, but why is it
					 * not deterministic then?! Strange.
					 * Anyway, it does recover by eventually failing through
					 * into INIT_SELECTING state.
					 */
					send_renew(xid, server_addr, requested_ip);
					timeout >>= 1;
					continue;
				}
				/* Timed out, enter rebinding state */
				log1("Entering rebinding state");
				state = REBINDING;
				/* fall right through */
			case REBINDING:
				/* Switch to bcast receive */
				change_listen_mode(LISTEN_RAW);
				/* Lease is *really* about to run out,
				 * try to find DHCP server using broadcast */
				if (timeout > 0) {
					/* send a broadcast renew request */
					send_renew(xid, 0 /*INADDR_ANY*/, requested_ip);
					timeout >>= 1;
					continue;
				}
				/* Timed out, enter init state */
				bb_info_msg("Lease lost, entering init state");
				udhcp_run_script(NULL, "deconfig");

#if defined CONFIG_PACKAGE_smartip
#if (CONFIG_IBUS_METHOD == IBUS_USE_UBUS)
				udhcpc_send_event(DETECT_FAIL, client_config.interface, NULL);
#endif
#endif

				state = INIT_SELECTING;
				client_config.first_secs = 0; /* make secs field count from 0 */
				/*timeout = 0; - already is */
				packet_num = 0;
				continue;
				/* case RELEASED: */
			}
			/* yah, I know, *you* say it would never happen */
			timeout = INT_MAX;
			continue; /* back to main loop */
		} /* if select timed out */

		/* select() didn't timeout, something happened */

		/* Is it a signal? */
		/* note: udhcp_sp_read checks FD_ISSET before reading */
		switch (udhcp_sp_read(&rfds)) {
		case SIGUSR1:
			client_config.first_secs = 0; /* make secs field count from 0 */
			already_waited_sec = 0;
			perform_renew();
			if (state == RENEW_REQUESTED) {
				/* We might be either on the same network
				 * (in which case renew might work),
				 * or we might be on a completely different one
				 * (in which case renew won't ever succeed).
				 * For the second case, must make sure timeout
				 * is not too big, or else we can send
				 * futile renew requests for hours.
				 * (Ab)use -A TIMEOUT value (usually 20 sec)
				 * as a cap on the timeout.
				 */
				if (timeout > tryagain_timeout) {
					timeout = tryagain_timeout;
				}
				goto case_RENEW_REQUESTED;
			}
			/* Start things over */
			packet_num = 0;
			/* Kill any timeouts, user wants this to hurry along */
			timeout = 0;
			continue;
		case SIGUSR2:
			perform_release(server_addr, requested_ip);
			timeout = INT_MAX;
			continue;
		case SIGTERM:
			bb_info_msg("Received SIGTERM");
			goto ret0;
		}

		/* Is it a packet? */
		if (listen_mode == LISTEN_NONE || !FD_ISSET(sockfd, &rfds)) {
			continue;
		} /* no */

		{
			int len;

			/* A packet is ready, read it */
			if (listen_mode == LISTEN_KERNEL) {
				len = udhcp_recv_kernel_packet(&packet, sockfd);
			}
			else {
				len = udhcp_recv_raw_packet(&packet, sockfd);
			}
			if (len == -1) {
				/* Error is severe, reopen socket */
				bb_info_msg("Read error: %s, reopening socket", strerror(errno));
				sleep(discover_timeout); /* 3 seconds by default */
				change_listen_mode(listen_mode); /* just close and reopen */
			}
			/* If this packet will turn out to be unrelated/bogus,
			 * we will go back and wait for next one.
			 * Be sure timeout is properly decreased. */
			already_waited_sec += (unsigned) monotonic_sec() - timestamp_before_wait;
			if (len < 0) {
				continue;
			}
		}

		if (packet.xid != xid) {
			log1("xid %x (our is %x), ignoring packet",
			     (unsigned) packet.xid, (unsigned) xid);
			continue;
		}

		/* Ignore packets that aren't for us */
		if (packet.hlen != 6
		    || memcmp(packet.chaddr, client_config.client_mac, 6) != 0
				) {
//FIXME: need to also check that last 10 bytes are zero
			log1("chaddr does not match, ignoring packet"); // log2?
			continue;
		}

		message = udhcp_get_option(&packet, DHCP_MESSAGE_TYPE);
		if (message == NULL) {
			bb_error_msg("no message type option, ignoring packet");
			continue;
		}

		switch (state) {
		case INIT_SELECTING:
			/* Must be a DHCPOFFER */
			if (*message == DHCPOFFER) {
/* What exactly is server's IP? There are several values.
 * Example DHCP offer captured with tchdump:
 *
 * 10.34.25.254:67 > 10.34.25.202:68 // IP header's src
 * BOOTP fields:
 * Your-IP 10.34.25.202
 * Server-IP 10.34.32.125   // "next server" IP
 * Gateway-IP 10.34.25.254  // relay's address (if DHCP relays are in use)
 * DHCP options:
 * DHCP-Message Option 53, length 1: Offer
 * Server-ID Option 54, length 4: 10.34.255.7       // "server ID"
 * Default-Gateway Option 3, length 4: 10.34.25.254 // router
 *
 * We think that real server IP (one to use in renew/release)
 * is one in Server-ID option. But I am not 100% sure.
 * IP header's src and Gateway-IP (same in this example)
 * might work too.
 * "Next server" and router are definitely wrong ones to use, though...
 */
/* We used to ignore pcakets without DHCP_SERVER_ID.
 * I've got user reports from people who run "address-less" servers.
 * They either supply DHCP_SERVER_ID of 0.0.0.0 or don't supply it at all.
 * They say ISC DHCP client supports this case.
 */
				server_addr = 0;
				temp = udhcp_get_option(&packet, DHCP_SERVER_ID);
				if (!temp) {
					bb_error_msg("no server ID, using 0.0.0.0");
				}
				else {
					/* it IS unaligned sometimes, don't "optimize" */
					move_from_unaligned32(server_addr, temp);
				}
				/*xid = packet.xid; - already is */
				requested_ip = packet.yiaddr;

#if defined CONFIG_PACKAGE_smartip
				if (0 != strcmp(lan_type, "static"))
#endif
				{
					/* enter requesting state */
					state = REQUESTING;
				}
#if defined CONFIG_PACKAGE_smartip
				else {
					state = INIT_SELECTING;

#if (CONFIG_IBUS_METHOD == IBUS_USE_UBUS)
					udhcpc_send_event(DETECT_SUCCESS, client_config.interface, &packet);

#endif
					if (0 != first_detect) {
						first_detect = 0;
					}
				}
#endif /* CONFIG_PACKAGE_smartip */

				timeout = 0;
				packet_num = 0;
				already_waited_sec = 0;
			}
			continue;
		case REQUESTING:
		case RENEWING:
		case RENEW_REQUESTED:
		case REBINDING:
			if (*message == DHCPACK) {
				uint32_t lease_seconds;
				struct in_addr temp_addr;

				temp = udhcp_get_option(&packet, DHCP_LEASE_TIME);
				if (!temp) {
					bb_error_msg("no lease time with ACK, using 1 hour lease");
					lease_seconds = 60 * 60;
				}
				else {
					/* it IS unaligned sometimes, don't "optimize" */
					move_from_unaligned32(lease_seconds, temp);
					lease_seconds = ntohl(lease_seconds);
					/* paranoia: must not be too small and not prone to overflows */
					if (lease_seconds < 0x10) {
						lease_seconds = 0x10;
					}
					if (lease_seconds >= 0x10000000) {
						lease_seconds = 0x0fffffff;
					}
				}
#if ENABLE_FEATURE_UDHCPC_ARPING
				if (opt & OPT_a) {
/* RFC 2131 3.1 paragraph 5:
 * "The client receives the DHCPACK message with configuration
 * parameters. The client SHOULD perform a final check on the
 * parameters (e.g., ARP for allocated network address), and notes
 * the duration of the lease specified in the DHCPACK message. At this
 * point, the client is configured. If the client detects that the
 * address is already in use (e.g., through the use of ARP),
 * the client MUST send a DHCPDECLINE message to the server and restarts
 * the configuration process..." */
					if (!arpping(packet.yiaddr,
							NULL,
							(uint32_t) 0,
							client_config.client_mac,
							client_config.interface)
					) {
						bb_info_msg("Offered address is in use "
							"(got ARP reply), declining");
						send_decline(/*xid,*/ server_addr, packet.yiaddr);

						if (state != REQUESTING)
							udhcp_run_script(NULL, "deconfig");
						change_listen_mode(LISTEN_RAW);
						state = INIT_SELECTING;
						client_config.first_secs = 0; /* make secs field count from 0 */
						requested_ip = 0;
						timeout = tryagain_timeout;
						packet_num = 0;
						already_waited_sec = 0;
						continue; /* back to main loop */
					}
				}
#endif
				/* enter bound state */
				timeout = lease_seconds / 2;
				temp_addr.s_addr = packet.yiaddr;
				bb_info_msg("Lease of %s obtained, lease time %u",
				            inet_ntoa(temp_addr), (unsigned) lease_seconds);
				requested_ip = packet.yiaddr;
				udhcp_run_script(&packet, state == REQUESTING ? "bound" : "renew");

#if defined CONFIG_PACKAGE_smartip
#if (CONFIG_IBUS_METHOD == IBUS_USE_UBUS)
				udhcpc_send_event(DETECT_SUCCESS, client_config.interface, &packet);
#endif
#endif
				/* add by wanghao  */
				//handleRouteOption(&packet, client_config.interface);
				/* add end  */

				state = BOUND;
				change_listen_mode(LISTEN_NONE);
				if (opt & OPT_q) { /* quit after lease */
					goto ret0;
				}
				/* future renew failures should not exit (JM) */
				opt &= ~OPT_n;
#if BB_MMU /* NOMMU case backgrounded earlier */
				if (!(opt & OPT_f)) {
					client_background();
					/* do not background again! */
					opt = ((opt & ~OPT_b) | OPT_f);
				}
#endif
				/* make future renew packets use different xid */
				/* xid = random_xid(); ...but why bother? */
				already_waited_sec = 0;

				if (renew_gap) {
					change_listen_mode(LISTEN_RAW);
					state = INIT_SELECTING;
					client_config.first_secs = 0; /* make secs field count from 0 */
					timeout = renew_gap;
					packet_num = 0;
					already_waited_sec = 0;
				}
				continue; /* back to main loop */
			}
			if (*message == DHCPNAK) {
				/* return to init state */
				bb_info_msg("Received DHCP NAK");
				udhcp_run_script(&packet, "nak");
				if (state != REQUESTING) {
					udhcp_run_script(NULL, "deconfig");
				}
				change_listen_mode(LISTEN_RAW);
				sleep(3); /* avoid excessive network traffic */
				state = INIT_SELECTING;
				client_config.first_secs = 0; /* make secs field count from 0 */
				requested_ip = 0;
				timeout = 0;
				packet_num = 0;
				already_waited_sec = 0;
			}
			continue;
			/* case BOUND: - ignore all packets */
			/* case RELEASED: - ignore all packets */
		}
		/* back to main loop */
	} /* for (;;) - main loop ends */

ret0:
	if (opt & OPT_R) { /* release on quit */
		perform_release(server_addr, requested_ip);
	}
	retval = 0;
ret:
	/*if (client_config.pidfile) - remove_pidfile has its own check */
	remove_pidfile(client_config.pidfile);
	return retval;
}
