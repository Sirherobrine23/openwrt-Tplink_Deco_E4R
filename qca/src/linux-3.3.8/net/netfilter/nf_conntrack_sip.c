/* SIP extension for IP connection tracking.
 *
 * (C) 2005 by Christian Hentschel <chentschel@arnet.com.ar>
 * based on RR's ip_conntrack_ftp.c and other modules.
 * (C) 2007 United Security Providers
 * (C) 2007, 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <linux/netfilter/nf_conntrack_sip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christian Hentschel <chentschel@arnet.com.ar>");
MODULE_DESCRIPTION("SIP connection tracking helper");
MODULE_ALIAS("ip_conntrack_sip");
MODULE_ALIAS_NFCT_HELPER("sip");

//Current sip info number
static unsigned int g_current_sip_info_num = 0;
static rwlock_t sip_info_lock ;
static  char *lan_br_name =  "br-lan";
extern struct net init_net;

module_param(lan_br_name, charp, S_IRUGO|S_IWUSR );
MODULE_PARM_DESC(lan_br_name,"the interface name of interface \"lan bridge\"");

static DEFINE_RWLOCK(sip_info_lock);
//Sip info list
LIST_HEAD(sip_info);


#define MAX_PORTS	8
static unsigned short ports[MAX_PORTS];
static unsigned int ports_c;
module_param_array(ports, ushort, &ports_c, 0400);
MODULE_PARM_DESC(ports, "port numbers of SIP servers");

static unsigned int sip_timeout __read_mostly = SIP_TIMEOUT;
module_param(sip_timeout, uint, 0600);
MODULE_PARM_DESC(sip_timeout, "timeout for the master SIP session");

static int sip_direct_signalling __read_mostly = 1;
module_param(sip_direct_signalling, int, 0600);
MODULE_PARM_DESC(sip_direct_signalling, "expect incoming calls from registrar "
					"only (default 1)");

static int sip_direct_media __read_mostly = 1;
module_param(sip_direct_media, int, 0600);
MODULE_PARM_DESC(sip_direct_media, "Expect Media streams between signalling "
				   "endpoints only (default 1)");

unsigned int (*nf_nat_sip_hook)(struct sk_buff *skb, unsigned int dataoff,
				const char **dptr,
				unsigned int *datalen) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sip_hook);

void (*nf_nat_sip_seq_adjust_hook)(struct sk_buff *skb, s16 off) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sip_seq_adjust_hook);

unsigned int (*nf_nat_sip_expect_hook)(struct sk_buff *skb,
				       unsigned int dataoff,
				       const char **dptr,
				       unsigned int *datalen,
				       struct nf_conntrack_expect *exp,
				       unsigned int matchoff,
				       unsigned int matchlen) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sip_expect_hook);

unsigned int (*nf_nat_sdp_addr_hook)(struct sk_buff *skb, unsigned int dataoff,
				     const char **dptr,
				     unsigned int *datalen,
				     unsigned int sdpoff,
				     enum sdp_header_types type,
				     enum sdp_header_types term,
				     const union nf_inet_addr *addr)
				     __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sdp_addr_hook);

unsigned int (*nf_nat_sdp_port_hook)(struct sk_buff *skb, unsigned int dataoff,
				     const char **dptr,
				     unsigned int *datalen,
				     unsigned int matchoff,
				     unsigned int matchlen,
				     u_int16_t port) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sdp_port_hook);

unsigned int (*nf_nat_sdp_session_hook)(struct sk_buff *skb,
					unsigned int dataoff,
					const char **dptr,
					unsigned int *datalen,
					unsigned int sdpoff,
					const union nf_inet_addr *addr)
					__read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sdp_session_hook);

unsigned int (*nf_nat_sdp_media_hook)(struct sk_buff *skb, unsigned int dataoff,
				      const char **dptr,
				      unsigned int *datalen,
				      struct nf_conntrack_expect *rtp_exp,
				      struct nf_conntrack_expect *rtcp_exp,
				      unsigned int mediaoff,
				      unsigned int medialen,
				      union nf_inet_addr *rtp_addr)
				      __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sdp_media_hook);

unsigned int (*nf_nat_sip_response_expect_hook)(struct sk_buff *skb,
                                      const char **dptr,
                                      unsigned int *datalen,
                                      struct nf_conntrack_expect *exp)
                                      __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sip_response_expect_hook);

static int string_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift)
{
	int len = 0;

	while (dptr < limit && isalpha(*dptr)) {
		dptr++;
		len++;
	}
	return len;
}

static int digits_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift)
{
	int len = 0;
	while (dptr < limit && isdigit(*dptr)) {
		dptr++;
		len++;
	}
	return len;
}

static int iswordc(const char c)
{
	if (isalnum(c) || c == '!' || c == '"' || c == '%' ||
	    (c >= '(' && c <= '/') || c == ':' || c == '<' || c == '>' ||
	    c == '?' || (c >= '[' && c <= ']') || c == '_' || c == '`' ||
	    c == '{' || c == '}' || c == '~')
		return 1;
	return 0;
}

static int word_len(const char *dptr, const char *limit)
{
	int len = 0;
	while (dptr < limit && iswordc(*dptr)) {
		dptr++;
		len++;
	}
	return len;
}

static int callid_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift)
{
	int len, domain_len;

	len = word_len(dptr, limit);
	dptr += len;
	if (!len || dptr == limit || *dptr != '@')
		return len;
	dptr++;
	len++;

	domain_len = word_len(dptr, limit);
	if (!domain_len)
		return 0;
	return len + domain_len;
}

/* get media type + port length */
static int media_len(const struct nf_conn *ct, const char *dptr,
		     const char *limit, int *shift)
{
	int len = string_len(ct, dptr, limit, shift);

	dptr += len;
	if (dptr >= limit || *dptr != ' ')
		return 0;
	len++;
	dptr++;

	return len + digits_len(ct, dptr, limit, shift);
}

static int parse_addr(const struct nf_conn *ct, const char *cp,
                      const char **endp, union nf_inet_addr *addr,
                      const char *limit)
{
	const char *end;
	int ret = 0;

	if (!ct)
		return 0;

	memset(addr, 0, sizeof(*addr));
	switch (nf_ct_l3num(ct)) {
	case AF_INET:
		ret = in4_pton(cp, limit - cp, (u8 *)&addr->ip, -1, &end);
		break;
	case AF_INET6:
		ret = in6_pton(cp, limit - cp, (u8 *)&addr->ip6, -1, &end);
		break;
	default:
		BUG();
	}

	if (ret == 0 || end == cp)
		return 0;
	if (endp)
		*endp = end;
	return 1;
}

/* skip ip address. returns its length. */
static int epaddr_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift)
{
	union nf_inet_addr addr;
	const char *aux = dptr;

	if (!parse_addr(ct, dptr, &dptr, &addr, limit)) {
		pr_debug("ip: %s parse failed.!\n", dptr);
		return 0;
	}

	/* Port number */
	if (*dptr == ':') {
		dptr++;
		dptr += digits_len(ct, dptr, limit, shift);
	}
	return dptr - aux;
}

/* get address length, skiping user info. */
static int skp_epaddr_len(const struct nf_conn *ct, const char *dptr,
			  const char *limit, int *shift)
{
	const char *start = dptr;
	int s = *shift;

	/* Search for @, but stop at the end of the line.
	 * We are inside a sip: URI, so we don't need to worry about
	 * continuation lines. */
	while (dptr < limit &&
	       *dptr != '@' && *dptr != '\r' && *dptr != '\n') {
		(*shift)++;
		dptr++;
	}

	if (dptr < limit && *dptr == '@') {
		dptr++;
		(*shift)++;
	} else {
		dptr = start;
		*shift = s;
	}

	return epaddr_len(ct, dptr, limit, shift);
}

/* Parse a SIP request line of the form:
 *
 * Request-Line = Method SP Request-URI SP SIP-Version CRLF
 *
 * and return the offset and length of the address contained in the Request-URI.
 */
int ct_sip_parse_request(const struct nf_conn *ct,
			 const char *dptr, unsigned int datalen,
			 unsigned int *matchoff, unsigned int *matchlen,
			 union nf_inet_addr *addr, __be16 *port)
{
	const char *start = dptr, *limit = dptr + datalen, *end;
	unsigned int mlen;
	unsigned int p;
	int shift = 0;

	/* Skip method and following whitespace */
	mlen = string_len(ct, dptr, limit, NULL);
	if (!mlen)
		return 0;
	dptr += mlen;
	if (++dptr >= limit)
		return 0;

	/* Find SIP URI */
	for (; dptr < limit - strlen("sip:"); dptr++) {
		if (*dptr == '\r' || *dptr == '\n')
			return -1;
		if (strnicmp(dptr, "sip:", strlen("sip:")) == 0) {
			dptr += strlen("sip:");
			break;
		}
	}
	if (!skp_epaddr_len(ct, dptr, limit, &shift))
		return 0;
	dptr += shift;

	if (!parse_addr(ct, dptr, &end, addr, limit))
		return -1;
	if (end < limit && *end == ':') {
		end++;
		p = simple_strtoul(end, (char **)&end, 10);
		if (p < 1024 || p > 65535)
			return -1;
		*port = htons(p);
	} else
		*port = htons(SIP_PORT);

	if (end == dptr)
		return 0;
	*matchoff = dptr - start;
	*matchlen = end - dptr;
	return 1;
}
EXPORT_SYMBOL_GPL(ct_sip_parse_request);

/* SIP header parsing: SIP headers are located at the beginning of a line, but
 * may span several lines, in which case the continuation lines begin with a
 * whitespace character. RFC 2543 allows lines to be terminated with CR, LF or
 * CRLF, RFC 3261 allows only CRLF, we support both.
 *
 * Headers are followed by (optionally) whitespace, a colon, again (optionally)
 * whitespace and the values. Whitespace in this context means any amount of
 * tabs, spaces and continuation lines, which are treated as a single whitespace
 * character.
 *
 * Some headers may appear multiple times. A comma separated list of values is
 * equivalent to multiple headers.
 */
static const struct sip_header ct_sip_hdrs[] = {
	[SIP_HDR_CSEQ]			= SIP_HDR("CSeq", NULL, NULL, digits_len),
	[SIP_HDR_FROM]			= SIP_HDR("From", "f", "sip:", skp_epaddr_len),
	[SIP_HDR_TO]			= SIP_HDR("To", "t", "sip:", skp_epaddr_len),
	[SIP_HDR_CONTACT]		= SIP_HDR("Contact", "m", "sip:", skp_epaddr_len),
	[SIP_HDR_VIA_UDP]		= SIP_HDR("Via", "v", "UDP ", epaddr_len),
	[SIP_HDR_VIA_TCP]		= SIP_HDR("Via", "v", "TCP ", epaddr_len),
	[SIP_HDR_EXPIRES]		= SIP_HDR("Expires", NULL, NULL, digits_len),
	[SIP_HDR_CONTENT_LENGTH]	= SIP_HDR("Content-Length", "l", NULL, digits_len),
	[SIP_HDR_CALL_ID]		= SIP_HDR("Call-Id", "i", NULL, callid_len),
};

static const char *sip_follow_continuation(const char *dptr, const char *limit)
{
	/* Walk past newline */
	if (++dptr >= limit)
		return NULL;

	/* Skip '\n' in CR LF */
	if (*(dptr - 1) == '\r' && *dptr == '\n') {
		if (++dptr >= limit)
			return NULL;
	}

	/* Continuation line? */
	if (*dptr != ' ' && *dptr != '\t')
		return NULL;

	/* skip leading whitespace */
	for (; dptr < limit; dptr++) {
		if (*dptr != ' ' && *dptr != '\t')
			break;
	}
	return dptr;
}

static const char *sip_skip_whitespace(const char *dptr, const char *limit)
{
	for (; dptr < limit; dptr++) {
		if (*dptr == ' ')
			continue;
		if (*dptr != '\r' && *dptr != '\n')
			break;
		dptr = sip_follow_continuation(dptr, limit);
		if (dptr == NULL)
			return NULL;
	}
	return dptr;
}

/* Locate URI if '<' is present. In order to handle the following situation.
 *      - Contact: "sip:100@192.168.1.33" <sip:100@192.168.1.33:2945>
 */
static const char *sip_locate_uri(const char *dptr, const char *limit)
{
        const char *pStart;

        for (pStart = dptr; pStart < limit; pStart++) {
                if (*pStart == '\r' || *pStart == '\n')
                        break;
                if (*pStart == '<')
                        return pStart;
        }

        return dptr;
}

/* Search within a SIP header value, dealing with continuation lines */
static const char *ct_sip_header_search(const char *dptr, const char *limit,
					const char *needle, unsigned int len)
{
	for (limit -= len; dptr < limit; dptr++) {
		if (*dptr == '\r' || *dptr == '\n') {
			dptr = sip_follow_continuation(dptr, limit);
			if (dptr == NULL)
				break;
			continue;
		}

		if (strnicmp(dptr, needle, len) == 0)
			return dptr;
	}
	return NULL;
}

int ct_sip_get_header(const struct nf_conn *ct, const char *dptr,
		      unsigned int dataoff, unsigned int datalen,
		      enum sip_header_types type,
		      unsigned int *matchoff, unsigned int *matchlen)
{
	const struct sip_header *hdr = &ct_sip_hdrs[type];
	const char *start = dptr, *limit = dptr + datalen;
	int shift = 0;

	for (dptr += dataoff; dptr < limit; dptr++) {
		/* Find beginning of line */
		if (*dptr != '\r' && *dptr != '\n')
			continue;
		if (++dptr >= limit)
			break;
		if (*(dptr - 1) == '\r' && *dptr == '\n') {
			if (++dptr >= limit)
				break;
		}

		/* Skip continuation lines */
		if (*dptr == ' ' || *dptr == '\t')
			continue;

		/* Find header. Compact headers must be followed by a
		 * non-alphabetic character to avoid mismatches. */
		if (limit - dptr >= hdr->len &&
		    strnicmp(dptr, hdr->name, hdr->len) == 0)
			dptr += hdr->len;
		else if (hdr->cname && limit - dptr >= hdr->clen + 1 &&
			 strnicmp(dptr, hdr->cname, hdr->clen) == 0 &&
			 !isalpha(*(dptr + hdr->clen)))
			dptr += hdr->clen;
		else
			continue;

		/* Find and skip colon */
		dptr = sip_skip_whitespace(dptr, limit);
		if (dptr == NULL)
			break;
		if (*dptr != ':' || ++dptr >= limit)
			break;

                /* Locate URI  if  "<" is present */
                dptr = sip_locate_uri(dptr, limit);

		/* Skip whitespace after colon */
		dptr = sip_skip_whitespace(dptr, limit);
		if (dptr == NULL)
			break;

		*matchoff = dptr - start;
		if (hdr->search) {
			dptr = ct_sip_header_search(dptr, limit, hdr->search,
						    hdr->slen);
			if (!dptr)
				return -1;
			dptr += hdr->slen;
		}

		*matchlen = hdr->match_len(ct, dptr, limit, &shift);
		if (!*matchlen)
			return -1;
		*matchoff = dptr - start + shift;
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ct_sip_get_header);

/* Get next header field in a list of comma separated values */
static int ct_sip_next_header(const struct nf_conn *ct, const char *dptr,
			      unsigned int dataoff, unsigned int datalen,
			      enum sip_header_types type,
			      unsigned int *matchoff, unsigned int *matchlen)
{
	const struct sip_header *hdr = &ct_sip_hdrs[type];
	const char *start = dptr, *limit = dptr + datalen;
	int shift = 0;

	dptr += dataoff;

	dptr = ct_sip_header_search(dptr, limit, ",", strlen(","));
	if (!dptr)
		return 0;

	dptr = ct_sip_header_search(dptr, limit, hdr->search, hdr->slen);
	if (!dptr)
		return 0;
	dptr += hdr->slen;

	*matchoff = dptr - start;
	*matchlen = hdr->match_len(ct, dptr, limit, &shift);
	if (!*matchlen)
		return -1;
	*matchoff += shift;
	return 1;
}

/* Walk through headers until a parsable one is found or no header of the
 * given type is left. */
static int ct_sip_walk_headers(const struct nf_conn *ct, const char *dptr,
			       unsigned int dataoff, unsigned int datalen,
			       enum sip_header_types type, int *in_header,
			       unsigned int *matchoff, unsigned int *matchlen)
{
	int ret;

	if (in_header && *in_header) {
		while (1) {
			ret = ct_sip_next_header(ct, dptr, dataoff, datalen,
						 type, matchoff, matchlen);
			if (ret > 0)
				return ret;
			if (ret == 0)
				break;
			dataoff += *matchoff;
		}
		*in_header = 0;
	}

	while (1) {
		ret = ct_sip_get_header(ct, dptr, dataoff, datalen,
					type, matchoff, matchlen);
		if (ret > 0)
			break;
		if (ret == 0)
			return ret;
		dataoff += *matchoff;
	}

	if (in_header)
		*in_header = 1;
	return 1;
}

/* Locate a SIP header, parse the URI and return the offset and length of
 * the address as well as the address and port themselves. A stream of
 * headers can be parsed by handing in a non-NULL datalen and in_header
 * pointer.
 */
int ct_sip_parse_header_uri(const struct nf_conn *ct, const char *dptr,
			    unsigned int *dataoff, unsigned int datalen,
			    enum sip_header_types type, int *in_header,
			    unsigned int *matchoff, unsigned int *matchlen,
			    union nf_inet_addr *addr, __be16 *port)
{
	const char *c, *limit = dptr + datalen;
	unsigned int p;
	int ret;

	ret = ct_sip_walk_headers(ct, dptr, dataoff ? *dataoff : 0, datalen,
				  type, in_header, matchoff, matchlen);
	WARN_ON(ret < 0);
	if (ret == 0)
		return ret;

	if (!parse_addr(ct, dptr + *matchoff, &c, addr, limit))
		return -1;
	if (*c == ':') {
		c++;
		p = simple_strtoul(c, (char **)&c, 10);
		if (p < 1024 || p > 65535)
			return -1;
		*port = htons(p);
	} else
		*port = htons(SIP_PORT);

	if (dataoff)
		*dataoff = c - dptr;
	return 1;
}
EXPORT_SYMBOL_GPL(ct_sip_parse_header_uri);

static int ct_sip_parse_param(const struct nf_conn *ct, const char *dptr,
			      unsigned int dataoff, unsigned int datalen,
			      const char *name,
			      unsigned int *matchoff, unsigned int *matchlen)
{
	const char *limit = dptr + datalen;
	const char *start;
	const char *end;

	limit = ct_sip_header_search(dptr + dataoff, limit, ",", strlen(","));
	if (!limit)
		limit = dptr + datalen;

	start = ct_sip_header_search(dptr + dataoff, limit, name, strlen(name));
	if (!start)
		return 0;
	start += strlen(name);

	end = ct_sip_header_search(start, limit, ";", strlen(";"));
	if (!end)
		end = limit;

	*matchoff = start - dptr;
	*matchlen = end - start;
	return 1;
}

/* Parse address from header parameter and return address, offset and length */
int ct_sip_parse_address_param(const struct nf_conn *ct, const char *dptr,
			       unsigned int dataoff, unsigned int datalen,
			       const char *name,
			       unsigned int *matchoff, unsigned int *matchlen,
			       union nf_inet_addr *addr)
{
	const char *limit = dptr + datalen;
	const char *start, *end;

	limit = ct_sip_header_search(dptr + dataoff, limit, ",", strlen(","));
	if (!limit)
		limit = dptr + datalen;

	start = ct_sip_header_search(dptr + dataoff, limit, name, strlen(name));
	if (!start)
		return 0;

	start += strlen(name);
	if (!parse_addr(ct, start, &end, addr, limit))
		return 0;
	*matchoff = start - dptr;
	*matchlen = end - start;
	return 1;
}
EXPORT_SYMBOL_GPL(ct_sip_parse_address_param);

/* Parse numerical header parameter and return value, offset and length */
int ct_sip_parse_numerical_param(const struct nf_conn *ct, const char *dptr,
				 unsigned int dataoff, unsigned int datalen,
				 const char *name,
				 unsigned int *matchoff, unsigned int *matchlen,
				 unsigned int *val)
{
	const char *limit = dptr + datalen;
	const char *start;
	char *end;

	limit = ct_sip_header_search(dptr + dataoff, limit, ",", strlen(","));
	if (!limit)
		limit = dptr + datalen;

	start = ct_sip_header_search(dptr + dataoff, limit, name, strlen(name));
	if (!start)
		return 0;

	start += strlen(name);
	*val = simple_strtoul(start, &end, 0);
	if (start == end)
		return 0;
	if (matchoff && matchlen) {
		*matchoff = start - dptr;
		*matchlen = end - start;
	}
	return 1;
}
EXPORT_SYMBOL_GPL(ct_sip_parse_numerical_param);

/* Parse expires parameter in CONTACT header and return value, offset and length */
static int ct_sip_parse_expires_param_in_contact(const struct nf_conn *ct, const char *dptr,
                                 unsigned int dataoff, unsigned int datalen,
                                 const char *name,
                                 unsigned int *matchoff, unsigned int *matchlen,
                                 unsigned int *val)
{
        const char *limit = dptr + datalen;
        const char *start;
        char *end;

        limit = strstr(dptr + dataoff, "\r\n");
        if (!limit)
                return -1;

        start = ct_sip_header_search(dptr + dataoff, limit, name, strlen(name));
        if (!start)
                return 0;

        start += strlen(name);
        *val = simple_strtoul(start, &end, 0);
        if (start == end)
                return 0;
        if (matchoff && matchlen) {
                *matchoff = start - dptr;
                *matchlen = end - start;
        }
        return 1;
}

static int ct_sip_parse_transport(struct nf_conn *ct, const char *dptr,
				  unsigned int dataoff, unsigned int datalen,
				  u8 *proto)
{
	unsigned int matchoff, matchlen;

	if (ct_sip_parse_param(ct, dptr, dataoff, datalen, "transport=",
			       &matchoff, &matchlen)) {
		if (!strnicmp(dptr + matchoff, "TCP", strlen("TCP")))
			*proto = IPPROTO_TCP;
		else if (!strnicmp(dptr + matchoff, "UDP", strlen("UDP")))
			*proto = IPPROTO_UDP;
		else
			return 0;

		if (*proto != nf_ct_protonum(ct))
			return 0;
	} else
		*proto = nf_ct_protonum(ct);

	return 1;
}

/* SDP header parsing: a SDP session description contains an ordered set of
 * headers, starting with a section containing general session parameters,
 * optionally followed by multiple media descriptions.
 *
 * SDP headers always start at the beginning of a line. According to RFC 2327:
 * "The sequence CRLF (0x0d0a) is used to end a record, although parsers should
 * be tolerant and also accept records terminated with a single newline
 * character". We handle both cases.
 */
static const struct sip_header ct_sdp_hdrs[] = {
	[SDP_HDR_VERSION]		= SDP_HDR("v=", NULL, digits_len),
	[SDP_HDR_OWNER_IP4]		= SDP_HDR("o=", "IN IP4 ", epaddr_len),
	[SDP_HDR_CONNECTION_IP4]	= SDP_HDR("c=", "IN IP4 ", epaddr_len),
	[SDP_HDR_OWNER_IP6]		= SDP_HDR("o=", "IN IP6 ", epaddr_len),
	[SDP_HDR_CONNECTION_IP6]	= SDP_HDR("c=", "IN IP6 ", epaddr_len),
	[SDP_HDR_MEDIA]			= SDP_HDR("m=", NULL, media_len),
};

/* Linear string search within SDP header values */
static const char *ct_sdp_header_search(const char *dptr, const char *limit,
					const char *needle, unsigned int len)
{
	for (limit -= len; dptr < limit; dptr++) {
		if (*dptr == '\r' || *dptr == '\n')
			break;
		if (strncmp(dptr, needle, len) == 0)
			return dptr;
	}
	return NULL;
}

/* Locate a SDP header (optionally a substring within the header value),
 * optionally stopping at the first occurrence of the term header, parse
 * it and return the offset and length of the data we're interested in.
 */
int ct_sip_get_sdp_header(const struct nf_conn *ct, const char *dptr,
			  unsigned int dataoff, unsigned int datalen,
			  enum sdp_header_types type,
			  enum sdp_header_types term,
			  unsigned int *matchoff, unsigned int *matchlen)
{
	const struct sip_header *hdr = &ct_sdp_hdrs[type];
	const struct sip_header *thdr = &ct_sdp_hdrs[term];
	const char *start = dptr, *limit = dptr + datalen;
	int shift = 0;

	for (dptr += dataoff; dptr < limit; dptr++) {
		/* Find beginning of line */
		if (*dptr != '\r' && *dptr != '\n')
			continue;
		if (++dptr >= limit)
			break;
		if (*(dptr - 1) == '\r' && *dptr == '\n') {
			if (++dptr >= limit)
				break;
		}

		if (term != SDP_HDR_UNSPEC &&
		    limit - dptr >= thdr->len &&
		    strnicmp(dptr, thdr->name, thdr->len) == 0)
			break;
		else if (limit - dptr >= hdr->len &&
			 strnicmp(dptr, hdr->name, hdr->len) == 0)
			dptr += hdr->len;
		else
			continue;

		*matchoff = dptr - start;
		if (hdr->search) {
			dptr = ct_sdp_header_search(dptr, limit, hdr->search,
						    hdr->slen);
			if (!dptr)
				return -1;
			dptr += hdr->slen;
		}

		*matchlen = hdr->match_len(ct, dptr, limit, &shift);
		if (!*matchlen)
			return -1;
		*matchoff = dptr - start + shift;
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ct_sip_get_sdp_header);

static int ct_sip_parse_sdp_addr(const struct nf_conn *ct, const char *dptr,
				 unsigned int dataoff, unsigned int datalen,
				 enum sdp_header_types type,
				 enum sdp_header_types term,
				 unsigned int *matchoff, unsigned int *matchlen,
				 union nf_inet_addr *addr)
{
	int ret;

	ret = ct_sip_get_sdp_header(ct, dptr, dataoff, datalen, type, term,
				    matchoff, matchlen);
	if (ret <= 0)
		return ret;

	if (!parse_addr(ct, dptr + *matchoff, NULL, addr,
			dptr + *matchoff + *matchlen))
		return -1;
	return 1;
}

#if 0
static int refresh_signalling_expectation(struct nf_conn *ct,
					  union nf_inet_addr *addr,
					  u8 proto, __be16 port,
					  unsigned int expires)
{
	struct nf_conn_help *help = nfct_help(ct);
	struct nf_conntrack_expect *exp;
	struct hlist_node *n, *next;
	int found = 0;

	spin_lock_bh(&nf_conntrack_lock);
	hlist_for_each_entry_safe(exp, n, next, &help->expectations, lnode) {
		if (exp->class != SIP_EXPECT_SIGNALLING ||
		    !nf_inet_addr_cmp(&exp->tuple.dst.u3, addr) ||
		    exp->tuple.dst.protonum != proto ||
		    exp->tuple.dst.u.udp.port != port)
			continue;
		if (!del_timer(&exp->timeout))
			continue;
		exp->flags &= ~NF_CT_EXPECT_INACTIVE;
		exp->timeout.expires = jiffies + expires * HZ;
		add_timer(&exp->timeout);
		found = 1;
		break;
	}
	spin_unlock_bh(&nf_conntrack_lock);
	return found;
}

static void flush_expectations(struct nf_conn *ct, bool media)
{
	struct nf_conn_help *help = nfct_help(ct);
	struct nf_conntrack_expect *exp;
	struct hlist_node *n, *next;

	spin_lock_bh(&nf_conntrack_lock);
	hlist_for_each_entry_safe(exp, n, next, &help->expectations, lnode) {
		if ((exp->class != SIP_EXPECT_SIGNALLING) ^ media)
			continue;
		if (!del_timer(&exp->timeout))
			continue;
		nf_ct_unlink_expect(exp);
		nf_ct_expect_put(exp);
		if (!media)
			break;
	}
	spin_unlock_bh(&nf_conntrack_lock);
}
#else
#if SIP_ALG_DEBUG_MODE
static void print_conntrack(struct nf_conn *ct)
{
	printk("\n--------------- %s --------------\n", __FUNCTION__);
	printk("\t Dir 0,src %u.%u.%u.%u:%u, dst %u.%u.%u.%u:%u\n",
		NIPQUAD(ct->tuplehash[0].tuple.src.u3.ip), 
		ntohs(ct->tuplehash[0].tuple.src.u.udp.port),
		NIPQUAD(ct->tuplehash[0].tuple.dst.u3.ip), 
		ntohs(ct->tuplehash[0].tuple.dst.u.udp.port));
	printk("\t Dir 1,src %u.%u.%u.%u:%u, dst %u.%u.%u.%u:%u\n",
		NIPQUAD(ct->tuplehash[1].tuple.src.u3.ip), 
		ntohs(ct->tuplehash[1].tuple.src.u.udp.port),
		NIPQUAD(ct->tuplehash[1].tuple.dst.u3.ip), 
		ntohs(ct->tuplehash[1].tuple.dst.u.udp.port));
	
	printk("--------------- %s --------------\n\n", __FUNCTION__);
}

static void dump_sip_info(void)
{
	struct list_head * pHead, *n;
	struct sip_info *j;
	int i = 1;
	
	read_lock_bh(&sip_info_lock);
	
	printk("\n--------------- %s, Max num %d --------------\n", __FUNCTION__, MAX_SIP_INFO_NUM);
	if(list_empty(&sip_info))
	{
		goto out;
	}	
	list_for_each_safe(pHead, n, &sip_info)
	{	
		j = list_entry(pHead, struct sip_info, head);
		printk("\t%d. expire %lu, exp dst %u.%u.%u.%u:%u, local %u.%u.%u.%u:%u, invite:%d %d il:%d %d\n",
				i,
				(j->timeout.expires - jiffies)/HZ,
				NIPQUAD(j->exp_dst_ip), ntohs(j->exp_dst_port),
				NIPQUAD(j->local_ip), ntohs(j->local_port), ntohs(j->nat_media_port[0]),
				ntohs(j->nat_media_port[1]), ntohs(j->local_media_port[0]), ntohs(j->local_media_port[1]));				
		i++;
	}
out:	

	read_unlock_bh(&sip_info_lock);
	printk("--------------- %s, Current num %d --------------\n\n", __FUNCTION__, g_current_sip_info_num);
}

//Dump expect list
static void dump_expect_list(struct nf_conn *ct)
{
	struct nf_conn_help *help = nfct_help(ct);
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_expect *exp;
	struct hlist_node *n, *next;
	int i = 0, h = 0;
	
	printk("----------------------------------------\n");
	printk("Dump expext start:\n");
	spin_lock_bh(&nf_conntrack_lock);

	if (!net->ct.expect_count)
	{
		printk("\t----\tExpect list empty!\n");
		goto out;
	}

	printk("\tnf_conntrack_expect  count: %d, max 4096\n\n", 
		net->ct.expect_count);

	/*Dump sip ct expect */
	printk("\t----CT expectation----\n");
	
	/*Dump sip expect information*/
	for(i = SIP_EXPECT_SIGNALLING; i < __SIP_EXPECT_MAX; i++)
	{
		printk("\t-%*s count: %d, max %d, timeout %4d\n", 
		12,	
		help->helper->expect_policy[i].name,
		help->expecting[i], 
		help->helper->expect_policy[i].max_expected,
		help->helper->expect_policy[i].timeout);
	}

	printk("\n");
	
	hlist_for_each_entry_safe(exp, n, next, &help->expectations, lnode)
	{
		i++;
		printk("\t----\t%d: %s timer %ld, src=%u.%u.%u.%u:%u, dst=%u.%u.%u.%u:%u"
			", local=%u.%u.%u.%u:%u\n",
			i, (exp->class ? "SIP_EXPECT_AUDIO" : "SIP_EXPECT_SIGNALLING"),
			(long)(exp->timeout.expires - jiffies)/HZ, 
			NIPQUAD(exp->tuple.src.u3.ip), ntohs(exp->tuple.src.u.udp.port),
			NIPQUAD(exp->tuple.dst.u3.ip), ntohs(exp->tuple.dst.u.udp.port),
			NIPQUAD(exp->saved_ip), ntohs(exp->saved_proto.udp.port));
	}
	printk("\t----CT expectation----\n\n");

	printk("\t----Expectation list----\n");

	/*Dump expect list*/
	i = 0;
	for (h = 0; h < nf_ct_expect_hsize; h++)
	{
		hlist_for_each_entry_rcu(exp, n, &net->ct.expect_hash[h], hnode) 
		{ 
			if (!exp || !exp->helper)
			{
				printk("empty expect list.\n");
				break;
			}
			if(strcmp(exp->helper->name, "sip"))
			{
				continue;
			}
			
			i++;
			printk("\t----\t%d:  %s/%s timer %ld src=%u.%u.%u.%u:%u, dst=%u.%u.%u.%u:%u"
				", local=%u.%u.%u.%u:%u\n",
				i, 
				exp->helper->name, exp->helper->expect_policy[exp->class].name,
				(long)(exp->timeout.expires - jiffies)/HZ, 
				NIPQUAD(exp->tuple.src.u3.ip), ntohs(exp->tuple.src.u.udp.port),
				NIPQUAD(exp->tuple.dst.u3.ip), ntohs(exp->tuple.dst.u.udp.port),
				NIPQUAD(exp->saved_ip), ntohs(exp->saved_proto.udp.port));
		}
	}
	printk("\t----Expectation list----\n");

out:
	spin_unlock_bh(&nf_conntrack_lock);
	printk("Dump expext end:\n");
	printk("----------------------------------------\n\n");

}

#endif/*SIP_ALG_DEBUG_MODE*/

struct sip_info *allocSipInfo(void)
{
	struct sip_info *new;
	new = kmalloc(sizeof(struct sip_info), GFP_KERNEL);
	if (!new)
	{
		return NULL;
	}
	memset(new, 0, sizeof(struct sip_info));
	return new;
}

static void sipInfoTimerout(unsigned long ul_sip_info)
{
	struct sip_info *pSaved_info = (void *)ul_sip_info;
	struct list_head * pHead, *n;
	struct sip_info *j;
	unsigned long temp;
	int found = 0;

	SIP_ALG_DBG("sip info %lu time out!",ul_sip_info);

	write_lock_bh(&sip_info_lock);
	if(list_empty(&sip_info))
	{
		goto out;
	}
		
	list_for_each_safe(pHead, n, &sip_info)
	{	
		j = list_entry(pHead, struct sip_info, head);
		temp = (unsigned long)j;
		if(temp == ul_sip_info)
		{
			found = 1;
			list_del(&pSaved_info->head);
			kfree(pSaved_info);
			g_current_sip_info_num--;	
			break;
		}
	}
	
out:
	write_unlock_bh(&sip_info_lock);

	if(found)
	{	
		SIP_ALG_DBG("pSaved_info %lu delete ok\n", ul_sip_info);
	}
	else
	{
		SIP_ALG_DBG("pSaved_info %lu not found\n", ul_sip_info);
	}

#if SIP_ALG_DEBUG_MODE
	dump_sip_info();
#endif/*SIP_ALG_DEBUG_MODE*/
}


static int insertSipInfo(struct sip_info *psip_info, unsigned int expire)
{
	
	write_lock_bh(&sip_info_lock);		

	if(g_current_sip_info_num >= MAX_SIP_INFO_NUM)
	{
		SIP_ALG_DBG("SIP INFO list is full, fail to insert!");
		write_unlock_bh(&sip_info_lock);
		return 0;
	}
	
	g_current_sip_info_num++;
	list_add(&psip_info->head, &sip_info);	
	setup_timer(&psip_info->timeout, sipInfoTimerout, (unsigned long) psip_info);
	psip_info->timeout.expires = jiffies + expire * HZ;
	add_timer(&psip_info->timeout);
	write_unlock_bh(&sip_info_lock);
	
	SIP_ALG_DBG("success to insert sip info to list!");
#if SIP_ALG_DEBUG_MODE
	dump_sip_info();
#endif/*SIP_ALG_DEBUG_MODE*/
	
	return 1;	
}

static struct sip_info *findSipInfobyIp(__be32 addr, __be16 port, enum SIP_INFO_TYPE flag)
{
	struct list_head * pHead, *n;
	struct sip_info *j;
	int found = 0;

	if(list_empty(&sip_info))
	{
		goto out;
	}
	
	list_for_each_safe(pHead, n, &sip_info)
	{	
		j = list_entry(pHead, struct sip_info, head);

		if(EXP_DST == flag)
		{
			if(j->exp_dst_ip== addr && j->exp_dst_port== port)
			{
				found = 1;
				break;	
			}
		}
		else if(LOCAL == flag)
		{
			if(j->local_ip == addr && j->local_port == port)
			{
				found = 1;
				break;	
			}
		}
		else
		{
			break;
		}		
	}
out:	
	return found ? j : NULL;
}

static struct sip_info *findSipInfoByMediaPort(__be32 addr, __be16 nmedia_port, __be16 *lmedia_port, enum SIP_INFO_TYPE flag)
{
	struct list_head * pHead, *n;
	struct sip_info *j;
	int i = 0;
	int found = 0;

	if(list_empty(&sip_info) || NULL == lmedia_port)
	{
		goto out;
	}
	
	list_for_each_safe(pHead, n, &sip_info)
	{	
		j = list_entry(pHead, struct sip_info, head);

		if(EXP_DST == flag)
		{
			if(j->exp_dst_ip == addr)
			{
				for (i = 0; i < SIP_MAX_MEDIA_DESCRIPTION; i++)
				{
					if (j->nat_media_port[i] == nmedia_port)
					{
						*lmedia_port = j->local_media_port[i];
						found = 1;
						break;
					}
				}
				if (found)
					break;	
			}
		}
		else if(LOCAL == flag)
		{
			if(j->local_ip == addr)
			{
				for (i = 0; i < SIP_MAX_MEDIA_DESCRIPTION; i++)
				{
					if (j->nat_media_port[i] == nmedia_port)
					{
						*lmedia_port = j->local_media_port[i];
						found = 1;
						break;
					}
				}
				if (found)
					break;
			}
		}
		else
		{
			break;
		}		
	}
out:	
	return found ? j : NULL;
}


static int updateMediaPort(__be32 src_addr, __be16 src_port, __be16 nmedia_port, __be16 lmedia_port)
{
	struct sip_info *pSip = findSipInfobyIp(src_addr, src_port, LOCAL);
	int i = 0;

	if(NULL == pSip)
		return -1;

	for (i = 0; i < pSip->media_num; i++)
	{
		if (pSip->nat_media_port[i] == nmedia_port)
		{
			pSip->local_media_port[i] = lmedia_port;
			return 0;
		}
	}
	
	if (pSip->media_num < SIP_MAX_MEDIA_DESCRIPTION - 1)
	{
		pSip->nat_media_port[pSip->media_num] = nmedia_port;
		pSip->local_media_port[pSip->media_num] = lmedia_port;
		pSip->media_num++;
		return 0;
	}

	return 1;
}

static int addSipInfo(__be32 dst_ip, __be16 dst_port,
					__be32 local_ip, __be16 local_port,
					__be32 nmedia_port, __be16 lmedia_port,unsigned int expire)
{
 	struct sip_info *psip_info;
	int ret = 0;;
	
	psip_info = allocSipInfo();
	if(psip_info == NULL)
	{
		return 0;
	}

	psip_info->exp_dst_ip = dst_ip;
	psip_info->local_ip = local_ip;	
	psip_info->exp_dst_port = dst_port;
	psip_info->local_port= local_port;
	if (nmedia_port && lmedia_port)
	{
		psip_info->nat_media_port[psip_info->media_num] = nmedia_port;
		psip_info->local_media_port[psip_info->media_num] = lmedia_port;
		psip_info->media_num++;
	}
		
	ret = insertSipInfo(psip_info, expire);

	if(!ret && psip_info)
		kfree(psip_info);

	return  ret;
}
//EXPORT_SYMBOL_GPL(addSipInfo);

static void refreshSipInfo(__be32 addr, __be16 port, unsigned int expire,
						enum SIP_INFO_TYPE flag)
{
	struct sip_info *pSipInfo;

	write_lock_bh(&sip_info_lock);
	pSipInfo = findSipInfobyIp(addr, port, flag);
	if(pSipInfo)
	{
		SIP_ALG_DBG("Refresh sip info, find sip info, dst %u.%u.%u.%u:%u"
			", local %u.%u.%u.%u:%u",
			NIPQUAD(pSipInfo->exp_dst_ip), pSipInfo->exp_dst_port,
			NIPQUAD(pSipInfo->local_ip), pSipInfo->local_port);
		if(del_timer(&pSipInfo->timeout))
		{
			pSipInfo->timeout.expires = jiffies + expire * HZ;
			add_timer(&pSipInfo->timeout);

			SIP_ALG_DBG("Refresh sip info, success to refresh sip info timer, new expire time (%u)!", 
				expire);
		}
	}
	write_unlock_bh(&sip_info_lock);

#if SIP_ALG_DEBUG_MODE
	dump_sip_info();
#endif/*SIP_ALG_DEBUG_MODE*/	
}

static int delSipInfo(__be32 addr, __be16 port, enum SIP_INFO_TYPE flag)
{
	struct sip_info *j;
	int found = 0;

	write_lock_bh(&sip_info_lock);
	j = findSipInfobyIp(addr, port, flag);

	if(NULL != j)
	{	
		del_timer(&j->timeout);
		list_del(&j->head);
		kfree(j);
		g_current_sip_info_num--;
		SIP_ALG_DBG("success to delete sip info!");
	}
	write_unlock_bh(&sip_info_lock);

#if SIP_ALG_DEBUG_MODE
	dump_sip_info();
#endif/*SIP_ALG_DEBUG_MODE*/
	
	return found;
}

static void cleanSipInfoList(void)
{
	struct list_head * pHead, *n;
	struct sip_info *j;

	write_lock_bh(&sip_info_lock);
	if(list_empty(&sip_info))
	{
		goto out;
	}

	list_for_each_safe(pHead, n, &sip_info)
	{	
		j = list_entry(pHead, struct sip_info, head);
		if(NULL != j)
		{
			del_timer(&j->timeout);			
			list_del(&j->head);	
			kfree(j);			
		}
	}
out:	
	g_current_sip_info_num = 0;
	write_unlock_bh(&sip_info_lock);

#if SIP_ALG_DEBUG_MODE
	dump_sip_info();
#endif/*SIP_ALG_DEBUG_MODE*/
}

int map_addr_according_expectition(struct sk_buff *skb,
			__be32 *addr, __be16 *port)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	struct sip_info *pSipInfo;
	__be32 newaddr = 0;
	__be16 newport = 0;

	read_lock_bh(&sip_info_lock);

	/*From wan to lan*/
	if (ct->tuplehash[dir].tuple.src.u3.ip ==	
		ct->tuplehash[!dir].tuple.dst.u3.ip)
	{
		pSipInfo = findSipInfobyIp(*addr, *port, EXP_DST);
		if(NULL == pSipInfo)
			goto out;

		newaddr = pSipInfo->local_ip;
		newport = pSipInfo->local_port;
	}
	else
	{
		pSipInfo = findSipInfobyIp(*addr, *port, LOCAL);
		if(NULL == pSipInfo)
			goto out;
		
		newaddr = pSipInfo->exp_dst_ip;
		newport = pSipInfo->exp_dst_port;
	}
out:		
	read_unlock_bh(&sip_info_lock);

	if (newaddr && newport && (newaddr != *addr || newport != *port))
	{
		*addr = newaddr;
		*port = newport;
	}

	return 1;
}
EXPORT_SYMBOL_GPL(map_addr_according_expectition);

static int refresh_signalling_expectation(struct nf_conn *ct,
					  union nf_inet_addr *addr,
					  __be16 port,
					  unsigned int expires)
{
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_expect *exp;
	struct nf_conntrack_tuple tuple;
	int found = 0;

	SIP_ALG_DBG("Register response, refresh expectation src=0.0.0.0:0 dst=%u.%u.%u.%u:%u",
		NIPQUAD(addr->ip), port);

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.l3num = nf_ct_l3num(ct);
	tuple.dst.protonum	= IPPROTO_UDP;
	tuple.dst.u3 = *addr;
	tuple.dst.u.udp.port = port;

	spin_lock_bh(&nf_conntrack_lock);
	exp = __nf_ct_expect_find(net, nf_ct_zone(ct), &tuple);
	if(NULL == exp)
	{
		SIP_ALG_DBG("Register response, signalling expectation not find, fail to refresh time!");
		goto out;
	}

	if(del_timer(&exp->timeout))
	{
		exp->timeout.expires = jiffies + (expires + SIP_EXPECT_SIGNALLING_TIMEOUT)* HZ;
		add_timer(&exp->timeout);
		found = 1;

		SIP_ALG_DBG("Register response, success to refresh expectation, new expire time (%u)!", 
			(expires + SIP_EXPECT_SIGNALLING_TIMEOUT));
		SIP_ALG_DBG("Register response, signalling expectation : src %u.%u.%u.%u:%u, dst %u.%u.%u.%u:%u"
			", local %u.%u.%u.%u:%u",
			NIPQUAD(exp->tuple.src.u3.ip), exp->tuple.src.u.udp.port,
			NIPQUAD(exp->tuple.dst.u3.ip), exp->tuple.dst.u.udp.port,
			NIPQUAD(exp->saved_ip), exp->saved_proto.udp.port);
	}
	else
	{
		SIP_ALG_DBG("Register response, delete timer error, fail to refresh time!");
	}
out:
	spin_unlock_bh(&nf_conntrack_lock);

	if(found)
	{
		refreshSipInfo(addr->ip, port, expires, EXP_DST);
	}

#if SIP_ALG_DEBUG_MODE
		dump_expect_list(ct);
#endif/*SIP_ALG_DEBUG_MODE*/
	
	return found;
}

static void flush_expectations(struct nf_conn *ct, 
	 				union nf_inet_addr *addr,
					 __be16 port)
{
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_expect *exp;
	struct nf_conntrack_tuple tuple;

	SIP_ALG_DBG("Register response, flush expectation src 0.0.0.0:0, dst %u.%u.%u.%u:%u.",
		NIPQUAD(addr->ip), port);

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.l3num = nf_ct_l3num(ct);
	tuple.dst.protonum	= IPPROTO_UDP;
	tuple.dst.u3 = *addr;
	tuple.dst.u.udp.port = port;

	spin_lock_bh(&nf_conntrack_lock);
	exp = __nf_ct_expect_find(net, nf_ct_zone(ct), &tuple);
	if(NULL == exp)
	{
		SIP_ALG_DBG("Register response, signalling expectation not find, fail to flush!");
		goto out;
	}

	SIP_ALG_DBG("Register response, find signalling expectation: timer %ld, src %u.%u.%u.%u:%u, dst %u.%u.%u.%u:%u"
			", local %u.%u.%u.%u:%u.",
			(long)(exp->timeout.expires - jiffies)/HZ, 
			NIPQUAD(exp->tuple.src.u3.ip), exp->tuple.src.u.udp.port,
			NIPQUAD(exp->tuple.dst.u3.ip), exp->tuple.dst.u.udp.port,
			NIPQUAD(exp->saved_ip), exp->saved_proto.udp.port);
	
	if (del_timer(&exp->timeout))
	{
		nf_ct_unlink_expect(exp);
		nf_ct_expect_put(exp);
		SIP_ALG_DBG("Register response, success to flush signalling expectation!");
	}
	else
	{
		SIP_ALG_DBG("Register response, delete timer error, fail to flush!");
	}
out:
	spin_unlock_bh(&nf_conntrack_lock);

	delSipInfo(addr->ip, port, EXP_DST);
	
#if SIP_ALG_DEBUG_MODE
		dump_expect_list(ct);
#endif/*SIP_ALG_DEBUG_MODE*/	
}
#endif/*0*/

/* For local directly invite response.*/
static int set_expected_invite_response(struct sk_buff *skb,
		       const char **dptr, unsigned int *datalen,
		       unsigned int cseq) 
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	struct nf_conntrack_expect * exp;
	unsigned int matchoff = 0;
	unsigned int matchlen = 0;
	union nf_inet_addr daddr;
	__be16 port;
	int ret;
	typeof(nf_nat_sip_response_expect_hook) nf_nat_sip_response_expect;

	if (ct->tuplehash[dir].tuple.src.u3.ip != ct->tuplehash[!dir].tuple.dst.u3.ip)
	{
		SIP_ALG_DBG("Local invite response, don't need invite response expectation!");
		return NF_ACCEPT;
	}
	else
	{
		SIP_ALG_DBG("Remote invite response, build invite response expectation!");
	}
	
	ret = ct_sip_parse_header_uri(ct, *dptr, NULL, *datalen,
			      SIP_HDR_CONTACT, NULL,
			      &matchoff, &matchlen, &daddr, &port);
	if(!matchlen)
	{
		return 0;
	}

	/*For inter call*/
	if(daddr.ip == ct->tuplehash[dir].tuple.dst.u3.ip)
	{	
		SIP_ALG_DBG("Remote invite response, Inter call don't need invite response expectation!");
		return 0;
	}

	exp = nf_ct_expect_alloc(ct);
	if (exp == NULL)
	{
		return 0;
	}
	
	nf_ct_expect_init(exp, SIP_EXPECT_SIGNALLING, nf_ct_l3num(ct), NULL, &daddr,
			  IPPROTO_UDP, NULL, &port);

	exp->timeout.expires = sip_timeout * HZ;
	exp->helper = nfct_help(ct)->helper;

	SIP_ALG_DBG("Remote invite response expectation src %u.%u.%u.%u:%u,"
			" dst %u.%u.%u.%u:%u",		
			NIPQUAD(exp->tuple.src.u3.ip), ntohs(exp->tuple.src.u.udp.port), 	
			NIPQUAD(exp->tuple.dst.u3.ip), ntohs(exp->tuple.dst.u.udp.port));
	
	nf_nat_sip_response_expect = rcu_dereference(nf_nat_sip_response_expect_hook);
	if (nf_nat_sip_response_expect && ct->status & IPS_NAT_MASK)
	{
		ret = nf_nat_sip_response_expect(skb, dptr, datalen, exp);
	}
	else 
	{
		if (nf_ct_expect_related(exp) != 0)
		{
			ret = 0;
		}
		else
		{
			ret = 1;
		}
	}
	nf_ct_expect_put(exp);

	return ret;
}

static int set_expected_rtp_rtcp(struct sk_buff *skb, unsigned int dataoff,
				 const char **dptr, unsigned int *datalen,
				 union nf_inet_addr *daddr, __be16 port,
				 enum sip_expectation_classes class,
				 unsigned int mediaoff, unsigned int medialen)
{
#if 0
	struct nf_conntrack_expect *exp, *rtp_exp, *rtcp_exp;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct net *net = nf_ct_net(ct);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	union nf_inet_addr *saddr;
	struct nf_conntrack_tuple tuple;
	int direct_rtp = 0, skip_expect = 0, ret = NF_DROP;
	u_int16_t base_port;
#else
        struct nf_conntrack_expect *rtp_exp, *rtcp_exp;
        enum ip_conntrack_info ctinfo;
        struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
        union nf_inet_addr *saddr;
        union nf_inet_addr daddr_bk;
        int direct_rtp = 0, ret = NF_DROP;
        u_int16_t base_port;
        struct net_device *dev_br = NULL;
        struct in_device *pdev_ipaddr = NULL;
        __be32 netmask = htonl(0xffffff00);
        __be32 localIp = 0;
#endif/*0*/
	__be16 rtp_port, rtcp_port;
	typeof(nf_nat_sdp_port_hook) nf_nat_sdp_port;
	typeof(nf_nat_sdp_media_hook) nf_nat_sdp_media;
#if 0
	saddr = NULL;
	if (sip_direct_media) {
		/*if (!nf_inet_addr_cmp(daddr, &ct->tuplehash[dir].tuple.src.u3))
			return NF_ACCEPT;*/
		saddr = &ct->tuplehash[!dir].tuple.src.u3;
	}

	/* We need to check whether the registration exists before attempting
	 * to register it since we can see the same media description multiple
	 * times on different connections in case multiple endpoints receive
	 * the same call.
	 *
	 * RTP optimization: if we find a matching media channel expectation
	 * and both the expectation and this connection are SNATed, we assume
	 * both sides can reach each other directly and use the final
	 * destination address from the expectation. We still need to keep
	 * the NATed expectations for media that might arrive from the
	 * outside, and additionally need to expect the direct RTP stream
	 * in case it passes through us even without NAT.
	 */
	memset(&tuple, 0, sizeof(tuple));
	if (saddr)
		tuple.src.u3 = *saddr;
	tuple.src.l3num		= nf_ct_l3num(ct);
	tuple.dst.protonum	= IPPROTO_UDP;
	tuple.dst.u3		= *daddr;
	tuple.dst.u.udp.port	= port;

        dump_expect_list(ct);
        dump_sip_info();

	rcu_read_lock();
	do {
		exp = __nf_ct_expect_find(net, nf_ct_zone(ct), &tuple);

                if (exp)
                {
                        SIP_ALG_DBG("saved ip:%pI4, port:%d", &exp->saved_ip, exp->saved_proto.udp.port);
                        SIP_ALG_DBG("master ?= %d, help ?= %d, class e:t %d:%d", exp->master == ct ? 1:0, 
                                nfct_help(exp->master)->helper != nfct_help(ct)->helper ? 1:0,
                                exp->class, class);
                }

		if (!exp || exp->master == ct ||
		    nfct_help(exp->master)->helper != nfct_help(ct)->helper ||
		    exp->class != class)
			break;
#ifdef CONFIG_NF_NAT_NEEDED
                SIP_ALG_DBG("saved ip:%pI4, port:%d", &exp->saved_ip, exp->saved_proto.udp.port);
		if (exp->tuple.src.l3num == AF_INET && !direct_rtp &&
		    (exp->saved_ip != exp->tuple.dst.u3.ip ||
		     exp->saved_proto.udp.port != exp->tuple.dst.u.udp.port) &&
		    ct->status & IPS_NAT_MASK) {
			daddr->ip		= exp->saved_ip;
			tuple.dst.u3.ip		= exp->saved_ip;
			tuple.dst.u.udp.port	= exp->saved_proto.udp.port;
			direct_rtp = 1;
		} else
#endif
			skip_expect = 1;
	} while (!skip_expect);
	rcu_read_unlock();

	base_port = ntohs(tuple.dst.u.udp.port) & ~1;
	rtp_port = htons(base_port);
	rtcp_port = htons(base_port + 1);

        SIP_ALG_DBG("media dstip:%pI4, port:%d, direct_rtp:%d", &daddr->ip, base_port, direct_rtp);
	if (direct_rtp) {
		nf_nat_sdp_port = rcu_dereference(nf_nat_sdp_port_hook);
		if (nf_nat_sdp_port &&
		    !nf_nat_sdp_port(skb, dataoff, dptr, datalen,
				     mediaoff, medialen, ntohs(rtp_port)))
			goto err1;
	}

	if (skip_expect)
		return NF_ACCEPT;

#endif/*0*/

#if 1
	saddr = NULL;
	direct_rtp = 0;
        memcpy(&daddr_bk, daddr, sizeof(daddr_bk));
#ifdef CONFIG_NF_NAT_NEEDED
        /*Build rtp expectation for lan ports sip phones.*/
        if (ct->tuplehash[dir].tuple.src.u3.ip
                == ct->tuplehash[!dir].tuple.dst.u3.ip)
        {
                struct sip_info * pSip = findSipInfoByMediaPort(daddr->ip, port, &base_port, EXP_DST);
                if (pSip && pSip->local_ip != ct->tuplehash[!dir].tuple.src.u3.ip
                                && pSip->local_port != ct->tuplehash[!dir].tuple.src.u.all)
                {
                        daddr->ip = pSip->local_ip;
                        port = base_port;
                        direct_rtp = 1;
                        SIP_ALG_DBG("change sip dstip:%pI4, port:%d, direct_rtp:%d", &daddr->ip, base_port, direct_rtp);
                }
        }
        else
        {
                dev_br = dev_get_by_name(&init_net, lan_br_name);
                if (dev_br == NULL) {
                        printk(KERN_ERR "sip alg can't get dev %s\n", lan_br_name);
                }
                else
                {
                        if (dev_br->ip_ptr)
                        {
                                pdev_ipaddr = (struct in_device *) dev_br->ip_ptr;
                                if (pdev_ipaddr->ifa_list)
                                {
                                        netmask = pdev_ipaddr->ifa_list->ifa_mask;
                                        localIp = pdev_ipaddr->ifa_list->ifa_local;
                                        SIP_ALG_DBG("new mask is %pI4", &netmask);
                                        SIP_ALG_DBG("new local ip is %pI4", &netmask);
                                }
                        }

                }
                if(dev_br)
                {
                        dev_put(dev_br);
                }
                if ((daddr_bk.ip & netmask) != (ct->tuplehash[dir].tuple.src.u3.ip & netmask))
                {
                        SIP_ALG_DBG("client ip %pI4 != media ip %pI4, donot change sdp.", &ct->tuplehash[dir].tuple.src.u3.ip, &daddr_bk.ip);
                        return NF_ACCEPT;
                }

        }
#endif /*CONFIG_NF_NAT_NEEDED*/
        base_port = ntohs(port) & ~1;
        rtp_port = htons(base_port);
        rtcp_port = htons(base_port + 1);

        SIP_ALG_DBG("media dstip:%pI4, port:%d, direct_rtp:%d", &daddr->ip, base_port, direct_rtp);
        if (direct_rtp) {
                nf_nat_sdp_port = rcu_dereference(nf_nat_sdp_port_hook);
                if (nf_nat_sdp_port &&
                        !nf_nat_sdp_port(skb, dataoff, dptr, datalen,
                                         mediaoff, medialen, ntohs(rtp_port)))
                        goto err1;
        }
#endif

	rtp_exp = nf_ct_expect_alloc(ct);
	if (rtp_exp == NULL)
		goto err1;
	nf_ct_expect_init(rtp_exp, class, nf_ct_l3num(ct), saddr, daddr,
			  IPPROTO_UDP, NULL, &rtp_port);

	rtcp_exp = nf_ct_expect_alloc(ct);
	if (rtcp_exp == NULL)
		goto err2;
	nf_ct_expect_init(rtcp_exp, class, nf_ct_l3num(ct), saddr, daddr,
			  IPPROTO_UDP, NULL, &rtcp_port);

	nf_nat_sdp_media = rcu_dereference(nf_nat_sdp_media_hook);
	if (nf_nat_sdp_media && ct->status & IPS_NAT_MASK && !direct_rtp)
	{
		ret = nf_nat_sdp_media(skb, dataoff, dptr, datalen,
				       rtp_exp, rtcp_exp,
				       mediaoff, medialen, daddr);
		SIP_ALG_DBG("nat sip srcip:%pI4, port:%d, mediaip:%pI4, mediaport:%d", &ct->tuplehash[dir].tuple.src.u3.ip,
                ntohs(ct->tuplehash[dir].tuple.src.u.udp.port), &daddr->ip, ntohs(rtp_exp->tuple.dst.u.all));
                if (NF_ACCEPT == ret && ct->tuplehash[dir].tuple.src.u3.ip != ct->tuplehash[!dir].tuple.dst.u3.ip &&
		(daddr_bk.ip & netmask) == (localIp & netmask) && 
                     updateMediaPort(ct->tuplehash[dir].tuple.src.u3.ip, ct->tuplehash[dir].tuple.src.u.udp.port, rtp_exp->tuple.dst.u.all, rtp_port) < 0)
                {
                        SIP_ALG_DBG("add new sip srcip:%pI4, port:%d, invite:%d", &ct->tuplehash[dir].tuple.src.u3.ip,
                                ntohs(ct->tuplehash[dir].tuple.src.u.udp.port), ntohs(rtp_exp->tuple.dst.u.all));
                        addSipInfo(ct->tuplehash[!dir].tuple.dst.u3.ip, ct->tuplehash[!dir].tuple.dst.u.udp.port,
                                ct->tuplehash[dir].tuple.src.u3.ip, ct->tuplehash[dir].tuple.src.u.udp.port,
                                rtp_exp->tuple.dst.u.all, rtp_port, SIP_EXPECT_SIGNALLING_TIMEOUT);
                }

	}
	else {
		if (nf_ct_expect_related(rtp_exp) == 0) {
			if (nf_ct_expect_related(rtcp_exp) != 0)
				nf_ct_unexpect_related(rtp_exp);
			else
				ret = NF_ACCEPT;
		}
	}
	nf_ct_expect_put(rtcp_exp);
err2:
	nf_ct_expect_put(rtp_exp);
err1:
	return ret;
}

static const struct sdp_media_type sdp_media_types[] = {
	SDP_MEDIA_TYPE("audio ", SIP_EXPECT_AUDIO),
	SDP_MEDIA_TYPE("video ", SIP_EXPECT_VIDEO),
	SDP_MEDIA_TYPE("image ", SIP_EXPECT_IMAGE),
};

static const struct sdp_media_type *sdp_media_type(const char *dptr,
						   unsigned int matchoff,
						   unsigned int matchlen)
{
	const struct sdp_media_type *t;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sdp_media_types); i++) {
		t = &sdp_media_types[i];
		if (matchlen < t->len ||
		    strncmp(dptr + matchoff, t->name, t->len))
			continue;
		return t;
	}
	return NULL;
}

static int process_sdp(struct sk_buff *skb, unsigned int dataoff,
		       const char **dptr, unsigned int *datalen,
		       unsigned int cseq)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	unsigned int matchoff, matchlen;
	unsigned int mediaoff, medialen;
	unsigned int sdpoff;
	unsigned int caddr_len, maddr_len;
	unsigned int i;
	union nf_inet_addr caddr, maddr, rtp_addr;
	unsigned int port;
	enum sdp_header_types c_hdr;
	const struct sdp_media_type *t;
	int ret = NF_ACCEPT;
	typeof(nf_nat_sdp_addr_hook) nf_nat_sdp_addr;
	typeof(nf_nat_sdp_session_hook) nf_nat_sdp_session;

	nf_nat_sdp_addr = rcu_dereference(nf_nat_sdp_addr_hook);
	c_hdr = nf_ct_l3num(ct) == AF_INET ? SDP_HDR_CONNECTION_IP4 :
					     SDP_HDR_CONNECTION_IP6;

	/* Find beginning of session description */
	if (ct_sip_get_sdp_header(ct, *dptr, 0, *datalen,
				  SDP_HDR_VERSION, SDP_HDR_UNSPEC,
				  &matchoff, &matchlen) <= 0)
		return NF_ACCEPT;
	sdpoff = matchoff;

	/* The connection information is contained in the session description
	 * and/or once per media description. The first media description marks
	 * the end of the session description. */
	caddr_len = 0;
	if (ct_sip_parse_sdp_addr(ct, *dptr, sdpoff, *datalen,
				  c_hdr, SDP_HDR_MEDIA,
				  &matchoff, &matchlen, &caddr) > 0)
		caddr_len = matchlen;

	mediaoff = sdpoff;
	for (i = 0; i < ARRAY_SIZE(sdp_media_types); ) {
		if (ct_sip_get_sdp_header(ct, *dptr, mediaoff, *datalen,
					  SDP_HDR_MEDIA, SDP_HDR_UNSPEC,
					  &mediaoff, &medialen) <= 0)
			break;

		/* Get media type and port number. A media port value of zero
		 * indicates an inactive stream. */
		t = sdp_media_type(*dptr, mediaoff, medialen);
		if (!t) {
			mediaoff += medialen;
			continue;
		}
		mediaoff += t->len;
		medialen -= t->len;

		port = simple_strtoul(*dptr + mediaoff, NULL, 10);
		if (port == 0)
			continue;
		if (port < 1024 || port > 65535)
			return NF_DROP;

		/* The media description overrides the session description. */
		maddr_len = 0;
		if (ct_sip_parse_sdp_addr(ct, *dptr, mediaoff, *datalen,
					  c_hdr, SDP_HDR_MEDIA,
					  &matchoff, &matchlen, &maddr) > 0) {
			maddr_len = matchlen;
			memcpy(&rtp_addr, &maddr, sizeof(rtp_addr));
		} else if (caddr_len)
			memcpy(&rtp_addr, &caddr, sizeof(rtp_addr));
		else
			return NF_DROP;

                SIP_ALG_DBG("media rtpaddr:%pI4, port:%d", &rtp_addr.ip, port);

		ret = set_expected_rtp_rtcp(skb, dataoff, dptr, datalen,
					    &rtp_addr, htons(port), t->class,
					    mediaoff, medialen);
		if (ret != NF_ACCEPT)
			return ret;

		/* Update media connection address if present */
		if (maddr_len && nf_nat_sdp_addr && ct->status & IPS_NAT_MASK) {
			ret = nf_nat_sdp_addr(skb, dataoff, dptr, datalen,
					      mediaoff, c_hdr, SDP_HDR_MEDIA,
					      &rtp_addr);
			if (ret != NF_ACCEPT)
				return ret;
		}
		i++;
	}

	/* Update session connection and owner addresses */
	nf_nat_sdp_session = rcu_dereference(nf_nat_sdp_session_hook);
	if (nf_nat_sdp_session && ct->status & IPS_NAT_MASK)
		ret = nf_nat_sdp_session(skb, dataoff, dptr, datalen, sdpoff,
					 &rtp_addr);

	return ret;
}
static int process_invite_response(struct sk_buff *skb, unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
				   unsigned int cseq, unsigned int code)
{
	if ((code >= 100 && code <= 199) ||
	    (code >= 200 && code <= 299))
	{
		set_expected_invite_response(skb, dptr, datalen, cseq);
		return process_sdp(skb, dataoff, dptr, datalen, cseq);
	}
	return NF_ACCEPT;
}

static int process_update_response(struct sk_buff *skb, unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
				   unsigned int cseq, unsigned int code)
{
	if ((code >= 100 && code <= 199) ||
	    (code >= 200 && code <= 299))
	{
                set_expected_invite_response(skb, dptr, datalen, cseq);
		return process_sdp(skb, dataoff, dptr, datalen, cseq);
	}	
	return NF_ACCEPT;
}

static int process_prack_response(struct sk_buff *skb, unsigned int dataoff,
				  const char **dptr, unsigned int *datalen,
				  unsigned int cseq, unsigned int code)
{
	if ((code >= 100 && code <= 199) ||
	    (code >= 200 && code <= 299))
	{
                set_expected_invite_response(skb, dptr, datalen, cseq);
		return process_sdp(skb, dataoff, dptr, datalen, cseq);
	}	
	return NF_ACCEPT;
}

static int process_invite_request(struct sk_buff *skb, unsigned int dataoff,
				  const char **dptr, unsigned int *datalen,
				  unsigned int cseq)
{
	unsigned int ret;

	ret = process_sdp(skb, dataoff, dptr, datalen, cseq);
	return ret;
}

static int process_bye_request(struct sk_buff *skb, unsigned int dataoff,
			       const char **dptr, unsigned int *datalen,
			       unsigned int cseq)
{
	return NF_ACCEPT;
}

/* Parse a REGISTER request and create a permanent expectation for incoming
 * signalling connections. The expectation is marked inactive and is activated
 * when receiving a response indicating success from the registrar.
 */
static int process_register_request(struct sk_buff *skb, unsigned int dataoff,
				    const char **dptr, unsigned int *datalen,
				    unsigned int cseq)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_conn_help *help = nfct_help(ct);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned int matchoff, matchlen;
	struct nf_conntrack_expect *exp;
        struct hlist_node *n, *next;
        int found = 0;
	union nf_inet_addr *saddr, daddr;
	__be16 port;
	u8 proto;
        unsigned int expires = 5; /* any non-zero value just in case there is no Expires Header */
	int ret;
	typeof(nf_nat_sip_expect_hook) nf_nat_sip_expect;
        unsigned int exp_expire = 0;

	/* Expected connections can not register again. */
	if (ct->status & IPS_EXPECTED)
		return NF_ACCEPT;

	/* We must check the expiration time: a value of zero signals the
	 * registrar to release the binding. We'll remove our expectation
	 * when receiving the new bindings in the response, but we don't
	 * want to create new ones.
	 *
	 * The expiration time may be contained in Expires: header, the
	 * Contact: header parameters or the URI parameters.
	 */
	if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_EXPIRES,
			      &matchoff, &matchlen) > 0)
		expires = simple_strtoul(*dptr + matchoff, NULL, 10);

	ret = ct_sip_parse_header_uri(ct, *dptr, NULL, *datalen,
				      SIP_HDR_CONTACT, NULL,
				      &matchoff, &matchlen, &daddr, &port);
	if (ret < 0)
		return NF_DROP;
	else if (ret == 0)
		return NF_ACCEPT;

	/* We don't support third-party registrations */
	if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.src.u3, &daddr))
	{
                //printk("Sip Alg : Third-party registrations, don't support, src ip %u.%u.%u.%u, contact %u.%u.%u.%u.\n", NIPQUAD(ct->tuplehash[dir].tuple.src.u3.ip), NIPQUAD(daddr.ip));
		return NF_ACCEPT;
	}

	if (ct_sip_parse_transport(ct, *dptr, matchoff + matchlen, *datalen,
				   &proto) == 0)
		return NF_ACCEPT;

	if (ct_sip_parse_expires_param_in_contact(ct, *dptr,
					 matchoff + matchlen, *datalen,
					 "expires=", NULL, NULL, &expires) < 0)
		return NF_DROP;

	/*Release binding request, return*/
        if (expires == 0)
        {
                SIP_ALG_DBG("Register request, expires %u, release binding.", expires);
                return NF_ACCEPT;
        }

        /*For IAD, Iad phone don't need expectation*/
        if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip ==
                ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip &&
                ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip ==
                ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip)
        {
                SIP_ALG_DBG("Direct signalling, Don't need expectation!");
                return NF_ACCEPT;
        }

        /*Try to find the signalling expectation*/
        spin_lock_bh(&nf_conntrack_lock);
        hlist_for_each_entry_safe(exp, n, next, &help->expectations, lnode)
        {
                if (exp->class != SIP_EXPECT_SIGNALLING ||
                    (exp->saved_ip != daddr.ip) ||
                    (exp->saved_proto.udp.port != port))
                {
                        continue;
                }

                found = 1;

                /*Dump expectation*/
                SIP_ALG_DBG("Register request, find corresponding signalling expectation :src=%u.%u.%u.%u:%u,"
                        " dst=%u.%u.%u.%u:%u",
                        NIPQUAD(exp->tuple.src.u3.ip), ntohs(exp->tuple.src.u.udp.port),
                        NIPQUAD(exp->tuple.dst.u3.ip), ntohs(exp->tuple.dst.u.udp.port));

                if(((long)(exp->timeout.expires - jiffies)/HZ -
                        (long)SIP_EXPECT_SIGNALLING_TIMEOUT) >= 0)
                {
                        SIP_ALG_DBG("Register request, signalling expectation Expires (%ld), no need to refresh!",
                                (long)(exp->timeout.expires - jiffies) /HZ);
                        exp_expire = (exp->timeout.expires - jiffies) / HZ;
                        break;
                }

                if (del_timer(&exp->timeout))
                {
                        SIP_ALG_DBG("Register request, refresh signalling expectation, old timer (%ld), new timer (%d)", 
                                (long)(exp->timeout.expires - jiffies) /HZ,
                                SIP_EXPECT_SIGNALLING_TIMEOUT);
                        exp->timeout.expires = jiffies + SIP_EXPECT_SIGNALLING_TIMEOUT * HZ;
                        add_timer(&exp->timeout);
                        exp_expire = (exp->timeout.expires - jiffies) / HZ;
                        break;
                }
        }
        spin_unlock_bh(&nf_conntrack_lock);

        /*No need to build signalling expectation again, Just return*/
        if(found)
        {
#if SIP_ALG_DEBUG_MODE
                dump_expect_list(ct);
#endif/*SIP_ALG_DEBUG_MODE*/
                if(exp_expire)
                        refreshSipInfo(daddr.ip, port, exp_expire, LOCAL);
                return NF_ACCEPT;
        }

	exp = nf_ct_expect_alloc(ct);
	if (!exp)
		return NF_DROP;

        SIP_ALG_DBG("Register request, build signalling expectation.");

	saddr = NULL;
	nf_ct_expect_init(exp, SIP_EXPECT_SIGNALLING, nf_ct_l3num(ct),
			  saddr, &daddr, proto, NULL, &port);
	exp->timeout.expires = sip_timeout * HZ;
	exp->helper = nfct_help(ct)->helper;
	exp->flags = NF_CT_EXPECT_PERMANENT;

	nf_nat_sip_expect = rcu_dereference(nf_nat_sip_expect_hook);
	if (nf_nat_sip_expect && ct->status & IPS_NAT_MASK)
	{
		ret = nf_nat_sip_expect(skb, dataoff, dptr, datalen, exp,
					matchoff, matchlen);
		if(NF_ACCEPT == ret && exp)
                {
                        addSipInfo(exp->tuple.dst.u3.ip, exp->tuple.dst.u.all,
                                exp->saved_ip, exp->saved_proto.all, 0, 0, SIP_EXPECT_SIGNALLING_TIMEOUT);
                }
	}
	else {
		if (nf_ct_expect_related(exp) != 0)
			ret = NF_DROP;
		else
			ret = NF_ACCEPT;
	}
	nf_ct_expect_put(exp);

#if SIP_ALG_DEBUG_MODE
                dump_expect_list(ct);
#endif/*SIP_ALG_DEBUG_MODE*/

	return ret;
}

static int process_register_response(struct sk_buff *skb, unsigned int dataoff,
				     const char **dptr, unsigned int *datalen,
				     unsigned int cseq, unsigned int code)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	//struct nf_conn_help *help = nfct_help(ct);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	union nf_inet_addr addr;
	__be16 port;
	u8 proto;
	unsigned int matchoff, matchlen, coff = 0;
	unsigned int expires = 0;
	int in_contact = 0, ret;
        int found_expires = 0;

	/* According to RFC 3261, "UAs MUST NOT send a new registration until
	 * they have received a final response from the registrar for the
	 * previous one or the previous REGISTER request has timed out".
	 *
	 * However, some servers fail to detect retransmissions and send late
	 * responses, so we store the sequence number of the last valid
	 * request and compare it here.
	 */

	if (code >= 100 && code <= 199)
		return NF_ACCEPT;
	if (code < 200 || code > 299)
		goto flush;

	if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_EXPIRES,
			      &matchoff, &matchlen) > 0)
	{
                found_expires = 1;
		expires = simple_strtoul(*dptr + matchoff, NULL, 10);
	}

	while (1) {
		unsigned int c_expires = expires;

		ret = ct_sip_parse_header_uri(ct, *dptr, &coff, *datalen,
					      SIP_HDR_CONTACT, &in_contact,
					      &matchoff, &matchlen,
					      &addr, &port);
		if (ret < 0)
			return NF_DROP;
		else if (ret == 0)
			break;

		/* We don't support third-party registrations */
		if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.dst.u3, &addr))
			continue;

		if (ct_sip_parse_transport(ct, *dptr, matchoff + matchlen,
					   *datalen, &proto) == 0)
			continue;

		ret = ct_sip_parse_expires_param_in_contact(ct, *dptr,
						   matchoff + matchlen,
						   *datalen, "expires=",
						   NULL, NULL, &c_expires);
		if (ret < 0)
			return NF_DROP;
                else if(ret > 0)
                        found_expires = 1;

                /*expires is needed*/
                if (!found_expires)
                        continue;

		if (c_expires == 0)
			break;

                if (refresh_signalling_expectation(ct, &addr, port, c_expires))
                        return NF_ACCEPT;
	}

flush:
        flush_expectations(ct, &addr, port);
	return NF_ACCEPT;
}

static const struct sip_handler sip_handlers[] = {
	SIP_HANDLER("INVITE", process_invite_request, process_invite_response),
	SIP_HANDLER("UPDATE", process_sdp, process_update_response),
	SIP_HANDLER("ACK", process_sdp, NULL),
	SIP_HANDLER("PRACK", process_sdp, process_prack_response),
	SIP_HANDLER("BYE", process_bye_request, NULL),
	SIP_HANDLER("REGISTER", process_register_request, process_register_response),
};

static int process_sip_response(struct sk_buff *skb, unsigned int dataoff,
				const char **dptr, unsigned int *datalen)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	unsigned int matchoff, matchlen, matchend;
	unsigned int code, cseq, i;

#if SIP_ALG_DEBUG_MODE
        char str[30] = {0};
#endif/* SIP_ALG_DEBUG_MODE*/

	if (*datalen < strlen("SIP/2.0 200"))
		return NF_ACCEPT;
	code = simple_strtoul(*dptr + strlen("SIP/2.0 "), NULL, 10);
	if (!code)
		return NF_DROP;

	if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_CSEQ,
			      &matchoff, &matchlen) <= 0)
		return NF_DROP;
	cseq = simple_strtoul(*dptr + matchoff, NULL, 10);
	if (!cseq)
		return NF_DROP;
	matchend = matchoff + matchlen + 1;

	for (i = 0; i < ARRAY_SIZE(sip_handlers); i++) {
		const struct sip_handler *handler;

		handler = &sip_handlers[i];
		if (handler->response == NULL)
			continue;
		if (*datalen < matchend + handler->len ||
		    strnicmp(*dptr + matchend, handler->method, handler->len))
			continue;

#if SIP_ALG_DEBUG_MODE
                memcpy(str, handler->method, handler->len);
                SIP_ALG_DBG("Response %s, code %u", str, code);
#endif/* SIP_ALG_DEBUG_MODE*/

		return handler->response(skb, dataoff, dptr, datalen,
					 cseq, code);
	}
	return NF_ACCEPT;
}

static int process_sip_request(struct sk_buff *skb, unsigned int dataoff,
			       const char **dptr, unsigned int *datalen)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_conn_help *help = nfct_help(ct);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned int matchoff, matchlen;
	unsigned int cseq, i;
	union nf_inet_addr addr;
	__be16 port;
#if SIP_ALG_DEBUG_MODE
        char str[30] = {0};
#endif/* SIP_ALG_DEBUG_MODE*/

	/* Many Cisco IP phones use a high source port for SIP requests, but
	 * listen for the response on port 5060.  If we are the local
	 * router for one of these phones, save the port number from the
	 * Via: header so that nf_nat_sip can redirect the responses to
	 * the correct port.
	 */
	if (ct_sip_parse_header_uri(ct, *dptr, NULL, *datalen,
				    SIP_HDR_VIA_UDP, NULL, &matchoff,
				    &matchlen, &addr, &port) > 0 &&
	    port != ct->tuplehash[dir].tuple.src.u.udp.port &&
	    nf_inet_addr_cmp(&addr, &ct->tuplehash[dir].tuple.src.u3))
		help->help.ct_sip_info.forced_dport = port;

	for (i = 0; i < ARRAY_SIZE(sip_handlers); i++) {
		const struct sip_handler *handler;

		handler = &sip_handlers[i];
		if (handler->request == NULL)
			continue;
		if (*datalen < handler->len ||
		    strnicmp(*dptr, handler->method, handler->len))
			continue;

#if SIP_ALG_DEBUG_MODE
                memcpy(str, handler->method, handler->len);
                SIP_ALG_DBG("Request %s", str);
#endif/* SIP_ALG_DEBUG_MODE*/

		if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_CSEQ,
				      &matchoff, &matchlen) <= 0)
			return NF_DROP;
		cseq = simple_strtoul(*dptr + matchoff, NULL, 10);
		if (!cseq)
			return NF_DROP;

		return handler->request(skb, dataoff, dptr, datalen, cseq);
	}
	return NF_ACCEPT;
}

static int process_sip_msg(struct sk_buff *skb, struct nf_conn *ct,
			   unsigned int dataoff, const char **dptr,
			   unsigned int *datalen)
{
	typeof(nf_nat_sip_hook) nf_nat_sip;
	int ret;

#if SIP_ALG_DEBUG_MODE
        print_conntrack(ct);
#endif/*SIP_ALG_DEBUG_MODE*/

	if (strnicmp(*dptr, "SIP/2.0 ", strlen("SIP/2.0 ")) != 0)
		ret = process_sip_request(skb, dataoff, dptr, datalen);
	else
		ret = process_sip_response(skb, dataoff, dptr, datalen);

	if (ret == NF_ACCEPT && ct->status & IPS_NAT_MASK) {
		nf_nat_sip = rcu_dereference(nf_nat_sip_hook);
		if (nf_nat_sip && !nf_nat_sip(skb, dataoff, dptr, datalen))
			ret = NF_DROP;
	}

	return ret;
}

static int sip_help_tcp(struct sk_buff *skb, unsigned int protoff,
			struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	struct tcphdr *th, _tcph;
	unsigned int dataoff, datalen;
	unsigned int matchoff, matchlen, clen;
	unsigned int msglen, origlen;
	const char *dptr, *end;
	s16 diff, tdiff = 0;
	int ret = NF_ACCEPT;
	bool term;
	typeof(nf_nat_sip_seq_adjust_hook) nf_nat_sip_seq_adjust;

	if (ctinfo != IP_CT_ESTABLISHED &&
	    ctinfo != IP_CT_ESTABLISHED_REPLY)
		return NF_ACCEPT;

	/* No Data ? */
	th = skb_header_pointer(skb, protoff, sizeof(_tcph), &_tcph);
	if (th == NULL)
		return NF_ACCEPT;
	dataoff = protoff + th->doff * 4;
	if (dataoff >= skb->len)
		return NF_ACCEPT;

	nf_ct_refresh(ct, skb, sip_timeout * HZ);

	if (unlikely(skb_linearize(skb)))
		return NF_DROP;

	dptr = skb->data + dataoff;
	datalen = skb->len - dataoff;
	if (datalen < strlen("SIP/2.0 200"))
		return NF_ACCEPT;

	while (1) {
		if (ct_sip_get_header(ct, dptr, 0, datalen,
				      SIP_HDR_CONTENT_LENGTH,
				      &matchoff, &matchlen) <= 0)
			break;

		clen = simple_strtoul(dptr + matchoff, (char **)&end, 10);
		if (dptr + matchoff == end)
			break;

		term = false;
		for (; end + strlen("\r\n\r\n") <= dptr + datalen; end++) {
			if (end[0] == '\r' && end[1] == '\n' &&
			    end[2] == '\r' && end[3] == '\n') {
				term = true;
				break;
			}
		}
		if (!term)
			break;
		end += strlen("\r\n\r\n") + clen;

		msglen = origlen = end - dptr;
		if (msglen > datalen)
			return NF_ACCEPT;

		ret = process_sip_msg(skb, ct, dataoff, &dptr, &msglen);
		if (ret != NF_ACCEPT)
			break;
		diff     = msglen - origlen;
		tdiff   += diff;

		dataoff += msglen;
		dptr    += msglen;
		datalen  = datalen + diff - msglen;
	}

	if (ret == NF_ACCEPT && ct->status & IPS_NAT_MASK) {
		nf_nat_sip_seq_adjust = rcu_dereference(nf_nat_sip_seq_adjust_hook);
		if (nf_nat_sip_seq_adjust)
			nf_nat_sip_seq_adjust(skb, tdiff);
	}

	return ret;
}

static int sip_help_udp(struct sk_buff *skb, unsigned int protoff,
			struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	unsigned int dataoff, datalen;
	const char *dptr;

	/* No Data ? */
	dataoff = protoff + sizeof(struct udphdr);
	if (dataoff >= skb->len)
		return NF_ACCEPT;

	nf_ct_refresh(ct, skb, sip_timeout * HZ);

	if (unlikely(skb_linearize(skb)))
		return NF_DROP;

	dptr = skb->data + dataoff;
	datalen = skb->len - dataoff;
	if (datalen < strlen("SIP/2.0 200"))
		return NF_ACCEPT;

	return process_sip_msg(skb, ct, dataoff, &dptr, &datalen);
}

static struct nf_conntrack_helper sip[MAX_PORTS][4] __read_mostly;
static char sip_names[MAX_PORTS][4][sizeof("sip-65535")] __read_mostly;

static const struct nf_conntrack_expect_policy sip_exp_policy[SIP_EXPECT_MAX + 1] = {
	[SIP_EXPECT_SIGNALLING] = {
		.name		= "signalling",
		.max_expected	= 1,
                .timeout        = SIP_EXPECT_SIGNALLING_TIMEOUT,
	},
	[SIP_EXPECT_AUDIO] = {
		.name		= "audio",
		.max_expected	= 2 * IP_CT_DIR_MAX,
                .timeout        = SIP_EXPECT_MEDIA_TIMEOUT,
	},
	[SIP_EXPECT_VIDEO] = {
		.name		= "video",
		.max_expected	= 2 * IP_CT_DIR_MAX,
                .timeout        = SIP_EXPECT_MEDIA_TIMEOUT,
	},
	[SIP_EXPECT_IMAGE] = {
		.name		= "image",
		.max_expected	= IP_CT_DIR_MAX,
                .timeout        = SIP_EXPECT_MEDIA_TIMEOUT,
	},
};

static void nf_conntrack_sip_fini(void)
{
	int i, j;

        cleanSipInfoList();

	for (i = 0; i < ports_c; i++) {
		for (j = 0; j < ARRAY_SIZE(sip[i]); j++) {
			if (sip[i][j].me == NULL)
				continue;
			nf_conntrack_helper_unregister(&sip[i][j]);
		}
	}
}

static int __init nf_conntrack_sip_init(void)
{
	int i, j, ret;
	char *tmpname;

	if (ports_c == 0)
		ports[ports_c++] = SIP_PORT;

        g_current_sip_info_num = 0;

	for (i = 0; i < ports_c; i++) {
		memset(&sip[i], 0, sizeof(sip[i]));

		sip[i][0].tuple.src.l3num = AF_INET;
		sip[i][0].tuple.dst.protonum = IPPROTO_UDP;
		sip[i][0].help = sip_help_udp;
		sip[i][1].tuple.src.l3num = AF_INET;
		sip[i][1].tuple.dst.protonum = IPPROTO_TCP;
		sip[i][1].help = sip_help_tcp;

		sip[i][2].tuple.src.l3num = AF_INET6;
		sip[i][2].tuple.dst.protonum = IPPROTO_UDP;
		sip[i][2].help = sip_help_udp;
		sip[i][3].tuple.src.l3num = AF_INET6;
		sip[i][3].tuple.dst.protonum = IPPROTO_TCP;
		sip[i][3].help = sip_help_tcp;

		for (j = 0; j < ARRAY_SIZE(sip[i]); j++) {
			sip[i][j].tuple.src.u.udp.port = htons(ports[i]);
			sip[i][j].expect_policy = sip_exp_policy;
			sip[i][j].expect_class_max = SIP_EXPECT_MAX;
			sip[i][j].me = THIS_MODULE;

			tmpname = &sip_names[i][j][0];
			if (ports[i] == SIP_PORT)
				sprintf(tmpname, "sip");
			else
				sprintf(tmpname, "sip-%u", i);
			sip[i][j].name = tmpname;

			pr_debug("port #%u: %u\n", i, ports[i]);

			ret = nf_conntrack_helper_register(&sip[i][j]);
			if (ret) {
				printk(KERN_ERR "nf_ct_sip: failed to register"
				       " helper for pf: %u port: %u\n",
				       sip[i][j].tuple.src.l3num, ports[i]);
				nf_conntrack_sip_fini();
				return ret;
			}
		}
	}
	return 0;
}

module_init(nf_conntrack_sip_init);
module_exit(nf_conntrack_sip_fini);
