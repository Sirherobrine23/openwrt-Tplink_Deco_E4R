//
// Created by xfs on 12/19/17.
//

#include "deco.h"

#include <uci.h>
#include <libubox/kvlist.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

static int kv_get_zero_len(struct kvlist *kv UNUSED_PARAM, const void *data UNUSED_PARAM)
{
	return 0;
}

static inline int format_mac_char(char *ch_formatted, char ch)
{
	if (('0' <= ch && ch <= '9') || ('A' <= ch && ch <= 'Z')) {
		*ch_formatted = ch;
		return 1;
	}

	if ('a' <= ch && ch <= 'z') {
		*ch_formatted = (char) ('A' + (ch - 'a'));
		return 1;
	}

	if (ch == '-' || ch == ':' || ch == ' ') {
		return 0;
	}

	bb_error_msg("Invalid letter in MAC: %u='%c'", ch, ch);
	return -1;
}

static char *format_mac(char *mac, size_t len)
{
	size_t shift = 0;
	char *ptr = mac;

	while (shift < len) {
		int res = format_mac_char(ptr, mac[shift]);
		if (res == -1) {
			break;
		}

		if (res > 0) {
			++ptr;
		}
		++shift;
	}

	if (shift == len) {
		*ptr = '\0';
		return mac;
	}

	return NULL;
}

enum {
    WORK_MODE_ATTR_LINK2AP = 0,
    WORK_MODE_ATTR_CAP_MAC,
    __WORK_MODE_MAX
};

const char *deco_get_cap_mac(void)
{
    static struct blob_buf b;
    static char mac[18] = {'\0'};

    const char *const path = "/tmp/work_mode";

    struct blobmsg_policy policy[__WORK_MODE_MAX] = {
//            [WORK_MODE_ATTR_LINK2AP] =
            { .name = "link2ap", .type = BLOBMSG_TYPE_INT32 },
//            [WORK_MODE_ATTR_CAP_MAC] =
            { .name = "cap_mac", .type = BLOBMSG_TYPE_STRING }
    };

    struct blob_attr *tb[__WORK_MODE_MAX];
    const char *ret = NULL;

    blob_buf_init(&b, 0);
    if (!blobmsg_add_json_from_file(&b, path)) {
        bb_error_msg("Failed to get CAP MAC");
        return NULL;
    }

    blobmsg_parse(policy, ARRAY_SIZE(policy), tb, blob_data(b.head), blob_len(b.head));
    if (tb[WORK_MODE_ATTR_CAP_MAC] == NULL) {
        goto finished;
    }

    strncpy(mac, blobmsg_get_string(tb[WORK_MODE_ATTR_CAP_MAC]), sizeof(mac) - 1);
    ret = format_mac(mac, strlen(mac));

finished:
    blob_buf_free(&b);
    return ret;
}

struct kvlist *deco_get_mac_list(void)
{
	static struct kvlist macs = {0};

	const char *const path = "/etc/config/bind_device_list";

	struct uci_context *ctx;
	struct uci_package *pkg = NULL;
	struct uci_element *ele;

	char tmp_mac[18] = {'\0'};
    bool device_list_empty = true;

	ctx = uci_alloc_context();
	if (ctx == NULL) {
		return NULL;
	}

	if (uci_load(ctx, path, &pkg) != UCI_OK) {
		uci_free_context(ctx);
		return NULL;
	}

	if (macs.get_len == NULL) {
		kvlist_init(&macs, kv_get_zero_len);
	}

	uci_foreach_element(&pkg->sections, ele) {
		struct uci_section *sec = uci_to_section(ele);
		const char *val;

		printf("Section type: %s\n", sec->type);

		if ((val = uci_lookup_option_string(ctx, sec, "mac")) != NULL) {
			strncpy(tmp_mac, val, sizeof(tmp_mac) - 1);
			if (format_mac(tmp_mac, sizeof(tmp_mac) - 1) != NULL) {
                kvlist_set(&macs, tmp_mac, tmp_mac);
                device_list_empty = false;
            }
            else {
				bb_error_msg("Invalid MAC string\n");
				continue;
			}
		}
	}

	uci_unload(ctx, pkg);
	uci_free_context(ctx);

    if (device_list_empty) {
        const char *cap_mac = NULL;
        cap_mac = deco_get_cap_mac();
        if (cap_mac != NULL) {
            kvlist_set(&macs, cap_mac, cap_mac);
        }
    }

	return &macs;
}


#define SNAME_PREFIX "DECO_"
#define SNAME_MAC_LEN (sizeof("0123456789ab") - 1)
#define OPT_MAC_SHIFT (OPT_DATA + sizeof(SNAME_PREFIX) - 1)
#define OPT_MAC_SHIFT_MAX (OPT_MAC_SHIFT + SNAME_MAC_LEN)

/**
 * Generate server name(device MAC string) in DHCP option format
 * @return
 */
uint8_t *deco_gen_sname(void)
{
	static char buf[] = "B" " " SNAME_PREFIX "0123456789ab";
	static void *ret = NULL;

	char ch;
	unsigned char shift = OPT_MAC_SHIFT;
	FILE *fp = NULL;

	if (ret != NULL) {
		return ret;
	}

	fp = popen("getfirm MAC", "r");
	if (fp == NULL) {
		bb_error_msg("Failed to get MAC: %s", strerror(errno));
		return NULL;
	}

	while (shift < OPT_MAC_SHIFT_MAX && fscanf(fp, "%c", &ch) != EOF) {
		int res = format_mac_char(&buf[shift], ch);
		if (res == -1) {
			break;
		}

		if (res > 0) {
			++shift;
		}
	}

	if (shift < OPT_MAC_SHIFT_MAX) {
		goto finished;
	}

	buf[shift++] = '\0';
	buf[OPT_CODE] = DHCP_HOST_NAME;
	buf[OPT_LEN] = (char) (shift - OPT_DATA);

	ret = buf;

finished:
	pclose(fp);
	bb_info_msg("Host name generated: %s", (char *) ret + OPT_DATA);
	return ret;
}

const char *deco_get_mac_from_sname(const char *opt)
{
	size_t len;

	if (opt == NULL) {
		return NULL;
	}

	len = strlen(opt);
	if (len < sizeof(SNAME_PREFIX) - 1 + SNAME_MAC_LEN) {
		return NULL;
	}

	return (opt + sizeof(SNAME_PREFIX) - 1);
}
