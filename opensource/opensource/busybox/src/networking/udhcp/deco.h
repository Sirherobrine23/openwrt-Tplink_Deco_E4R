//
// Created by xfs on 12/19/17.
//

#include "common.h"

#include <libubox/kvlist.h>

#include <elf.h>

#ifndef BUSYBOX_UDHCP_DECO_H
#define BUSYBOX_UDHCP_DECO_H

uint8_t *deco_gen_sname(void);

const char *deco_get_mac_from_sname(const char *opt);

struct kvlist *deco_get_mac_list(void);

#endif //BUSYBOX_UDHCP_DECO_H
