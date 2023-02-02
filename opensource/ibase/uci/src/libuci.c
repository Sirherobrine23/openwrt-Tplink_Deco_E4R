/*
 * libuci - Library for the Unified Configuration Interface
 * Copyright (C) 2008 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

/*
 * This file contains some common code for the uci library
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <glob.h>
#include "uci.h"

static const char *uci_errstr[] = {
	[UCI_OK] =            "Success",
	[UCI_ERR_MEM] =       "Out of memory",
	[UCI_ERR_INVAL] =     "Invalid argument",
	[UCI_ERR_NOTFOUND] =  "Entry not found",
	[UCI_ERR_IO] =        "I/O error",
	[UCI_ERR_PARSE] =     "Parse error",
	[UCI_ERR_DUPLICATE] = "Duplicate entry",
	[UCI_ERR_UNKNOWN] =   "Unknown error",
};

#include "uci_internal.h"
#include "list.c"

__private const char *uci_confdir = UCI_CONFDIR;
__private const char *uci_savedir = UCI_SAVEDIR;

/* exported functions */
struct uci_context *uci_alloc_context(void)
{
	struct uci_context *ctx;

	ctx = (struct uci_context *) malloc(sizeof(struct uci_context));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(struct uci_context));
	uci_list_init(&ctx->root);
	uci_list_init(&ctx->delta_path);
	uci_list_init(&ctx->backends);
	ctx->flags = UCI_FLAG_STRICT | UCI_FLAG_SAVED_DELTA;

	ctx->confdir = (char *) uci_confdir;
	ctx->savedir = (char *) uci_savedir;
	uci_add_delta_path(ctx, uci_savedir);

	uci_list_add(&ctx->backends, &uci_file_backend.e.list);
	ctx->backend = &uci_file_backend;

	return ctx;
}

void uci_free_context(struct uci_context *ctx)
{
	struct uci_element *e, *tmp;

	if (ctx->confdir != uci_confdir)
		free(ctx->confdir);
	if (ctx->savedir != uci_savedir)
		free(ctx->savedir);

	uci_cleanup(ctx);
	UCI_TRAP_SAVE(ctx, ignore);
	uci_foreach_element_safe(&ctx->root, tmp, e) {
		struct uci_package *p = uci_to_package(e);
		uci_free_package(&p);
	}
	uci_foreach_element_safe(&ctx->delta_path, tmp, e) {
		uci_free_element(e);
	}
	UCI_TRAP_RESTORE(ctx);
	free(ctx);

ignore:
	return;
}

int uci_set_confdir(struct uci_context *ctx, const char *dir)
{
	char *cdir;

	UCI_HANDLE_ERR(ctx);
	UCI_ASSERT(ctx, dir != NULL);

	cdir = uci_strdup(ctx, dir);
	if (ctx->confdir != uci_confdir)
		free(ctx->confdir);
	ctx->confdir = cdir;
	return 0;
}

__private void uci_cleanup(struct uci_context *ctx)
{
	struct uci_parse_context *pctx;

	if (ctx->buf) {
		free(ctx->buf);
		ctx->buf = NULL;
		ctx->bufsz = 0;
	}

	pctx = ctx->pctx;
	if (!pctx)
		return;

	ctx->pctx = NULL;
	if (pctx->package)
		uci_free_package(&pctx->package);

	if (pctx->buf)
		free(pctx->buf);

	free(pctx);
}

void
uci_perror(struct uci_context *ctx, const char *str)
{
	uci_get_errorstr(ctx, NULL, str);
}

void
uci_get_errorstr(struct uci_context *ctx, char **dest, const char *prefix)
{
	static char error_info[128];
	int err;
	const char *format =
		"%s%s" /* prefix */
		"%s%s" /* function */
		"%s" /* error */
		"%s"; /* details */

	error_info[0] = 0;

	if (!ctx)
		err = UCI_ERR_INVAL;
	else
		err = ctx->err;

	if ((err < 0) || (err >= UCI_ERR_LAST))
		err = UCI_ERR_UNKNOWN;

	switch (err) {
	case UCI_ERR_PARSE:
		if (ctx->pctx) {
			snprintf(error_info, sizeof(error_info) - 1, " (%s) at line %d, byte %d", (ctx->pctx->reason ? ctx->pctx->reason : "unknown"), ctx->pctx->line, ctx->pctx->byte);
			break;
		}
		break;
	default:
		break;
	}
	if (dest) {
		err = asprintf(dest, format,
			(prefix ? prefix : ""), (prefix ? ": " : ""),
			(ctx && ctx->func ? ctx->func : ""), (ctx && ctx->func ? ": " : ""),
			uci_errstr[err],
			error_info);
		if (err < 0)
			*dest = NULL;
	} else {
		strcat(error_info, "\n");
		fprintf(stderr, format,
			(prefix ? prefix : ""), (prefix ? ": " : ""),
			(ctx && ctx->func ? ctx->func : ""), (ctx && ctx->func ? ": " : ""),
			uci_errstr[err],
			error_info);
	}
}

int uci_list_configs(struct uci_context *ctx, char ***list)
{
	UCI_HANDLE_ERR(ctx);
	UCI_ASSERT(ctx, list != NULL);
	UCI_ASSERT(ctx, ctx->backend && ctx->backend->list_configs);
	*list = ctx->backend->list_configs(ctx);
	return 0;
}

int uci_commit(struct uci_context *ctx, struct uci_package **package, bool overwrite)
{
	struct uci_package *p;
	UCI_HANDLE_ERR(ctx);
	UCI_ASSERT(ctx, package != NULL);
	p = *package;
	UCI_ASSERT(ctx, p != NULL);
	UCI_ASSERT(ctx, p->backend && p->backend->commit);
	p->backend->commit(ctx, package, overwrite);
	return 0;
}

int uci_load(struct uci_context *ctx, const char *name, struct uci_package **package)
{
	struct uci_package *p;

	UCI_HANDLE_ERR(ctx);
	UCI_ASSERT(ctx, ctx->backend && ctx->backend->load);
	p = ctx->backend->load(ctx, name);
	if (package)
		*package = p;

	return 0;
}

int uci_set_backend(struct uci_context *ctx, const char *name)
{
	struct uci_element *e;

	UCI_HANDLE_ERR(ctx);
	UCI_ASSERT(ctx, name != NULL);
	e = uci_lookup_list(&ctx->backends, name);
	if (!e)
		UCI_THROW(ctx, UCI_ERR_NOTFOUND);
	ctx->backend = uci_to_backend(e);
	return 0;
}

/* porting by wanghao */
int uci_get_profile(char* config, char* option)
{


    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *p = NULL;
    struct uci_ptr ptr;
    char   opt_name[255];
    int ret;
   
    /* load /var/state/dos_protection */
    uci_set_confdir(ctx, "/etc/profile.d");
    ret = uci_load(ctx, "profile", &p);
    if (ret != UCI_OK)
    { 
        printf("uci_load not ok");
        return -1;
    }


    strncpy(opt_name, "profile" , 255);
    strcat(opt_name, ".@");
    strcat(opt_name, config);
    strcat(opt_name, "[0].");
    strcat(opt_name, option);
   
    if (uci_lookup_ptr(ctx, &ptr, opt_name, true) != UCI_OK) {
        uci_perror(ctx, "lookup ptr");
        printf("uci_lookup_ptr not ok");
        uci_free_context(ctx);
        return -1;
    }

    if (!strcmp(ptr.o->v.string, "on"))
    {
        uci_free_context(ctx);
        return 1;
    }

    else if (!strcmp(ptr.o->v.string, "off"))
    {
        uci_free_context(ctx);
        return 0;
    }

    else
    {
    	ret = atoi(ptr.o->v.string);
    	uci_free_context(ctx);
        return ret;
    }

}

int uci_get_profile_global(char* dest, char* option)
{


    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *p = NULL;
    struct uci_ptr ptr;
    char   opt_name[255];
    int ret;
   
    /* load /var/state/dos_protection */
    uci_set_confdir(ctx, "/etc/profile.d");
    ret = uci_load(ctx, "profile", &p);
    if (ret != UCI_OK)
    { 
        printf("uci_load not ok");
        uci_free_context(ctx);
        return -1;
    }


    strncpy(opt_name, "profile" , 255);
    strcat(opt_name, ".@");
    strcat(opt_name, "global");
    strcat(opt_name, "[0].");
    strcat(opt_name, option);
   
    if (uci_lookup_ptr(ctx, &ptr, opt_name, true) != UCI_OK) {
        uci_perror(ctx, "lookup ptr");
        printf("uci_lookup_ptr not ok");
        uci_free_context(ctx);
        return -1;
    }

    strcpy(dest, ptr.o->v.string);
    uci_free_context(ctx);
    return 0;
 
}
/* porting end */

int uci_get_profile_eths(char (*eths)[IFNAMSIZ], int max_eths)
{
    struct uci_context *uciCtx  = NULL;
    struct uci_package *pkg     = NULL;
    struct uci_section *section = NULL;
    struct uci_option  *option = NULL;
    struct uci_element *e, *ee;

    int idx = 0;

    uciCtx = uci_alloc_context();
    
    if(NULL == eths || 2 > max_eths ||NULL == uciCtx) {
        return -1;
    }
    
    uci_set_confdir(uciCtx, "/etc/profile.d");
    if(UCI_OK != uci_load(uciCtx, "interfaces", &pkg)){
        uci_free_context(uciCtx);
        return -1;
    }

    uci_foreach_element(&pkg->sections, e)
    {
        section = uci_to_section(e);

        if(idx >= max_eths) {
            break;
        }

        if(0 == strcmp(section->type, "interface")) {
        
            uci_foreach_element(&section->options, ee)
            {
                option = uci_to_option(ee);
                if(!option || option->type != UCI_TYPE_STRING) {
                    continue;
                }

                if(strcmp("name", option->e.name) == 0) {
                    strncpy(eths[idx], option->v.string, IFNAMSIZ - 1);
                    idx++;
                }
            }
        }
        
    }

    uci_unload(uciCtx, pkg);
    uci_free_context(uciCtx);

    return 0;

}

