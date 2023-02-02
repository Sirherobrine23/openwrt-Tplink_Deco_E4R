/*!Copyright(c) 2017-2018 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     libxt_pctl.c
 *\brief    userspace/iptables part for parental control. 
 *
 *\author   Hu Luyao
 *\version  1.0.0
 *\date     23Dec13
 *
 *\history  \arg 1.0.0, creat this based on "httphost" from IPF
 *                  
 */

/***************************************************************************/
/*                      CONFIGURATIONS                   */
/***************************************************************************/


/***************************************************************************/
/*                      INCLUDE_FILES                    */
/***************************************************************************/
#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/in.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include "xt_pctl.h"


/***************************************************************************/
/*                      DEFINES                      */
/***************************************************************************/

 
/***************************************************************************/
/*                      TYPES                            */
/***************************************************************************/
static const struct option pctl_opts[] = {
    {.name = "id", .has_arg = true, .val = '1'},
    {.name = "blocked", .has_arg = true, .val = '2'},
    {.name = "workday", .has_arg = true, .val = '3'},
    {.name = "weekend", .has_arg = true, .val = '4'},
    {.name = "workday_limit", .has_arg = true, .val = '5'},
    {.name = "workday_time", .has_arg = true, .val = '6'},
    {.name = "workday_bedtime", .has_arg = true, .val = '7'},
    {.name = "workday_begin", .has_arg = true, .val = '8'},
    {.name = "workday_end", .has_arg = true, .val = '9'},
    {.name = "weekend_limit", .has_arg = true, .val = 'a'},
    {.name = "weekend_time", .has_arg = true, .val = 'b'},
    {.name = "weekend_bedtime", .has_arg = true, .val = 'c'},
    {.name = "weekend_begin", .has_arg = true, .val = 'd'},
    {.name = "weekend_end", .has_arg = true, .val = 'e'},
    {.name = "key", .has_arg = true, .val = 'f'},
    {.name = "host", .has_arg = true, .val = 'g'},
    XT_GETOPT_TABLEEND,
};


/***************************************************************************/
/*                      EXTERN_PROTOTYPES                    */
/***************************************************************************/


/***************************************************************************/
/*                      LOCAL_PROTOTYPES                     */
/***************************************************************************/
/*!
 *\fn           static void pctl_help(void)
 *\brief        help information
 *\return       N/A
 */
static void pctl_help(void);

/*!
 *\fn           static int _parse_write(const char *host, size_t len, struct _xt_pctl_info *info)
 *\brief        write urls into info->hosts[]
 *\return       N/A
 */
static int _parse_write(const char *host, size_t len, struct _xt_pctl_info *info);

/*!
 *\fn           static void _parse_spilt(const char *arg, struct _xt_pctl_info *info)
 *\brief        
 *\return       none
 */
static void _parse_spilt(const char *arg, struct _xt_pctl_info *info);

/*!
 *\fn           static void _parse_key_spilt(const char *arg, struct _xt_pctl_info *info)
 *\brief        
 *\return       none
 */
static void _parse_key_spilt(const char *arg, struct _xt_pctl_info *info);

/*!
 *\fn          static int pctl_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match)
 *\brief        xt_entry_match **match 
 *\return       success or not
 */
static int pctl_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match);

/*!
 *\fn           static void pctl_check(unsigned int flags)
 *\brief        check the flags. 0 means error.
 *\return       none
 */
static void pctl_check(unsigned int flags);

/*!
 *\fn           static void pctl_print(const void *ip, const struct xt_entry_match *match, int numeric)
 *\brief        iptables print
 *\return       none
 */
static void pctl_print(const void *ip, const struct xt_entry_match *match, int numeric);

/*!
 *\fn           static void pctl_save(const void *ip, const struct xt_entry_match *match)
 *\brief        iptables save
 *\return       none
 */
static void pctl_save(const void *ip, const struct xt_entry_match *match);

/*!
 *\fn           static void pctl_init(struct xt_entry_match *match)
 *\brief        iptables init
 *\return       none
 */
static void pctl_init(struct xt_entry_match *match);

/***************************************************************************/
/*                      VARIABLES                        */
/***************************************************************************/
static struct xtables_match pctl_match = { 
    .family         = NFPROTO_UNSPEC,
    .name           = "pctl",
    .version        = XTABLES_VERSION,
    .size           = XT_ALIGN(sizeof(struct _xt_pctl_info)),
    .userspacesize  = XT_ALIGN(sizeof(struct _xt_pctl_info)),
    .help           = pctl_help,
    .parse          = pctl_parse,
    .init           = pctl_init,
    .final_check    = pctl_check,
    .print          = pctl_print,
    .save           = pctl_save,
    .extra_opts     = pctl_opts,
};

 
/***************************************************************************/
/*                      LOCAL_FUNCTIONS                  */
/***************************************************************************/
/*!
 *\fn           static void pctl_help(void)
 *\brief        help information
 *\return       N/A
 */
static void pctl_help(void)
{
	printf(
"IPMARK target options:\n"
"  --id value               Child's id\n"
"  --blocked value          Internet Paused.\n"
"  --workday value    7bit means workday or weekend\n"
"  --weekend value     \n"
"  --workday_limit value    Is workday limit enabled ?\n"
"  --workday_time value     \n"
"  --workday_bedtime value     \n"
"  --workday_begin value    \n"
"  --workday_end value      \n"
"  --weekend_limit value    Is weekend limit enabled ?\n"
"  --weekend_time value     \n"
"  --weekend_bedtime value     \n"
"  --weekend_begin value    \n"
"  --weekend_end value      \n"
"  --key key1[,key2][,key3]    \n"
"  --host host1[,host2][,host3]    \n"
"\n");
}

/*!
 *\fn           static int _parse_write(const char *host, size_t len, struct _xt_pctl_info *info)
 *\brief        write urls into info->hosts[]
 *\return       N/A
 */
static int _parse_write(const char *host, size_t len, struct _xt_pctl_info *info)
{
    if(len >= PCTL_URL_LEN) {
        return FALSE;
    }

    if (strncpy(info->hosts[info->num], host, len) == NULL)
    {
        return FALSE;
    }
    info->num ++;
    return TRUE;
}

/*!
 *\fn           static void _parse_spilt(const char *arg, struct _xt_pctl_info *info)
 *\brief        
 *\return       none
 */
static void _parse_spilt(const char *arg, struct _xt_pctl_info *info)
{
    char *pIndex = NULL;

    /* write arg to info*/
    while ((pIndex = strchr(arg, ',')) != NULL)
    {   
        if (pIndex == arg || !_parse_write(arg, pIndex - arg, info))
        {
            xtables_error(PARAMETER_PROBLEM, "Bad host name \"%s\"", arg);
        }
        arg = pIndex + 1;
    }

    if (!*arg)
    {
        xtables_error(PARAMETER_PROBLEM, "\"--host\" requires a list of "
                          "host name with no spaces, e.g. "
                          "www.baidu.com,www.taobao.com");
    }

    if (strlen(arg) == 0 || !_parse_write(arg, strlen(arg), info))
    {
        xtables_error(PARAMETER_PROBLEM, "Bad host name \"%s\"", arg);
    }
}

/*!
 *\fn           static void _parse_key_spilt(const char *arg, struct _xt_pctl_info *info)
 *\brief        
 *\return       none
 */
static void _parse_key_spilt(const char *arg, struct _xt_pctl_info *info)
{
    char *pIndex = NULL;
    unsigned int index = 0;
    char buff[PCTL_KEY_LEN] = {0};
    /* write arg to info*/
    while ((pIndex = strchr(arg, ',')) != NULL)
    {   
        if (pIndex == arg || PCTL_KEY_LEN <= (pIndex - arg))
        {
            goto error;
        }
        memcpy(buff, arg, pIndex - arg);
        index = atoi(buff);
        if (index <= 0  || index >= PCTL_URL_NUM)
        {
            goto error;
        }
        info->forbid[index - 1] = TRUE;
        memset(buff, 0, sizeof(buff));
        arg = pIndex + 1;
    }

    if (!*arg || strlen(arg) == 0 || PCTL_KEY_LEN <= strlen(arg))
    {
        goto error;
    }
    index = atoi(arg);
    if (index <= 0  || index >= PCTL_URL_NUM)
    {
        goto error;
    }
    info->forbid[index - 1] = TRUE; 
    return;
error:
    xtables_error(PARAMETER_PROBLEM, "Bad key name ");
    
}

/*!
 *\fn          static int pctl_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match)
 *\brief        xt_entry_match **match 
 *\return       success or not
 */
static int pctl_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match)
{
    int i;
    struct _xt_pctl_info *info = (struct _xt_pctl_info *)(*match)->data;
    /* c means the "--" option. look "value" in urlfilter_opts[] */
    switch (c) {
    case '1':       /* id */
        info->id = atoi(optarg);
        *flags = 1;
        break;

    case '2':       /* blocked */
        info->blocked = atoi(optarg);
        break;

    case '3':       /* workday */
        info->workday = atoi(optarg);
        break;

    case '4':       /* weekday */
        info->weekend = atoi(optarg);
        break;

    case '5':       /* workday_limit */
        info->workday_limit = atoi(optarg);
        break;

    case '6':       /* workday_time */
        info->workday_time = atoi(optarg);
        break;

    case '7':       /* workday_bedtime */
        info->workday_bedtime = atoi(optarg);
        break;

    case '8':       /* workday_begin */
        info->workday_begin = atoi(optarg);
        break;

    case '9':       /* workday_end */
        info->workday_end = atoi(optarg);
        break;

    case 'a':       /* weekend_limit */
        info->weekend_limit = atoi(optarg);
        break;

    case 'b':       /* weekend_time */
        info->weekend_time = atoi(optarg);
        break;

    case 'c':       /* weekend_bedtime */
        info->weekend_bedtime = atoi(optarg);
        break;

    case 'd':       /* weekend_begin */
        info->weekend_begin = atoi(optarg);
        break;

    case 'e':       /* weekend_end */
        info->weekend_end = atoi(optarg);
        break;

    case 'f':     /* key */
        _parse_key_spilt(optarg, info);
        break;
    case 'g':     /* hosts */
        _parse_spilt(optarg, info);
        for (i = 0; i < PCTL_URL_NUM; ++i)
        {
            if ('\0' == *(info->hosts[i]))
            {
                break;
            }
        }
        break;

    default:
        return FALSE;
    }
    return TRUE;
}

/*!
 *\fn           static void pctl_check(unsigned int flags)
 *\brief        check the flags. 0 means error.
 *\return       none
 */
static void pctl_check(unsigned int flags)
{
    if (flags == 0)
    {
        xtables_error(PARAMETER_PROBLEM, "pctl match: You must specify `--id'\n ");
    }
}

/*!
 *\fn           static void pctl_print(const void *ip, const struct xt_entry_match *match, int numeric)
 *\brief        iptables print
 *\return       none
 */
static void pctl_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
    struct _xt_pctl_info *info = (struct _xt_pctl_info *)match->data;
    int i = 0;

    printf(" --id %d", info->id);

    if(PCTL_OWNER_ID_ALL != info->id) {
        printf(" --blocked %d", info->blocked);
        printf(" --workday %d", info->workday);
        printf(" --weekend %d", info->weekend);
        printf(" --workday_limit %d", info->workday_limit);
        printf(" --workday_time %d", info->workday_time);
        printf(" --workday_bedtime %d", info->workday_bedtime);
        printf(" --workday_begin %d", info->workday_begin);
        printf(" --workday_end %d", info->workday_end);
        printf(" --weekend_limit %d", info->weekend_limit);
        printf(" --weekend_time %d", info->weekend_time);
        printf(" --weekend_bedtime %d", info->weekend_bedtime);
        printf(" --weekend_begin %d", info->weekend_begin);
        printf(" --weekend_end %d", info->weekend_end);

        if(info->num > 0) 
        {
            printf(" --host ");
            for(i=0; i<info->num; i++)
            {
                if(i < info->num - 1)
                {
                    printf("%s,",info->hosts[i]);
                }else
                {
                    printf("%s",info->hosts[i]);
                }
            }
        }
    }
    printf("\n");
}

/*!
 *\fn           static void pctl_save(const void *ip, const struct xt_entry_match *match)
 *\brief        iptables save
 *\return       none
 */
static void pctl_save(const void *ip, const struct xt_entry_match *match)
{
    struct _xt_pctl_info *info = (struct _xt_pctl_info *)match->data;
    int i = 0;

    printf(" --id %d", info->id);

    if(PCTL_OWNER_ID_ALL != info->id) {
        printf(" --blocked %d", info->blocked);
        printf(" --workday %d", info->workday);
        printf(" --weekend %d", info->weekend);
        printf(" --workday_limit %d", info->workday_limit);
        printf(" --workday_time %d", info->workday_time);
        printf(" --workday_bedtime %d", info->workday_bedtime);
        printf(" --workday_begin %d", info->workday_begin);
        printf(" --workday_end %d", info->workday_end);
        printf(" --weekend_limit %d", info->weekend_limit);
        printf(" --weekend_time %d", info->weekend_time);
        printf(" --weekend_bedtime %d", info->weekend_bedtime);
        printf(" --weekend_begin %d", info->weekend_begin);
        printf(" --weekend_end %d", info->weekend_end);

        if(info->num > 0) 
        {
            printf(" --host ");
            for(i=0; i<info->num; i++)
            {
                if(i < info->num - 1)
                {
                    printf("%s,",info->hosts[i]);
                }else
                {
                    printf("%s",info->hosts[i]);
                }
            }
        }
    }
    printf("\n");
}

/*!
 *\fn           static void pctl_init(struct xt_entry_match *match)
 *\brief        iptables init
 *\return       none
 */
static void pctl_init(struct xt_entry_match *match)
{
    struct _xt_pctl_info *info = (struct _xt_pctl_info *)match->data;
    memset(info, 0, sizeof(struct _xt_pctl_info));
    //  printf("pctl size %d",XT_ALIGN(sizeof(struct _xt_pctl_info)));
}

/***************************************************************************/
/*                      PUBLIC_FUNCTIONS                     */
/***************************************************************************/
/*!
 *\fn           static void _init(void)
 *\brief        iptables register
 *\return       none
 */
static __attribute__((constructor)) void _pctl_mt_ldr(void)
{
    xtables_register_match(&pctl_match);
}

/***************************************************************************/
/*                      GLOBAL_FUNCTIONS                     */
/***************************************************************************/
