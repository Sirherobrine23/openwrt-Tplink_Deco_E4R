/*
 * runqueue-example.c
 *
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <libubox/uloop.h>
#include <libubox/runqueue.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <json-c/json.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glob.h>

#include <libubox/ustream.h>

#include "procd.h"
#include "rcS.h"

#define GROUP_INFO_FILE             "/tmp/group-info"
#define GROUP_INFO_PARTITION_NAME   "group-info"

static struct runqueue q, r;

struct initd {
	struct ustream_fd fd;
	struct runqueue_process proc;
	char *file;
	char *param;
};

static int device_is_bound(void)
{    
    int ret = -1;    
    char result[512] = {0};   
	int fd = 0;

    if ((fd = open(GROUP_INFO_FILE, O_RDONLY) ) < 0)
	{		   
        char cmd[128] = {0};
        FILE *fp = NULL; 
        
        memset(result, 0, sizeof(result));  
        memset(cmd, 0, sizeof(cmd));         
        ERROR("group-info file is not exist");

        snprintf(cmd, sizeof(cmd), "nvrammanager -p %s -r /dev/console", GROUP_INFO_PARTITION_NAME);

        fp = popen(cmd, "r"); 
        if (NULL == fp)    
        {        
            ERROR("failed to get group-info partition:%s", strerror(errno));
            return ret;
        }    

        while (fgets(result, 512, fp) != NULL)
        {
            ERROR("#group-info result:%s", result); 
            if ((strstr(result, "key") != NULL))
            {
    		    ret = 1;
    		    goto out; 
            }
            memset(result, 0, sizeof(result));             
        }   
         
        ret = 0;  
out:    
        pclose(fp); 
	}
    else
    {
	    int cnt = 0;
        memset(result, 0, sizeof(result));
        cnt = read(fd, result, 512);
        if (cnt > 0)
    	{
            ERROR("#group-info result:%s", result);  
            if ((strstr(result, "key") != NULL))
            {
                ret = 1;
            }
            else
            {
                ret = 0;
            }
    	}
        else if (cnt == 0)
        {
            ret = 0;
        }
        else
        {
            ret = -1;
        }
        close(fd);
    }

   return ret;
}

static void pipe_cb(struct ustream *s, int bytes)
{
	char *newline, *str;
	int len;

	do {
		str = ustream_get_read_buf(s, NULL);
		if (!str)
			break;
		newline = strchr(str, '\n');
		if (!newline)
			break;
		*newline = 0;
		len = newline + 1 - str;
		syslog(0, "%s", str);
#ifdef SHOW_BOOT_ON_CONSOLE
		fprintf(stderr, "%s\n", str);
#endif
		ustream_consume(s, len);
	} while (1);
}

#define BOOT_DHCPD_FILE "/tmp/udhcpd_br-lan.pid"
#define BOOT_DHCPC_FILE "/tmp/udhcpc_br-lan.pid"
#define BOOT_WIFI_DONE "/tmp/wifi_set_done"
#define BOOT_WAN_DETECT "/etc/rc.d/S45wan"
#define BOOT_CONN_INDICATOR "/etc/rc.d/S47conn-indicator"
#define BOOT_SMARTIPD "/etc/rc.d/S47smartipd"
#define BOOT_TMP_SVR "/etc/rc.d/S49tpmodules"
static void q_initd_run(struct runqueue *q, struct runqueue_task *t)
{
	struct initd *s = container_of(t, struct initd, proc.task);
	int pipefd[2];
	pid_t pid;
	int left_time = 0;
	int is_bound = 0;

	if(0 == strcmp("running", s->param)) {
		return;
	}
    
	DEBUG(2, "start %s %s \n", s->file, s->param);
	if (pipe(pipefd) == -1) {
		ERROR("Failed to create pipe\n");
		return;
	}

	pid = fork();
	if (pid < 0)
		return;

	if (pid) {
		close(pipefd[1]);
		s->fd.stream.string_data = true,
		s->fd.stream.notify_read = pipe_cb,
		runqueue_process_add(q, &s->proc, pid);
		ustream_fd_init(&s->fd, pipefd[0]);
        
		if(!strcmp(BOOT_WAN_DETECT, s->file)) {

			while(access(BOOT_WIFI_DONE, 0)) {
                		sleep(1);
			}
		}
        	else if(!strcmp(BOOT_CONN_INDICATOR, s->file)) {
			left_time = 3;
			while(left_time) {
				left_time = sleep(left_time);
			}
		} 
		else if(!strcmp(BOOT_SMARTIPD, s->file)) {
			left_time = 3;
			while(left_time) {
				left_time = sleep(left_time);
			}
			is_bound = device_is_bound();
			if (0 == is_bound)
			{
				while(access(BOOT_DHCPD_FILE, 0)) {
					sleep(1);
				}
			}
						
		}
		else if(!strcmp(BOOT_TMP_SVR, s->file)) {
			left_time = 3;
			while(left_time) {
				left_time = sleep(left_time);
			}
		}
        
		return;
	}
	close(pipefd[0]);
	dup2(pipefd[1], STDOUT_FILENO);
	dup2(pipefd[1], STDERR_FILENO);

	execlp(s->file, s->file, s->param, NULL);
	exit(1);
}

static void q_initd_complete(struct runqueue *q, struct runqueue_task *p)
{
	struct initd *s = container_of(p, struct initd, proc.task);

	DEBUG(2, "stop %s %s \n", s->file, s->param);
	ustream_free(&s->fd.stream);
	close(s->fd.fd.fd);
	free(s);
}

static void add_initd(struct runqueue *q, char *file, char *param)
{
	static const struct runqueue_task_type initd_type = {
		.run = q_initd_run,
		.cancel = runqueue_process_cancel_cb,
		.kill = runqueue_process_kill_cb,
	};
	struct initd *s;
	char *p, *f;

	s = calloc_a(sizeof(*s), &f, strlen(file) + 1, &p, strlen(param) + 1);
	if (!s) {
		ERROR("Out of memory in %s.\n", file);
		return;
	}
	s->proc.task.type = &initd_type;
	s->proc.task.complete = q_initd_complete;
	if (!strcmp(param, "stop") || !strcmp(param, "shutdown"))
		s->proc.task.run_timeout = 15000;
	else if(!strcmp(param, "boot")) {
		s->proc.task.run_timeout = 10000;
		s->proc.task.timeout_raise = true;
		memset(s->proc.task.boot_param, 0, 64);
		strncpy(s->proc.task.boot_param, file, 63);
	}
	s->param = p;
	s->file = f;
	strcpy(s->param, param);
	strcpy(s->file, file);
	runqueue_task_add(q, &s->proc.task, false);
}

static int _rc(struct runqueue *q, char *path, const char *file, char *pattern, char *param)
{
	char *dir = alloca(2 + strlen(path) + strlen(file) + strlen(pattern));
	glob_t gl;
	int j;

	if (!dir) {
		ERROR("Out of memory in %s.\n", file);
		return -1;
	}

	DEBUG(2, "running %s/%s%s %s\n", path, file, pattern, param);
	sprintf(dir, "%s/%s%s", path, file, pattern);
	if (glob(dir, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl)) {
		DEBUG(2, "glob failed on %s\n", dir);
		return -1;
	}

	for (j = 0; j < gl.gl_pathc; j++)
		add_initd(q, gl.gl_pathv[j], param);

	globfree(&gl);

	return 0;
}

int rcS(char *pattern, char *param, void (*q_empty)(struct runqueue *))
{
	runqueue_init(&q);
	q.empty_cb = q_empty;
	q.max_running_tasks = 1;

	return _rc(&q, "/etc/rc.d", pattern, "*", param);
}

int rc(const char *file, char *param)
{
	return _rc(&r, "/etc/init.d", file, "", param);
}

static void r_empty(struct runqueue *q)
{

}

static void __attribute__((constructor)) rc_init() {
	runqueue_init(&r);
	r.empty_cb = r_empty;
	r.max_running_tasks = 8;
}
