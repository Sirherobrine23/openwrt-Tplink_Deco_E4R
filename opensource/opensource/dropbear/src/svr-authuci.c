#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"

#ifdef ENABLE_SVR_UCI_AUTH

#include <uci.h>

static int check_passwd(const unsigned char *username, const unsigned char *password) {
#define PACKAGE_NAME "accountmgnt"
#define CONFIG_TYPE "cloud_account"
#define OPTION_USERNAME "username"
#define OPTION_SHADOW "shadow"

	struct uci_context *ctx = uci_alloc_context();
	struct uci_package *pkg = NULL;
	struct uci_element *e1, *e2;
	struct uci_section *s;
	struct uci_option *opt;
	const char *opt_username, *opt_shadow;
	const char *testcrypt;
	char *err = NULL;
	int uci_ret = UCI_OK;
	int retval = 0;

	if (ctx == NULL) {
		dropbear_log(LOG_WARNING, "uci_alloc_context() failed");
		return 0;
	}

	uci_ret = uci_load(ctx, PACKAGE_NAME, &pkg);
	if (uci_ret != UCI_OK) {
		goto done;
	}

	uci_foreach_element(&pkg->sections, e1) {
		s = uci_to_section(e1);
		if (strcmp(s->type, CONFIG_TYPE) != 0) {
			continue;
		}

		opt_username = NULL;
		opt_shadow = NULL;
		uci_foreach_element(&s->options, e2) {
			opt = uci_to_option(e2);
			if (strcmp(opt->e.name, OPTION_USERNAME) == 0) {
				opt_username = opt->v.string;
			} else if (strcmp(opt->e.name, OPTION_SHADOW) == 0) {
				opt_shadow = opt->v.string;
			}
		}

		if (NULL == opt_username || NULL == opt_shadow) {
			dropbear_log(LOG_WARNING, "username or shadow option is missing");
			continue;
		}

		if (opt_shadow[0] == '\0') {
			dropbear_log(LOG_WARNING, "password shadow is empty");
			continue;
		}

		if (strcasecmp(username, opt_username) != 0) {
			dropbear_log(LOG_WARNING, "invalid username %s", username);
			continue;
		}

		testcrypt = crypt((char *)password, opt_shadow);
		if (NULL == testcrypt) {
			dropbear_log(LOG_WARNING, "invalid shadow");
			continue;
		}

		if (strcmp(opt_shadow, testcrypt) == 0) {
			retval = 1;
			break;
		}
	}

done:
	if (uci_ret != UCI_OK) {
		uci_get_errorstr(ctx, &err, "");
		dropbear_log(LOG_WARNING, "%s", err);
		free(err);
	}
	uci_free_context(ctx);
	return retval;
}

void svr_auth_uci() {
	unsigned char * password;
	unsigned char * username;
	unsigned int passwordlen;
	unsigned int changepw;

	/* check if client wants to change password */
	changepw = buf_getbool(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		send_msg_userauth_failure(0, 1);
		return;
	}

	password = buf_getstring(ses.payload, &passwordlen);
	username = ses.authstate.username;

	/* check for empty password */
	if (password[0] == '\0') {
		dropbear_log(LOG_WARNING, "User has blank password, rejected");
		send_msg_userauth_failure(0, 1);
		return;
	}

	/* Check username */
	if (username == NULL || username[0] == '\0') {
		dropbear_log(LOG_WARNING, "User name is empty, rejected");
		send_msg_userauth_failure(0, 1);
		return;
	}

	if (check_passwd(username, password)) {
		/* successful authentication */
		dropbear_log(LOG_NOTICE,
					 "Password auth succeeded from %s",
					 svr_ses.addrstring);
		send_msg_userauth_success();
	} else {
		dropbear_log(LOG_WARNING,
					 "Bad password attempt from %s",
					 svr_ses.addrstring);
		send_msg_userauth_failure(0, 1);
	}

	m_burn(password, passwordlen);
	m_free(password);
}

#endif
