/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2014, Digium, Inc.
 *
 * Matt Jordan <mjordan@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \brief A module that sends security statistics to statsd
 *
 * \author Matt Jordan <mjordan@digium.com>
 */

/*** MODULEINFO
	<support_level>extended</support_level>
	<depend>res_statsd</depend>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: $")

#include "asterisk/module.h"
#include "asterisk/stasis.h"
#include "asterisk/security_events.h"
#include "asterisk/json.h"
#include "asterisk/statsd.h"

/*! Our Stasis subscription to the security topic */
static struct stasis_subscription *sub;

static char *sanitize_address(char *buffer)
{
	char *current = buffer;

	while ((current = strchr(current, '.'))) {
		*current = '_';
	}

	current = strrchr(buffer, '/');
	current = '\0';

	return buffer;
}

static void handle_security_event(void *data, struct stasis_subscription *sub,
	struct stasis_message *message)
{
	struct ast_str *remote_msg;
	struct ast_str *count_msg;
	struct ast_json_payload *payload;
	const char *service;
	char *remote_address;
	int event_type;

	if (stasis_message_type(message) != ast_security_event_type()) {
		return;
	}

	payload = stasis_message_data(message);
	if (!payload || !payload->json) {
		return;
	}

	event_type = ast_json_integer_get(ast_json_object_get(payload->json, "SecurityEvent"));
	switch (event_type) {
	case AST_SECURITY_EVENT_INVAL_ACCT_ID:
	case AST_SECURITY_EVENT_INVAL_PASSWORD:
	case AST_SECURITY_EVENT_CHAL_RESP_FAILED:
		break;
	default:
		return;
	}

	remote_msg = ast_str_create(64);
	count_msg = ast_str_create(64);
	if (!remote_msg || !count_msg) {
		ast_free(remote_msg);
		ast_free(count_msg);
		return;
	}

	service = ast_json_string_get(ast_json_object_get(payload->json, "Service"));

	ast_str_set(&count_msg, 0, "security.failed_auth.%s.count", service);
	ast_statsd_log(ast_str_buffer(count_msg), AST_STATSD_METER, 1);

	remote_address = ast_strdupa(ast_json_string_get(ast_json_object_get(payload->json, "RemoteAddress")));
	remote_address = sanitize_address(remote_address);

	ast_str_set(&remote_msg, 0, "security.failed_auth.%s.%s", service, remote_address);
	ast_statsd_log(ast_str_buffer(remote_msg), AST_STATSD_METER, 1);

	ast_free(remote_msg);
	ast_free(count_msg);
}

static int unload_module(void)
{
	stasis_unsubscribe_and_join(sub);
	sub = NULL;

	return 0;
}

static int load_module(void)
{

	sub = stasis_subscribe(ast_security_topic(), handle_security_event, NULL);
	if (!sub) {
		return AST_MODULE_LOAD_FAILURE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Security stats module");

