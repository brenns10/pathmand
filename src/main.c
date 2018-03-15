/* pathmand - user-space path manager for MPTCP
 * Stephen Brennan <stephen@brennan.io>
 */
#include <stdio.h>

#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/handlers.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>

#include "mptcp_genl.h"

#define ARRAY_SIZE(x) (sizeof(x) /sizeof(x[0]))

struct pathmand {
	struct nl_sock *notify_sk;
	struct nl_sock *request_sk;
};

#define CMD(u, l) { \
	.c_id = MPTCP_C_ ## u, \
	.c_name = #l, \
	.c_maxattr = MPTCP_A_MAX, \
	.c_attr_policy = mptcp_genl_policy, \
	.c_msg_parser = mptcp_ ## l, \
}

/* forward declare commands */
int mptcp_new_connection(struct nl_cache_ops *, struct genl_cmd *, struct genl_info *, void *);
int mptcp_new_addr(struct nl_cache_ops *, struct genl_cmd *, struct genl_info *, void *);
int mptcp_join_attempt(struct nl_cache_ops *, struct genl_cmd *, struct genl_info *, void *);
int mptcp_new_subflow(struct nl_cache_ops *, struct genl_cmd *, struct genl_info *, void *);
int mptcp_subflow_closed(struct nl_cache_ops *, struct genl_cmd *, struct genl_info *, void *);
int mptcp_conn_closed(struct nl_cache_ops *, struct genl_cmd *, struct genl_info *, void *);

/* Only declare commands we are prepared to handle. */
static struct genl_cmd mptcp_genl_cmds[] = {
	CMD(NEW_CONNECTION, new_connection),
	CMD(NEW_ADDR, new_addr),
	CMD(JOIN_ATTEMPT, join_attempt),
	CMD(NEW_SUBFLOW, new_subflow),
	CMD(SUBFLOW_CLOSED, subflow_closed),
	CMD(CONN_CLOSED, conn_closed),
};

static struct genl_ops mptcp_family = {
	.o_hdrsize = 0,
	.o_name = "mptcp",
	.o_cmds = mptcp_genl_cmds,
	.o_ncmds = ARRAY_SIZE(mptcp_genl_cmds),
};

static char *mptcp_groups[] = {
	"new_connection",
	"new_addr",
	"join_attempt",
	"new_subflow",
	"subflow_closed",
	"conn_closed",
};

/* Callback functions
 */

int mptcp_new_connection(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	printf("new_connection()\n");
	return NL_OK;
}

int mptcp_new_addr(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	printf("new_addr()\n");
	return NL_OK;
}

int mptcp_join_attempt(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	printf("join_attempt()\n");
	return NL_OK;
}

int mptcp_new_subflow(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	printf("new_subflow()\n");
	return NL_OK;
}

int mptcp_subflow_closed(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	printf("subflow_closed()\n");
	return NL_OK;
}

int mptcp_conn_closed(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	printf("conn_closed()\n");
	return NL_OK;
}

/* Initialize the path manager daemon. This initializes our netlink sockets and
 * callbacks.
 */
static int pathmand_init(struct pathmand *pm)
{
	int rc = 0;
	int i, group;

	pm->notify_sk = nl_socket_alloc();
	if (!pm->notify_sk) {
		fprintf(stderr, "error allocating netlink notify socket\n");
		goto err_return;
	}

	rc = genl_connect(pm->notify_sk);
	if (rc != 0) {
		nl_perror(rc, "genl_connect(notify_sk)");
		goto err_return;
	}

	pm->request_sk = nl_socket_alloc();
	if (!pm->request_sk) {
		fprintf(stderr, "error allocating netlink request socket\n");
		goto err_cleanup_notify_sk;
	}

	rc = genl_connect(pm->request_sk);
	if (rc != 0) {
		nl_perror(rc, "genl_connect(request_sk)");
		goto err_cleanup_notify_sk;
	}

	/* register genl family so genl_handle_msg will call us */
	rc = genl_register_family(&mptcp_family);
	if (rc != 0) {
		nl_perror(rc, "genl_register_family");
		goto err_cleanup_request_sk;
	}

	/* register genl_handle_msg as the callback for the notify_sk */
	rc = nl_socket_modify_cb(pm->notify_sk, NL_CB_VALID, NL_CB_CUSTOM,
		genl_handle_msg, pm);
	if (rc != 0) {
		nl_perror(rc, "genl_socket_modify_cb");
		goto err_cleanup_request_sk;
	}

	/* resolve and subscribe to all mptcp multicast groups */
	for (i = 0; i < ARRAY_SIZE(mptcp_groups); i++) {
		group = genl_ctrl_resolve_grp(
			pm->notify_sk, mptcp_family.o_name, mptcp_groups[i]);
		if (group < 0) {
			nl_perror(group, mptcp_groups[i]);
			goto err_cleanup_request_sk;
		}

		rc = nl_socket_add_memberships(
			pm->notify_sk, group, NFNLGRP_NONE);
		if (rc < 0) {
			nl_perror(rc, "nl_socket_add_memberships");
			goto err_cleanup_request_sk;
		}
	}


	return 0;

err_cleanup_request_sk:
	nl_socket_free(pm->request_sk);
err_cleanup_notify_sk:
	nl_socket_free(pm->notify_sk);
err_return:
	return -1;
}

/* Run the path manager daemon indefinitely...
 */
static void pathmand_run(struct pathmand *pm)
{
	for (;;) {
		nl_recvmsgs_default(pm->notify_sk);
	}
}

/* Destroy the resources held by the path manager daemon. */
static void pathmand_destroy(struct pathmand *pm)
{
	nl_socket_free(pm->notify_sk);
	nl_socket_free(pm->request_sk);
}

int main(int argc, char **argv)
{
	struct pathmand pm;
	int rc;

	rc = pathmand_init(&pm);
	if (rc != 0)
		return rc;

	pathmand_run(&pm);

	/* lol */
	pathmand_destroy(&pm);

	return 0;
}
