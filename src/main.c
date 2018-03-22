/* pathmand - user-space path manager for MPTCP
 * Stephen Brennan <stephen@brennan.io>
 */
#include <dlfcn.h>
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
#define PM_NAMESIZ 32
#define MAX_PMS 8

struct path_manager {
	void *handle;
	char name[PM_NAMESIZ];
	void (*init_path_manager)(void);
	void (*exit_path_manager)(void);
	void (*new_connection)(void);
	void (*new_addr)(void);
	void (*join_attempt)(void);
	void (*new_subflow)(void);
	void (*subflow_closed)(void);
	void (*conn_closed)(void);
};

struct pathmand {
	struct nl_sock *notify_sk;
	struct nl_sock *request_sk;
	struct path_manager pms[MAX_PMS];
	unsigned int n_pms;
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

struct path_manager *choose_path_manager(struct pathmand *pmd)
{
	/* This function will eventually take (a) the connection id, and (b) the
	 * connection info. It will implement policy for selecting a path
	 * manager, and then store the path manager selection in a hash table
	 * by the connection ID.
	 */
	if (pmd->n_pms <= 0)
		return NULL;
	else {
		return &pmd->pms[0];
	}
}

struct path_manager *get_path_manager(struct pathmand *pmd)
{
	/* This function will eventually do a hash table lookup on the
	 * connection ID, returning the already mapped path manager. Right now
	 * it just uses the same logic as choose_path_manager().
	 */
	return choose_path_manager(pmd);
}

/* Callback functions
 */

int mptcp_new_connection(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	struct pathmand *pmd = void_pm;
	struct path_manager *mgr = choose_path_manager(pmd);
	if (mgr) {
		mgr->new_connection();
	} else {
		printf("unhandled new_connection()\n");
	}
	return NL_OK;
}

int mptcp_new_addr(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	struct pathmand *pmd = void_pm;
	struct path_manager *mgr = choose_path_manager(pmd);
	if (mgr) {
		mgr->new_addr();
	} else {
		printf("unhandled new_addr()\n");
	}
	return NL_OK;
	printf("new_addr()\n");
	return NL_OK;
}

int mptcp_join_attempt(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	struct pathmand *pmd = void_pm;
	struct path_manager *mgr = get_path_manager(pmd);
	if (mgr) {
		mgr->join_attempt();
	} else {
		printf("unhandled join_attempt()\n");
	}
	return NL_OK;
	printf("join_attempt()\n");
	return NL_OK;
}

int mptcp_new_subflow(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	struct pathmand *pmd = void_pm;
	struct path_manager *mgr = get_path_manager(pmd);
	if (mgr) {
		mgr->new_subflow();
	} else {
		printf("unhandled new_subflow()\n");
	}
	return NL_OK;
}

int mptcp_subflow_closed(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	struct pathmand *pmd = void_pm;
	struct path_manager *mgr = get_path_manager(pmd);
	if (mgr) {
		mgr->subflow_closed();
	} else {
		printf("unhandled subflow_closed()\n");
	}
	return NL_OK;
}

int mptcp_conn_closed(struct nl_cache_ops *ops, struct genl_cmd *cmd,
		struct genl_info *info, void *void_pm)
{
	struct pathmand *pmd = void_pm;
	struct path_manager *mgr = get_path_manager(pmd);
	if (mgr) {
		mgr->conn_closed();
	} else {
		printf("unhandled conn_closed()\n");
	}
	return NL_OK;
}

static void pathmand_destroy_pms(struct pathmand *pm)
{
	struct path_manager *mgr;

	for (; pm->n_pms; pm->n_pms--) {
		mgr = &pm->pms[pm->n_pms - 1];

		mgr->exit_path_manager();

		mgr->init_path_manager = NULL;
		mgr->exit_path_manager = NULL;
		mgr->new_connection = NULL;
		mgr->new_addr = NULL;
		mgr->join_attempt = NULL;
		mgr->new_subflow = NULL;
		mgr->subflow_closed = NULL;
		mgr->conn_closed = NULL;

		dlclose(mgr->handle);
	}
}

static void pathmand_destroy_nl(struct pathmand *pm)
{
	nl_close(pm->notify_sk);
	nl_close(pm->request_sk);
	nl_socket_free(pm->notify_sk);
	nl_socket_free(pm->request_sk);
}

static int pathmand_init_pms(struct pathmand *pm, int argc, char **argv)
{
	int rc;
	char buf[PM_NAMESIZ + 5];
	struct path_manager *mgr;
	pm->n_pms = 0;

	/* In the final implementation, we'll likely populate:
	 *
	 * 1. A linked list of path_manager structs
	 * 2. A hash table mapping connection IDs to their path managers
	 *
	 * (instead of this simple static array)
	 */

	if (argc - 1 > MAX_PMS) {
		fprintf(stderr, "error: too many path managers\n");
		return -1;
	}

	while (--argc) {
		rc = snprintf(buf, sizeof(buf), "./%s.so", *++argv);
		if (rc >= sizeof(buf) || rc < 0) {
			fprintf(stderr, "error: path manager name \"%s\" "
				"too long\n", *argv);
			goto cleanup;
		}

		mgr = &pm->pms[pm->n_pms];
		strncpy(mgr->name, *argv, sizeof(mgr->name));

		mgr->handle = dlopen(buf, RTLD_NOW);
		if (!mgr->handle) {
			fprintf(stderr, "dlopen: %s\n", dlerror());
			goto cleanup;
		}

		pm->n_pms += 1;

		/* let's not have repetitive code */
		#define INIT_FUNC(func) do { \
			mgr->func = dlsym(mgr->handle, #func); \
			if (!mgr->func) { \
				fprintf(stderr, "error finding symbol \"%s\"" \
					": %s\n", #func, dlerror()); \
				goto close_then_cleanup; \
			} \
		} while (0)

		INIT_FUNC(init_path_manager);
		INIT_FUNC(exit_path_manager);
		INIT_FUNC(new_connection);
		INIT_FUNC(new_addr);
		INIT_FUNC(join_attempt);
		INIT_FUNC(new_subflow);
		INIT_FUNC(subflow_closed);
		INIT_FUNC(conn_closed);


		#undef INIT_FUNC

		mgr->init_path_manager();
	}

	return 0;
close_then_cleanup:
	dlclose(mgr->handle);
cleanup:
	pathmand_destroy_pms(pm);
	return -1;
}

/* Initialize the path manager daemon. This initializes our netlink sockets and
 * callbacks.
 */
static int pathmand_init_nl(struct pathmand *pm)
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

	/* disable sequence check in order to receive events (not just replies)
	 */
	nl_socket_disable_seq_check(pm->notify_sk);

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

	/* need to resolve the family name to ID */
	rc = genl_ops_resolve(pm->notify_sk, &mptcp_family);
	if (rc != 0) {
		nl_perror(rc, "genl_ops_resolve");
	}
	printf("resolve family mptcp = 0x%x\n", mptcp_family.o_id);

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
		printf("resolve group %s.%s = 0x%x\n", mptcp_family.o_name,
			mptcp_groups[i], group);

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

static int pathmand_init(struct pathmand *pm, int argc, char **argv)
{
	int rc;

	rc = pathmand_init_pms(pm, argc, argv);
	if (rc != 0)
		return rc;

	rc = pathmand_init_nl(pm);
	if (rc != 0) {
		pathmand_destroy_pms(pm);
		return rc;
	}
	return 0;
}

/* Run the path manager daemon indefinitely...
 */
static void pathmand_run(struct pathmand *pm)
{
	int rc;

	for (;;) {
		rc = nl_recvmsgs_default(pm->notify_sk);
		if (rc < 0)
			nl_perror(rc, "nl_recvmsgs_default");
	}
}

/* Destroy the resources held by the path manager daemon. */
static void pathmand_destroy(struct pathmand *pm)
{
	pathmand_destroy_pms(pm);
	pathmand_destroy_nl(pm);
}

int main(int argc, char **argv)
{
	struct pathmand pm;
	int rc;

	rc = pathmand_init(&pm, argc, argv);
	if (rc != 0)
		return rc;

	pathmand_run(&pm);

	/* lol */
	pathmand_destroy(&pm);

	return 0;
}
