/* MPTCP Generic Netlink Family - constants declarations
 */

#ifndef MPTCP_GENL_H
#define MPTCP_GENL_H

enum {
	MPTCP_A_UNSPEC,
	MPTCP_A_CONNECTION_ID,
	MPTCP_A_SUBFLOW_ID,
	MPTCP_A_ADDRESS_ID,
	MPTCP_A_LOCAL_ADDRESS,
	MPTCP_A_LOCAL_PORT,
	MPTCP_A_REMOTE_ADDRESS,
	MPTCP_A_REMOTE_PORT,
	MPTCP_A_BACKUP,
	__MPTCP_A_MAX,
};

#define MPTCP_A_MAX (__MPTCP_A_MAX - 1)

static struct nla_policy mptcp_genl_policy[MPTCP_A_MAX + 1] = {
	[MPTCP_A_CONNECTION_ID] = { .type = NLA_U32 }, /* TODO verify */
	[MPTCP_A_SUBFLOW_ID] = { .type = NLA_U32 },    /* TODO verify */
	[MPTCP_A_ADDRESS_ID] = { .type = NLA_U32 },    /* TODO verify */
	[MPTCP_A_LOCAL_ADDRESS] = { .type = NLA_UNSPEC, .minlen = 4, .maxlen = 16 },
	[MPTCP_A_LOCAL_PORT] = { .type = NLA_U16 },
	[MPTCP_A_REMOTE_ADDRESS] = { .type = NLA_UNSPEC, .minlen = 4, .maxlen = 16 },
	[MPTCP_A_REMOTE_PORT] = { .type = NLA_U16 },
	[MPTCP_A_BACKUP] = { .type = NLA_FLAG },
};

enum {
	MPTCP_C_SEND_ADDR,
	MPTCP_C_ADD_SUBFLOW,
	MPTCP_C_ALLOW_JOIN,     /* TODO change this */
	MPTCP_C_SET_BACKUP,
	MPTCP_C_REMOVE_SUBFLOW,
	MPTCP_C_NEW_CONNECTION, /* sent by kernel */
	MPTCP_C_NEW_ADDR,       /* sent by kernel */
	MPTCP_C_JOIN_ATTEMPT,   /* sent by kernel */
	MPTCP_C_NEW_SUBFLOW,    /* sent by kernel */
	MPTCP_C_SUBFLOW_CLOSED, /* sent by kernel */
	MPTCP_C_CONN_CLOSED,    /* sent by kernel */
	__MPTCP_C_MAX,
};

#define MPTCP_C_MAX (__MPTCP_C_MAX - 1)

#endif
