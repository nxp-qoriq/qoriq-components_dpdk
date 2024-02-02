/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef _RTE_REMOTE_DIRECT_FLOW_H
#define _RTE_REMOTE_DIRECT_FLOW_H
#include <linux/msg.h>
#include <sys/stat.h>

key_t
ftok(const char *__pathname, int __proj_id);
int
msgget(key_t __key, int __msgflg);
ssize_t
msgrcv(int __msqid, void *__msgp, size_t __msgsz,
			long __msgtyp, int __msgflg);
int
msgsnd(int __msqid, const void *__msgp, size_t __msgsz,
			int __msgflg);

#ifndef RTE_LOGTYPE_remote_dir
#define RTE_LOGTYPE_remote_dir RTE_LOGTYPE_USER1
#endif

enum rte_remote_dir_cfg {
	RTE_REMOTE_DIR_NONE = 0,
	RTE_REMOTE_DIR_RSP = (1 << 0),
	RTE_REMOTE_DIR_REQ = (1 << 1)
};

enum rte_remote_dir_req_param {
	FLD_REMOTE_FROM_PORT = 0,
	FLD_REMOTE_TO_PORT,
	FLD_PROTOCOL,
	FLD_PROTOCOL_FIELD,
	FLD_PROTOCOL_FIELD_VAL,
	FLD_FLOW_MAX
};

struct rte_remote_dir_req {
	char from_name[RTE_ETH_NAME_MAX_LEN];
	char to_name[RTE_ETH_NAME_MAX_LEN];
	char prot[64];
	char fld[64];
	uint64_t fld_val;
};

#define MAX_FLOW_ITEM_NUM 8

struct rte_remote_dir_flow {
	char from[RTE_ETH_NAME_MAX_LEN];
	char to[RTE_ETH_NAME_MAX_LEN];
	uint16_t group;
	uint16_t prior;
	uint16_t item_num;
	struct rte_flow_item items[MAX_FLOW_ITEM_NUM];
};

#define MAX_TYPE_NUM 8
#define MAX_SPEC_SIZE 64

struct rte_remote_dir_create_param {
	char from_name[RTE_ETH_NAME_MAX_LEN];
	char to_name[RTE_ETH_NAME_MAX_LEN];
	enum rte_flow_item_type types[MAX_TYPE_NUM];
	char spec[MAX_TYPE_NUM][MAX_SPEC_SIZE];
	char mask[MAX_TYPE_NUM][MAX_SPEC_SIZE];
	uint8_t spec_valid[MAX_TYPE_NUM];
	uint8_t mask_valid[MAX_TYPE_NUM];
	uint16_t type_num;
	uint16_t group;
	uint32_t priority;
};

#define RTE_REMOTE_DIR_CREATE_PARAM_SZ \
	sizeof(struct rte_remote_dir_create_param)

#define MAX_DIR_REQ_NUM 8
static struct rte_remote_dir_req s_dir_req[MAX_DIR_REQ_NUM];
static uint16_t s_dir_req_num;

#define DEFAULT_DIRECT_GROUP 0
#define DEFAULT_DIRECT_PRIORITY 1

#define MAX_DEF_DIR_NUM 8
static struct rte_remote_dir_req s_def_dir[MAX_DEF_DIR_NUM];
static uint16_t s_def_dir_num;

#define DPAA2_MUX_NAME_PREFIX "dpdmux."
#define REMOTE_EP_NAME_PREFIX "dpni."

static inline int
rte_remote_mux_parse_ep_name(const char *ep_name,
	char *cmux_id, int *mux_id,
	char *cmux_ep_id, int *mux_ep_id)
{
	uint16_t idx, id_len;
	char dpdmux_id[8], dpdmux_ep_id[8];

	if (!strncmp(DPAA2_MUX_NAME_PREFIX, ep_name,
		strlen(DPAA2_MUX_NAME_PREFIX))) {
		idx = strlen(DPAA2_MUX_NAME_PREFIX);
		id_len = 0;
		while (ep_name[idx] >= '0' &&
			ep_name[idx] <= '9') {
			dpdmux_id[id_len] = ep_name[idx];
			id_len++;
			idx++;
		}
		dpdmux_id[id_len] = 0;
		idx++;
		id_len = 0;
		while (ep_name[idx] >= '0' &&
			ep_name[idx] <= '9') {
			dpdmux_ep_id[id_len] = ep_name[idx];
			id_len++;
			idx++;
		}
		dpdmux_ep_id[id_len] = 0;
		if (mux_id)
			*mux_id = atoi(dpdmux_id);
		if (mux_ep_id)
			*mux_ep_id = atoi(dpdmux_ep_id);
		if (cmux_id)
			strcpy(cmux_id, dpdmux_id);
		if (cmux_ep_id)
			strcpy(cmux_ep_id, dpdmux_ep_id);

		return 0;
	}

	return -EINVAL;
}

static inline int
rte_remote_parse_ep_name(const char *ep_name,
	char *cid, int *id)
{
	uint16_t idx, id_len;
	char local_id[8];

	if (!strncmp(REMOTE_EP_NAME_PREFIX, ep_name,
		strlen(REMOTE_EP_NAME_PREFIX))) {
		idx = strlen(DPAA2_MUX_NAME_PREFIX);
		id_len = 0;
		while (ep_name[idx] >= '0' &&
			ep_name[idx] <= '9') {
			local_id[id_len] = ep_name[idx];
			id_len++;
			idx++;
		}
		local_id[id_len] = 0;

		if (id)
			*id = atoi(local_id);
		if (cid)
			strcpy(cid, local_id);

		return 0;
	}

	return -EINVAL;
}

static inline void rte_trim_and_lowercase(char *s,
	int l)
{
	int i;
	char *start = s;
	const char offset = 'A' - 'a';

	while (*s == ' ')
		s++;
	for (i = strlen(s) - 1; s[i] == ' '; i--)
		;
	s[i + 1] = '\0';
	memmove(start, s, strlen(s));
	start[strlen(s)] = '\0';

	if (!l)
		return;

	i = 0;
	while (start[i] != '\0') {
		if (start[i] >= 'A' && start[i] <= 'Z')
			start[i] -= offset;
		i++;
	}
}

static int
remote_direct_single_config(const char *p,
	struct rte_remote_dir_req *dir_req,
	uint32_t size)
{
	char s[256];
	char *end;
	char *str_fld[FLD_FLOW_MAX];
	int i, num;

	if (size >= sizeof(s))
		return -EINVAL;

	snprintf(s, sizeof(s), "%.*s", size, p);
	num = rte_strsplit(s, sizeof(s), str_fld,
		FLD_FLOW_MAX, ',');
	if (num > FLD_FLOW_MAX || num < 0)
		return -EINVAL;
	for (i = 0; i < num; i++) {
		errno = 0;
		if (i == FLD_REMOTE_FROM_PORT) {
			strcpy(dir_req->from_name, str_fld[i]);
			rte_trim_and_lowercase(dir_req->from_name, 0);
		} else if (i == FLD_REMOTE_TO_PORT) {
			strcpy(dir_req->to_name, str_fld[i]);
			rte_trim_and_lowercase(dir_req->to_name, 0);
		} else if (i == FLD_PROTOCOL) {
			strcpy(dir_req->prot, str_fld[i]);
			rte_trim_and_lowercase(dir_req->prot, 1);
		} else if (i == FLD_PROTOCOL_FIELD) {
			strcpy(dir_req->fld, str_fld[i]);
			rte_trim_and_lowercase(dir_req->fld, 1);
		} else if (i == FLD_PROTOCOL_FIELD_VAL) {
			dir_req->fld_val = strtoul(str_fld[i],
				&end, 0);
			if (errno != 0 || end == str_fld[i])
				return -EINVAL;
		}
	}

	return 0;
}

/** Manually configuration by flow_arg:
 * example: "(dpni.1, dpni.2, udp, dst, 0x1234)"
 * ie. direct UDP traffic with destination port(0x1234)
 * from dpni.1 to dpni.2.
 */
static inline int
rte_remote_direct_parse_config(const char *flow_arg,
	int is_remote)
{
	const char *p, *p0 = flow_arg;
	int ret;
	uint32_t size, max, num = 0;
	struct rte_remote_dir_req *dir_req;
	char rule_str[256];

	if (is_remote) {
		dir_req = s_dir_req;
		max = MAX_DIR_REQ_NUM;
	} else {
		dir_req = s_def_dir;
		max = MAX_DEF_DIR_NUM;
	}

	p = strchr(p0, '(');
	while (p) {
		if (num >= max)
			return -EINVAL;
		++p;
		p0 = strchr(p, ')');
		if (!p0)
			return -EINVAL;

		size = p0 - p;

		ret = remote_direct_single_config(p,
			dir_req, size);
		if (ret)
			return ret;

		if (is_remote) {
			if (dir_req->fld[0]) {
				sprintf(rule_str, "%s:%s is 0x%lx",
					dir_req->prot, dir_req->fld,
					dir_req->fld_val);
			} else {
				sprintf(rule_str, "%s", dir_req->prot);
			}
			RTE_LOG(INFO, remote_dir,
				"remote_cfg[%d]: from(%s)->(%s)->to(%s)\n",
				num, dir_req->from_name,
				rule_str,
				dir_req->to_name);
		} else {
			RTE_LOG(INFO, remote_dir,
				"default_cfg[%d]: from(%s)->to(%s)\n",
				num, dir_req->from_name, dir_req->to_name);
		}

		dir_req++;
		num++;
		p = strchr(p0, '(');
	}

	if (is_remote)
		s_dir_req_num = num;
	else
		s_def_dir_num = num;

	return 0;
}

#define REMOTE_DIR_MSG_FILE \
	"/tmp/remote_direct"

#define REMOTE_DIRECT_MSG_REQ 0x1234
#define REMOTE_DIRECT_MSG_COMPLETE 0x5678

enum remote_direct_req_rst {
	REMOTE_DIRECT_FLOW_SUCCESS = 0,
	REMOTE_DIRECT_FLOW_NO_SRC = (1 << 0),
	REMOTE_DIRECT_FLOW_NO_DEST = (1 << 1),
	REMOTE_DIRECT_FLOW_CREATE_ERR = (1 << 2),
};

static int
remote_dir_ipc_init(int *pqid)
{
	static key_t key = -1;
	static int qid = -1;
	struct stat file_info;

	if (stat(REMOTE_DIR_MSG_FILE, &file_info)) {
		if (!fopen(REMOTE_DIR_MSG_FILE, "wb")) {
			RTE_LOG(ERR, remote_dir,
				"%s: Create %s failed\n",
				__func__, REMOTE_DIR_MSG_FILE);
			return -EIO;
		}
	}

	/**Check again.*/
	if (stat(REMOTE_DIR_MSG_FILE, &file_info)) {
		RTE_LOG(ERR, remote_dir,
			"%s: Stat %s failed\n",
			__func__, REMOTE_DIR_MSG_FILE);
		return -EIO;
	}

	if (key < 0) {
		key = ftok(REMOTE_DIR_MSG_FILE, 'C');
		if (key < 0) {
			RTE_LOG(ERR, remote_dir,
				"%s: ftok(%s) failed(%d)\n",
				__func__, REMOTE_DIR_MSG_FILE,
				(int)key);
			return key;
		}
	}

	if (qid < 0) {
		qid = msgget(key, IPC_CREAT | 0666);
		if (qid < 0) {
			RTE_LOG(ERR, remote_dir,
				"%s: IPC create failed(%d)\n",
				__func__, qid);
			return qid;
		}
	}

	*pqid = qid;

	return 0;
}

static int
remote_direct_req(const char *from,
	const char *to, struct rte_flow_item items[],
	uint8_t item_num, uint8_t group, uint16_t prio)
{
	int ret, qid;
	uint8_t i, req_buf[4096], rsp_buf[1024], complete;
	struct rte_remote_dir_create_param redir;
	struct msgbuf *msg;

	ret = remote_dir_ipc_init(&qid);
	if (ret) {
		RTE_LOG(ERR, remote_dir,
			"%s: IPC init failed(%d)\n",
			__func__, ret);
	}

	memset(&redir, 0, sizeof(redir));
	strcpy(redir.from_name, from);
	strcpy(redir.to_name, to);
	for (i = 0; i < item_num; i++) {
		if (items[i].type == RTE_FLOW_ITEM_TYPE_UDP) {
			if (items[i].spec) {
				rte_memcpy(&redir.spec[i][0],
					items[i].spec,
					sizeof(struct rte_flow_item_udp));
				redir.spec_valid[i] = 1;
			} else {
				redir.spec_valid[i] = 0;
			}
			if (items[i].mask) {
				rte_memcpy(&redir.mask[i][0],
					items[i].mask,
					sizeof(struct rte_flow_item_udp));
				redir.mask_valid[i] = 1;
			} else {
				redir.mask_valid[i] = 0;
			}
		} else if (items[i].type == RTE_FLOW_ITEM_TYPE_GTP) {
			if (items[i].spec) {
				rte_memcpy(&redir.spec[i][0],
					items[i].spec,
					sizeof(struct rte_flow_item_gtp));
				redir.spec_valid[i] = 1;
			} else {
				redir.spec_valid[i] = 0;
			}
			if (items[i].mask) {
				rte_memcpy(&redir.mask[i][0],
					items[i].mask,
					sizeof(struct rte_flow_item_gtp));
				redir.mask_valid[i] = 1;
			} else {
				redir.mask_valid[i] = 0;
			}
		} else if (items[i].type == RTE_FLOW_ITEM_TYPE_ECPRI) {
			if (items[i].spec) {
				rte_memcpy(&redir.spec[i][0],
					items[i].spec,
					sizeof(struct rte_flow_item_ecpri));
				redir.spec_valid[i] = 1;
			} else {
				redir.spec_valid[i] = 0;
			}
			if (items[i].mask) {
				rte_memcpy(&redir.mask[i][0],
					items[i].mask,
					sizeof(struct rte_flow_item_ecpri));
				redir.mask_valid[i] = 1;
			} else {
				redir.mask_valid[i] = 0;
			}
		} else {
			RTE_LOG(ERR, remote_dir,
				"%s: items[%d].type(%d) not supported\n",
				__func__, i, items[i].type);
			return -ENOTSUP;
		}
		redir.types[i] = items[i].type;
	}
	redir.type_num = item_num;
	redir.group = group;
	redir.priority = prio;

	msg = (void *)req_buf;
	msg->mtype = REMOTE_DIRECT_MSG_REQ;
	rte_memcpy(msg->mtext, &redir, sizeof(redir));

	ret = msgsnd(qid, msg,
		RTE_REMOTE_DIR_CREATE_PARAM_SZ, 0);
	if (ret) {
		RTE_LOG(ERR, remote_dir,
			"%s: msgsnd qid(%d) failed(%d)\n",
			__func__, qid, ret);
		return ret;
	}

	msg = (void *)rsp_buf;
	ret = msgrcv(qid, rsp_buf, sizeof(uint8_t),
		REMOTE_DIRECT_MSG_COMPLETE, 0);
	complete = *((uint8_t *)msg->mtext);
	if (ret == sizeof(uint8_t) &&
		complete == REMOTE_DIRECT_FLOW_SUCCESS)
		return 0;

	if (ret != sizeof(uint8_t)) {
		RTE_LOG(ERR, remote_dir,
			"%s: msgrcv complete qid(%d) failed(%d)\n",
			__func__, qid, ret);

		return -EINVAL;
	}

	RTE_LOG(ERR, remote_dir,
		"%s: msgrcv complete qid(%d) result(%d)\n",
		__func__, qid, complete);

	return -EINVAL;
}

static struct rte_flow *
rte_remote_default_direct(const char *from_name,
	const char *to_name, uint16_t *from_port_id,
	uint32_t group, uint32_t prio)
{
	int ret, portid, from_id = -1, to_id = -1;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	struct rte_flow_attr flow_attr;
	struct rte_flow_item flow_item[2];
	struct rte_flow_action flow_action[2];
	struct rte_flow_action_port_id dst_port;
	struct rte_flow *flow = NULL;

	RTE_ETH_FOREACH_DEV(portid) {
		ret = rte_eth_dev_get_name_by_port(portid, port_name);
		if (ret)
			continue;
		if (!strcmp(from_name, port_name))
			from_id = portid;
		if (!strcmp(to_name, port_name))
			to_id = portid;
	}

	if (from_id < 0) {
		RTE_LOG(ERR, remote_dir,
			"%s: source port(%s) does NOT exist.\n",
			__func__, from_name);

		return NULL;
	}

	if (to_id < 0) {
		RTE_LOG(ERR, remote_dir,
			"%s: dest port(%s) does NOT exist.\n",
			__func__, to_name);

		return NULL;
	}

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.group = group;
	flow_attr.priority = prio;
	flow_attr.ingress = 1;
	flow_attr.egress = 0;

	flow_item[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	flow_item[0].spec = NULL;
	flow_item[0].mask = NULL;
	flow_item[0].last = NULL;
	flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;

	flow_action[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	dst_port.original = 0;
	dst_port.id = to_id;
	flow_action[0].conf = &dst_port;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	ret = rte_flow_validate(from_id, &flow_attr, flow_item,
		flow_action, NULL);
	if (ret) {
		RTE_LOG(ERR, remote_dir,
			"%s: redirect flow validate failed(%d)\n",
			__func__, ret);
		return NULL;
	}
	flow = rte_flow_create(from_id, &flow_attr, flow_item,
		flow_action, NULL);
	if (!flow) {
		RTE_LOG(ERR, remote_dir,
			"%s: redirect flow create failed\n",
			__func__);

		return NULL;
	}

	if (from_port_id)
		*from_port_id = from_id;

	return flow;
}

static struct rte_flow *
_remote_direct_rsp(uint16_t *from_port_id)
{
	uint8_t rsp_buf[1024], complete, i;
	uint8_t rcv_buf[4096];
	char port_name[RTE_ETH_NAME_MAX_LEN];
	int ret, qid;
	struct msgbuf *msg;
	struct rte_remote_dir_create_param *redir;
	int from_id = -1, to_id = -1, portid;
	struct rte_flow_attr flow_attr;
	struct rte_flow_item flow_item[MAX_TYPE_NUM + 1];
	struct rte_flow_action flow_action[2];
	struct rte_flow_action_port_id dst_port;
	struct rte_flow *flow = NULL;

	ret = remote_dir_ipc_init(&qid);
	if (ret) {
		RTE_LOG(ERR, remote_dir,
			"%s: IPC init failed(%d)\n",
			__func__, ret);

		return NULL;
	}

	errno = 0;
	ret = msgrcv(qid, rcv_buf,
		RTE_REMOTE_DIR_CREATE_PARAM_SZ,
		REMOTE_DIRECT_MSG_REQ, IPC_NOWAIT);
	if (ret == (-1) && errno == ENOMSG)
		return NULL;
	if (ret != RTE_REMOTE_DIR_CREATE_PARAM_SZ) {
		RTE_LOG(ERR, remote_dir,
			"%s: receive remote req failed(%d)\n",
			__func__, ret);
		return NULL;
	}
	msg = (void *)rcv_buf;
	redir = (void *)msg->mtext;

	msg = (void *)rsp_buf;
	msg->mtype = REMOTE_DIRECT_MSG_COMPLETE;

	RTE_ETH_FOREACH_DEV(portid) {
		ret = rte_eth_dev_get_name_by_port(portid, port_name);
		if (ret)
			continue;
		if (!strcmp(redir->from_name, port_name))
			from_id = portid;
		if (!strcmp(redir->to_name, port_name))
			to_id = portid;
	}

	if (from_id < 0) {
		RTE_LOG(ERR, remote_dir,
			"%s: source port(%s) does NOT exist.\n",
			__func__, redir->from_name);
		complete = REMOTE_DIRECT_FLOW_NO_SRC;
		rte_memcpy(msg->mtext, &complete, sizeof(uint8_t));
		ret = msgsnd(qid, msg, sizeof(uint8_t), 0);
		if (ret) {
			RTE_LOG(ERR, remote_dir,
				"%s: No source feedback failed(%d)\n",
				__func__, ret);
		}
		return NULL;
	}

	if (to_id < 0) {
		RTE_LOG(ERR, remote_dir,
			"%s: dest port(%s) does NOT exist.\n",
			__func__, redir->to_name);
		complete = REMOTE_DIRECT_FLOW_NO_DEST;
		rte_memcpy(msg->mtext, &complete, sizeof(uint8_t));
		ret = msgsnd(qid, msg, sizeof(uint8_t), 0);
		if (ret) {
			RTE_LOG(ERR, remote_dir,
				"%s: No dest feedback failed(%d)\n",
				__func__, ret);
		}
		return NULL;
	}

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.group = redir->group;
	flow_attr.priority = redir->priority;
	flow_attr.ingress = 1;
	flow_attr.egress = 0;

	memset(flow_item, 0, sizeof(flow_item));
	for (i = 0; i < redir->type_num; i++) {
		flow_item[i].type = redir->types[i];
		if (redir->spec_valid[i])
			flow_item[i].spec = &redir->spec[i][0];
		if (redir->mask_valid[i])
			flow_item[i].mask = &redir->mask[i][0];
	}
	flow_item[redir->type_num].type = RTE_FLOW_ITEM_TYPE_END;

	flow_action[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	dst_port.original = 0;
	dst_port.id = to_id;
	flow_action[0].conf = &dst_port;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	ret = rte_flow_validate(from_id, &flow_attr, flow_item,
		flow_action, NULL);
	if (ret) {
		RTE_LOG(ERR, remote_dir,
			"%s: redirect flow validate failed(%d)\n",
			__func__, ret);
		flow = NULL;
		goto redirect_rsp;
	}
	flow = rte_flow_create(from_id, &flow_attr, flow_item,
		flow_action, NULL);
	if (!flow) {
		RTE_LOG(ERR, remote_dir,
			"%s: redirect flow create failed\n",
			__func__);
	}

redirect_rsp:
	if (ret || !flow)
		complete = REMOTE_DIRECT_FLOW_CREATE_ERR;
	else
		complete = REMOTE_DIRECT_FLOW_SUCCESS;
	rte_memcpy(msg->mtext, &complete, sizeof(uint8_t));
	ret = msgsnd(qid, msg, sizeof(uint8_t), 0);
	if (ret) {
		RTE_LOG(ERR, remote_dir,
			"%s: flow create success feedback failed(%d)\n",
			__func__, ret);
		if (flow) {
			ret = rte_flow_destroy(from_id, flow, NULL);
			RTE_LOG(ERR, remote_dir,
				"%s: flow destroy failed(%d)\n",
				__func__, ret);
		}

		return NULL;
	}

	if (from_port_id)
		*from_port_id = from_id;

	return flow;
}

#define MAX_REDIRECT_FLOW_NUM 512
struct remote_dir_ingress_flow {
	uint16_t port_id;
	struct rte_flow *flow;
};

static void *
remote_direct_rsp(void *arg)
{
	struct rte_flow *flow;
	struct rte_ring *ring;
	int ret;
	uint16_t port_id = 0, i;
	struct remote_dir_ingress_flow *in_flow = NULL;

	ring = rte_ring_create("direct_flow_ring",
		MAX_REDIRECT_FLOW_NUM, 0, 0);
	if (!ring) {
		RTE_LOG(ERR, remote_dir,
			"Create redirect flow ring failed\n");

		return arg;
	}

	for (i = 0; i < s_def_dir_num; i++) {
		flow = rte_remote_default_direct(s_def_dir[i].from_name,
			s_def_dir[i].to_name, &port_id,
			DEFAULT_DIRECT_GROUP,
			DEFAULT_DIRECT_PRIORITY);
		if (flow) {
			in_flow = rte_malloc(NULL,
				sizeof(struct remote_dir_ingress_flow), 0);
			if (!in_flow) {
				RTE_LOG(ERR, remote_dir,
					"Malloc default flow failed\n");
				ret = rte_flow_destroy(port_id, flow, NULL);
				if (ret) {
					RTE_LOG(ERR, remote_dir,
						"Destroy port(%d)'s default flow failed(%d)\n",
						port_id, ret);
				}
				goto wait;
			}
			in_flow->port_id = port_id;
			in_flow->flow = flow;
			ret = rte_ring_enqueue(ring, in_flow);
			if (ret) {
				RTE_LOG(ERR, remote_dir,
					"Save port(%d)'s default flow failed(%d)\n",
					port_id, ret);
				ret = rte_flow_destroy(port_id, flow, NULL);
				if (ret) {
					RTE_LOG(ERR, remote_dir,
						"Destroy port(%d)'s default flow failed(%d)\n",
						port_id, ret);
				}
				rte_free(in_flow);
			} else {
				RTE_LOG(INFO, remote_dir,
					"Create default direct flow from port(%d)\n",
					port_id);
			}
		}
	}

	while (1) {
		flow = _remote_direct_rsp(&port_id);
		if (flow) {
			in_flow = rte_malloc(NULL,
				sizeof(struct remote_dir_ingress_flow), 0);
			if (!in_flow) {
				RTE_LOG(ERR, remote_dir,
					"Malloc remote flow failed\n");
				ret = rte_flow_destroy(port_id, flow, NULL);
				if (ret) {
					RTE_LOG(ERR, remote_dir,
						"Destroy port(%d)'s flow failed(%d)\n",
						port_id, ret);
				}
				goto wait;
			}
			in_flow->port_id = port_id;
			in_flow->flow = flow;
			ret = rte_ring_enqueue(ring, in_flow);
			if (ret) {
				RTE_LOG(ERR, remote_dir,
					"Save port(%d)'s flow failed(%d)\n",
					port_id, ret);
				ret = rte_flow_destroy(port_id, flow, NULL);
				if (ret) {
					RTE_LOG(ERR, remote_dir,
						"Destroy port(%d)'s flow failed(%d)\n",
						port_id, ret);
				}
				rte_free(in_flow);
			} else {
				RTE_LOG(INFO, remote_dir,
					"Create direct flow from port(%d)\n",
					port_id);
			}
		}
wait:
		sleep(1);
	}

	do {
		if (!ring)
			return arg;
		ret = rte_ring_dequeue(ring, (void **)&in_flow);
		if (!ret) {
			ret = rte_flow_destroy(in_flow->port_id,
				in_flow->flow, NULL);
			if (ret) {
				RTE_LOG(ERR, remote_dir,
					"Destroy port(%d)'s flow failed(%d)\n",
					port_id, ret);
			}
			rte_free(in_flow);
		} else {
			break;
		}
	} while (1);

	if (ring)
		rte_ring_free(ring);

	return arg;
}

static struct rte_flow_item *
remote_dir_find_flow(struct rte_remote_dir_flow flows[],
	enum rte_flow_item_type type,
	const char *from, const char *to,
	uint16_t max_flows, uint16_t *flow_idx,
	uint16_t group, uint16_t prior)
{
	uint16_t i, j;
	struct rte_flow_item *item;

	for (i = 0; i < max_flows; i++) {
		if (!strcmp(flows[i].from, from) && !strcmp(flows[i].to, to)) {
			if (flow_idx)
				*flow_idx = i;
			for (j = 0; j < flows[i].item_num; j++) {
				if (flows[i].items[j].type == type)
					return &flows[i].items[j];
			}
			item = &flows[i].items[j];
			flows[i].item_num++;
			item->type = type;
			return item;
		}
	}

	strcpy(flows[max_flows].from, from);
	strcpy(flows[max_flows].to, to);
	flows[max_flows].group = group;
	flows[max_flows].prior = prior;
	flows[max_flows].item_num++;
	if (flow_idx)
		*flow_idx = max_flows;

	flows[max_flows].items[0].type = type;

	return &flows[max_flows].items[0];
}

static inline int
rte_remote_direct_traffic(enum rte_remote_dir_cfg cfg)
{
	uint16_t i, j, max_idx = 0, this_idx, prior = 0;
	const char *from;
	const char *to;
	uint16_t cpu_16;
	uint32_t cpu_32;
	int ret;
	struct rte_remote_dir_flow flows[MAX_DIR_REQ_NUM];
	struct rte_flow_item *item;
	pthread_t pid;
	struct rte_flow_item_udp udp_hdr;
	struct rte_flow_item_udp udp_mask;

	struct rte_flow_item_gtp gtp_hdr;
	struct rte_flow_item_gtp gtp_mask;

	struct rte_flow_item_ecpri ecpri_hdr;
	struct rte_flow_item_ecpri ecpri_mask;

	if (cfg & RTE_REMOTE_DIR_RSP) {
		ret = pthread_create(&pid, NULL,
				remote_direct_rsp, NULL);
		if (ret)
			return ret;
	}

	if (!(cfg & RTE_REMOTE_DIR_REQ))
		return 0;

	memset(flows, 0, sizeof(flows));
	for (i = 0; i < MAX_DIR_REQ_NUM; i++) {
		for (j = 0; j < MAX_FLOW_ITEM_NUM; j++)
			flows[i].items[j].type = RTE_FLOW_ITEM_TYPE_END;
	}

	memset(&udp_mask, 0, sizeof(udp_mask));
	memset(&gtp_mask, 0, sizeof(gtp_mask));
	memset(&ecpri_mask, 0, sizeof(ecpri_mask));

	for (i = 0; i < s_dir_req_num; i++) {
		from = s_dir_req[i].from_name;
		to = s_dir_req[i].to_name;
		item = NULL;
		if (!strcmp("udp", s_dir_req[i].prot)) {
			item = remote_dir_find_flow(flows,
				RTE_FLOW_ITEM_TYPE_UDP, from, to, max_idx,
				&this_idx, 0, prior);
		} else if (!strcmp("gtp", s_dir_req[i].prot)) {
			item = remote_dir_find_flow(flows,
				RTE_FLOW_ITEM_TYPE_GTP, from, to, max_idx,
				&this_idx, 0, prior);
		} else if (!strcmp("ecpri", s_dir_req[i].prot)) {
			item = remote_dir_find_flow(flows,
				RTE_FLOW_ITEM_TYPE_ECPRI, from, to, max_idx,
				&this_idx, 0, prior);
		} else if (!strcmp("eth", s_dir_req[i].prot)) {
			item = remote_dir_find_flow(flows,
				RTE_FLOW_ITEM_TYPE_ETH, from, to, max_idx,
				&this_idx, 0, prior);
		} else {
			RTE_LOG(ERR, remote_dir,
				"Unsupported protocol(%s)\n",
				s_dir_req[i].prot);
			return -ENOTSUP;
		}

		if (this_idx >= max_idx) {
			/**New flow.*/
			prior++;
			max_idx++;
		}

		if (!item)
			return -EINVAL;

		if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
			if (!strcmp("dst", s_dir_req[i].fld)) {
				if (!item->spec)
					item->spec = &udp_hdr;
				if (!item->mask)
					item->mask = &udp_mask;

				cpu_16 = s_dir_req[i].fld_val;

				udp_hdr.hdr.dst_port = rte_cpu_to_be_16(cpu_16);
				udp_mask.hdr.dst_port = 0xffff;
			} else if (s_dir_req[i].fld[0]) {
				RTE_LOG(ERR, remote_dir,
					"Unsupported udp field(%s)\n",
					s_dir_req[i].fld);
				return -ENOTSUP;
			}
		} else if (item->type == RTE_FLOW_ITEM_TYPE_GTP) {
			if (!strcmp("teid", s_dir_req[i].fld)) {
				if (!item->spec)
					item->spec = &gtp_hdr;
				if (!item->mask)
					item->mask = &gtp_mask;

				cpu_32 = s_dir_req[i].fld_val;

				gtp_hdr.teid = rte_cpu_to_be_32(cpu_32);
				gtp_mask.teid = 0xffffffff;
			} else if (s_dir_req[i].fld[0]) {
				RTE_LOG(ERR, remote_dir,
					"Unsupported gtp field(%s)\n",
					s_dir_req[i].fld);
				return -ENOTSUP;
			}
		} else if (item->type == RTE_FLOW_ITEM_TYPE_ECPRI) {
			if (!strcmp("common type", s_dir_req[i].fld)) {
				if (!item->spec)
					item->spec = &ecpri_hdr;
				if (!item->mask)
					item->mask = &ecpri_mask;

				ecpri_hdr.hdr.common.type =
					s_dir_req[i].fld_val;
				ecpri_mask.hdr.common.type = 0xff;
			} else if (!strcmp("pc_id", s_dir_req[i].fld)) {
				if (!item->spec)
					item->spec = &ecpri_hdr;
				if (!item->mask)
					item->mask = &ecpri_mask;

				ecpri_hdr.hdr.common.type =
					RTE_ECPRI_MSG_TYPE_IQ_DATA;
				ecpri_mask.hdr.common.type = 0xff;

				cpu_16 = s_dir_req[i].fld_val;
				ecpri_hdr.hdr.type0.pc_id =
					rte_cpu_to_be_16(cpu_16);
				ecpri_mask.hdr.type0.pc_id = 0xffff;
			} else if (!strcmp("common type iq_data",
				s_dir_req[i].fld)) {
				if (!item->spec)
					item->spec = &ecpri_hdr;
				if (!item->mask)
					item->mask = &ecpri_mask;

				ecpri_hdr.hdr.common.type =
					RTE_ECPRI_MSG_TYPE_IQ_DATA;
				ecpri_mask.hdr.common.type = 0xff;
			} else if (!strcmp("common type iq_data pc_id",
				s_dir_req[i].fld)) {
				if (!item->spec)
					item->spec = &ecpri_hdr;
				if (!item->mask)
					item->mask = &ecpri_mask;

				ecpri_hdr.hdr.common.type =
					RTE_ECPRI_MSG_TYPE_IQ_DATA;
				ecpri_mask.hdr.common.type = 0xff;

				cpu_16 = s_dir_req[i].fld_val;
				ecpri_hdr.hdr.type0.pc_id =
					rte_cpu_to_be_16(cpu_16);
				ecpri_mask.hdr.type0.pc_id = 0xffff;
			} else if (s_dir_req[i].fld[0]) {
				RTE_LOG(ERR, remote_dir,
					"Unsupported ecpri field(%s)\n",
					s_dir_req[i].fld);
				return -ENOTSUP;
			}
		} else if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
			if (s_dir_req[i].fld[0]) {
				RTE_LOG(ERR, remote_dir,
					"Unsupported eth field(%s)\n",
					s_dir_req[i].fld);
				return -ENOTSUP;
			}
		}
	}

	for (i = 0; i < max_idx; i++) {
		ret = remote_direct_req(flows[i].from, flows[i].to,
			flows[i].items, flows[i].item_num,
			flows[i].group, flows[i].prior);
		if (ret)
			return ret;
	}

	return 0;
}

#endif
