/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023-2024 NXP
 */

#ifndef _RTE_DPAA2_MUX_DEMO_H
#define _RTE_DPAA2_MUX_DEMO_H
#include <rte_pmd_dpaa2.h>

enum {
	TRAFFIC_SPLIT_NONE,
	TRAFFIC_SPLIT_ETHTYPE,
	TRAFFIC_SPLIT_IP_PROTO,
	TRAFFIC_SPLIT_UDP_DST_PORT,
	TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP,
	TRAFFIC_SPLIT_IP_FRAG_PROTO,
	TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP_AND_ESP,
	TRAFFIC_SPLIT_VLAN,
	TRAFFIC_SPLIT_ECPRI,
	TRAFFIC_SPLIT_MAX_NUM
};

static uint8_t s_mux_demo_proto; /**< Split traffic based on this protocol ID */
static uint16_t s_mux_demo_ethtype; /**< Split traffic based on eth type */

static uint8_t s_mux_type; /**< Split traffic based on type */
static uint32_t s_mux_val;

static uint8_t s_mux_ep_id;

#ifndef RTE_LOGTYPE_dpaa2_mux_demo
#define RTE_LOGTYPE_dpaa2_mux_demo RTE_LOGTYPE_USER1
#endif

static int
dpaa2_mux_demo_get_mux_id(void)
{
	int dpdmux_id = -ENODEV, ret, offset = 0;
	FILE *fp;
	char nm[1024];

	offset += sprintf(&nm[offset], "restool dprc show $DPRC ");
	offset += sprintf(&nm[offset], "| grep dpdmux ");
	offset += sprintf(&nm[offset], "| cut -f 1 | cut -d . -f 2");
	/* Get the dpdmux ID from environment */
	fp = popen(nm, "r");
	if (!fp) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"Error in getting dpdmux id\n");
		return -ENODEV;
	}

	ret = fscanf(fp, "%d", &dpdmux_id);
	if (ret != 1) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"Failed to get dpdmux id\n");
		dpdmux_id = -ENODEV;
	}
	pclose(fp);

	return dpdmux_id;
}

static int
parse_traffic_split_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_SPLIT_TYPE = 0,
		FLD_SPLIT_VAL,
		FLD_MUX_CONN_ID,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned int size;
	int dpdmux_id;;
	char mux_ep_nm[64];

	p = strchr(p0, '(');
	++p;
	p0 = strchr(p, ')');
	if (!p0)
		return -EINVAL;

	size = p0 - p;
	if (size >= sizeof(s))
		return -EINVAL;

	snprintf(s, sizeof(s), "%.*s", size, p);
	if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
		return -EINVAL;
	for (i = 0; i < _NUM_FLD; i++) {
		errno = 0;
		int_fld[i] = strtoul(str_fld[i], &end, 0);
		if (errno || end == str_fld[i])
			return -EINVAL;
	}

	s_mux_type = (uint8_t)int_fld[FLD_SPLIT_TYPE];
	if (s_mux_type >= TRAFFIC_SPLIT_MAX_NUM) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"Invalid MUX split type(%d)\n", s_mux_type);
		return -EINVAL;
	}
	s_mux_val = int_fld[FLD_SPLIT_VAL];
	s_mux_ep_id = (uint8_t)int_fld[FLD_MUX_CONN_ID];

	dpdmux_id = dpaa2_mux_demo_get_mux_id();
	if (dpdmux_id < 0) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"get mux ID failed(%d)\n", dpdmux_id);
		return dpdmux_id;
	}
	sprintf(mux_ep_nm, "dpdmux.%d.%d", dpdmux_id, s_mux_ep_id);

	RTE_LOG(INFO, dpaa2_mux_demo,
		"Splitting MUX traffic on type:%d with val:%d on %s\n",
		s_mux_type, s_mux_val, mux_ep_nm);

	return 0;
}

static inline int
parse_traffic_split_info(const char *split_args)
{
	int key, dpni_id;
	char *dup_str;
	char *dpni, *proto;
	char delim = ':';

	/* the string would be in format <number>:<number> */
	dup_str = strdup(split_args);
	if (!dup_str)
		return -ENOBUFS;
	proto = dup_str;
	dpni = strchr(dup_str, delim);
	if (dpni) {
		proto[dpni - proto] = '\0';
		dpni += 1;
	} else
		goto err_ret;

	key = strtod(proto, NULL);
	if (proto[0] == '\0' || key <= 0 || key > USHRT_MAX)
		goto err_ret;

	dpni_id = strtod(dpni, NULL);
	if (dpni[0] == '\0' || dpni_id < 0 || dpni_id > INT_MAX)
		goto err_ret;

	/* if key is < 0xff - consider it tobe IP protocol
	 * else it is ether type
	 */
	if (key > 0xff)
		s_mux_demo_ethtype = key;
	else
		s_mux_demo_proto = key;
	s_mux_ep_id = dpni_id;

	RTE_LOG(INFO, dpaa2_mux_demo,
		"Split on %s(0x%x) to DPNI.%d\n",
		s_mux_demo_ethtype ?
		"ETH with ethtype" : "IP with next prot",
		s_mux_demo_ethtype ?
		s_mux_demo_ethtype : s_mux_demo_proto,
		s_mux_ep_id);

	return 0;

err_ret:
	if (dup_str)
		free(dup_str);
	return -EINVAL;
}

static inline int
rte_dpaa2_mux_demo_split_flow(void)
{
	if (s_mux_type > TRAFFIC_SPLIT_NONE &&
		s_mux_type < TRAFFIC_SPLIT_MAX_NUM)
		return true;

	return false;
}

static inline int
rte_dpaa2_mux_demo_split_eth_ip(void)
{
	return (s_mux_demo_proto || s_mux_demo_ethtype);
}

/* Constraints of this function:
 * 1. Assumes that only a single rule is being created, which is matching
 *    IPv4 proto_id field or ethertype.
 * 2. Mask for this match condition is 0xFF - which would be for exact match
 *    to user-provided s_mux_demo_proto
 */
static int
rte_dpaa2_mux_demo_config_ip_eth_split(void)
{
	int ret;
	struct rte_flow_item pattern[2];
	struct rte_flow_action actions[1];
	struct rte_flow_action_vf vf;
	struct rte_flow_item_ipv4 ipv4_item;
	struct rte_flow_item_eth eitem;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item_eth emask;
	int dpdmux_id;

	memset(&ipv4_item, 0, sizeof(ipv4_item));
	memset(&eitem, 0, sizeof(eitem));
	memset(&ipv4_mask, 0, sizeof(ipv4_mask));
	memset(&emask, 0, sizeof(emask));

	dpdmux_id = dpaa2_mux_demo_get_mux_id();
	if (dpdmux_id < 0) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"get mux ID failed(%d)\n", dpdmux_id);
		return dpdmux_id;
	}

	vf.id = s_mux_ep_id;

	if (s_mux_demo_proto) {
		ipv4_item.hdr.next_proto_id = s_mux_demo_proto;
		ipv4_mask.hdr.next_proto_id = 0xff;
		pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[0].spec = &ipv4_item;
		pattern[0].mask = &ipv4_mask;
	} else {
		eitem.type = rte_cpu_to_be_16(s_mux_demo_ethtype);
		emask.type = 0xffff;
		pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		pattern[0].spec = &eitem;
		pattern[0].mask = &emask;
	}
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	actions[0].type = RTE_FLOW_ACTION_TYPE_VF;
	actions[0].conf = &vf;

	ret = rte_pmd_dpaa2_mux_flow_create(dpdmux_id, pattern,
			actions);
	if (ret) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"%s: Create mux flow failed(%d)\n", __func__, ret);
	}

	return ret;
}

#define MAX_PATTERN_NUM 10
static int
rte_dpaa2_mux_demo_config_split_traffic(void)
{
	int ret, dpdmux_id, flow_nb = 0, start = 0;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action actions[1];
	struct rte_flow_action_vf vf;

	struct rte_flow_item_udp udp_item[MAX_PATTERN_NUM];
	struct rte_flow_item_ipv4 ip_item[MAX_PATTERN_NUM];
	struct rte_flow_item_eth eth_item[MAX_PATTERN_NUM];
	struct rte_flow_item_vlan vlan_item[MAX_PATTERN_NUM];
	struct rte_flow_item_ecpri ecpri_item[MAX_PATTERN_NUM];

	struct rte_flow_item_udp udp_mask[MAX_PATTERN_NUM];
	struct rte_flow_item_ipv4 ip_mask[MAX_PATTERN_NUM];
	struct rte_flow_item_eth eth_mask[MAX_PATTERN_NUM];
	struct rte_flow_item_vlan vlan_mask[MAX_PATTERN_NUM];
	struct rte_flow_item_ecpri ecpri_mask[MAX_PATTERN_NUM];

	memset(pattern, 0, sizeof(pattern));
	memset(actions, 0, sizeof(actions));
	memset(&vf, 0, sizeof(vf));
	memset(udp_item, 0, sizeof(udp_item));
	memset(ip_item, 0, sizeof(ip_item));
	memset(eth_item, 0, sizeof(eth_item));
	memset(vlan_item, 0, sizeof(vlan_item));
	memset(ecpri_item, 0, sizeof(ecpri_item));
	memset(udp_mask, 0, sizeof(udp_mask));
	memset(ip_mask, 0, sizeof(ip_mask));
	memset(eth_mask, 0, sizeof(eth_mask));
	memset(vlan_mask, 0, sizeof(vlan_mask));
	memset(ecpri_mask, 0, sizeof(ecpri_mask));

	dpdmux_id = dpaa2_mux_demo_get_mux_id();
	if (dpdmux_id < 0) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"get mux ID failed(%d)\n", dpdmux_id);
		return dpdmux_id;
	}

	vf.id = s_mux_ep_id;

	switch (s_mux_type) {
	case TRAFFIC_SPLIT_NONE:
		return 0;
	case TRAFFIC_SPLIT_ETHTYPE:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on ETH with Type(0x%x)\n", s_mux_val);
		eth_item[0].type =
			rte_cpu_to_be_16((uint16_t)s_mux_val);
		eth_mask[0].type = 0xffff;
		pattern[0].spec = &eth_item[0];
		pattern[0].mask = &eth_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_IP_PROTO:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on IP protocol(0x%x)\n", s_mux_val);
		ip_item[0].hdr.next_proto_id = s_mux_val;
		ip_mask[0].hdr.next_proto_id = 0xff;
		pattern[0].spec = &ip_item[0];
		pattern[0].mask = &ip_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_UDP_DST_PORT:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on UDP with DST port(0x%x)\n", s_mux_val);
		udp_item[0].hdr.dst_port =
			rte_cpu_to_be_16((uint16_t)s_mux_val);
		udp_mask[0].hdr.dst_port = 0xffff;
		pattern[0].spec = &udp_item[0];
		pattern[0].mask = &udp_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_UDP;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP_AND_ESP:
	case TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP:
		if (s_mux_type == TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP) {
			RTE_LOG(INFO, dpaa2_mux_demo,
				"Split on IP frag/UDP or GTP\n");
		} else {
			RTE_LOG(INFO, dpaa2_mux_demo,
				"Split on IP frag/UDP or GTP or ESP\n");
		}
		ip_item[0].hdr.fragment_offset = RTE_IPV4_HDR_MF_FLAG;
		ip_mask[0].hdr.fragment_offset = RTE_IPV4_HDR_MF_FLAG;
		pattern[0].spec = &ip_item[0];
		pattern[0].mask = &ip_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[1].spec = NULL;
		pattern[1].mask = NULL;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_UDP;
		pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		pattern[3].spec = NULL;
		pattern[3].mask = NULL;
		pattern[3].type = RTE_FLOW_ITEM_TYPE_GTP;
		pattern[4].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		if (s_mux_type == TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP)
			break;
		pattern[5].spec = NULL;
		pattern[5].mask = NULL;
		pattern[5].type = RTE_FLOW_ITEM_TYPE_ESP;
		pattern[6].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_IP_FRAG_PROTO:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on IP grag with next prot(0x%x)\n", s_mux_val);
		ip_item[0].hdr.next_proto_id = s_mux_val;
		ip_mask[0].hdr.next_proto_id = 0xff;
		pattern[0].spec = &ip_item[0];
		pattern[0].mask = &ip_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		ip_item[1].hdr.fragment_offset = RTE_IPV4_HDR_MF_FLAG;
		ip_mask[1].hdr.fragment_offset = RTE_IPV4_HDR_MF_FLAG;
		pattern[1].spec = &ip_item[1];
		pattern[1].mask = &ip_mask[1];
		pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_VLAN:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on VLAN with vlan ID(0x%x)\n", s_mux_val);
		vlan_item[0].hdr.vlan_tci =
			rte_cpu_to_be_16((uint16_t)s_mux_val);
		vlan_mask[0].hdr.vlan_tci = RTE_BE16(0x0fff);
		pattern[0].spec = &vlan_item[0];
		pattern[0].mask = &vlan_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_ECPRI:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on IQ eCPRI with physical channel(0x%x)\n",
			s_mux_val);
		ecpri_item[0].hdr.common.type = RTE_ECPRI_MSG_TYPE_IQ_DATA;
		ecpri_item[0].hdr.type0.pc_id =
			rte_cpu_to_be_16((uint16_t)s_mux_val);
		ecpri_mask[0].hdr.common.type = 0xff;
		ecpri_mask[0].hdr.type0.pc_id = 0xffff;
		pattern[0].spec = &ecpri_item[0];
		pattern[0].mask = &ecpri_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_ECPRI;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	default:
		RTE_LOG(ERR, dpaa2_mux_demo,
			"Invalid MUX split type(%d)\n", s_mux_type);
		return -EINVAL;
	}

	actions[0].type = RTE_FLOW_ACTION_TYPE_VF;
	actions[0].conf = &vf;

	while (flow_nb) {
		ret = rte_pmd_dpaa2_mux_flow_create(dpdmux_id, &pattern[start],
				actions);
		if (ret < 0) {
			RTE_LOG(ERR, dpaa2_mux_demo,
				"%s: MUX flow create failed(%d)\n",
				__func__, ret);
			break;
		}
		flow_nb--;
		if (!flow_nb)
			break;
		while (pattern[start].type != RTE_FLOW_ITEM_TYPE_END) {
			start++;
			if (start >= (MAX_PATTERN_NUM))
				break;
		}
		start++;
		if (start >= (MAX_PATTERN_NUM)) {
			RTE_LOG(ERR, dpaa2_mux_demo,
				"MUX flow pattern index(%d) overflow\n",
				start);
			break;
		}
	}

	return ret >= 0 ? 0 : ret;
}
#endif
