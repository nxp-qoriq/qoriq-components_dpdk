/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#include <stdbool.h>
#include <ethdev_pci.h>
#include <rte_random.h>
#include <dpaax_iova_table.h>
#include "base/enetc4_hw.h"
#include "base/enetc_hw.h"
#include "enetc_logs.h"
#include "enetc.h"

int
enetc4_vf_dev_stop(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
enetc4_vf_dev_start(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
enetc4_vf_stats_get(struct rte_eth_dev *dev __rte_unused,
			struct rte_eth_stats *stats __rte_unused)
{
	return 0;
}

/* Messaging */
static void
enetc4_msg_vsi_write_msg(struct enetc_hw *hw,
		struct enetc_msg_swbd *msg)
{
	uint32_t val;

	val = enetc_vsi_set_msize(msg->size) | lower_32_bits(msg->dma);
	enetc_wr(hw, ENETC4_VSIMSGSNDAR1, upper_32_bits(msg->dma));
	enetc_wr(hw, ENETC4_VSIMSGSNDAR0, val);
}

static int
enetc4_msg_vsi_send(struct enetc_hw *enetc_hw, struct enetc_msg_swbd *msg)
{
	int timeout = ENETC4_DEF_VSI_WAIT_TIMEOUT_UPDATE;
	int delay_us = ENETC4_DEF_VSI_WAIT_DELAY_UPDATE;
	int vsimsgsr;

	enetc4_msg_vsi_write_msg(enetc_hw, msg);

	if (getenv("ENETC4_VSI_WAIT_TIMEOUT_UPDATE"))
		timeout = atoi(getenv("ENETC4_VSI_WAIT_TIMEOUT_UPDATE"));

	if (getenv("ENETC4_VSI_WAIT_DELAY_UPDATE"))
		delay_us = atoi(getenv("ENETC4_VSI_WAIT_DELAY_UPDATE"));

	do {
		vsimsgsr = enetc_rd(enetc_hw, ENETC4_VSIMSGSR);
		if (!(vsimsgsr & ENETC4_VSIMSGSR_MB)){
			break;
		}
		rte_delay_us(delay_us);
	} while (--timeout);

	if (!timeout)
		return -ETIMEDOUT;

	/* check for message delivery error */
	if (vsimsgsr & ENETC4_VSIMSGSR_MS) {
		ENETC_PMD_ERR("Transfer error when copying the data.\n");
		return -EIO;
	}

	/* Check the user-defined completion status. */
	if (ENETC_SIMSGSR_GET_MC(vsimsgsr)) {
		ENETC_PMD_ERR("VSI command execute error %d\n",ENETC_SIMSGSR_GET_MC(vsimsgsr));

		if (ENETC_SIMSGSR_GET_MC(vsimsgsr) == ENETC_MSG_CMD_NOT_SUPPORT) {
			ENETC_PMD_ERR("VSI command not supported");
			return -EOPNOTSUPP;
		}
		else
			return -EIO;
	}

	return 0;
}

static int
enetc4_vf_set_mac_addr(struct rte_eth_dev *dev, struct rte_ether_addr *addr)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct enetc_hw *enetc_hw = &hw->hw;
	struct enetc_msg_cmd_set_primary_mac *cmd;
	struct enetc_msg_swbd *msg;
	int msg_size;
	int err = 0;

	/* meaning no VF */
	if (hw->device_id != ENETC4_DEV_ID_VF) {
		ENETC_PMD_ERR("No VFs");
		return -1;
	}

	msg = rte_zmalloc(NULL, sizeof(*msg), RTE_CACHE_LINE_SIZE);
	if (!msg) {
		ENETC_PMD_ERR("Failed to alloc msg");
		err = -ENOMEM;
		return err;
        }

	msg_size = RTE_ALIGN(sizeof(struct enetc_msg_cmd_set_primary_mac), RTE_CACHE_LINE_SIZE);
	msg->vaddr = rte_zmalloc(NULL, msg_size, 0);
	if (!msg->vaddr) {
		ENETC_PMD_ERR("Failed to alloc memory for msg");
		rte_free(msg);
		return -ENOMEM;
	}

	msg->dma = rte_mem_virt2iova((const void *) msg->vaddr);
	msg->size = msg_size;

	cmd = (struct enetc_msg_cmd_set_primary_mac *)msg->vaddr;
	cmd->header.type = ENETC_MSG_CMD_MNG_MAC;
	cmd->header.id = ENETC_MSG_CMD_MNG_ADD;
	memcpy(&cmd->mac.sa_data, addr, sizeof(struct rte_ether_addr));

	dcbf(cmd);
	/* send the command and wait */
	err = enetc4_msg_vsi_send(enetc_hw, msg);
	if (err){
		ENETC_PMD_ERR("VSI message send error");
		goto end;
	}

	rte_ether_addr_copy((struct rte_ether_addr *) &cmd->mac.sa_data,
			&dev->data->mac_addrs[0]);

end:
	/* free memory no longer required */
	rte_free(msg->vaddr);
	rte_free(msg);
	return err;
}

static int
enetc4_vf_promisc_send_message(struct rte_eth_dev *dev, bool uc_promisc, bool mc_promisc)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct enetc_hw *enetc_hw = &hw->hw;
	struct enetc_msg_config_mac_filter *cmd;
	struct enetc_msg_swbd *msg;
	int msg_size;
	int err = 0;

	msg = rte_zmalloc(NULL, sizeof(*msg), RTE_CACHE_LINE_SIZE);
	if (!msg) {
		ENETC_PMD_ERR("Failed to alloc msg");
		err = -ENOMEM;
		return err;
	}

	msg_size = RTE_ALIGN(sizeof(struct enetc_msg_config_mac_filter), RTE_CACHE_LINE_SIZE);
	msg->vaddr = rte_zmalloc(NULL, msg_size, 0);
	if (!msg->vaddr) {
		ENETC_PMD_ERR("Failed to alloc memory for msg");
		rte_free(msg);
		return -ENOMEM;
	}

	msg->dma = rte_mem_virt2iova((const void *) msg->vaddr);
	msg->size = msg_size;

	cmd = (struct enetc_msg_config_mac_filter *)msg->vaddr;
	memset(cmd, 0, sizeof(*cmd));
	cmd->header.type = ENETC_MSG_CMD_MNG_RX_MAC_FILTER;
	cmd->header.id = ENETC_MSG_CMD_MNG_ADD;
	cmd->uc_promisc = uc_promisc;
	cmd->mc_promisc = mc_promisc;

	dcbf(cmd);
	/* send the command and wait */
	err = enetc4_msg_vsi_send(enetc_hw, msg);
	if(err){
		ENETC_PMD_ERR("VSI message send error");
		goto end;
	}

end:
	/* free memory no longer required */
	rte_free(msg->vaddr);
	rte_free(msg);
	return err;
}

static int
enetc4_vf_multicast_enable(struct rte_eth_dev *dev)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	bool mc_promisc = true;
	int err;

	err = enetc4_vf_promisc_send_message(dev, hw->uc_promisc, mc_promisc);
	if(err) {
		ENETC_PMD_ERR("Failed to enable multicast promiscuous mode");
		return err;
	}

	hw->mc_promisc = true;

	return 0;
}

static int
enetc4_vf_multicast_disable(struct rte_eth_dev *dev)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	bool mc_promisc = false;
	int err;

	err = enetc4_vf_promisc_send_message(dev, hw->uc_promisc, mc_promisc);
	if(err) {
		ENETC_PMD_ERR("Failed to disable multicast promiscuous mode");
		return err;
	}

	hw->mc_promisc = false;

	return 0;
}

static int
enetc4_vf_promisc_enable(struct rte_eth_dev *dev)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	bool uc_promisc = true;
	int err;

	err = enetc4_vf_promisc_send_message(dev, uc_promisc, hw->mc_promisc);
	if(err) {
		ENETC_PMD_ERR("Failed to enable promiscuous mode");
		return err;
	}

	hw->uc_promisc = true;

	return 0;
}

static int
enetc4_vf_promisc_disable(struct rte_eth_dev *dev)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	bool uc_promisc = false;
	int err;

	err = enetc4_vf_promisc_send_message(dev, uc_promisc, hw->mc_promisc);
	if(err) {
		ENETC_PMD_ERR("Failed to disable promiscuous mode");
		return err;
	}

	hw->uc_promisc = false;

	return 0;
}


/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_vf_id_enetc4_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_NXP, ENETC4_DEV_ID_VF) },
	{ .vendor_id = 0, /* sentinel */ },
};

/* Features supported by this driver */
static const struct eth_dev_ops enetc4_vf_ops = {
.dev_configure        = enetc4_dev_configure,
.dev_start            = enetc4_vf_dev_start,
.dev_stop             = enetc4_vf_dev_stop,
.dev_close            = enetc4_dev_close,
.stats_get            = enetc4_vf_stats_get,
.link_update          = enetc4_link_update,
.dev_infos_get        = enetc4_dev_infos_get,
.mac_addr_set         = enetc4_vf_set_mac_addr,
.promiscuous_enable   = enetc4_vf_promisc_enable,
.promiscuous_disable  = enetc4_vf_promisc_disable,
.allmulticast_enable  = enetc4_vf_multicast_enable,
.allmulticast_disable = enetc4_vf_multicast_disable,
.rx_queue_setup       = enetc4_rx_queue_setup,
.rx_queue_start       = enetc4_rx_queue_start,
.rx_queue_stop        = enetc4_rx_queue_stop,
.rx_queue_release     = enetc4_rx_queue_release,
.tx_queue_setup       = enetc4_tx_queue_setup,
.tx_queue_start       = enetc4_tx_queue_start,
.tx_queue_stop        = enetc4_tx_queue_stop,
.tx_queue_release     = enetc4_tx_queue_release,
};

static int
enetc4_vf_mac_init(struct enetc_eth_hw *hw, struct rte_eth_dev *eth_dev)
{
	uint32_t *mac = (uint32_t *)hw->mac.addr;
	struct enetc_hw *enetc_hw = &hw->hw;
	uint32_t high_mac = 0;
	uint16_t low_mac = 0;
	char vf_eth_name[ENETC_ETH_NAMESIZE];

	PMD_INIT_FUNC_TRACE();

	/* Enabling Station Interface */
	enetc4_wr(enetc_hw, ENETC_SIMR, ENETC_SIMR_EN);
	*mac = (uint32_t)enetc_rd(enetc_hw, ENETC_SIPMAR0);
	high_mac = (uint32_t)*mac;
	mac++;
	*mac = (uint32_t)enetc_rd(enetc_hw, ENETC_SIPMAR1);
	low_mac = (uint16_t)*mac;

	if ((high_mac | low_mac) == 0) {
		char *first_byte;
		ENETC_PMD_NOTICE("MAC is not available for this SI, "
				 "set random MAC\n");
		mac = (uint32_t *)hw->mac.addr;
		*mac = (uint32_t)rte_rand();
		first_byte = (char *)mac;
		*first_byte &= 0xfe;    /* clear multicast bit */
		*first_byte |= 0x02;    /* set local assignment bit (IEEE802) */
		enetc4_port_wr(enetc_hw, ENETC4_PMAR0, *mac);
		mac++;
		*mac = (uint16_t)rte_rand();
		enetc4_port_wr(enetc_hw, ENETC4_PMAR1, *mac);
		print_ethaddr("New address: ",
			(const struct rte_ether_addr *)hw->mac.addr);
	}

	/* Allocate memory for storing MAC addresses */
	snprintf(vf_eth_name, sizeof(vf_eth_name), "enetc4_vf_eth_%d", eth_dev->data->port_id);
	eth_dev->data->mac_addrs = rte_zmalloc(vf_eth_name,
					RTE_ETHER_ADDR_LEN, 0);
	if (!eth_dev->data->mac_addrs) {
		ENETC_PMD_ERR("Failed to allocate %d bytes needed to "
			      "store MAC addresses",
			      RTE_ETHER_ADDR_LEN * 1);
		return -ENOMEM;
	}

	/* Copy the permanent MAC address */
	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac.addr,
			     &eth_dev->data->mac_addrs[0]);

	return 0;
}

static int
enetc4_vf_dev_init(struct rte_eth_dev *eth_dev)
{
	struct enetc_eth_hw *hw =
			    ENETC_DEV_PRIVATE_TO_HW(eth_dev->data->dev_private);
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	int error = 0;

	PMD_INIT_FUNC_TRACE();
	eth_dev->dev_ops = &enetc4_vf_ops;
	hw->uc_promisc = false;
	hw->mc_promisc = false;
	enetc4_dev_hw_init(eth_dev);

	error = enetc4_vf_mac_init(hw, eth_dev);
	if (error != 0) {
		ENETC_PMD_ERR("MAC initialization failed!!");
		return -1;
	}

	if (rte_eal_iova_mode() == RTE_IOVA_PA)
		dpaax_iova_table_populate();

	ENETC_PMD_DEBUG("port_id %d vendorID=0x%x deviceID=0x%x",
			eth_dev->data->port_id, pci_dev->id.vendor_id,
			pci_dev->id.device_id);
	return 0;
}

static int
enetc4_vf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		    struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct enetc_eth_adapter),
					     enetc4_vf_dev_init);
}

static struct rte_pci_driver rte_enetc4_vf_pmd = {
	.id_table = pci_vf_id_enetc4_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = enetc4_vf_pci_probe,
	.remove = enetc4_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_enetc4_vf, rte_enetc4_vf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_enetc4_vf, pci_vf_id_enetc4_map);
RTE_PMD_REGISTER_KMOD_DEP(net_enetc4_vf, "* uio_pci_generic");
RTE_LOG_REGISTER_DEFAULT(enetc4_vf_logtype_pmd, NOTICE);
