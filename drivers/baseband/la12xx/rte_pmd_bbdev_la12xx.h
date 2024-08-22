/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2024 NXP
 */

#ifndef _PMD_LA12XX_H_
#define _PMD_LA12XX_H_

#include <rte_bbdev.h>
#include <rte_bbuf.h>

#include <geul_feca.h>

/** Structure specifying a polar operation for la12xx */
struct rte_pmd_la12xx_polar_params {
	/** Mempool which op instance is in */
	struct rte_mempool *mempool;
	/** Parameters for FECA job */
	feca_job_t feca_obj;
	/** The input buffer */
	struct rte_bbdev_op_data input;
	/** The output buffer */
	struct rte_bbdev_op_data output;
	/** In case of SD-CD demux, this can be used to get
	 *  the LLRs for CD after the demuxing. These LLRs
	 *  can be used to further process CD in software.
	 *  This is only used when sd_cd_demux is used.
	 */
	bool dequeue_polar_deq_llrs;
};

/** Structure specifying a raw operation for la12xx */
struct rte_pmd_la12xx_raw_params {
	/** The input buffer */
	struct rte_bbdev_op_data input;
	/** The output buffer */
	struct rte_bbdev_op_data output;
	/** Associated metadata */
	void *metadata;
};

/** Structure specifying a VSPA operation for la12xx */
struct rte_pmd_la12xx_vspa_params {
	/** The input buffer */
	struct rte_bbdev_op_data input;
	/** The output buffer */
	struct rte_bbdev_op_data output;
	/** Associated metadata */
	void *metadata;
	/** extra data to be send to VSPA */
	uint32_t extra_data[8];
};

/** Structure specifying a single operation for la12xx */
struct rte_pmd_la12xx_op {
	/** operation type */
	enum rte_bbdev_op_type op_type;
	/** Status of operation that was performed */
	int status;
	/** Opaque pointer for user data */
	void *opaque_data;
	union {
		/** Polar op */
		struct rte_pmd_la12xx_polar_params polar_params;
		/** RAW op */
		struct rte_pmd_la12xx_raw_params raw_params;
		/** VSPA op */
		struct rte_pmd_la12xx_vspa_params vspa_params;
	};
};

#define RTE_PMD_LA12xx_SET_POLAR_DEC(p) \
	(p)->polar_params.feca_obj.job_type =  FECA_JOB_CD;
#define RTE_PMD_LA12xx_SET_POLAR_DEC_DEMUX_ACK(p) \
	(p)->polar_params.feca_obj.job_type =  FECA_JOB_CD_DCM_ACK;
#define RTE_PMD_LA12xx_SET_POLAR_DEC_DEMUX_CSI1(p) \
	(p)->polar_params.feca_obj.job_type =  FECA_JOB_CD_DCM_CS1;
#define RTE_PMD_LA12xx_SET_POLAR_DEC_DEMUX_CSI2(p) \
	(p)->polar_params.feca_obj.job_type =  FECA_JOB_CD_DCM_CS2;
#define RTE_PMD_LA12xx_SET_POLAR_ENC(p) \
	(p)->polar_params.feca_obj.job_type =  FECA_JOB_CE;
#define RTE_PMD_LA12xx_SET_POLAR_ENC_MUX(p) \
	(p)->polar_params.feca_obj.job_type =  FECA_JOB_CE_DCM;
#define RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_ACK(p) \
	((p)->polar_params.feca_obj.job_type == FECA_JOB_CD_DCM_ACK)
#define RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI1(p) \
	((p)->polar_params.feca_obj.job_type == FECA_JOB_CD_DCM_CS1)
#define RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI2(p) \
	((p)->polar_params.feca_obj.job_type == FECA_JOB_CD_DCM_CS2)
#define RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX(p) \
	((RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_ACK(p)) || \
	(RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI1(p)) || \
	(RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI2(p)))
#define RTE_PMD_LA12xx_IS_POLAR_ENC_MUX(p) \
	((p)->polar_params.feca_obj.job_type == FECA_JOB_CE_DCM)

#define RTE_PMD_LA12xx_PD_pd_n(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.pd_n
#define RTE_PMD_LA12xx_PD_input_deint_bypass(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.input_deint_bypass
#define RTE_PMD_LA12xx_PD_output_deint_bypass(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.output_deint_bypass
#define	RTE_PMD_LA12xx_PD_rm_mode(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.rm_mode
#define RTE_PMD_LA12xx_PD_pc_en(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.pc_en
#define RTE_PMD_LA12xx_PD_crc_type(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.crc_type
#define RTE_PMD_LA12xx_PD_K(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.K
#define RTE_PMD_LA12xx_PD_E(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg2.E
#define RTE_PMD_LA12xx_PD_crc_rnti(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg2.crc_rnti
#define RTE_PMD_LA12xx_PD_pc_index0(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_pe_indices.pc_index0
#define RTE_PMD_LA12xx_PD_pc_index1(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_pe_indices.pc_index1
#define RTE_PMD_LA12xx_PD_pc_index2(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_pe_indices.pc_index2
#define RTE_PMD_LA12xx_PD_FZ_LUT(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_fz_lut
#define RTE_PMD_LA12xx_PD_DEQUEUE_LLRS(p) \
	((p)->polar_params.dequeue_polar_deq_llrs)

#define RTE_PMD_LA12xx_PE_pe_n(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.pe_n
#define RTE_PMD_LA12xx_PE_input_int_bypass(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.input_int_bypass
#define RTE_PMD_LA12xx_PE_output_int_bypass(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.output_int_bypass
#define	RTE_PMD_LA12xx_PE_rm_mode(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.rm_mode
#define RTE_PMD_LA12xx_PE_pc_en(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.pc_en
#define RTE_PMD_LA12xx_PE_crc_type(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.crc_type
#define RTE_PMD_LA12xx_PE_dst_sel(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg1.dst_sel
#define RTE_PMD_LA12xx_PE_K(p) \
	(p)->polar_params.feca_obj.command_chain_t.cd_command_ch_obj.cd_cfg1.K
#define RTE_PMD_LA12xx_PE_E(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg2.E
#define RTE_PMD_LA12xx_PE_crc_rnti(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg2.crc_rnti
#define RTE_PMD_LA12xx_PE_out_pad_bytes(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg3.out_pad_bytes
#define RTE_PMD_LA12xx_PE_block_concat_en(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_cfg3.block_concat_en
#define RTE_PMD_LA12xx_PE_pc_index0(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_pe_indices.pc_index0
#define RTE_PMD_LA12xx_PE_pc_index1(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_pe_indices.pc_index1
#define RTE_PMD_LA12xx_PE_pc_index2(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_pe_indices.pc_index2
#define RTE_PMD_LA12xx_PE_FZ_LUT(p) \
	(p)->polar_params.feca_obj.command_chain_t.ce_command_ch_obj.ce_fz_lut
#define RTE_PMD_LA12xx_POLAR_OP_DESC(p) \
	((p)->polar_params.feca_obj)
__rte_experimental
void
rte_pmd_la12xx_op_init(struct rte_mempool *mempool,
		__rte_unused void *arg, void *element,
		__rte_unused unsigned int n);

/**
 * Enqueue a burst of operations for encode or decode to a queue of the device.
 * This functions only enqueues as many operations as currently possible and
 * does not block until @p num_ops entries in the queue are available.
 * This function does not provide any error notification to avoid the
 * corresponding overhead.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_id
 *   The index of the queue.
 * @param ops
 *   Pointer array containing operations to be enqueued Must have at least
 *   @p num_ops entries
 * @param num_ops
 *   The maximum number of operations to enqueue.
 *
 * @return
 *   The number of operations actually enqueued (this is the number of processed
 *   entries in the @p ops array).
 */
__rte_experimental
uint16_t
rte_pmd_la12xx_enqueue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_pmd_la12xx_op **ops, uint16_t num_ops);

/**
 * Dequeue a burst of processed encode/decode operations from a queue of
 * the device.
 * This functions returns only the current contents of the queue, and does not
 * block until @ num_ops is available.
 * This function does not provide any error notification to avoid the
 * corresponding overhead.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_id
 *   The index of the queue.
 * @param ops
 *   Pointer array where operations will be dequeued to. Must have at least
 *   @p num_ops entries
 * @param num_ops
 *   The maximum number of operations to dequeue.
 *
 * @return
 *   The number of operations actually dequeued (this is the number of entries
 *   copied into the @p ops array).
 */
__rte_experimental
uint16_t
rte_pmd_la12xx_dequeue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_pmd_la12xx_op **ops, uint16_t num_ops);

/**
 * Assign a particular processing core on LA12xx for a particular queue.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_ids
 *   Queue ID's
 * @param core_ids
 *   Core ID's corresponding to the queues
 * @param num_ops
 *   Number of Queues.
 *
 * @return
 *   0 - Success, otherwise Failure
 */
__rte_experimental
uint16_t
rte_pmd_la12xx_queue_core_config(uint16_t dev_id, uint16_t queue_ids[],
		uint16_t core_ids[], uint16_t num_queues);

/**
 * Assign a particular processing core on LA12xx for a particular queue.
 * This is only supported for LDPC channels.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_id
 *   Queue ID
 * @param input_circ_size
 *   Input circular buffer size for FECA
 *
 * @return
 *   0 - Success, otherwise Failure
 */
__rte_experimental
uint16_t
rte_pmd_la12xx_queue_input_circ_size(uint16_t dev_id, uint16_t queue_id,
				    uint32_t input_circ_size);

/**
 * Check if LA12XX is active.
 * If LA12xx device has crashed/hung and needs reset/reboot, bbdev application
 * can call  * 'rte_pmd_la12xx_reset_restore_cfg' to reboot and re-configure
 * LA12xx device.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   1 - Device is Active, 0 - Device Needs Reset, < 0 - Error
 */
__rte_experimental
int
rte_pmd_la12xx_is_active(uint16_t dev_id);

/**
 * Reset (reboot to default state) LA12xx device.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   0 - Success, otherwise Failure
 */
__rte_experimental
int
rte_pmd_la12xx_reset(uint16_t dev_id);

/**
 * Reset bbdev device only.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   0 - Success, otherwise Failure
 */
__rte_experimental
int
rte_pmd_bbdev_reset(uint16_t dev_id);

/**
 * Reset (reboot) LA12xx device and restore the configuration.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   0 - Success, otherwise Failure
 */
__rte_experimental
int
rte_pmd_la12xx_reset_restore_cfg(uint16_t dev_id);

/**
 * Adjust the bbuf and provides updated start address to write the buffer
 * onto for LDPC Encode (Shared Encode).
 * NOTE: There should be 4096 bytes additionally available in the bbuf in the
 * in tailroom.
 *
 * @param bbuf
 *   The packet bbuf.
 * @param num_bytes
 *   Number of bytes which will be written into the buffer.
 *
 * @return
 *   0 - Success, otherwise Failure (in case enough tailroom is not available)
 */
__rte_experimental
int
rte_pmd_la12xx_ldpc_enc_adj_bbuf(struct rte_bbuf *bbuf, uint64_t num_bytes);

/**
 * Adjust the address and provides updated start address to write the buffer
 * onto for LDPC Encode (Shared Encode).
 * NOTE: There should be 4096 bytes available before the start add (addr)
 * provided as length adjusted would return an address in range
 * of (addr - 4096) to addr.
 *
 * @param addr
 *   Start address of the buffer for which address adjustment is required.
 * @param num_bytes
 *   Number of bytes which will be written into the buffer.
 *
 * @return
 *   Adjusted start address to write the buffer.
 */
__rte_experimental
void *
rte_pmd_la12xx_ldpc_enc_adj_addr(void *addr, uint64_t num_bytes);

/**
 * This options enable use of single QDMA for FECA SD input.
 * By default Multi-QDMA is used, but can be configured to use
 * single QDMA for enhanced performance. Using single QDMA can
 * cause problem in some scenarios where FECA becomes slow in
 * processing and QDMA overwrites previous unread data (like in
 * some of DEMUX cases). So single QDMA for SD input should be
 * used cautiously and only when all the scenarios are verified
 * to be passed.
 *
 * @param dev_id
 *   The identifier of the device.
 */
__rte_experimental
void
rte_pmd_la12xx_ldpc_dec_single_input_dma(uint16_t dev_id);

/**
 * This API can be used to map the hugepage address.
 * With DPDK APIs the allocation of the memory for ring, mempools,
 * mbuf/bbuf pools or malloc start from the end of the allocated
 * hugepage. Thus this API maps the memory starting from the end
 * and returns the size of the address which is mapped of that
 * hugepage memory. For instance if only 512 MB of memory can be
 * mapped to the modem and the addr provided is for a 1 GB hugepage,
 * the last 512 MB of the hugepage memory would be mapped.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @param addr
 *   Address to be mapped over PCI.
 *
 * @return
 *   size of the mapping created. This could be 0 in case mapping
 *   already exists.
 *   < 0 in case of failure.
 */
__rte_experimental
int
rte_pmd_la12xx_map_hugepage_addr(uint16_t dev_id, void *addr);


/**
 * This API can be used to know the mapped PCI address for a given
 * host addrs, which should be used for sending address to the LA12xx
 * map the hugepage address.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @param addr
 *   Address for which mapped address is needed.
 *.. It is 32 bit -as the LA12xx can only support 32 bit address
 *
 * @return
 *   mapped physical address.
  *  0 - if mapping not available.
 */
__rte_experimental
int
rte_pmd_get_la12xx_mapaddr(uint16_t dev_id, void *addr);

/**
 * This options reset FECA and bbdev queues to state which was after
 * BBDEV configuration i.e. before calling of rte_bbdev_start() API.
 * Application needs to stop any BBDEV processing on all cores before
 * calling this FECA reset API.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   0 - Success, otherwise Failure
 */
__rte_experimental
int
rte_pmd_la12xx_feca_reset(uint16_t dev_id);

/**
 * Get the eventfd for the device. This eventfd gets triggered when device
 * does not work properly (wdog gets triggered) and needs a reset.
 *
 * If LA12xx device has crashed/hung and needs reset/reboot, this event fd
 * gets triggered. Bbdev application can call
 * 'rte_pmd_la12xx_reset_restore_cfg' to reboot and re-configure LA12xx device.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   event_fd, < 0 - Error
 */
__rte_experimental
int
rte_pmd_la12xx_get_event_fd(uint16_t dev_id);

/**
 * Read and clear the event fd data. This is done after event is triggered.
 *
 * @param dev_id
 *   The identifier of the device.
 */
__rte_experimental
void
rte_pmd_la12xx_clear_event_fd(uint16_t dev_id);

#endif
