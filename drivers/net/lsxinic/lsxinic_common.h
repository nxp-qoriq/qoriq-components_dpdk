/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#ifndef _LSXINIC_COMMON_H_
#define _LSXINIC_COMMON_H_

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
#define LSINIC_MERGE_DEFAULT_THRESHOLD (600) /* bytes */
#endif

#define LSINIC_ETH_FCS_SIZE \
	(RTE_TM_ETH_FRAMING_OVERHEAD_FCS - RTE_TM_ETH_FRAMING_OVERHEAD)

#define LSINIC_ETH_OVERHEAD_SIZE \
	RTE_TM_ETH_FRAMING_OVERHEAD_FCS

#ifndef RTE_VERIFY
#define RTE_VERIFY(exp) do {} while (0)
#endif

struct lsinic_pcie_svr_map {
	uint32_t svr_id;
	uint16_t pci_dev_id;
	uint16_t rsv;
};

#ifndef SVR_LX2160A
#define SVR_LX2160A	0x87360000
#endif

static const
struct lsinic_pcie_svr_map s_lsinic_rev2_id_map[] = {
	{SVR_LX2160A | 0x0120, 0x8d81, 0},
	{SVR_LX2160A | 0x1020, 0x8d90, 0},
	{SVR_LX2160A | 0x0020, 0x8d80, 0},
	{SVR_LX2160A | 0x1120, 0x8d91, 0},
	{SVR_LX2160A | 0x2120, 0x8da1, 0},
	{SVR_LX2160A | 0x3020, 0x8db0, 0},
	{SVR_LX2160A | 0x2020, 0x8da0, 0},
	{SVR_LX2160A | 0x3120, 0x8db1, 0},
	{SVR_LX2160A | 0x0320, 0x8d83, 0},
	{SVR_LX2160A | 0x1220, 0x8d92, 0},
	{SVR_LX2160A | 0x0220, 0x8d82, 0},
	{SVR_LX2160A | 0x1320, 0x8d93, 0}
};

#define NXP_PCI_VENDOR_ID (0x1957)
#define NXP_DEFAULT_SOC_IDX 2
#define NXP_PCI_DEV_ID_LX2160A_DEFAULT \
	s_lsinic_rev2_id_map[NXP_DEFAULT_SOC_IDX].pci_dev_id

#define NXP_PCI_DEV_ID_LS2088A (0x8240)
#define NXP_PCI_DEV_ID_NULL (0)
#define NXP_PCI_CLASS_ID (0x0200)

#define XMIT_IDX_EXTRA_SPACE 2

enum lsinic_xfer_complete_flag {
	LSINIC_XFER_COMPLETE_INIT_FLAG = 0,
	LSINIC_XFER_COMPLETE_DONE_FLAG = 1
};

enum lsinic_dev_type {
	LSINIC_VIRTIO_DEV,
	LSINIC_NXP_DEV
};

enum lsinic_port_type {
	LSINIC_EP_PORT,
	LSINIC_RC_PORT,
	LSINIC_EPVIO_PORT
};

#define LSINIC_RING_MAX_COUNT 8
#define LSINIC_RING_DEFAULT_MAX_QP 4

#define LSINIC_MAX_BURST_NUM 32

#define MAX_U32 ((uint64_t)4 * 1024 * 1024 * 1024 - 1)
#define MAX_U16 0xffff

#define UNUSED(x) (void)(x)

static inline __attribute__((always_inline))
void mem_cp128b_atomic(uint8_t *dst, const uint8_t *src)
{
	__uint128_t *dst128 = (__uint128_t *)dst;
	const __uint128_t *src128 = (const __uint128_t *)src;
	*dst128 = *src128;
}

static inline int is_align_16(void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x1)
		return 0;

	return 1;
}

static inline int is_align_32(void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x3)
		return 0;

	return 1;
}

static inline int is_align_64(void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x7)
		return 0;

	return 1;
}

static inline int is_align_128(void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0xf)
		return 0;

	return 1;
}

/* Length of data >= 16 && data is 16B aligned*/
static inline void
lsinic_pcie_memset_align(uint8_t *dst,
	const uint8_t data[], uint16_t size)
{
	const void *src = data;
	const uint64_t *src64 = src;
	const __uint128_t *src128 = src;
	const uint32_t *src32 = src;
	const uint16_t *src16 = src;

	if (!is_align_16(dst) && size > 0) {
		*dst = data[0];
		dst++;
		size--;
	}

	if (!is_align_32(dst) &&
		size >= sizeof(uint16_t)) {
		*((uint16_t *)dst) = src16[0];
		dst += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	if (!is_align_64(dst) &&
		size >= sizeof(uint32_t)) {
		*((uint32_t *)dst) = src32[0];
		dst += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	if (!is_align_128(dst) &&
		size >= sizeof(uint64_t)) {
		*((uint64_t *)dst) = src64[0];
		dst += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(__uint128_t)) {
		RTE_VERIFY(is_align_128(dst));
		*((__uint128_t *)dst) = *src128;
		dst += sizeof(__uint128_t);
		size -= sizeof(__uint128_t);
	}

	while (size >= sizeof(uint64_t)) {
		RTE_VERIFY(is_align_64(dst));
		*((uint64_t *)dst) = src64[0];
		dst += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(uint32_t)) {
		RTE_VERIFY(is_align_32(dst));
		*((uint32_t *)dst) = src32[0];
		dst += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	while (size >= sizeof(uint16_t)) {
		RTE_VERIFY(is_align_16(dst));
		*((uint16_t *)dst) = src16[0];
		dst += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	while (size > 0) {
		*dst = data[0];
		dst++;
		size--;
	}
}

static inline void
lsinic_pcie_memcp_align(void *vdst,
	const void *vsrc, uint32_t size)
{
	uint8_t *dst = vdst;
	const uint8_t *src = vsrc;

	RTE_VERIFY(((uint64_t)dst & 0x7) == ((uint64_t)src & 0x7));

	if (!is_align_16(dst) && size > 0) {
		*dst = *src;
		dst++;
		src++;
		size--;
	}

	if (!is_align_32(dst) &&
		size >= sizeof(uint16_t)) {
		*((uint16_t *)dst) = *((const uint16_t *)src);
		dst += sizeof(uint16_t);
		src += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	if (!is_align_64(dst) &&
		size >= sizeof(uint32_t)) {
		*((uint32_t *)dst) = *((const uint32_t *)src);
		dst += sizeof(uint32_t);
		src += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	if (!is_align_128(dst) &&
		size >= sizeof(uint64_t)) {
		*((uint64_t *)dst) = *((const uint64_t *)src);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(__uint128_t)) {
		RTE_VERIFY(is_align_128(dst));
		*((__uint128_t *)dst) = *((const __uint128_t *)src);
		dst += sizeof(__uint128_t);
		src += sizeof(__uint128_t);
		size -= sizeof(__uint128_t);
	}

	while (size >= sizeof(uint64_t)) {
		RTE_VERIFY(is_align_64(dst));
		*((uint64_t *)dst) = *((const uint64_t *)src);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(uint32_t)) {
		RTE_VERIFY(is_align_32(dst));
		*((uint32_t *)dst) = *((const uint32_t *)src);
		dst += sizeof(uint32_t);
		src += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	while (size >= sizeof(uint16_t)) {
		RTE_VERIFY(is_align_16(dst));
		*((uint16_t *)dst) = *((const uint16_t *)src);
		dst += sizeof(uint16_t);
		src += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	while (size > 0) {
		*dst = *src;
		dst++;
		src++;
		size--;
	}
}

#define PCI_CONFIG_CAP_CTL_OFFSET 0x78
#define PCI_CONFIG_LINK_CAP_OFFSET 0x80
#define PCI_CONFIG_SPACE_SIZE 0x1000
#define PCI_DEVCTL_NOSNOOP	0x0800

#define LSINIC_EP_MAP_MEM_ENV \
	"LSINIC_XFER_HOST_ACCESS_EP_MEM"

#endif /*  _LSXINIC_COMMON_H_ */
