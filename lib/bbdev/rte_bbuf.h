/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2024 NXP
 */

#ifndef _RTE_BBUF_H_
#define _RTE_BBUF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_errno.h>
#include <rte_hexdump.h>

/** Alignment constraint of bbuf private area. */
#define RTE_BBUF_PRIV_ALIGN 8
#define RTE_BBUF_HEADROOM RTE_PKTMBUF_HEADROOM

#define rte_bbuf rte_mbuf
#define rte_bbuf_mtod rte_pktmbuf_mtod
#define rte_bbuf_alloc_bulk rte_pktmbuf_alloc_bulk
#define rte_bbuf_alloc rte_pktmbuf_alloc
#define rte_bbuf_mtod_offset rte_pktmbuf_mtod_offset
#define rte_bbuf_data_len rte_pktmbuf_pkt_len
#define rte_bbuf_reset rte_pktmbuf_reset
#define rte_bbuf_free rte_pktmbuf_free
#define rte_bbuf_free_bulk rte_pktmbuf_free_bulk
#define rte_bbuf_tailroom rte_pktmbuf_tailroom

/**
 * Append len bytes to an bbuf.
 *
 * Append len bytes to an bbuf and return a pointer to the start address
 * of the added data. If there is not enough tailroom in the last
 * segment, the function will return NULL, without modifying the bbuf.
 *
 * @param b
 *   The packet bbuf.
 * @param len
 *   The amount of data to append (in bytes).
 * @return
 *   A pointer to the start of the newly appended data, or
 *   NULL if there is not enough tailroom space in the last segment
 */
static inline
char *rte_bbuf_append(struct rte_bbuf *b, uint32_t len)
{
	void *tail;
	struct rte_mbuf *m_last;

	m_last = rte_pktmbuf_lastseg(b);

	/* We take an assumption here that there is enough tailroom present */
	tail = (char *)m_last->buf_addr + m_last->data_off + m_last->pkt_len;
	m_last->pkt_len  = (m_last->pkt_len + len);
	return (char *) tail;
}

/**
 * Create a bbuf pool.
 *
 * This function creates and initializes a packet bbuf pool. It is
 * a wrapper to rte_mempool functions.
 *
 * @param name
 *   The name of the bbuf pool.
 * @param n
 *   The number of elements in the bbuf pool. The optimum size (in terms
 *   of memory usage) for a mempool is when n is a power of two minus one:
 *   n = (2^q - 1).
 * @param cache_size
 *   Size of the per-core object cache. See rte_mempool_create() for
 *   details.
 * @param priv_size
 *   Size of application private are between the rte_bbuf structure
 *   and the data buffer. This value must be aligned to RTE_BBUF_PRIV_ALIGN.
 * @param data_room_size
 *   Size of data buffer in each bbuf, including RTE_PKTBBUF_HEADROOM.
 * @param socket_id
 *   The socket identifier where the memory should be allocated. The
 *   value can be *SOCKET_ID_ANY* if there is no NUMA constraint for the
 *   reserved zone.
 * @return
 *   The pointer to the new allocated mempool, on success. NULL on error
 *   with rte_errno set appropriately. Possible rte_errno values include:
 *    - E_RTE_NO_CONFIG - function could not get pointer to rte_config structure
 *    - E_RTE_SECONDARY - function was called from a secondary process instance
 *    - EINVAL - cache size provided is too large, or priv_size is not aligned.
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
static inline struct rte_mempool *
rte_bbuf_pool_create(const char *name, unsigned int n,
	unsigned int cache_size, uint16_t priv_size, uint32_t data_room_size,
	int socket_id)
{
	struct rte_mempool *mp;
	struct rte_pktmbuf_pool_private mbp_priv;
	const char *mp_ops_name = NULL;
	unsigned elt_size;
	int ret;

	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		RTE_LOG(ERR, MBUF, "mbuf priv_size=%u is not aligned\n",
			priv_size);
		rte_errno = EINVAL;
		return NULL;
	}

	elt_size = sizeof(struct rte_mbuf) + (unsigned)priv_size +
		(unsigned)data_room_size;
	memset(&mbp_priv, 0, sizeof(mbp_priv));
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = priv_size;

	mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
		 sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mp == NULL)
		return NULL;

	if (mp_ops_name == NULL)
		mp_ops_name = rte_mbuf_best_mempool_ops();
	ret = rte_mempool_set_ops_byname(mp, mp_ops_name, NULL);
	if (ret != 0) {
		RTE_LOG(ERR, MBUF, "error setting mempool handler\n");
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	ret = rte_mempool_populate_default(mp);
	if (ret < 0) {
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);

	return mp;
}

/**
 * Returns the length of the bbuf packet.
 *
 * @param b
 *   The packet bbuf.
 */
static inline uint32_t rte_bbuf_pkt_len(struct rte_bbuf *b)
{
	uint32_t pkt_len = b->pkt_len;

	while (b->next != NULL) {
		b = b->next;
		pkt_len += b->pkt_len;
	}
	return pkt_len;
}

/**
 * Chain a bbuf to another bbuf, thereby creating a segmented packet.
 *
 * Note: The implementation will do a linear walk over the segments to find
 * the tail entry. For cases when there are many segments, it's better to
 * chain the entries manually.
 *
 * @param head
 *   The head of the bbuf chain (the first packet)
 * @param tail
 *   The bbuf to put last in the chain
 *
 * @return
 *   - 0, on success.
 *   - -EOVERFLOW, if the chain segment limit exceeded
 */
static inline int rte_bbuf_chain(
		struct rte_bbuf *head,
		struct rte_bbuf *tail)
{
	struct rte_mbuf *cur_tail;

	/* Check for number-of-segments-overflow */
	if (head->nb_segs + tail->nb_segs > RTE_MBUF_MAX_NB_SEGS)
		return -EOVERFLOW;

	/* Chain 'tail' onto the old tail */
	cur_tail = rte_pktmbuf_lastseg(head);
	cur_tail->next = tail;

	/* accumulate number of segments and total length.
	 * NB: elaborating the addition like this instead of using
	 *     -= allows us to ensure the result type is uint16_t
	 *     avoiding compiler warnings on gcc 8.1 at least */
	head->nb_segs = (uint16_t)(head->nb_segs + tail->nb_segs);
	return 0;
}

/**
 * Dump an bbuf structure to a file.
 *
 * Dump all fields for the given bbuf and all its associated
 * segments (in the case of a chained buffer).
 *
 * @param f
 *   A pointer to a file for output
 * @param b
 *   The bbuf.
 * @param dump_len
 *   If dump_len != 0, also dump the "dump_len" first data bytes of
 *   the packet.
 */
static inline void
rte_bbuf_dump(FILE *f, const struct rte_bbuf *b, unsigned int dump_len)
{
	unsigned int len;
	unsigned int nb_segs;

	__rte_mbuf_sanity_check(b, 1);

	fprintf(f, "dump bbuf at %p, iova=%"PRIx64", buf_len=%u\n",
		b, (uint64_t)b->buf_iova, (unsigned int)b->buf_len);
	fprintf(f, "  pkt_len=%"PRIu32", ol_flags=%"PRIx64", nb_segs=%u, in_port=%u\n",
		b->pkt_len, b->ol_flags,
		(unsigned int)b->nb_segs, (unsigned int)b->port);
	nb_segs = b->nb_segs;

	while (b && nb_segs != 0) {
		fprintf(f, "  segment at %p, data=%p, pkt_len=%u\n",
			b, rte_pktmbuf_mtod(b, void *), (unsigned int)b->pkt_len);
		len = dump_len;
		if (len > b->pkt_len)
			len = b->pkt_len;
		if (len != 0)
			rte_hexdump(f, NULL, rte_pktmbuf_mtod(b, void *), len);
		dump_len -= len;
		b = b->next;
		nb_segs--;
	}
}

#ifdef __cplusplus
}
#endif

#endif
