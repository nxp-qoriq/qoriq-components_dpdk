/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <signal.h>

#include <linux/videodev2.h>

#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_io.h>
#include <rte_malloc.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#define CLEAR(x) memset(&(x), 0, sizeof(x))
#define FMT_NUM_PLANES 1

#define RTP_PT_PRIVATE 96
#define RTP_VERSION 2
#define PTS 3000

/* Channel Interrupt Enable Register */
#define  CHNL_IER				0x10
#define  CHNL_IER_FRM_RCVD_EN_OFFSET		29
#define  CHNL_IER_FRM_RCVD_EN_MASK		0x20000000


/* Channel Status Register */
#define  CHNL_STS				0x14
#define  CHNL_STS_LINE_STRD_OFFSET		30
#define  CHNL_STS_LINE_STRD_MASK		0x40000000

/* Channel RGB or Luma (Y) Output Buffer 1 Address */
#define  CHNL_OUT_BUF1_ADDR_Y			0x70

/* Channel RGB or Luma (Y) Output Buffer 2 Address */
#define  CHNL_OUT_BUF2_ADDR_Y		0x8C
#define  CHNL_OUT_BUF_CTRL		0x8
#define  CHNL_OUT_BUF_CTRL_LOAD_BUF1_ADDR_MASK			0x4000
#define  CHNL_OUT_BUF_CTRL_LOAD_BUF2_ADDR_MASK			0x8000

#define ISI_OUT_BUF_NUM 2

struct buffer {
	uint8_t *buf[ISI_OUT_BUF_NUM];
	rte_iova_t dma_handle[ISI_OUT_BUF_NUM];
};

struct rte_rtp_hdr {
	uint8_t v_p_x_cc;
	uint8_t m_pt;
	rte_be16_t seq;
	rte_be32_t timestamp;
	rte_be32_t ssrc;
} __rte_packed;

struct rtp_context {
	int payload_type;
	uint32_t ssrc;
	int seq;
	uint32_t timestamp;
	uint32_t base_timestamp;
	uint32_t cur_timestamp;
	int xinc;
	int pgroup;
	int bpp;
	size_t sizeimage, bytesperline;
	unsigned int packet_count;
};

static const char *dev_name = "/dev/video0";
static int fd = -1;
static struct buffer frame_buf;
static int pixel_width = 640;
static int pixel_height = 480;
static int frame_rate = 30;
static volatile bool force_quit;

static uint32_t src_ip_addr = RTE_IPV4(192, 168, 1, 1);
static uint32_t dest_ip_addr = RTE_IPV4(192, 168, 1, 2);
static uint8_t src_ether_addr[RTE_ETHER_ADDR_LEN] = {0x00, 0x04, 0x9f, 0x05, 0x9e, 0x61};
static uint8_t dest_ether_addr[RTE_ETHER_ADDR_LEN] = {0x68, 0x05, 0xca, 0x57, 0xea, 0xf4};
static uint16_t src_port = 5004;
static uint16_t dest_port = 5004;
static struct rtp_context rtp_cntxt;
static int reserved_bytes = 64;

static struct rte_mempool *mbuf_pool;
static struct rte_mbuf_ext_shared_info shinfo;

/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

static void *isi_baseaddr_v;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static int
read_random(uint32_t *dst, const char *file)
{
	int fd;
	int err = -1;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;

	err = read(fd, dst, sizeof(*dst));
	close(fd);

	return err;
}

static uint32_t
get_random_seed(void)
{
	uint32_t seed;

	if (read_random(&seed, "/dev/urandom") == sizeof(seed))
		return seed;

	if (read_random(&seed, "/dev/random")  == sizeof(seed))
		return seed;

	return rand();
}

static void
ext_buf_free_callback_fn(void *addr __rte_unused, void *opaque __rte_unused)
{
}

static void
rtp_send_data(uint8_t *buf, uint16_t len, rte_iova_t buf_iova, int m)
{
	uint16_t hdr_offset;
	uint16_t offset = 0;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_rtp_hdr *rtp_hdr;
	uint16_t udplen = sizeof(struct rte_udp_hdr) + sizeof(struct rte_rtp_hdr) + len;
	int payload_type = RTP_PT_PRIVATE;
	uint16_t portid = 0;
	int ret;
	struct rte_mbuf *mbuf;

	hdr_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_udp_hdr) + sizeof(struct rte_rtp_hdr) + 8;
	buf -= hdr_offset;
	buf_iova -= hdr_offset;

	mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf)
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");

	shinfo.free_cb = ext_buf_free_callback_fn;
	rte_pktmbuf_attach_extbuf(mbuf, buf, buf_iova, len + 54, &shinfo);

	if (mbuf->ol_flags != RTE_MBUF_F_EXTERNAL)
		printf("%s: External buffer is not attached to mbuf\n", __func__);

	rtp_cntxt.timestamp = rtp_cntxt.cur_timestamp;

	/* rtphdr */
	offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_udp_hdr);
	rtp_hdr = (struct rte_rtp_hdr *)(buf + offset);
	rtp_hdr->v_p_x_cc = RTP_VERSION << 6;
	rtp_hdr->m_pt = (payload_type & 0x7f) | ((m & 0x01) << 7);
	rtp_hdr->seq = rte_cpu_to_be_16((uint16_t)rtp_cntxt.seq);
	rtp_hdr->timestamp = rte_cpu_to_be_32(rtp_cntxt.timestamp);
	rtp_hdr->ssrc = rte_cpu_to_be_32(rtp_cntxt.ssrc);

	/* udphdr */
	offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
	udp_hdr = (struct rte_udp_hdr *)(buf + offset);
	udp_hdr->src_port = rte_cpu_to_be_16(src_port);
	udp_hdr->dst_port = rte_cpu_to_be_16(dest_port);
	udp_hdr->dgram_len = rte_cpu_to_be_16(udplen);
	udp_hdr->dgram_cksum = 0;

	/* iphdr */
	offset = sizeof(struct rte_ether_hdr);
	ip_hdr = (struct rte_ipv4_hdr *)(buf + offset);
	ip_hdr->version_ihl = 0x45;
	ip_hdr->type_of_service = 0;
	ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + udplen);
	ip_hdr->packet_id = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = 64;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->src_addr = rte_cpu_to_be_32(src_ip_addr);
	ip_hdr->dst_addr = rte_cpu_to_be_32(dest_ip_addr);
	ip_hdr->hdr_checksum = 0;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

	/* ethhdr */
	eth_hdr = (struct rte_ether_hdr *)buf;
	rte_memcpy(eth_hdr->src_addr.addr_bytes, src_ether_addr, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth_hdr->dst_addr.addr_bytes, dest_ether_addr, RTE_ETHER_ADDR_LEN);
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	mbuf->pkt_len = mbuf->buf_len;
	mbuf->data_len = 0;

	ret = rte_eth_tx_burst(portid, 0, &mbuf, 1);
	if (!ret)
		rte_pktmbuf_free(mbuf);

	rtp_cntxt.seq = (rtp_cntxt.seq + 1) & 0xffff;
	rtp_cntxt.packet_count++;
}

static void
errno_exit(const char *s)
{
	fprintf(stderr, "%s error %d, %s\n", s, errno, strerror(errno));
	exit(EXIT_FAILURE);
}

static int
xioctl(int fh, int request, void *arg)
{
	int r;

	do {
		r = ioctl(fh, request, arg);
	} while (-1 == r && EINTR == errno);

	return r;
}

static void
rtp_send_raw_rfc4175(uint8_t *buf, rte_iova_t buf_iova, int line_no)
{
	int head_size = 8;
	uint8_t *dest = NULL;
	uint32_t offset;

	if (!line_no)
		offset = reserved_bytes + pixel_width * rtp_cntxt.bpp;
	else if (line_no == pixel_height - 1)
		offset = (reserved_bytes + pixel_width * rtp_cntxt.bpp) * (pixel_height - 2);
	else
		offset = (reserved_bytes + pixel_width * rtp_cntxt.bpp) * line_no;

	dest = buf + offset;

	/* Offset and Continuation marker */
	*(--dest) = 0;
	*(--dest) = 0;

	/* Line No and Field identification */
	*(--dest) = line_no & 0xff;
	*(--dest) = (line_no >> 8) & 0x7f;

	/* Length */
	*(--dest) = (pixel_width * rtp_cntxt.bpp) & 0xff;
	*(--dest) = ((pixel_width * rtp_cntxt.bpp) >> 8) & 0xff;

	/* Extended Sequence Number */
	*(--dest) = 0;
	*(--dest) = 0;

	rtp_send_data(buf + offset, head_size + pixel_width * rtp_cntxt.bpp,
		buf_iova + offset, line_no == pixel_height - 1);
}

static void
isi_channel_set_outbuf(rte_iova_t dma_handle, int index)
{
	uint32_t val;
	int offset;

	if (index == 0)
		offset = CHNL_OUT_BUF1_ADDR_Y;
	else
		offset = CHNL_OUT_BUF2_ADDR_Y;
	rte_write32(rte_cpu_to_le_32(dma_handle), (uint8_t *)isi_baseaddr_v + offset);

	val = rte_read32((uint8_t *)isi_baseaddr_v + CHNL_OUT_BUF_CTRL);
	if (index == 0)
		val ^= CHNL_OUT_BUF_CTRL_LOAD_BUF1_ADDR_MASK;
	else
		val ^= CHNL_OUT_BUF_CTRL_LOAD_BUF2_ADDR_MASK;
	rte_write32(rte_cpu_to_le_32(val), (uint8_t *)isi_baseaddr_v + CHNL_OUT_BUF_CTRL);
}

static void alloc_videobuf(void)
{
	int i;

	for (i = 0; i < ISI_OUT_BUF_NUM; ++i) {
		frame_buf.buf[i] = rte_malloc(NULL, rtp_cntxt.sizeimage, 0);
		if (!frame_buf.buf[i])
			rte_exit(EXIT_FAILURE, "rte_malloc");

		frame_buf.dma_handle[i] = rte_malloc_virt2iova(frame_buf.buf[i]);
		if (frame_buf.dma_handle[i] == RTE_BAD_IOVA) {
			rte_free(frame_buf.buf[i]);
			rte_exit(EXIT_FAILURE, "rte_malloc_virt2iova");
		}

		isi_channel_set_outbuf(frame_buf.dma_handle[i], i);
	}
}

static void
read_frame(void)
{
	uint32_t frame_count = 0;
	int bufid = 0;
	uint32_t status;
	int line_no = 0;


	rte_write32(0, (uint8_t *)isi_baseaddr_v + CHNL_IER);

	while (!force_quit) {
		rtp_cntxt.cur_timestamp = rtp_cntxt.base_timestamp + frame_count * PTS;

		while (line_no < pixel_height) {
			status = rte_read32((uint8_t *)isi_baseaddr_v + CHNL_STS);
			rte_write32(rte_cpu_to_le_32(status), (uint8_t *)isi_baseaddr_v + CHNL_STS);
			if (status & CHNL_STS_LINE_STRD_MASK) {
				rtp_send_raw_rfc4175(frame_buf.buf[bufid],
					frame_buf.dma_handle[bufid], line_no);
				++line_no;
			}
		}

		if (force_quit)
			return;

		line_no = 0;
		bufid = !bufid;
		++frame_count;
	}
}

static void
stop_capturing(void)
{
	enum v4l2_buf_type type;

	type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	if (-1 == xioctl(fd, VIDIOC_STREAMOFF, &type))
		errno_exit("VIDIOC_STREAMOFF");
}

static void
start_capturing(void)
{
	enum v4l2_buf_type type;
	int i;

	/* dummy */
	for (i = 0; i < 2; ++i) {
		struct v4l2_buffer buf;
		struct v4l2_plane planes[FMT_NUM_PLANES];

		CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = i;
		buf.m.planes = planes;
		buf.length	= FMT_NUM_PLANES;

		if (-1 == xioctl(fd, VIDIOC_QBUF, &buf))
			errno_exit("VIDIOC_QBUF");
	}

	type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	if (-1 == xioctl(fd, VIDIOC_STREAMON, &type))
		errno_exit("VIDIOC_STREAMON");
}

static void
free_videobuf(void)
{
	int i;

	for (i = 0; i < ISI_OUT_BUF_NUM; ++i)
		rte_free(frame_buf.buf[i]);
}

static void
init_device(void)
{
	struct v4l2_capability cap;
	struct v4l2_format fmt;
	struct v4l2_streamparm streamparm;
	struct v4l2_requestbuffers req;

	if (-1 == xioctl(fd, VIDIOC_QUERYCAP, &cap)) {
		if (errno == EINVAL) {
			fprintf(stderr, "%s is no V4L2 device\n",
				 dev_name);
			exit(EXIT_FAILURE);
		} else {
			errno_exit("VIDIOC_QUERYCAP");
		}
	}

	if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE_MPLANE)) {
		fprintf(stderr, "%s is no video capture device\n",
			 dev_name);
		exit(EXIT_FAILURE);
	}

	if (!(cap.capabilities & V4L2_CAP_STREAMING)) {
		fprintf(stderr, "%s does not support streaming i/o\n", dev_name);
		exit(EXIT_FAILURE);
	}

	CLEAR(fmt);

	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	fmt.fmt.pix_mp.width       = pixel_width;
	fmt.fmt.pix_mp.height      = pixel_height;
	fmt.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_BGR24;
	fmt.fmt.pix_mp.field       = V4L2_FIELD_NONE;
	fmt.fmt.pix_mp.plane_fmt[0].bytesperline  = rtp_cntxt.bytesperline;
	fmt.fmt.pix_mp.plane_fmt[0].sizeimage  = rtp_cntxt.sizeimage;

	if (-1 == xioctl(fd, VIDIOC_S_FMT, &fmt))
		errno_exit("VIDIOC_S_FMT");

	/* Set stream params: frame rate */
	CLEAR(streamparm);

	streamparm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	streamparm.parm.capture.timeperframe.denominator = frame_rate;
	streamparm.parm.capture.timeperframe.numerator = 1;
	if (-1 == ioctl(fd, VIDIOC_S_PARM, &streamparm))
		errno_exit("VIDIOC_S_PARM");

	CLEAR(req);

	req.count = 2;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;

	if (-1 == xioctl(fd, VIDIOC_REQBUFS, &req)) {
		if (errno == EINVAL) {
			fprintf(stderr, "%s does not support "
				 "memory mappingn", dev_name);
			exit(EXIT_FAILURE);
		} else {
			errno_exit("VIDIOC_REQBUFS");
		}
	}

	if (req.count < 2) {
		fprintf(stderr, "Insufficient buffer memory on %s\n",
			 dev_name);
		exit(EXIT_FAILURE);
	}
}

static void
close_device(void)
{
	if (-1 == close(fd))
		errno_exit("close");

	fd = -1;
}

static void
open_device(void)
{
	struct stat st;

	if (-1 == stat(dev_name, &st)) {
		fprintf(stderr, "Cannot identify '%s': %d, %s\n",
			 dev_name, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!S_ISCHR(st.st_mode)) {
		fprintf(stderr, "%s is no devicen", dev_name);
		exit(EXIT_FAILURE);
	}

	fd = open(dev_name, O_RDWR | O_NONBLOCK, 0);

	if (-1 == fd) {
		fprintf(stderr, "Cannot open '%s': %d, %s\n",
			 dev_name, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_conf local_port_conf = port_conf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &local_port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	rxconf = dev_info.default_rxconf;
	rxconf.offloads = local_port_conf.rxmode.offloads;
	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = local_port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	return 0;
}
/* >8 End of main functional part of port initialization. */

#define MAX_LINE_SIZE		64
#define ISI_CCSR_SIZE		0x10000
#define EXTRACT_CCSR_ADDR(s)	(s + strlen(s) - 8)

static int parse_ccsr_addr(size_t *ccsr_addr, size_t *ccsr_size)
{
	char *dtb_entry;
	FILE *file;
	int ret, rt;
	int cnt;

	file = fopen("/proc/device-tree/aliases/isi0", "r");
	if (file) {
		dtb_entry = malloc(MAX_LINE_SIZE);
		if (!dtb_entry) {
			printf("malloc failed!!");
			rt = -1;
			fclose(file);
			goto err;
		}
		memset(dtb_entry, 0, MAX_LINE_SIZE);
		cnt = fread(dtb_entry, sizeof(char), MAX_LINE_SIZE, file);
		/* fread success */
		if (cnt) {
			ret = sscanf(EXTRACT_CCSR_ADDR(dtb_entry), "%lx",
					 ccsr_addr);
			if (ret != 1) {
				printf("sscanf failed!!");
				rt = -1;
				free(dtb_entry);
				fclose(file);
				goto err;
			}
			*ccsr_size = ISI_CCSR_SIZE;
			printf("%s ccsr_addr=0x%lx\n", __func__, *ccsr_addr);
		}
		free(dtb_entry);
		fclose(file);
	} else {
		printf("File open failed!!");
		rt = -1;
		goto err;
	}

err:
		return rt;
}

static void
lcore_main(void)
{
	int mem_fd;
	size_t ccsr_addr, ccsr_size;

	rtp_cntxt.ssrc = get_random_seed();
	rtp_cntxt.seq = get_random_seed() & 0x0fff;
	rtp_cntxt.base_timestamp = get_random_seed();
	rtp_cntxt.timestamp = rtp_cntxt.base_timestamp;
	rtp_cntxt.cur_timestamp = 0;
	rtp_cntxt.xinc = 1;
	rtp_cntxt.pgroup = 3;
	rtp_cntxt.bpp = rtp_cntxt.pgroup / rtp_cntxt.xinc;
	rtp_cntxt.bytesperline = (pixel_width * rtp_cntxt.pgroup) / rtp_cntxt.xinc + reserved_bytes;
	rtp_cntxt.sizeimage = rtp_cntxt.bytesperline * pixel_height;

	parse_ccsr_addr(&ccsr_addr, &ccsr_size);

	mem_fd = open("/dev/mem", O_RDWR);
	if (mem_fd) {
		isi_baseaddr_v = mmap(NULL, ccsr_size, PROT_READ | PROT_WRITE,
				      MAP_SHARED, mem_fd, ccsr_addr);
		if (isi_baseaddr_v == MAP_FAILED) {
			printf("Can not map CCSR base");
			close(mem_fd);
			return;
		}
		close(mem_fd);
	} else {
		printf("Failed to open /dev/mem");
		return;
	}

	open_device();
	init_device();

	start_capturing();
	alloc_videobuf();
	read_frame();

	stop_capturing();
	free_videobuf();
	close_device();
	fprintf(stderr, "\n");
}

#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_IP_DEST "ip-dest"
#define CMD_LINE_OPT_PORT_DEST "port-dest"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_ETH_DEST_NUM,
	CMD_LINE_OPT_IP_DEST_NUM,
	CMD_LINE_OPT_PORT_DEST_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_ETH_DEST, 1, 0, CMD_LINE_OPT_ETH_DEST_NUM},
	{CMD_LINE_OPT_IP_DEST, 1, 0, CMD_LINE_OPT_IP_DEST_NUM},
	{CMD_LINE_OPT_PORT_DEST, 1, 0, CMD_LINE_OPT_PORT_DEST_NUM},
	{NULL, 0, 0, 0}
};

/* display usage */
static void
print_usage(const char *prgname)
{
	fprintf(stderr, "%s [EAL options] --"
		" [-d /dev/videoX]"
		" [-w WIDTH]"
		" [-h HEIGHT]"
		" [-r FRAMERATE]"
		" [--eth-dest MM:MM:MM:MM:MM:MM]"
		" [--ip-dest XXX.XXX.XXX.XXX]"
		" [--port-dest X]\n\n"

		"  --eth-dest MM:MM:MM:MM:MM:MM: Ethernet destination\n"
		"  --ip-dest XXX.XXX.XXX.XXX: IP destination\n"
		"  --port-dest X: UDP port destination\n",
		prgname);
}

static void
parse_eth_dest(const char *optarg)
{
	uint8_t c, peer_addr[6];

	if (cmdline_parse_etheraddr(NULL, optarg,
		&peer_addr, sizeof(peer_addr)) < 0)
		rte_exit(EXIT_FAILURE,
		"Invalid ethernet address: %s\n",
		optarg);

	for (c = 0; c < 6; c++)
		dest_ether_addr[c] = peer_addr[c];
}

static void
parse_ip_dest(const char *optarg)
{
	uint32_t ip_addr;

	if (strlen(optarg) >= INET_ADDRSTRLEN)
		rte_exit(EXIT_FAILURE,
		"Invalid ipv4 address length: %s\n",
		optarg);

	if (inet_pton(AF_INET, optarg, &ip_addr) != 1)
		rte_exit(EXIT_FAILURE,
		"Invalid ipv4 address: %s\n",
		optarg);

	dest_ip_addr = rte_be_to_cpu_32(ip_addr);
	src_ip_addr = dest_ip_addr + 1;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "d:w:h:r:",
				  lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'd':
			dev_name = optarg;
			break;

		case 'w':
			pixel_width = atoi(optarg);
			break;

		case 'h':
			pixel_height = atoi(optarg);
			break;

		case 'r':
			frame_rate = atoi(optarg);
			break;

		/* long options */
		case CMD_LINE_OPT_ETH_DEST_NUM:
			parse_eth_dest(optarg);
			break;

		case CMD_LINE_OPT_IP_DEST_NUM:
			parse_ip_dest(optarg);
			break;

		case CMD_LINE_OPT_PORT_DEST_NUM:
			dest_port = (uint16_t)atoi(optarg);
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}


/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned int nb_ports;
	uint16_t portid;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	}

	/* >8 End of initializing all ports. */

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	RTE_ETH_FOREACH_DEV(portid) {
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
