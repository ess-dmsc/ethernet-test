/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#include <stdio.h>

#include <rte_bitops.h>
#include <rte_net.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_vxlan.h>
#include <rte_ethdev.h>
#include <rte_flow.h>

#include "testpmd.h"

#define MAX_STRING_LEN 8192

#define MKDUMPSTR(buf, buf_size, cur_len, ...) \
do { \
	if (cur_len >= buf_size) \
		break; \
	cur_len += snprintf(buf + cur_len, buf_size - cur_len, __VA_ARGS__); \
} while (0)

static inline void
print_ether_addr(const char *what, const struct rte_ether_addr *eth_addr,
		 char print_buf[], size_t buf_size, size_t *cur_len)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	MKDUMPSTR(print_buf, buf_size, *cur_len, "%s%s", what, buf);
}

static inline bool
is_timestamp_enabled(const struct rte_mbuf *mbuf)
{
	static uint64_t timestamp_rx_dynflag;
	int timestamp_rx_dynflag_offset;

	if (timestamp_rx_dynflag == 0) {
		timestamp_rx_dynflag_offset = rte_mbuf_dynflag_lookup(
				RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, NULL);
		if (timestamp_rx_dynflag_offset < 0)
			return false;
		timestamp_rx_dynflag = RTE_BIT64(timestamp_rx_dynflag_offset);
	}

	return (mbuf->ol_flags & timestamp_rx_dynflag) != 0;
}

static inline rte_mbuf_timestamp_t
get_timestamp(const struct rte_mbuf *mbuf)
{
	static int timestamp_dynfield_offset = -1;

	if (timestamp_dynfield_offset < 0) {
		timestamp_dynfield_offset = rte_mbuf_dynfield_lookup(
				RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
		if (timestamp_dynfield_offset < 0)
			return 0;
	}

	return *RTE_MBUF_DYNFIELD(mbuf,
			timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}


uint16_t
tx_pkt_set_md(uint16_t port_id, __rte_unused uint16_t queue,
	      struct rte_mbuf *pkts[], uint16_t nb_pkts,
	      __rte_unused void *user_param)
{
	uint16_t i = 0;

	/*
	 * Add metadata value to every Tx packet,
	 * and set ol_flags accordingly.
	 */
	if (rte_flow_dynf_metadata_avail())
		for (i = 0; i < nb_pkts; i++) {
			*RTE_FLOW_DYNF_METADATA(pkts[i]) =
						ports[port_id].tx_metadata;
			pkts[i]->ol_flags |= PKT_TX_DYNF_METADATA;
		}
	return nb_pkts;
}


uint16_t
tx_pkt_set_dynf(uint16_t port_id, __rte_unused uint16_t queue,
		struct rte_mbuf *pkts[], uint16_t nb_pkts,
		__rte_unused void *user_param)
{
	uint16_t i = 0;

	if (ports[port_id].mbuf_dynf)
		for (i = 0; i < nb_pkts; i++)
			pkts[i]->ol_flags |= ports[port_id].mbuf_dynf;
	return nb_pkts;
}

void
add_tx_dynf_callback(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_tx_queues; queue++)
		if (!ports[portid].tx_set_dynf_cb[queue])
			ports[portid].tx_set_dynf_cb[queue] =
				rte_eth_add_tx_callback(portid, queue,
							tx_pkt_set_dynf, NULL);
}

void
remove_tx_dynf_callback(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_tx_queues; queue++)
		if (ports[portid].tx_set_dynf_cb[queue]) {
			rte_eth_remove_tx_callback(portid, queue,
				ports[portid].tx_set_dynf_cb[queue]);
			ports[portid].tx_set_dynf_cb[queue] = NULL;
		}
}

int
eth_dev_info_get_print_err(uint16_t port_id,
					struct rte_eth_dev_info *dev_info)
{
	int ret;

	ret = rte_eth_dev_info_get(port_id, dev_info);
	if (ret != 0)
		printf("Error during getting device (port %u) info: %s\n",
				port_id, strerror(-ret));

	return ret;
}

void
eth_set_promisc_mode(uint16_t port, int enable)
{
	int ret;

	if (enable)
		ret = rte_eth_promiscuous_enable(port);
	else
		ret = rte_eth_promiscuous_disable(port);

	if (ret != 0)
		printf("Error during %s promiscuous mode for port %u: %s\n",
			enable ? "enabling" : "disabling",
			port, rte_strerror(-ret));
}

void
eth_set_allmulticast_mode(uint16_t port, int enable)
{
	int ret;

	if (enable)
		ret = rte_eth_allmulticast_enable(port);
	else
		ret = rte_eth_allmulticast_disable(port);

	if (ret != 0)
		printf("Error during %s all-multicast mode for port %u: %s\n",
			enable ? "enabling" : "disabling",
			port, rte_strerror(-ret));
}

int
eth_link_get_nowait_print_err(uint16_t port_id, struct rte_eth_link *link)
{
	int ret;

	ret = rte_eth_link_get_nowait(port_id, link);
	if (ret < 0)
		printf("Device (port %u) link get (without wait) failed: %s\n",
			port_id, rte_strerror(-ret));

	return ret;
}

int
eth_macaddr_get_print_err(uint16_t port_id, struct rte_ether_addr *mac_addr)
{
	int ret;

	ret = rte_eth_macaddr_get(port_id, mac_addr);
	if (ret != 0)
		printf("Error getting device (port %u) mac address: %s\n",
				port_id, rte_strerror(-ret));

	return ret;
}
