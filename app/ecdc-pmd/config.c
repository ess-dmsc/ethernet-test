/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation.
 * Copyright 2013-2014 6WIND S.A.
 */

#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_flow.h>
#include <rte_mtr.h>
#include <rte_errno.h>
#ifdef RTE_NET_IXGBE
#include <rte_pmd_ixgbe.h>
#endif
#ifdef RTE_NET_I40E
#include <rte_pmd_i40e.h>
#endif
#ifdef RTE_NET_BNXT
#include <rte_pmd_bnxt.h>
#endif
#include <rte_gro.h>
#include <rte_hexdump.h>

#include "testpmd.h"

#define ETHDEV_FWVERS_LEN 32

#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif

#define NS_PER_SEC 1E9

static char *flowtype_to_str(uint16_t flow_type);

static const struct {
	enum tx_pkt_split split;
	const char *name;
} tx_split_name[] = {
	{
		.split = TX_PKT_SPLIT_OFF,
		.name = "off",
	},
	{
		.split = TX_PKT_SPLIT_ON,
		.name = "on",
	},
	{
		.split = TX_PKT_SPLIT_RND,
		.name = "rand",
	},
};

const struct rss_type_info rss_type_table[] = {
	{ "all", ETH_RSS_ETH | ETH_RSS_VLAN | ETH_RSS_IP | ETH_RSS_TCP |
		ETH_RSS_UDP | ETH_RSS_SCTP | ETH_RSS_L2_PAYLOAD |
		ETH_RSS_L2TPV3 | ETH_RSS_ESP | ETH_RSS_AH | ETH_RSS_PFCP |
		ETH_RSS_GTPU | ETH_RSS_ECPRI | ETH_RSS_MPLS},
	{ "none", 0 },
	{ "eth", ETH_RSS_ETH },
	{ "l2-src-only", ETH_RSS_L2_SRC_ONLY },
	{ "l2-dst-only", ETH_RSS_L2_DST_ONLY },
	{ "vlan", ETH_RSS_VLAN },
	{ "s-vlan", ETH_RSS_S_VLAN },
	{ "c-vlan", ETH_RSS_C_VLAN },
	{ "ipv4", ETH_RSS_IPV4 },
	{ "ipv4-frag", ETH_RSS_FRAG_IPV4 },
	{ "ipv4-tcp", ETH_RSS_NONFRAG_IPV4_TCP },
	{ "ipv4-udp", ETH_RSS_NONFRAG_IPV4_UDP },
	{ "ipv4-sctp", ETH_RSS_NONFRAG_IPV4_SCTP },
	{ "ipv4-other", ETH_RSS_NONFRAG_IPV4_OTHER },
	{ "ipv6", ETH_RSS_IPV6 },
	{ "ipv6-frag", ETH_RSS_FRAG_IPV6 },
	{ "ipv6-tcp", ETH_RSS_NONFRAG_IPV6_TCP },
	{ "ipv6-udp", ETH_RSS_NONFRAG_IPV6_UDP },
	{ "ipv6-sctp", ETH_RSS_NONFRAG_IPV6_SCTP },
	{ "ipv6-other", ETH_RSS_NONFRAG_IPV6_OTHER },
	{ "l2-payload", ETH_RSS_L2_PAYLOAD },
	{ "ipv6-ex", ETH_RSS_IPV6_EX },
	{ "ipv6-tcp-ex", ETH_RSS_IPV6_TCP_EX },
	{ "ipv6-udp-ex", ETH_RSS_IPV6_UDP_EX },
	{ "port", ETH_RSS_PORT },
	{ "vxlan", ETH_RSS_VXLAN },
	{ "geneve", ETH_RSS_GENEVE },
	{ "nvgre", ETH_RSS_NVGRE },
	{ "ip", ETH_RSS_IP },
	{ "udp", ETH_RSS_UDP },
	{ "tcp", ETH_RSS_TCP },
	{ "sctp", ETH_RSS_SCTP },
	{ "tunnel", ETH_RSS_TUNNEL },
	{ "l3-pre32", RTE_ETH_RSS_L3_PRE32 },
	{ "l3-pre40", RTE_ETH_RSS_L3_PRE40 },
	{ "l3-pre48", RTE_ETH_RSS_L3_PRE48 },
	{ "l3-pre56", RTE_ETH_RSS_L3_PRE56 },
	{ "l3-pre64", RTE_ETH_RSS_L3_PRE64 },
	{ "l3-pre96", RTE_ETH_RSS_L3_PRE96 },
	{ "l3-src-only", ETH_RSS_L3_SRC_ONLY },
	{ "l3-dst-only", ETH_RSS_L3_DST_ONLY },
	{ "l4-src-only", ETH_RSS_L4_SRC_ONLY },
	{ "l4-dst-only", ETH_RSS_L4_DST_ONLY },
	{ "esp", ETH_RSS_ESP },
	{ "ah", ETH_RSS_AH },
	{ "l2tpv3", ETH_RSS_L2TPV3 },
	{ "pfcp", ETH_RSS_PFCP },
	{ "pppoe", ETH_RSS_PPPOE },
	{ "gtpu", ETH_RSS_GTPU },
	{ "ecpri", ETH_RSS_ECPRI },
	{ "mpls", ETH_RSS_MPLS },
	{ NULL, 0 },
};

static const struct {
	enum rte_eth_fec_mode mode;
	const char *name;
} fec_mode_name[] = {
	{
		.mode = RTE_ETH_FEC_NOFEC,
		.name = "off",
	},
	{
		.mode = RTE_ETH_FEC_AUTO,
		.name = "auto",
	},
	{
		.mode = RTE_ETH_FEC_BASER,
		.name = "baser",
	},
	{
		.mode = RTE_ETH_FEC_RS,
		.name = "rs",
	},
};

static void
print_ethaddr(const char *name, struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

void
nic_stats_display(portid_t port_id)
{
	static uint64_t prev_pkts_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_pkts_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_ns[RTE_MAX_ETHPORTS];
	struct timespec cur_time;
	uint64_t diff_pkts_rx, diff_pkts_tx, diff_bytes_rx, diff_bytes_tx,
								diff_ns;
	uint64_t mpps_rx, mpps_tx, mbps_rx, mbps_tx;
	struct rte_eth_stats stats;

	if (port_id_is_invalid(port_id, ENABLED_WARN)) {
		print_valid_ports();
		return;
	}
	rte_eth_stats_get(port_id, &stats);
	printf("\nNIC statistics for port %-2d\n", port_id);

	diff_ns = 0;
	if (clock_gettime(CLOCK_TYPE_ID, &cur_time) == 0) {
		uint64_t ns;

		ns = cur_time.tv_sec * NS_PER_SEC;
		ns += cur_time.tv_nsec;

		if (prev_ns[port_id] != 0)
			diff_ns = ns - prev_ns[port_id];
		prev_ns[port_id] = ns;
	}

	diff_pkts_rx = (stats.ipackets > prev_pkts_rx[port_id]) ?
		(stats.ipackets - prev_pkts_rx[port_id]) : 0;
	diff_pkts_tx = (stats.opackets > prev_pkts_tx[port_id]) ?
		(stats.opackets - prev_pkts_tx[port_id]) : 0;
	prev_pkts_rx[port_id] = stats.ipackets;
	prev_pkts_tx[port_id] = stats.opackets;
	mpps_rx = diff_ns > 0 ?
		(double)diff_pkts_rx / diff_ns * NS_PER_SEC : 0;
	mpps_tx = diff_ns > 0 ?
		(double)diff_pkts_tx / diff_ns * NS_PER_SEC : 0;

	diff_bytes_rx = (stats.ibytes > prev_bytes_rx[port_id]) ?
		(stats.ibytes - prev_bytes_rx[port_id]) : 0;
	diff_bytes_tx = (stats.obytes > prev_bytes_tx[port_id]) ?
		(stats.obytes - prev_bytes_tx[port_id]) : 0;
	prev_bytes_rx[port_id] = stats.ibytes;
	prev_bytes_tx[port_id] = stats.obytes;
	mbps_rx = diff_ns > 0 ?
		(double)diff_bytes_rx / diff_ns * NS_PER_SEC : 0;
	mbps_tx = diff_ns > 0 ?
		(double)diff_bytes_tx / diff_ns * NS_PER_SEC : 0;

	printf("\n  Throughput (since last show)\n");
	printf("  Rx-pps: %12"PRIu64"          Rx-bps: %12"PRIu64"\n  Tx-pps: %12"
	       PRIu64"          Tx-bps: %12"PRIu64"\n", mpps_rx, mbps_rx * 8,
	       mpps_tx, mbps_tx * 8);
	// printf("  %s############################%s\n",
	//        nic_stats_border, nic_stats_border);
}

void
nic_stats_clear(portid_t port_id)
{
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN)) {
		print_valid_ports();
		return;
	}

	ret = rte_eth_stats_reset(port_id);
	if (ret != 0) {
		printf("%s: Error: failed to reset stats (port %u): %s",
		       __func__, port_id, strerror(-ret));
		return;
	}

	ret = rte_eth_stats_get(port_id, &ports[port_id].stats);
	if (ret != 0) {
		if (ret < 0)
			ret = -ret;
		printf("%s: Error: failed to get stats (port %u): %s",
		       __func__, port_id, strerror(ret));
		return;
	}
	printf("\n  NIC statistics for port %d cleared\n", port_id);
}

void
nic_xstats_display(portid_t port_id)
{
	struct rte_eth_xstat *xstats;
	int cnt_xstats, idx_xstat;
	struct rte_eth_xstat_name *xstats_names;

	if (port_id_is_invalid(port_id, ENABLED_WARN)) {
		print_valid_ports();
		return;
	}
	printf("###### NIC extended statistics for port %-2d\n", port_id);
	if (!rte_eth_dev_is_valid_port(port_id)) {
		printf("Error: Invalid port number %i\n", port_id);
		return;
	}

	/* Get count */
	cnt_xstats = rte_eth_xstats_get_names(port_id, NULL, 0);
	if (cnt_xstats  < 0) {
		printf("Error: Cannot get count of xstats\n");
		return;
	}

	/* Get id-name lookup table */
	xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * cnt_xstats);
	if (xstats_names == NULL) {
		printf("Cannot allocate memory for xstats lookup\n");
		return;
	}
	if (cnt_xstats != rte_eth_xstats_get_names(
			port_id, xstats_names, cnt_xstats)) {
		printf("Error: Cannot get xstats lookup\n");
		free(xstats_names);
		return;
	}

	/* Get stats themselves */
	xstats = malloc(sizeof(struct rte_eth_xstat) * cnt_xstats);
	if (xstats == NULL) {
		printf("Cannot allocate memory for xstats\n");
		free(xstats_names);
		return;
	}
	if (cnt_xstats != rte_eth_xstats_get(port_id, xstats, cnt_xstats)) {
		printf("Error: Unable to get xstats\n");
		free(xstats_names);
		free(xstats);
		return;
	}

	/* Display xstats */
	for (idx_xstat = 0; idx_xstat < cnt_xstats; idx_xstat++) {
		if (xstats_hide_zero && !xstats[idx_xstat].value)
			continue;
		printf("%s: %"PRIu64"\n",
			xstats_names[idx_xstat].name,
			xstats[idx_xstat].value);
	}
	free(xstats_names);
	free(xstats);
}

void
nic_xstats_clear(portid_t port_id)
{
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN)) {
		print_valid_ports();
		return;
	}

	ret = rte_eth_xstats_reset(port_id);
	if (ret != 0) {
		printf("%s: Error: failed to reset xstats (port %u): %s",
		       __func__, port_id, strerror(-ret));
		return;
	}

	ret = rte_eth_stats_get(port_id, &ports[port_id].stats);
	if (ret != 0) {
		if (ret < 0)
			ret = -ret;
		printf("%s: Error: failed to get stats (port %u): %s",
		       __func__, port_id, strerror(ret));
		return;
	}
}

static const char *
get_queue_state_name(uint8_t queue_state)
{
	if (queue_state == RTE_ETH_QUEUE_STATE_STOPPED)
		return "stopped";
	else if (queue_state == RTE_ETH_QUEUE_STATE_STARTED)
		return "started";
	else if (queue_state == RTE_ETH_QUEUE_STATE_HAIRPIN)
		return "hairpin";
	else
		return "unknown";
}

void
rx_queue_infos_display(portid_t port_id, uint16_t queue_id)
{
	struct rte_eth_burst_mode mode;
	struct rte_eth_rxq_info qinfo;
	int32_t rc;
	static const char *info_border = "*********************";

	rc = rte_eth_rx_queue_info_get(port_id, queue_id, &qinfo);
	if (rc != 0) {
		printf("Failed to retrieve information for port: %u, "
			"RX queue: %hu\nerror desc: %s(%d)\n",
			port_id, queue_id, strerror(-rc), rc);
		return;
	}

	printf("\n%s Infos for port %-2u, RX queue %-2u %s",
	       info_border, port_id, queue_id, info_border);

	printf("\nMempool: %s", (qinfo.mp == NULL) ? "NULL" : qinfo.mp->name);
	printf("\nRX prefetch threshold: %hhu", qinfo.conf.rx_thresh.pthresh);
	printf("\nRX host threshold: %hhu", qinfo.conf.rx_thresh.hthresh);
	printf("\nRX writeback threshold: %hhu", qinfo.conf.rx_thresh.wthresh);
	printf("\nRX free threshold: %hu", qinfo.conf.rx_free_thresh);
	printf("\nRX drop packets: %s",
		(qinfo.conf.rx_drop_en != 0) ? "on" : "off");
	printf("\nRX deferred start: %s",
		(qinfo.conf.rx_deferred_start != 0) ? "on" : "off");
	printf("\nRX scattered packets: %s",
		(qinfo.scattered_rx != 0) ? "on" : "off");
	printf("\nRx queue state: %s", get_queue_state_name(qinfo.queue_state));
	if (qinfo.rx_buf_size != 0)
		printf("\nRX buffer size: %hu", qinfo.rx_buf_size);
	printf("\nNumber of RXDs: %hu", qinfo.nb_desc);

	if (rte_eth_rx_burst_mode_get(port_id, queue_id, &mode) == 0)
		printf("\nBurst mode: %s%s",
		       mode.info,
		       mode.flags & RTE_ETH_BURST_FLAG_PER_QUEUE ?
				" (per queue)" : "");

	printf("\n");
}

void
tx_queue_infos_display(portid_t port_id, uint16_t queue_id)
{
	struct rte_eth_burst_mode mode;
	struct rte_eth_txq_info qinfo;
	int32_t rc;
	static const char *info_border = "*********************";

	rc = rte_eth_tx_queue_info_get(port_id, queue_id, &qinfo);
	if (rc != 0) {
		printf("Failed to retrieve information for port: %u, "
			"TX queue: %hu\nerror desc: %s(%d)\n",
			port_id, queue_id, strerror(-rc), rc);
		return;
	}

	printf("\n%s Infos for port %-2u, TX queue %-2u %s",
	       info_border, port_id, queue_id, info_border);

	printf("\nTX prefetch threshold: %hhu", qinfo.conf.tx_thresh.pthresh);
	printf("\nTX host threshold: %hhu", qinfo.conf.tx_thresh.hthresh);
	printf("\nTX writeback threshold: %hhu", qinfo.conf.tx_thresh.wthresh);
	printf("\nTX RS threshold: %hu", qinfo.conf.tx_rs_thresh);
	printf("\nTX free threshold: %hu", qinfo.conf.tx_free_thresh);
	printf("\nTX deferred start: %s",
		(qinfo.conf.tx_deferred_start != 0) ? "on" : "off");
	printf("\nNumber of TXDs: %hu", qinfo.nb_desc);
	printf("\nTx queue state: %s", get_queue_state_name(qinfo.queue_state));

	if (rte_eth_tx_burst_mode_get(port_id, queue_id, &mode) == 0)
		printf("\nBurst mode: %s%s",
		       mode.info,
		       mode.flags & RTE_ETH_BURST_FLAG_PER_QUEUE ?
				" (per queue)" : "");

	printf("\n");
}

static int bus_match_all(const struct rte_bus *bus, const void *data)
{
	RTE_SET_USED(bus);
	RTE_SET_USED(data);
	return 0;
}

static void
device_infos_display_speeds(uint32_t speed_capa)
{
	printf("\n\tDevice speed capability:");
	if (speed_capa == ETH_LINK_SPEED_AUTONEG)
		printf(" Autonegotiate (all speeds)");
	if (speed_capa & ETH_LINK_SPEED_FIXED)
		printf(" Disable autonegotiate (fixed speed)  ");
	if (speed_capa & ETH_LINK_SPEED_10M_HD)
		printf(" 10 Mbps half-duplex  ");
	if (speed_capa & ETH_LINK_SPEED_10M)
		printf(" 10 Mbps full-duplex  ");
	if (speed_capa & ETH_LINK_SPEED_100M_HD)
		printf(" 100 Mbps half-duplex  ");
	if (speed_capa & ETH_LINK_SPEED_100M)
		printf(" 100 Mbps full-duplex  ");
	if (speed_capa & ETH_LINK_SPEED_1G)
		printf(" 1 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_2_5G)
		printf(" 2.5 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_5G)
		printf(" 5 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_10G)
		printf(" 10 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_20G)
		printf(" 20 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_25G)
		printf(" 25 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_40G)
		printf(" 40 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_50G)
		printf(" 50 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_56G)
		printf(" 56 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_100G)
		printf(" 100 Gbps  ");
	if (speed_capa & ETH_LINK_SPEED_200G)
		printf(" 200 Gbps  ");
}

void
device_infos_display(const char *identifier)
{
	static const char *info_border = "*********************";
	struct rte_bus *start = NULL, *next;
	struct rte_dev_iterator dev_iter;
	char name[RTE_ETH_NAME_MAX_LEN];
	struct rte_ether_addr mac_addr;
	struct rte_device *dev;
	struct rte_devargs da;
	portid_t port_id;
	struct rte_eth_dev_info dev_info;
	char devstr[128];

	memset(&da, 0, sizeof(da));
	if (!identifier)
		goto skip_parse;

	if (rte_devargs_parsef(&da, "%s", identifier)) {
		printf("cannot parse identifier\n");
		return;
	}

skip_parse:
	while ((next = rte_bus_find(start, bus_match_all, NULL)) != NULL) {

		start = next;
		if (identifier && da.bus != next)
			continue;

		/* Skip buses that don't have iterate method */
		if (!next->dev_iterate)
			continue;

		snprintf(devstr, sizeof(devstr), "bus=%s", next->name);
		RTE_DEV_FOREACH(dev, devstr, &dev_iter) {

			if (!dev->driver)
				continue;
			/* Check for matching device if identifier is present */
			if (identifier &&
			    strncmp(da.name, dev->name, strlen(dev->name)))
				continue;
			printf("\n%s Infos for device %s %s\n",
			       info_border, dev->name, info_border);
			printf("Bus name: %s", dev->bus->name);
			printf("\nDriver name: %s", dev->driver->name);
			printf("\nDevargs: %s",
			       dev->devargs ? dev->devargs->args : "");
			printf("\nConnect to socket: %d", dev->numa_node);
			printf("\n");

			/* List ports with matching device name */
			RTE_ETH_FOREACH_DEV_OF(port_id, dev) {
				printf("\n\tPort id: %-2d", port_id);
				if (eth_macaddr_get_print_err(port_id,
							      &mac_addr) == 0)
					print_ethaddr("\n\tMAC address: ",
						      &mac_addr);
				rte_eth_dev_get_name_by_port(port_id, name);
				printf("\n\tDevice name: %s", name);
				if (rte_eth_dev_info_get(port_id, &dev_info) == 0)
					device_infos_display_speeds(dev_info.speed_capa);
				printf("\n");
			}
		}
	};
	rte_devargs_reset(&da);
}

void
port_infos_display(portid_t port_id)
{
	struct rte_port *port;
	struct rte_ether_addr mac_addr;
	struct rte_eth_link link;
	struct rte_eth_dev_info dev_info;
	int vlan_offload;
	struct rte_mempool * mp;
	static const char *info_border = "*********************";
	uint16_t mtu;
	char name[RTE_ETH_NAME_MAX_LEN];
	int ret;
	char fw_version[ETHDEV_FWVERS_LEN];

	if (port_id_is_invalid(port_id, ENABLED_WARN)) {
		print_valid_ports();
		return;
	}
	port = &ports[port_id];
	ret = eth_link_get_nowait_print_err(port_id, &link);
	if (ret < 0)
		return;

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		return;

	printf("\n%s Infos for port %-2d %s\n",
	       info_border, port_id, info_border);
	if (eth_macaddr_get_print_err(port_id, &mac_addr) == 0)
		print_ethaddr("MAC address: ", &mac_addr);
	rte_eth_dev_get_name_by_port(port_id, name);
	printf("\nDevice name: %s", name);
	printf("\nDriver name: %s", dev_info.driver_name);

	if (rte_eth_dev_fw_version_get(port_id, fw_version,
						ETHDEV_FWVERS_LEN) == 0)
		printf("\nFirmware-version: %s", fw_version);
	else
		printf("\nFirmware-version: %s", "not available");

	if (dev_info.device->devargs && dev_info.device->devargs->args)
		printf("\nDevargs: %s", dev_info.device->devargs->args);
	printf("\nConnect to socket: %u", port->socket_id);

	if (port_numa[port_id] != NUMA_NO_CONFIG) {
		mp = mbuf_pool_find(port_numa[port_id], 0);
		if (mp)
			printf("\nmemory allocation on the socket: %d",
							port_numa[port_id]);
	} else
		printf("\nmemory allocation on the socket: %u",port->socket_id);

	printf("\nLink status: %s\n", (link.link_status) ? ("up") : ("down"));
	printf("Link speed: %s\n", rte_eth_link_speed_to_str(link.link_speed));
	printf("Link duplex: %s\n", (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
	       ("full-duplex") : ("half-duplex"));
	printf("Autoneg status: %s\n", (link.link_autoneg == ETH_LINK_AUTONEG) ?
	       ("On") : ("Off"));

	if (!rte_eth_dev_get_mtu(port_id, &mtu))
		printf("MTU: %u\n", mtu);

	printf("Promiscuous mode: %s\n",
	       rte_eth_promiscuous_get(port_id) ? "enabled" : "disabled");
	printf("Allmulticast mode: %s\n",
	       rte_eth_allmulticast_get(port_id) ? "enabled" : "disabled");
	printf("Maximum number of MAC addresses: %u\n",
	       (unsigned int)(port->dev_info.max_mac_addrs));
	printf("Maximum number of MAC addresses of hash filtering: %u\n",
	       (unsigned int)(port->dev_info.max_hash_mac_addrs));

	vlan_offload = rte_eth_dev_get_vlan_offload(port_id);
	if (vlan_offload >= 0){
		printf("VLAN offload: \n");
		if (vlan_offload & ETH_VLAN_STRIP_OFFLOAD)
			printf("  strip on, ");
		else
			printf("  strip off, ");

		if (vlan_offload & ETH_VLAN_FILTER_OFFLOAD)
			printf("filter on, ");
		else
			printf("filter off, ");

		if (vlan_offload & ETH_VLAN_EXTEND_OFFLOAD)
			printf("extend on, ");
		else
			printf("extend off, ");

		if (vlan_offload & ETH_QINQ_STRIP_OFFLOAD)
			printf("qinq strip on\n");
		else
			printf("qinq strip off\n");
	}

	if (dev_info.hash_key_size > 0)
		printf("Hash key size in bytes: %u\n", dev_info.hash_key_size);
	if (dev_info.reta_size > 0)
		printf("Redirection table size: %u\n", dev_info.reta_size);
	if (!dev_info.flow_type_rss_offloads)
		printf("No RSS offload flow type is supported.\n");
	else {
		uint16_t i;
		char *p;

		printf("Supported RSS offload flow types:\n");
		for (i = RTE_ETH_FLOW_UNKNOWN + 1;
		     i < sizeof(dev_info.flow_type_rss_offloads) * CHAR_BIT; i++) {
			if (!(dev_info.flow_type_rss_offloads & (1ULL << i)))
				continue;
			p = flowtype_to_str(i);
			if (p)
				printf("  %s\n", p);
			else
				printf("  user defined %d\n", i);
		}
	}

	printf("Minimum size of RX buffer: %u\n", dev_info.min_rx_bufsize);
	printf("Maximum configurable length of RX packet: %u\n",
		dev_info.max_rx_pktlen);
	printf("Maximum configurable size of LRO aggregated packet: %u\n",
		dev_info.max_lro_pkt_size);
	if (dev_info.max_vfs)
		printf("Maximum number of VFs: %u\n", dev_info.max_vfs);
	if (dev_info.max_vmdq_pools)
		printf("Maximum number of VMDq pools: %u\n",
			dev_info.max_vmdq_pools);

	printf("Current number of RX queues: %u\n", dev_info.nb_rx_queues);
	printf("Max possible RX queues: %u\n", dev_info.max_rx_queues);
	printf("Max possible number of RXDs per queue: %hu\n",
		dev_info.rx_desc_lim.nb_max);
	printf("Min possible number of RXDs per queue: %hu\n",
		dev_info.rx_desc_lim.nb_min);
	printf("RXDs number alignment: %hu\n", dev_info.rx_desc_lim.nb_align);

	printf("Current number of TX queues: %u\n", dev_info.nb_tx_queues);
	printf("Max possible TX queues: %u\n", dev_info.max_tx_queues);
	printf("Max possible number of TXDs per queue: %hu\n",
		dev_info.tx_desc_lim.nb_max);
	printf("Min possible number of TXDs per queue: %hu\n",
		dev_info.tx_desc_lim.nb_min);
	printf("TXDs number alignment: %hu\n", dev_info.tx_desc_lim.nb_align);
	printf("Max segment number per packet: %hu\n",
		dev_info.tx_desc_lim.nb_seg_max);
	printf("Max segment number per MTU/TSO: %hu\n",
		dev_info.tx_desc_lim.nb_mtu_seg_max);

	/* Show switch info only if valid switch domain and port id is set */
	if (dev_info.switch_info.domain_id !=
		RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID) {
		if (dev_info.switch_info.name)
			printf("Switch name: %s\n", dev_info.switch_info.name);

		printf("Switch domain Id: %u\n",
			dev_info.switch_info.domain_id);
		printf("Switch Port Id: %u\n",
			dev_info.switch_info.port_id);
	}
}

void
port_summary_header_display(void)
{
	uint16_t port_number;

	port_number = rte_eth_dev_count_avail();
	printf("Number of available ports: %i\n", port_number);
	printf("%-4s %-17s %-12s %-14s %-8s %s\n", "Port", "MAC Address", "Name",
			"Driver", "Status", "Link");
}

void
port_summary_display(portid_t port_id)
{
	struct rte_ether_addr mac_addr;
	struct rte_eth_link link;
	struct rte_eth_dev_info dev_info;
	char name[RTE_ETH_NAME_MAX_LEN];
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN)) {
		print_valid_ports();
		return;
	}

	ret = eth_link_get_nowait_print_err(port_id, &link);
	if (ret < 0)
		return;

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		return;

	rte_eth_dev_get_name_by_port(port_id, name);
	ret = eth_macaddr_get_print_err(port_id, &mac_addr);
	if (ret != 0)
		return;

	printf("%-4d %02X:%02X:%02X:%02X:%02X:%02X %-12s %-14s %-8s %s\n",
		port_id, mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
		mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
		mac_addr.addr_bytes[4], mac_addr.addr_bytes[5], name,
		dev_info.driver_name, (link.link_status) ? ("up") : ("down"),
		rte_eth_link_speed_to_str(link.link_speed));
}

void
port_eeprom_display(portid_t port_id)
{
	struct rte_dev_eeprom_info einfo;
	int ret;
	if (port_id_is_invalid(port_id, ENABLED_WARN)) {
		print_valid_ports();
		return;
	}

	int len_eeprom = rte_eth_dev_get_eeprom_length(port_id);
	if (len_eeprom < 0) {
		switch (len_eeprom) {
		case -ENODEV:
			printf("port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			printf("operation not supported by device\n");
			break;
		case -EIO:
			printf("device is removed\n");
			break;
		default:
			printf("Unable to get EEPROM: %d\n", len_eeprom);
			break;
		}
		return;
	}

	char buf[len_eeprom];
	einfo.offset = 0;
	einfo.length = len_eeprom;
	einfo.data = buf;

	ret = rte_eth_dev_get_eeprom(port_id, &einfo);
	if (ret != 0) {
		switch (ret) {
		case -ENODEV:
			printf("port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			printf("operation not supported by device\n");
			break;
		case -EIO:
			printf("device is removed\n");
			break;
		default:
			printf("Unable to get EEPROM: %d\n", ret);
			break;
		}
		return;
	}
	rte_hexdump(stdout, "hexdump", einfo.data, einfo.length);
	printf("Finish -- Port: %d EEPROM length: %d bytes\n", port_id, len_eeprom);
}

void
port_module_eeprom_display(portid_t port_id)
{
	struct rte_eth_dev_module_info minfo;
	struct rte_dev_eeprom_info einfo;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN)) {
		print_valid_ports();
		return;
	}


	ret = rte_eth_dev_get_module_info(port_id, &minfo);
	if (ret != 0) {
		switch (ret) {
		case -ENODEV:
			printf("port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			printf("operation not supported by device\n");
			break;
		case -EIO:
			printf("device is removed\n");
			break;
		default:
			printf("Unable to get module EEPROM: %d\n", ret);
			break;
		}
		return;
	}

	char buf[minfo.eeprom_len];
	einfo.offset = 0;
	einfo.length = minfo.eeprom_len;
	einfo.data = buf;

	ret = rte_eth_dev_get_module_eeprom(port_id, &einfo);
	if (ret != 0) {
		switch (ret) {
		case -ENODEV:
			printf("port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			printf("operation not supported by device\n");
			break;
		case -EIO:
			printf("device is removed\n");
			break;
		default:
			printf("Unable to get module EEPROM: %d\n", ret);
			break;
		}
		return;
	}

	rte_hexdump(stdout, "hexdump", einfo.data, einfo.length);
	printf("Finish -- Port: %d MODULE EEPROM length: %d bytes\n", port_id, einfo.length);
}

int
port_id_is_invalid(portid_t port_id, enum print_warning warning)
{
	uint16_t pid;

	if (port_id == (portid_t)RTE_PORT_ALL)
		return 0;

	RTE_ETH_FOREACH_DEV(pid)
		if (port_id == pid)
			return 0;

	if (warning == ENABLED_WARN)
		printf("Invalid port %d\n", port_id);

	return 1;
}

void print_valid_ports(void)
{
	portid_t pid;

	printf("The valid ports array is [");
	RTE_ETH_FOREACH_DEV(pid) {
		printf(" %d", pid);
	}
	printf(" ]\n");
}

static int
vlan_id_is_invalid(uint16_t vlan_id)
{
	if (vlan_id < 4096)
		return 0;
	printf("Invalid vlan_id %d (must be < 4096)\n", vlan_id);
	return 1;
}

static int
port_reg_off_is_invalid(portid_t port_id, uint32_t reg_off)
{
	const struct rte_pci_device *pci_dev;
	const struct rte_bus *bus;
	uint64_t pci_len;

	if (reg_off & 0x3) {
		printf("Port register offset 0x%X not aligned on a 4-byte "
		       "boundary\n",
		       (unsigned)reg_off);
		return 1;
	}

	if (!ports[port_id].dev_info.device) {
		printf("Invalid device\n");
		return 0;
	}

	bus = rte_bus_find_by_device(ports[port_id].dev_info.device);
	if (bus && !strcmp(bus->name, "pci")) {
		pci_dev = RTE_DEV_TO_PCI(ports[port_id].dev_info.device);
	} else {
		printf("Not a PCI device\n");
		return 1;
	}

	pci_len = pci_dev->mem_resource[0].len;
	if (reg_off >= pci_len) {
		printf("Port %d: register offset %u (0x%X) out of port PCI "
		       "resource (length=%"PRIu64")\n",
		       port_id, (unsigned)reg_off, (unsigned)reg_off,  pci_len);
		return 1;
	}
	return 0;
}

static int
reg_bit_pos_is_invalid(uint8_t bit_pos)
{
	if (bit_pos <= 31)
		return 0;
	printf("Invalid bit position %d (must be <= 31)\n", bit_pos);
	return 1;
}

#define display_port_and_reg_off(port_id, reg_off) \
	printf("port %d PCI register at offset 0x%X: ", (port_id), (reg_off))

static inline void
display_port_reg_value(portid_t port_id, uint32_t reg_off, uint32_t reg_v)
{
	display_port_and_reg_off(port_id, (unsigned)reg_off);
	printf("0x%08X (%u)\n", (unsigned)reg_v, (unsigned)reg_v);
}

void
port_reg_bit_display(portid_t port_id, uint32_t reg_off, uint8_t bit_x)
{
	uint32_t reg_v;


	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (port_reg_off_is_invalid(port_id, reg_off))
		return;
	if (reg_bit_pos_is_invalid(bit_x))
		return;
	reg_v = port_id_pci_reg_read(port_id, reg_off);
	display_port_and_reg_off(port_id, (unsigned)reg_off);
	printf("bit %d=%d\n", bit_x, (int) ((reg_v & (1 << bit_x)) >> bit_x));
}

void
port_reg_bit_field_display(portid_t port_id, uint32_t reg_off,
			   uint8_t bit1_pos, uint8_t bit2_pos)
{
	uint32_t reg_v;
	uint8_t  l_bit;
	uint8_t  h_bit;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (port_reg_off_is_invalid(port_id, reg_off))
		return;
	if (reg_bit_pos_is_invalid(bit1_pos))
		return;
	if (reg_bit_pos_is_invalid(bit2_pos))
		return;
	if (bit1_pos > bit2_pos)
		l_bit = bit2_pos, h_bit = bit1_pos;
	else
		l_bit = bit1_pos, h_bit = bit2_pos;

	reg_v = port_id_pci_reg_read(port_id, reg_off);
	reg_v >>= l_bit;
	if (h_bit < 31)
		reg_v &= ((1 << (h_bit - l_bit + 1)) - 1);
	display_port_and_reg_off(port_id, (unsigned)reg_off);
	printf("bits[%d, %d]=0x%0*X (%u)\n", l_bit, h_bit,
	       ((h_bit - l_bit) / 4) + 1, (unsigned)reg_v, (unsigned)reg_v);
}

void
port_reg_display(portid_t port_id, uint32_t reg_off)
{
	uint32_t reg_v;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (port_reg_off_is_invalid(port_id, reg_off))
		return;
	reg_v = port_id_pci_reg_read(port_id, reg_off);
	display_port_reg_value(port_id, reg_off, reg_v);
}

void
port_reg_bit_set(portid_t port_id, uint32_t reg_off, uint8_t bit_pos,
		 uint8_t bit_v)
{
	uint32_t reg_v;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (port_reg_off_is_invalid(port_id, reg_off))
		return;
	if (reg_bit_pos_is_invalid(bit_pos))
		return;
	if (bit_v > 1) {
		printf("Invalid bit value %d (must be 0 or 1)\n", (int) bit_v);
		return;
	}
	reg_v = port_id_pci_reg_read(port_id, reg_off);
	if (bit_v == 0)
		reg_v &= ~(1 << bit_pos);
	else
		reg_v |= (1 << bit_pos);
	port_id_pci_reg_write(port_id, reg_off, reg_v);
	display_port_reg_value(port_id, reg_off, reg_v);
}

void
port_reg_bit_field_set(portid_t port_id, uint32_t reg_off,
		       uint8_t bit1_pos, uint8_t bit2_pos, uint32_t value)
{
	uint32_t max_v;
	uint32_t reg_v;
	uint8_t  l_bit;
	uint8_t  h_bit;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (port_reg_off_is_invalid(port_id, reg_off))
		return;
	if (reg_bit_pos_is_invalid(bit1_pos))
		return;
	if (reg_bit_pos_is_invalid(bit2_pos))
		return;
	if (bit1_pos > bit2_pos)
		l_bit = bit2_pos, h_bit = bit1_pos;
	else
		l_bit = bit1_pos, h_bit = bit2_pos;

	if ((h_bit - l_bit) < 31)
		max_v = (1 << (h_bit - l_bit + 1)) - 1;
	else
		max_v = 0xFFFFFFFF;

	if (value > max_v) {
		printf("Invalid value %u (0x%x) must be < %u (0x%x)\n",
				(unsigned)value, (unsigned)value,
				(unsigned)max_v, (unsigned)max_v);
		return;
	}
	reg_v = port_id_pci_reg_read(port_id, reg_off);
	reg_v &= ~(max_v << l_bit); /* Keep unchanged bits */
	reg_v |= (value << l_bit); /* Set changed bits */
	port_id_pci_reg_write(port_id, reg_off, reg_v);
	display_port_reg_value(port_id, reg_off, reg_v);
}

void
port_reg_set(portid_t port_id, uint32_t reg_off, uint32_t reg_v)
{
	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (port_reg_off_is_invalid(port_id, reg_off))
		return;
	port_id_pci_reg_write(port_id, reg_off, reg_v);
	display_port_reg_value(port_id, reg_off, reg_v);
}

void
port_mtu_set(portid_t port_id, uint16_t mtu)
{
	int diag;
	struct rte_port *rte_port = &ports[port_id];
	struct rte_eth_dev_info dev_info;
	uint16_t eth_overhead;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		return;

	if (mtu > dev_info.max_mtu || mtu < dev_info.min_mtu) {
		printf("Set MTU failed. MTU:%u is not in valid range, min:%u - max:%u\n",
			mtu, dev_info.min_mtu, dev_info.max_mtu);
		return;
	}
	diag = rte_eth_dev_set_mtu(port_id, mtu);
	if (diag)
		printf("Set MTU failed. diag=%d\n", diag);
	else if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_JUMBO_FRAME) {
		/*
		 * Ether overhead in driver is equal to the difference of
		 * max_rx_pktlen and max_mtu in rte_eth_dev_info when the
		 * device supports jumbo frame.
		 */
		eth_overhead = dev_info.max_rx_pktlen - dev_info.max_mtu;
		if (mtu > RTE_ETHER_MTU) {
			rte_port->dev_conf.rxmode.offloads |=
						DEV_RX_OFFLOAD_JUMBO_FRAME;
			rte_port->dev_conf.rxmode.max_rx_pkt_len =
						mtu + eth_overhead;
		} else
			rte_port->dev_conf.rxmode.offloads &=
						~DEV_RX_OFFLOAD_JUMBO_FRAME;
	}
}

/* Generic flow management functions. */

const char *
port_flow_tunnel_type(struct rte_flow_tunnel *tunnel)
{
	const char *type;
	switch (tunnel->type) {
	default:
		type = "unknown";
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		type = "vxlan";
		break;
	}

	return type;
}

struct port_flow_tunnel *
port_flow_locate_tunnel(uint16_t port_id, struct rte_flow_tunnel *tun)
{
	struct rte_port *port = &ports[port_id];
	struct port_flow_tunnel *flow_tunnel;

	LIST_FOREACH(flow_tunnel, &port->flow_tunnel_list, chain) {
		if (!memcmp(&flow_tunnel->tunnel, tun, sizeof(*tun)))
			goto out;
	}
	flow_tunnel = NULL;

out:
	return flow_tunnel;
}

void port_flow_tunnel_list(portid_t port_id)
{
	struct rte_port *port = &ports[port_id];
	struct port_flow_tunnel *flt;

	LIST_FOREACH(flt, &port->flow_tunnel_list, chain) {
		printf("port %u tunnel #%u type=%s",
			port_id, flt->id, port_flow_tunnel_type(&flt->tunnel));
		if (flt->tunnel.tun_id)
			printf(" id=%" PRIu64, flt->tunnel.tun_id);
		printf("\n");
	}
}

void port_flow_tunnel_destroy(portid_t port_id, uint32_t tunnel_id)
{
	struct rte_port *port = &ports[port_id];
	struct port_flow_tunnel *flt;

	LIST_FOREACH(flt, &port->flow_tunnel_list, chain) {
		if (flt->id == tunnel_id)
			break;
	}
	if (flt) {
		LIST_REMOVE(flt, chain);
		free(flt);
		printf("port %u: flow tunnel #%u destroyed\n",
			port_id, tunnel_id);
	}
}

void port_flow_tunnel_create(portid_t port_id, const struct tunnel_ops *ops)
{
	struct rte_port *port = &ports[port_id];
	enum rte_flow_item_type	type;
	struct port_flow_tunnel *flt;

	if (!strcmp(ops->type, "vxlan"))
		type = RTE_FLOW_ITEM_TYPE_VXLAN;
	else {
		printf("cannot offload \"%s\" tunnel type\n", ops->type);
		return;
	}
	LIST_FOREACH(flt, &port->flow_tunnel_list, chain) {
		if (flt->tunnel.type == type)
			break;
	}
	if (!flt) {
		flt = calloc(1, sizeof(*flt));
		if (!flt) {
			printf("failed to allocate port flt object\n");
			return;
		}
		flt->tunnel.type = type;
		flt->id = LIST_EMPTY(&port->flow_tunnel_list) ? 1 :
				  LIST_FIRST(&port->flow_tunnel_list)->id + 1;
		LIST_INSERT_HEAD(&port->flow_tunnel_list, flt, chain);
	}
	printf("port %d: flow tunnel #%u type %s\n",
		port_id, flt->id, ops->type);
}


/** Print a message out of a flow error. */
static int
port_flow_complain(struct rte_flow_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_FLOW_ERROR_TYPE_NONE] = "no error",
		[RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
		[RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
		[RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
		[RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER] = "transfer field",
		[RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
		[RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
		[RTE_FLOW_ERROR_TYPE_ITEM_SPEC] = "item specification",
		[RTE_FLOW_ERROR_TYPE_ITEM_LAST] = "item specification range",
		[RTE_FLOW_ERROR_TYPE_ITEM_MASK] = "item specification mask",
		[RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
		[RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
		[RTE_FLOW_ERROR_TYPE_ACTION_CONF] = "action configuration",
		[RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
	};
	const char *errstr;
	char buf[32];
	int err = rte_errno;

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
	    !errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];
	printf("%s(): Caught PMD error type %d (%s): %s%s: %s\n", __func__,
	       error->type, errstr,
	       error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
					error->cause), buf) : "",
	       error->message ? error->message : "(no stated reason)",
	       rte_strerror(err));
	return -err;
}

static struct port_indirect_action *
action_get_by_id(portid_t port_id, uint32_t id)
{
	struct rte_port *port;
	struct port_indirect_action **ppia;
	struct port_indirect_action *pia = NULL;

	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return NULL;
	port = &ports[port_id];
	ppia = &port->actions_list;
	while (*ppia) {
		if ((*ppia)->id == id) {
			pia = *ppia;
			break;
		}
		ppia = &(*ppia)->next;
	}
	if (!pia)
		printf("Failed to find indirect action #%u on port %u\n",
		       id, port_id);
	return pia;
}

static int
action_alloc(portid_t port_id, uint32_t id,
	     struct port_indirect_action **action)
{
	struct rte_port *port;
	struct port_indirect_action **ppia;
	struct port_indirect_action *pia = NULL;

	*action = NULL;
	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return -EINVAL;
	port = &ports[port_id];
	if (id == UINT32_MAX) {
		/* taking first available ID */
		if (port->actions_list) {
			if (port->actions_list->id == UINT32_MAX - 1) {
				printf("Highest indirect action ID is already"
				" assigned, delete it first\n");
				return -ENOMEM;
			}
			id = port->actions_list->id + 1;
		} else {
			id = 0;
		}
	}
	pia = calloc(1, sizeof(*pia));
	if (!pia) {
		printf("Allocation of port %u indirect action failed\n",
		       port_id);
		return -ENOMEM;
	}
	ppia = &port->actions_list;
	while (*ppia && (*ppia)->id > id)
		ppia = &(*ppia)->next;
	if (*ppia && (*ppia)->id == id) {
		printf("Indirect action #%u is already assigned,"
			" delete it first\n", id);
		free(pia);
		return -EINVAL;
	}
	pia->next = *ppia;
	pia->id = id;
	*ppia = pia;
	*action = pia;
	return 0;
}

/** Create indirect action */
int
port_action_handle_create(portid_t port_id, uint32_t id,
			  const struct rte_flow_indir_action_conf *conf,
			  const struct rte_flow_action *action)
{
	struct port_indirect_action *pia;
	int ret;
	struct rte_flow_error error;

	ret = action_alloc(port_id, id, &pia);
	if (ret)
		return ret;
	if (action->type == RTE_FLOW_ACTION_TYPE_AGE) {
		struct rte_flow_action_age *age =
			(struct rte_flow_action_age *)(uintptr_t)(action->conf);

		pia->age_type = ACTION_AGE_CONTEXT_TYPE_INDIRECT_ACTION;
		age->context = &pia->age_type;
	}
	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x22, sizeof(error));
	pia->handle = rte_flow_action_handle_create(port_id, conf, action,
						    &error);
	if (!pia->handle) {
		uint32_t destroy_id = pia->id;
		port_action_handle_destroy(port_id, 1, &destroy_id);
		return port_flow_complain(&error);
	}
	pia->type = action->type;
	printf("Indirect action #%u created\n", pia->id);
	return 0;
}

/** Destroy indirect action */
int
port_action_handle_destroy(portid_t port_id,
			   uint32_t n,
			   const uint32_t *actions)
{
	struct rte_port *port;
	struct port_indirect_action **tmp;
	uint32_t c = 0;
	int ret = 0;

	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return -EINVAL;
	port = &ports[port_id];
	tmp = &port->actions_list;
	while (*tmp) {
		uint32_t i;

		for (i = 0; i != n; ++i) {
			struct rte_flow_error error;
			struct port_indirect_action *pia = *tmp;

			if (actions[i] != pia->id)
				continue;
			/*
			 * Poisoning to make sure PMDs update it in case
			 * of error.
			 */
			memset(&error, 0x33, sizeof(error));

			if (pia->handle && rte_flow_action_handle_destroy(
					port_id, pia->handle, &error)) {
				ret = port_flow_complain(&error);
				continue;
			}
			*tmp = pia->next;
			printf("Indirect action #%u destroyed\n", pia->id);
			free(pia);
			break;
		}
		if (i == n)
			tmp = &(*tmp)->next;
		++c;
	}
	return ret;
}


/** Get indirect action by port + id */
struct rte_flow_action_handle *
port_action_handle_get_by_id(portid_t port_id, uint32_t id)
{

	struct port_indirect_action *pia = action_get_by_id(port_id, id);

	return (pia) ? pia->handle : NULL;
}

/** Update indirect action */
int
port_action_handle_update(portid_t port_id, uint32_t id,
			  const struct rte_flow_action *action)
{
	struct rte_flow_error error;
	struct rte_flow_action_handle *action_handle;
	struct port_indirect_action *pia;
	const void *update;

	action_handle = port_action_handle_get_by_id(port_id, id);
	if (!action_handle)
		return -EINVAL;
	pia = action_get_by_id(port_id, id);
	if (!pia)
		return -EINVAL;
	switch (pia->type) {
	case RTE_FLOW_ACTION_TYPE_CONNTRACK:
		update = action->conf;
		break;
	default:
		update = action;
		break;
	}
	if (rte_flow_action_handle_update(port_id, action_handle, update,
					  &error)) {
		return port_flow_complain(&error);
	}
	printf("Indirect action #%u updated\n", id);
	return 0;
}



/** Add port meter policy */
int
port_meter_policy_add(portid_t port_id, uint32_t policy_id,
			const struct rte_flow_action *actions)
{
	struct rte_mtr_error error;
	const struct rte_flow_action *act = actions;
	const struct rte_flow_action *start;
	struct rte_mtr_meter_policy_params policy;
	uint32_t i = 0, act_n;
	int ret;

	for (i = 0; i < RTE_COLORS; i++) {
		for (act_n = 0, start = act;
			act->type != RTE_FLOW_ACTION_TYPE_END; act++)
			act_n++;
		if (act_n && act->type == RTE_FLOW_ACTION_TYPE_END)
			policy.actions[i] = start;
		else
			policy.actions[i] = NULL;
		act++;
	}
	ret = rte_mtr_meter_policy_add(port_id,
			policy_id,
			&policy, &error);

	return ret;
}

/** Restrict ingress traffic to the defined flow rules. */
int
port_flow_isolate(portid_t port_id, int set)
{
	struct rte_flow_error error;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x66, sizeof(error));
	if (rte_flow_isolate(port_id, set, &error))
		return port_flow_complain(&error);
	printf("Ingress traffic on port %u is %s to the defined flow rules\n",
	       port_id,
	       set ? "now restricted" : "not restricted anymore");
	return 0;
}

/*
 * RX/TX ring descriptors display functions.
 */
int
rx_queue_id_is_invalid(queueid_t rxq_id)
{
	if (rxq_id < nb_rxq)
		return 0;
	printf("Invalid RX queue %d (must be < nb_rxq=%d)\n", rxq_id, nb_rxq);
	return 1;
}

int
tx_queue_id_is_invalid(queueid_t txq_id)
{
	if (txq_id < nb_txq)
		return 0;
	printf("Invalid TX queue %d (must be < nb_txq=%d)\n", txq_id, nb_txq);
	return 1;
}


static int
get_tx_ring_size(portid_t port_id, queueid_t txq_id, uint16_t *ring_size)
{
	struct rte_port *port = &ports[port_id];
	struct rte_eth_txq_info tx_qinfo;
	int ret;

	ret = rte_eth_tx_queue_info_get(port_id, txq_id, &tx_qinfo);
	if (ret == 0) {
		*ring_size = tx_qinfo.nb_desc;
		return ret;
	}

	if (ret != -ENOTSUP)
		return ret;
	/*
	 * If the rte_eth_tx_queue_info_get is not support for this PMD,
	 * ring_size stored in testpmd will be used for validity verification.
	 * When configure the txq by rte_eth_tx_queue_setup with nb_tx_desc
	 * being 0, it will use a default value provided by PMDs to setup this
	 * txq. If the default value is 0, it will use the
	 * RTE_ETH_DEV_FALLBACK_TX_RINGSIZE to setup this txq.
	 */
	if (port->nb_tx_desc[txq_id])
		*ring_size = port->nb_tx_desc[txq_id];
	else if (port->dev_info.default_txportconf.ring_size)
		*ring_size = port->dev_info.default_txportconf.ring_size;
	else
		*ring_size = RTE_ETH_DEV_FALLBACK_TX_RINGSIZE;
	return 0;
}


union igb_ring_dword {
	uint64_t dword;
	struct {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
		uint32_t lo;
		uint32_t hi;
#else
		uint32_t hi;
		uint32_t lo;
#endif
	} words;
};

struct igb_ring_desc_32_bytes {
	union igb_ring_dword lo_dword;
	union igb_ring_dword hi_dword;
	union igb_ring_dword resv1;
	union igb_ring_dword resv2;
};

struct igb_ring_desc_16_bytes {
	union igb_ring_dword lo_dword;
	union igb_ring_dword hi_dword;
};


void
fwd_lcores_config_display(void)
{
	lcoreid_t lc_id;

	printf("List of forwarding lcores:");
	for (lc_id = 0; lc_id < nb_cfg_lcores; lc_id++)
		printf(" %2u", fwd_lcores_cpuids[lc_id]);
	printf("\n");
}
void
rxtx_config_display(void)
{
	printf("mjcdebug: %s\n", __FUNCTION__);
	portid_t pid;
	queueid_t qid;

	printf("  %s packet forwarding%s packets/burst=%d\n",
	       cur_fwd_eng->fwd_mode_name,
	       retry_enabled == 0 ? "" : " with retry",
	       nb_pkt_per_burst);

	printf("  nb forwarding cores=%d - nb forwarding ports=%d\n",
	       nb_fwd_lcores, nb_fwd_ports);

	RTE_ETH_FOREACH_DEV(pid) {
		struct rte_eth_rxconf *rx_conf = &ports[pid].rx_conf[0];
		struct rte_eth_txconf *tx_conf = &ports[pid].tx_conf[0];
		uint16_t *nb_rx_desc = &ports[pid].nb_rx_desc[0];
		uint16_t *nb_tx_desc = &ports[pid].nb_tx_desc[0];
		struct rte_eth_rxq_info rx_qinfo;
		struct rte_eth_txq_info tx_qinfo;
		uint16_t rx_free_thresh_tmp;
		uint16_t tx_free_thresh_tmp;
		uint16_t tx_rs_thresh_tmp;
		uint16_t nb_rx_desc_tmp;
		uint16_t nb_tx_desc_tmp;
		uint64_t offloads_tmp;
		uint8_t pthresh_tmp;
		uint8_t hthresh_tmp;
		uint8_t wthresh_tmp;
		int32_t rc;

		/* per port config */
		printf("  port %d: RX queue number: %d Tx queue number: %d\n",
				(unsigned int)pid, nb_rxq, nb_txq);

		printf("    Rx offloads=0x%"PRIx64" Tx offloads=0x%"PRIx64"\n",
				ports[pid].dev_conf.rxmode.offloads,
				ports[pid].dev_conf.txmode.offloads);

		/* per rx queue config only for first queue to be less verbose */
		for (qid = 0; qid < 1; qid++) {
			rc = rte_eth_rx_queue_info_get(pid, qid, &rx_qinfo);
			if (rc) {
				nb_rx_desc_tmp = nb_rx_desc[qid];
				rx_free_thresh_tmp =
					rx_conf[qid].rx_free_thresh;
				pthresh_tmp = rx_conf[qid].rx_thresh.pthresh;
				hthresh_tmp = rx_conf[qid].rx_thresh.hthresh;
				wthresh_tmp = rx_conf[qid].rx_thresh.wthresh;
				offloads_tmp = rx_conf[qid].offloads;
			} else {
				nb_rx_desc_tmp = rx_qinfo.nb_desc;
				rx_free_thresh_tmp =
						rx_qinfo.conf.rx_free_thresh;
				pthresh_tmp = rx_qinfo.conf.rx_thresh.pthresh;
				hthresh_tmp = rx_qinfo.conf.rx_thresh.hthresh;
				wthresh_tmp = rx_qinfo.conf.rx_thresh.wthresh;
				offloads_tmp = rx_qinfo.conf.offloads;
			}

			printf("    RX queue: %d\n", qid);
			printf("      RX desc=%d - RX free threshold=%d\n",
				nb_rx_desc_tmp, rx_free_thresh_tmp);
			printf("      RX threshold registers: pthresh=%d hthresh=%d "
				" wthresh=%d\n",
				pthresh_tmp, hthresh_tmp, wthresh_tmp);
			printf("      RX Offloads=0x%"PRIx64"\n", offloads_tmp);
		}

		/* per tx queue config only for first queue to be less verbose */
		for (qid = 0; qid < 1; qid++) {
			rc = rte_eth_tx_queue_info_get(pid, qid, &tx_qinfo);
			if (rc) {
				nb_tx_desc_tmp = nb_tx_desc[qid];
				tx_free_thresh_tmp =
					tx_conf[qid].tx_free_thresh;
				pthresh_tmp = tx_conf[qid].tx_thresh.pthresh;
				hthresh_tmp = tx_conf[qid].tx_thresh.hthresh;
				wthresh_tmp = tx_conf[qid].tx_thresh.wthresh;
				offloads_tmp = tx_conf[qid].offloads;
				tx_rs_thresh_tmp = tx_conf[qid].tx_rs_thresh;
			} else {
				nb_tx_desc_tmp = tx_qinfo.nb_desc;
				tx_free_thresh_tmp =
						tx_qinfo.conf.tx_free_thresh;
				pthresh_tmp = tx_qinfo.conf.tx_thresh.pthresh;
				hthresh_tmp = tx_qinfo.conf.tx_thresh.hthresh;
				wthresh_tmp = tx_qinfo.conf.tx_thresh.wthresh;
				offloads_tmp = tx_qinfo.conf.offloads;
				tx_rs_thresh_tmp = tx_qinfo.conf.tx_rs_thresh;
			}

			printf("    TX queue: %d\n", qid);
			printf("      TX desc=%d - TX free threshold=%d\n",
				nb_tx_desc_tmp, tx_free_thresh_tmp);
			printf("      TX threshold registers: pthresh=%d hthresh=%d "
				" wthresh=%d\n",
				pthresh_tmp, hthresh_tmp, wthresh_tmp);
			printf("      TX offloads=0x%"PRIx64" - TX RS bit threshold=%d\n",
				offloads_tmp, tx_rs_thresh_tmp);
		}
	}
}


/*
 * Setup forwarding configuration for each logical core.
 */
static void
setup_fwd_config_of_each_lcore(struct fwd_config *cfg)
{
	streamid_t nb_fs_per_lcore;
	streamid_t nb_fs;
	streamid_t sm_id;
	lcoreid_t  nb_extra;
	lcoreid_t  nb_fc;
	lcoreid_t  nb_lc;
	lcoreid_t  lc_id;

	nb_fs = cfg->nb_fwd_streams;
	nb_fc = cfg->nb_fwd_lcores;
	if (nb_fs <= nb_fc) {
		nb_fs_per_lcore = 1;
		nb_extra = 0;
	} else {
		nb_fs_per_lcore = (streamid_t) (nb_fs / nb_fc);
		nb_extra = (lcoreid_t) (nb_fs % nb_fc);
	}

	nb_lc = (lcoreid_t) (nb_fc - nb_extra);
	sm_id = 0;
	for (lc_id = 0; lc_id < nb_lc; lc_id++) {
		fwd_lcores[lc_id]->stream_idx = sm_id;
		fwd_lcores[lc_id]->stream_nb = nb_fs_per_lcore;
		sm_id = (streamid_t) (sm_id + nb_fs_per_lcore);
	}

	/*
	 * Assign extra remaining streams, if any.
	 */
	nb_fs_per_lcore = (streamid_t) (nb_fs_per_lcore + 1);
	for (lc_id = 0; lc_id < nb_extra; lc_id++) {
		fwd_lcores[nb_lc + lc_id]->stream_idx = sm_id;
		fwd_lcores[nb_lc + lc_id]->stream_nb = nb_fs_per_lcore;
		sm_id = (streamid_t) (sm_id + nb_fs_per_lcore);
	}
}

static portid_t
fwd_topology_tx_port_get(portid_t rxp)
{
	static int warning_once = 1;

	RTE_ASSERT(rxp < cur_fwd_config.nb_fwd_ports);

	switch (port_topology) {
	default:
	case PORT_TOPOLOGY_PAIRED:
		if ((rxp & 0x1) == 0) {
			if (rxp + 1 < cur_fwd_config.nb_fwd_ports)
				return rxp + 1;
			if (warning_once) {
				printf("\nWarning! port-topology=paired"
				       " and odd forward ports number,"
				       " the last port will pair with"
				       " itself.\n\n");
				warning_once = 0;
			}
			return rxp;
		}
		return rxp - 1;
	case PORT_TOPOLOGY_CHAINED:
		return (rxp + 1) % cur_fwd_config.nb_fwd_ports;
	case PORT_TOPOLOGY_LOOP:
		return rxp;
	}
}

static void
simple_fwd_config_setup(void)
{
	portid_t i;

	cur_fwd_config.nb_fwd_ports = (portid_t) nb_fwd_ports;
	cur_fwd_config.nb_fwd_streams =
		(streamid_t) cur_fwd_config.nb_fwd_ports;

	/* reinitialize forwarding streams */
	init_fwd_streams();

	/*
	 * In the simple forwarding test, the number of forwarding cores
	 * must be lower or equal to the number of forwarding ports.
	 */
	cur_fwd_config.nb_fwd_lcores = (lcoreid_t) nb_fwd_lcores;
	if (cur_fwd_config.nb_fwd_lcores > cur_fwd_config.nb_fwd_ports)
		cur_fwd_config.nb_fwd_lcores =
			(lcoreid_t) cur_fwd_config.nb_fwd_ports;
	setup_fwd_config_of_each_lcore(&cur_fwd_config);

	for (i = 0; i < cur_fwd_config.nb_fwd_ports; i++) {
		fwd_streams[i]->rx_port   = fwd_ports_ids[i];
		fwd_streams[i]->rx_queue  = 0;
		fwd_streams[i]->tx_port   =
				fwd_ports_ids[fwd_topology_tx_port_get(i)];
		fwd_streams[i]->tx_queue  = 0;
		fwd_streams[i]->peer_addr = fwd_streams[i]->tx_port;
		fwd_streams[i]->retry_enabled = retry_enabled;
	}
}

/**
 * For the RSS forwarding test all streams distributed over lcores. Each stream
 * being composed of a RX queue to poll on a RX port for input messages,
 * associated with a TX queue of a TX port where to send forwarded packets.
 */
static void
rss_fwd_config_setup(void)
{
	portid_t   rxp;
	portid_t   txp;
	queueid_t  rxq;
	queueid_t  nb_q;
	streamid_t  sm_id;

	nb_q = nb_rxq;
	if (nb_q > nb_txq)
		nb_q = nb_txq;
	cur_fwd_config.nb_fwd_lcores = (lcoreid_t) nb_fwd_lcores;
	cur_fwd_config.nb_fwd_ports = nb_fwd_ports;
	cur_fwd_config.nb_fwd_streams =
		(streamid_t) (nb_q * cur_fwd_config.nb_fwd_ports);

	if (cur_fwd_config.nb_fwd_streams < cur_fwd_config.nb_fwd_lcores)
		cur_fwd_config.nb_fwd_lcores =
			(lcoreid_t)cur_fwd_config.nb_fwd_streams;

	/* reinitialize forwarding streams */
	init_fwd_streams();

	setup_fwd_config_of_each_lcore(&cur_fwd_config);
	rxp = 0; rxq = 0;
	for (sm_id = 0; sm_id < cur_fwd_config.nb_fwd_streams; sm_id++) {
		struct fwd_stream *fs;

		fs = fwd_streams[sm_id];
		txp = fwd_topology_tx_port_get(rxp);
		fs->rx_port = fwd_ports_ids[rxp];
		fs->rx_queue = rxq;
		fs->tx_port = fwd_ports_ids[txp];
		fs->tx_queue = rxq;
		fs->peer_addr = fs->tx_port;
		fs->retry_enabled = retry_enabled;
		rxp++;
		if (rxp < nb_fwd_ports)
			continue;
		rxp = 0;
		rxq++;
	}
}


void
fwd_config_setup(void)
{
	cur_fwd_config.fwd_eng = cur_fwd_eng; // do not delete

	if ((nb_rxq > 1) && (nb_txq > 1)){
		rss_fwd_config_setup();
	}
	else
		simple_fwd_config_setup();
}

static const char *
mp_alloc_to_str(uint8_t mode)
{
	switch (mode) {
	case MP_ALLOC_NATIVE:
		return "native";
	case MP_ALLOC_ANON:
		return "anon";
	case MP_ALLOC_XMEM:
		return "xmem";
	case MP_ALLOC_XMEM_HUGE:
		return "xmemhuge";
	case MP_ALLOC_XBUF:
		return "xbuf";
	default:
		return "invalid";
	}
}

void
pkt_fwd_config_display(struct fwd_config *cfg)
{
	struct fwd_stream *fs;
	lcoreid_t  lc_id;
	streamid_t sm_id;

	printf("%s packet forwarding%s - ports=%d - cores=%d - streams=%d - "
		"NUMA support %s, MP allocation mode: %s\n",
		cfg->fwd_eng->fwd_mode_name,
		retry_enabled == 0 ? "" : " with retry",
		cfg->nb_fwd_ports, cfg->nb_fwd_lcores, cfg->nb_fwd_streams,
		numa_support == 1 ? "enabled" : "disabled",
		mp_alloc_to_str(mp_alloc_type));

	if (retry_enabled)
		printf("TX retry num: %u, delay between TX retries: %uus\n",
			burst_tx_retry_num, burst_tx_delay_time);
	for (lc_id = 0; lc_id < cfg->nb_fwd_lcores; lc_id++) {
		printf("Logical Core %u (socket %u) forwards packets on "
		       "%d streams:",
		       fwd_lcores_cpuids[lc_id],
		       rte_lcore_to_socket_id(fwd_lcores_cpuids[lc_id]),
		       fwd_lcores[lc_id]->stream_nb);
		for (sm_id = 0; sm_id < fwd_lcores[lc_id]->stream_nb; sm_id++) {
			fs = fwd_streams[fwd_lcores[lc_id]->stream_idx + sm_id];
			printf("\n  RX P=%d/Q=%d (socket %u) -> TX "
			       "P=%d/Q=%d (socket %u) ",
			       fs->rx_port, fs->rx_queue,
			       ports[fs->rx_port].socket_id,
			       fs->tx_port, fs->tx_queue,
			       ports[fs->tx_port].socket_id);
			print_ethaddr("peer=",
				      &peer_eth_addrs[fs->peer_addr]);
		}
		printf("\n");
	}
	printf("\n");
}

void
set_fwd_eth_peer(portid_t port_id, char *peer_addr)
{
	struct rte_ether_addr new_peer_addr;
	if (!rte_eth_dev_is_valid_port(port_id)) {
		printf("Error: Invalid port number %i\n", port_id);
		return;
	}
	if (rte_ether_unformat_addr(peer_addr, &new_peer_addr) < 0) {
		printf("Error: Invalid ethernet address: %s\n", peer_addr);
		return;
	}
	peer_eth_addrs[port_id] = new_peer_addr;
}

int
set_fwd_lcores_list(unsigned int *lcorelist, unsigned int nb_lc)
{
	unsigned int i;
	unsigned int lcore_cpuid;
	int record_now;

	record_now = 0;
 again:
	for (i = 0; i < nb_lc; i++) {
		lcore_cpuid = lcorelist[i];
		if (! rte_lcore_is_enabled(lcore_cpuid)) {
			printf("lcore %u not enabled\n", lcore_cpuid);
			return -1;
		}
		if (lcore_cpuid == rte_get_main_lcore()) {
			printf("lcore %u cannot be masked on for running "
			       "packet forwarding, which is the main lcore "
			       "and reserved for command line parsing only\n",
			       lcore_cpuid);
			return -1;
		}
		if (record_now)
			fwd_lcores_cpuids[i] = lcore_cpuid;
	}
	if (record_now == 0) {
		record_now = 1;
		goto again;
	}
	nb_cfg_lcores = (lcoreid_t) nb_lc;
	if (nb_fwd_lcores != (lcoreid_t) nb_lc) {
		printf("previous number of forwarding cores %u - changed to "
		       "number of configured cores %u\n",
		       (unsigned int) nb_fwd_lcores, nb_lc);
		nb_fwd_lcores = (lcoreid_t) nb_lc;
	}

	return 0;
}

int
set_fwd_lcores_mask(uint64_t lcoremask)
{
	unsigned int lcorelist[64];
	unsigned int nb_lc;
	unsigned int i;

	if (lcoremask == 0) {
		printf("Invalid NULL mask of cores\n");
		return -1;
	}
	nb_lc = 0;
	for (i = 0; i < 64; i++) {
		if (! ((uint64_t)(1ULL << i) & lcoremask))
			continue;
		lcorelist[nb_lc++] = i;
	}
	return set_fwd_lcores_list(lcorelist, nb_lc);
}

void
set_fwd_lcores_number(uint16_t nb_lc)
{
	if (test_done == 0) {
		printf("Please stop forwarding first\n");
		return;
	}
	if (nb_lc > nb_cfg_lcores) {
		printf("nb fwd cores %u > %u (max. number of configured "
		       "lcores) - ignored\n",
		       (unsigned int) nb_lc, (unsigned int) nb_cfg_lcores);
		return;
	}
	nb_fwd_lcores = (lcoreid_t) nb_lc;
	printf("Number of forwarding cores set to %u\n",
	       (unsigned int) nb_fwd_lcores);
}

void
set_fwd_ports_list(unsigned int *portlist, unsigned int nb_pt)
{
	unsigned int i;
	portid_t port_id;
	int record_now;

	record_now = 0;
 again:
	for (i = 0; i < nb_pt; i++) {
		port_id = (portid_t) portlist[i];
		if (port_id_is_invalid(port_id, ENABLED_WARN))
			return;
		if (record_now)
			fwd_ports_ids[i] = port_id;
	}
	if (record_now == 0) {
		record_now = 1;
		goto again;
	}
	nb_cfg_ports = (portid_t) nb_pt;
	if (nb_fwd_ports != (portid_t) nb_pt) {
		printf("previous number of forwarding ports %u - changed to "
		       "number of configured ports %u\n",
		       (unsigned int) nb_fwd_ports, nb_pt);
		nb_fwd_ports = (portid_t) nb_pt;
	}
}

/**
 * Parse the user input and obtain the list of forwarding ports
 *
 * @param[in] list
 *   String containing the user input. User can specify
 *   in these formats 1,3,5 or 1-3 or 1-2,5 or 3,5-6.
 *   For example, if the user wants to use all the available
 *   4 ports in his system, then the input can be 0-3 or 0,1,2,3.
 *   If the user wants to use only the ports 1,2 then the input
 *   is 1,2.
 *   valid characters are '-' and ','
 * @param[out] values
 *   This array will be filled with a list of port IDs
 *   based on the user input
 *   Note that duplicate entries are discarded and only the first
 *   count entries in this array are port IDs and all the rest
 *   will contain default values
 * @param[in] maxsize
 *   This parameter denotes 2 things
 *   1) Number of elements in the values array
 *   2) Maximum value of each element in the values array
 * @return
 *   On success, returns total count of parsed port IDs
 *   On failure, returns 0
 */
static unsigned int
parse_port_list(const char *list, unsigned int *values, unsigned int maxsize)
{
	unsigned int count = 0;
	char *end = NULL;
	int min, max;
	int value, i;
	unsigned int marked[maxsize];

	if (list == NULL || values == NULL)
		return 0;

	for (i = 0; i < (int)maxsize; i++)
		marked[i] = 0;

	min = INT_MAX;

	do {
		/*Remove the blank spaces if any*/
		while (isblank(*list))
			list++;
		if (*list == '\0')
			break;
		errno = 0;
		value = strtol(list, &end, 10);
		if (errno || end == NULL)
			return 0;
		if (value < 0 || value >= (int)maxsize)
			return 0;
		while (isblank(*end))
			end++;
		if (*end == '-' && min == INT_MAX) {
			min = value;
		} else if ((*end == ',') || (*end == '\0')) {
			max = value;
			if (min == INT_MAX)
				min = value;
			for (i = min; i <= max; i++) {
				if (count < maxsize) {
					if (marked[i])
						continue;
					values[count] = i;
					marked[i] = 1;
					count++;
				}
			}
			min = INT_MAX;
		} else
			return 0;
		list = end + 1;
	} while (*end != '\0');

	return count;
}

void
parse_fwd_portlist(const char *portlist)
{
	unsigned int portcount;
	unsigned int portindex[RTE_MAX_ETHPORTS];
	unsigned int i, valid_port_count = 0;

	portcount = parse_port_list(portlist, portindex, RTE_MAX_ETHPORTS);
	if (!portcount)
		rte_exit(EXIT_FAILURE, "Invalid fwd port list\n");

	/*
	 * Here we verify the validity of the ports
	 * and thereby calculate the total number of
	 * valid ports
	 */
	for (i = 0; i < portcount && i < RTE_DIM(portindex); i++) {
		if (rte_eth_dev_is_valid_port(portindex[i])) {
			portindex[valid_port_count] = portindex[i];
			valid_port_count++;
		}
	}

	set_fwd_ports_list(portindex, valid_port_count);
}

void
set_fwd_ports_mask(uint64_t portmask)
{
	unsigned int portlist[64];
	unsigned int nb_pt;
	unsigned int i;

	if (portmask == 0) {
		printf("Invalid NULL mask of ports\n");
		return;
	}
	nb_pt = 0;
	RTE_ETH_FOREACH_DEV(i) {
		if (! ((uint64_t)(1ULL << i) & portmask))
			continue;
		portlist[nb_pt++] = i;
	}
	set_fwd_ports_list(portlist, nb_pt);
}

void
set_fwd_ports_number(uint16_t nb_pt)
{
	if (nb_pt > nb_cfg_ports) {
		printf("nb fwd ports %u > %u (number of configured "
		       "ports) - ignored\n",
		       (unsigned int) nb_pt, (unsigned int) nb_cfg_ports);
		return;
	}
	nb_fwd_ports = (portid_t) nb_pt;
	printf("Number of forwarding ports set to %u\n",
	       (unsigned int) nb_fwd_ports);
}

int
port_is_forwarding(portid_t port_id)
{
	unsigned int i;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return -1;

	for (i = 0; i < nb_fwd_ports; i++) {
		if (fwd_ports_ids[i] == port_id)
			return 1;
	}

	return 0;
}

void
set_nb_pkt_per_burst(uint16_t nb)
{
	if (nb > MAX_PKT_BURST) {
		printf("nb pkt per burst: %u > %u (maximum packet per burst) "
		       " ignored\n",
		       (unsigned int) nb, (unsigned int) MAX_PKT_BURST);
		return;
	}
	nb_pkt_per_burst = nb;
	printf("Number of packets per burst set to %u\n",
	       (unsigned int) nb_pkt_per_burst);
}

static const char *
tx_split_get_name(enum tx_pkt_split split)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(tx_split_name); i++) {
		if (tx_split_name[i].split == split)
			return tx_split_name[i].name;
	}
	return NULL;
}

void
set_tx_pkt_split(const char *name)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(tx_split_name); i++) {
		if (strcmp(tx_split_name[i].name, name) == 0) {
			tx_pkt_split = tx_split_name[i].split;
			return;
		}
	}
	printf("unknown value: \"%s\"\n", name);
}

int
parse_fec_mode(const char *name, uint32_t *mode)
{
	uint8_t i;

	for (i = 0; i < RTE_DIM(fec_mode_name); i++) {
		if (strcmp(fec_mode_name[i].name, name) == 0) {
			*mode = RTE_ETH_FEC_MODE_TO_CAPA(fec_mode_name[i].mode);
			return 0;
		}
	}
	return -1;
}

void
show_fec_capability(unsigned int num, struct rte_eth_fec_capa *speed_fec_capa)
{
	unsigned int i, j;

	printf("FEC capabilities:\n");

	for (i = 0; i < num; i++) {
		printf("%s : ",
			rte_eth_link_speed_to_str(speed_fec_capa[i].speed));

		for (j = 0; j < RTE_DIM(fec_mode_name); j++) {
			if (RTE_ETH_FEC_MODE_TO_CAPA(j) &
						speed_fec_capa[i].capa)
				printf("%s ", fec_mode_name[j].name);
		}
		printf("\n");
	}
}

void
show_rx_pkt_offsets(void)
{
	uint32_t i, n;

	n = rx_pkt_nb_offs;
	printf("Number of offsets: %u\n", n);
	if (n) {
		printf("Segment offsets: ");
		for (i = 0; i != n - 1; i++)
			printf("%hu,", rx_pkt_seg_offsets[i]);
		printf("%hu\n", rx_pkt_seg_lengths[i]);
	}
}

void
set_rx_pkt_offsets(unsigned int *seg_offsets, unsigned int nb_offs)
{
	unsigned int i;

	if (nb_offs >= MAX_SEGS_BUFFER_SPLIT) {
		printf("nb segments per RX packets=%u >= "
		       "MAX_SEGS_BUFFER_SPLIT - ignored\n", nb_offs);
		return;
	}

	/*
	 * No extra check here, the segment length will be checked by PMD
	 * in the extended queue setup.
	 */
	for (i = 0; i < nb_offs; i++) {
		if (seg_offsets[i] >= UINT16_MAX) {
			printf("offset[%u]=%u > UINT16_MAX - give up\n",
			       i, seg_offsets[i]);
			return;
		}
	}

	for (i = 0; i < nb_offs; i++)
		rx_pkt_seg_offsets[i] = (uint16_t) seg_offsets[i];

	rx_pkt_nb_offs = (uint8_t) nb_offs;
}

void
show_rx_pkt_segments(void)
{
	uint32_t i, n;

	n = rx_pkt_nb_segs;
	printf("Number of segments: %u\n", n);
	if (n) {
		printf("Segment sizes: ");
		for (i = 0; i != n - 1; i++)
			printf("%hu,", rx_pkt_seg_lengths[i]);
		printf("%hu\n", rx_pkt_seg_lengths[i]);
	}
}

void
set_rx_pkt_segments(unsigned int *seg_lengths, unsigned int nb_segs)
{
	unsigned int i;

	if (nb_segs >= MAX_SEGS_BUFFER_SPLIT) {
		printf("nb segments per RX packets=%u >= "
		       "MAX_SEGS_BUFFER_SPLIT - ignored\n", nb_segs);
		return;
	}

	/*
	 * No extra check here, the segment length will be checked by PMD
	 * in the extended queue setup.
	 */
	for (i = 0; i < nb_segs; i++) {
		if (seg_lengths[i] >= UINT16_MAX) {
			printf("length[%u]=%u > UINT16_MAX - give up\n",
			       i, seg_lengths[i]);
			return;
		}
	}

	for (i = 0; i < nb_segs; i++)
		rx_pkt_seg_lengths[i] = (uint16_t) seg_lengths[i];

	rx_pkt_nb_segs = (uint8_t) nb_segs;
}

void
show_tx_pkt_segments(void)
{
	uint32_t i, n;
	const char *split;

	n = tx_pkt_nb_segs;
	split = tx_split_get_name(tx_pkt_split);

	printf("Number of segments: %u\n", n);
	printf("Segment sizes: ");
	for (i = 0; i != n - 1; i++)
		printf("%hu,", tx_pkt_seg_lengths[i]);
	printf("%hu\n", tx_pkt_seg_lengths[i]);
	printf("Split packet: %s\n", split);
}

static bool
nb_segs_is_invalid(unsigned int nb_segs)
{
	uint16_t ring_size;
	uint16_t queue_id;
	uint16_t port_id;
	int ret;

	RTE_ETH_FOREACH_DEV(port_id) {
		for (queue_id = 0; queue_id < nb_txq; queue_id++) {
			ret = get_tx_ring_size(port_id, queue_id, &ring_size);

			if (ret)
				return true;

			if (ring_size < nb_segs) {
				printf("nb segments per TX packets=%u >= "
				       "TX queue(%u) ring_size=%u - ignored\n",
				       nb_segs, queue_id, ring_size);
				return true;
			}
		}
	}

	return false;
}

void
set_tx_pkt_segments(unsigned int *seg_lengths, unsigned int nb_segs)
{
	uint16_t tx_pkt_len;
	unsigned int i;

	if (nb_segs_is_invalid(nb_segs))
		return;

	/*
	 * Check that each segment length is greater or equal than
	 * the mbuf data sise.
	 * Check also that the total packet length is greater or equal than the
	 * size of an empty UDP/IP packet (sizeof(struct rte_ether_hdr) +
	 * 20 + 8).
	 */
	tx_pkt_len = 0;
	for (i = 0; i < nb_segs; i++) {
		if (seg_lengths[i] > mbuf_data_size[0]) {
			printf("length[%u]=%u > mbuf_data_size=%u - give up\n",
			       i, seg_lengths[i], mbuf_data_size[0]);
			return;
		}
		tx_pkt_len = (uint16_t)(tx_pkt_len + seg_lengths[i]);
	}
	if (tx_pkt_len < (sizeof(struct rte_ether_hdr) + 20 + 8)) {
		printf("total packet length=%u < %d - give up\n",
				(unsigned) tx_pkt_len,
				(int)(sizeof(struct rte_ether_hdr) + 20 + 8));
		return;
	}

	for (i = 0; i < nb_segs; i++)
		tx_pkt_seg_lengths[i] = (uint16_t) seg_lengths[i];

	tx_pkt_length  = tx_pkt_len;
	tx_pkt_nb_segs = (uint8_t) nb_segs;
}

void
show_tx_pkt_times(void)
{
	printf("Interburst gap: %u\n", tx_pkt_times_inter);
	printf("Intraburst gap: %u\n", tx_pkt_times_intra);
}

void
set_tx_pkt_times(unsigned int *tx_times)
{
	tx_pkt_times_inter = tx_times[0];
	tx_pkt_times_intra = tx_times[1];
}


void
add_rx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_rx_queues; queue++)
		if (!ports[portid].rx_dump_cb[queue])
			ports[portid].rx_dump_cb[queue] =
				rte_eth_add_rx_callback(portid, queue,
					dump_rx_pkts, NULL);
}

void
add_tx_dump_callbacks(portid_t portid)
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
		if (!ports[portid].tx_dump_cb[queue])
			ports[portid].tx_dump_cb[queue] =
				rte_eth_add_tx_callback(portid, queue,
							dump_tx_pkts, NULL);
}

void
remove_rx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_rx_queues; queue++)
		if (ports[portid].rx_dump_cb[queue]) {
			rte_eth_remove_rx_callback(portid, queue,
				ports[portid].rx_dump_cb[queue]);
			ports[portid].rx_dump_cb[queue] = NULL;
		}
}

void
remove_tx_dump_callbacks(portid_t portid)
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
		if (ports[portid].tx_dump_cb[queue]) {
			rte_eth_remove_tx_callback(portid, queue,
				ports[portid].tx_dump_cb[queue]);
			ports[portid].tx_dump_cb[queue] = NULL;
		}
}

void
configure_rxtx_dump_callbacks(uint16_t verbose)
{
	portid_t portid;

#ifndef RTE_ETHDEV_RXTX_CALLBACKS
		TESTPMD_LOG(ERR, "setting rxtx callbacks is not enabled\n");
		return;
#endif

	RTE_ETH_FOREACH_DEV(portid)
	{
		if (verbose == 1 || verbose > 2)
			add_rx_dump_callbacks(portid);
		else
			remove_rx_dump_callbacks(portid);
		if (verbose >= 2)
			add_tx_dump_callbacks(portid);
		else
			remove_tx_dump_callbacks(portid);
	}
}

void
set_verbose_level(uint16_t vb_level)
{
	printf("Change verbose level from %u to %u\n",
	       (unsigned int) verbose_level, (unsigned int) vb_level);
	verbose_level = vb_level;
	configure_rxtx_dump_callbacks(verbose_level);
}

void
vlan_extend_set(portid_t port_id, int on)
{
	int diag;
	int vlan_offload;
	uint64_t port_rx_offloads = ports[port_id].dev_conf.rxmode.offloads;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	vlan_offload = rte_eth_dev_get_vlan_offload(port_id);

	if (on) {
		vlan_offload |= ETH_VLAN_EXTEND_OFFLOAD;
		port_rx_offloads |= DEV_RX_OFFLOAD_VLAN_EXTEND;
	} else {
		vlan_offload &= ~ETH_VLAN_EXTEND_OFFLOAD;
		port_rx_offloads &= ~DEV_RX_OFFLOAD_VLAN_EXTEND;
	}

	diag = rte_eth_dev_set_vlan_offload(port_id, vlan_offload);
	if (diag < 0) {
		printf("rx_vlan_extend_set(port_pi=%d, on=%d) failed "
	       "diag=%d\n", port_id, on, diag);
		return;
	}
	ports[port_id].dev_conf.rxmode.offloads = port_rx_offloads;
}

void
rx_vlan_strip_set(portid_t port_id, int on)
{
	int diag;
	int vlan_offload;
	uint64_t port_rx_offloads = ports[port_id].dev_conf.rxmode.offloads;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	vlan_offload = rte_eth_dev_get_vlan_offload(port_id);

	if (on) {
		vlan_offload |= ETH_VLAN_STRIP_OFFLOAD;
		port_rx_offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
	} else {
		vlan_offload &= ~ETH_VLAN_STRIP_OFFLOAD;
		port_rx_offloads &= ~DEV_RX_OFFLOAD_VLAN_STRIP;
	}

	diag = rte_eth_dev_set_vlan_offload(port_id, vlan_offload);
	if (diag < 0) {
		printf("rx_vlan_strip_set(port_pi=%d, on=%d) failed "
	       "diag=%d\n", port_id, on, diag);
		return;
	}
	ports[port_id].dev_conf.rxmode.offloads = port_rx_offloads;
}

void
rx_vlan_strip_set_on_queue(portid_t port_id, uint16_t queue_id, int on)
{
	int diag;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	diag = rte_eth_dev_set_vlan_strip_on_queue(port_id, queue_id, on);
	if (diag < 0)
		printf("rx_vlan_strip_set_on_queue(port_pi=%d, queue_id=%d, on=%d) failed "
	       "diag=%d\n", port_id, queue_id, on, diag);
}

void
rx_vlan_filter_set(portid_t port_id, int on)
{
	int diag;
	int vlan_offload;
	uint64_t port_rx_offloads = ports[port_id].dev_conf.rxmode.offloads;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	vlan_offload = rte_eth_dev_get_vlan_offload(port_id);

	if (on) {
		vlan_offload |= ETH_VLAN_FILTER_OFFLOAD;
		port_rx_offloads |= DEV_RX_OFFLOAD_VLAN_FILTER;
	} else {
		vlan_offload &= ~ETH_VLAN_FILTER_OFFLOAD;
		port_rx_offloads &= ~DEV_RX_OFFLOAD_VLAN_FILTER;
	}

	diag = rte_eth_dev_set_vlan_offload(port_id, vlan_offload);
	if (diag < 0) {
		printf("rx_vlan_filter_set(port_pi=%d, on=%d) failed "
	       "diag=%d\n", port_id, on, diag);
		return;
	}
	ports[port_id].dev_conf.rxmode.offloads = port_rx_offloads;
}

void
rx_vlan_qinq_strip_set(portid_t port_id, int on)
{
	int diag;
	int vlan_offload;
	uint64_t port_rx_offloads = ports[port_id].dev_conf.rxmode.offloads;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	vlan_offload = rte_eth_dev_get_vlan_offload(port_id);

	if (on) {
		vlan_offload |= ETH_QINQ_STRIP_OFFLOAD;
		port_rx_offloads |= DEV_RX_OFFLOAD_QINQ_STRIP;
	} else {
		vlan_offload &= ~ETH_QINQ_STRIP_OFFLOAD;
		port_rx_offloads &= ~DEV_RX_OFFLOAD_QINQ_STRIP;
	}

	diag = rte_eth_dev_set_vlan_offload(port_id, vlan_offload);
	if (diag < 0) {
		printf("%s(port_pi=%d, on=%d) failed "
	       "diag=%d\n", __func__, port_id, on, diag);
		return;
	}
	ports[port_id].dev_conf.rxmode.offloads = port_rx_offloads;
}

int
rx_vft_set(portid_t port_id, uint16_t vlan_id, int on)
{
	int diag;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return 1;
	if (vlan_id_is_invalid(vlan_id))
		return 1;
	diag = rte_eth_dev_vlan_filter(port_id, vlan_id, on);
	if (diag == 0)
		return 0;
	printf("rte_eth_dev_vlan_filter(port_pi=%d, vlan_id=%d, on=%d) failed "
	       "diag=%d\n",
	       port_id, vlan_id, on, diag);
	return -1;
}

void
rx_vlan_all_filter_set(portid_t port_id, int on)
{
	uint16_t vlan_id;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	for (vlan_id = 0; vlan_id < 4096; vlan_id++) {
		if (rx_vft_set(port_id, vlan_id, on))
			break;
	}
}

void
vlan_tpid_set(portid_t port_id, enum rte_vlan_type vlan_type, uint16_t tp_id)
{
	int diag;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	diag = rte_eth_dev_set_vlan_ether_type(port_id, vlan_type, tp_id);
	if (diag == 0)
		return;

	printf("tx_vlan_tpid_set(port_pi=%d, vlan_type=%d, tpid=%d) failed "
	       "diag=%d\n",
	       port_id, vlan_type, tp_id, diag);
}

void
tx_vlan_set(portid_t port_id, uint16_t vlan_id)
{
	struct rte_eth_dev_info dev_info;
	int ret;

	if (vlan_id_is_invalid(vlan_id))
		return;

	if (ports[port_id].dev_conf.txmode.offloads &
	    DEV_TX_OFFLOAD_QINQ_INSERT) {
		printf("Error, as QinQ has been enabled.\n");
		return;
	}

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		return;

	if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT) == 0) {
		printf("Error: vlan insert is not supported by port %d\n",
			port_id);
		return;
	}

	tx_vlan_reset(port_id);
	ports[port_id].dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_VLAN_INSERT;
	ports[port_id].tx_vlan_id = vlan_id;
}

void
tx_qinq_set(portid_t port_id, uint16_t vlan_id, uint16_t vlan_id_outer)
{
	struct rte_eth_dev_info dev_info;
	int ret;

	if (vlan_id_is_invalid(vlan_id))
		return;
	if (vlan_id_is_invalid(vlan_id_outer))
		return;

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		return;

	if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_QINQ_INSERT) == 0) {
		printf("Error: qinq insert not supported by port %d\n",
			port_id);
		return;
	}

	tx_vlan_reset(port_id);
	ports[port_id].dev_conf.txmode.offloads |= (DEV_TX_OFFLOAD_VLAN_INSERT |
						    DEV_TX_OFFLOAD_QINQ_INSERT);
	ports[port_id].tx_vlan_id = vlan_id;
	ports[port_id].tx_vlan_id_outer = vlan_id_outer;
}

void
tx_vlan_reset(portid_t port_id)
{
	ports[port_id].dev_conf.txmode.offloads &=
				~(DEV_TX_OFFLOAD_VLAN_INSERT |
				  DEV_TX_OFFLOAD_QINQ_INSERT);
	ports[port_id].tx_vlan_id = 0;
	ports[port_id].tx_vlan_id_outer = 0;
}

void
tx_vlan_pvid_set(portid_t port_id, uint16_t vlan_id, int on)
{
	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	rte_eth_dev_set_vlan_pvid(port_id, vlan_id, on);
}

void
set_qmap(portid_t port_id, uint8_t is_rx, uint16_t queue_id, uint8_t map_value)
{
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	if (is_rx ? (rx_queue_id_is_invalid(queue_id)) : (tx_queue_id_is_invalid(queue_id)))
		return;

	if (map_value >= RTE_ETHDEV_QUEUE_STAT_CNTRS) {
		printf("map_value not in required range 0..%d\n",
		       RTE_ETHDEV_QUEUE_STAT_CNTRS - 1);
		return;
	}

	if (!is_rx) { /* tx */
		ret = rte_eth_dev_set_tx_queue_stats_mapping(port_id, queue_id,
							     map_value);
		if (ret) {
			printf("failed to set tx queue stats mapping.\n");
			return;
		}
	} else { /* rx */
		ret = rte_eth_dev_set_rx_queue_stats_mapping(port_id, queue_id,
							     map_value);
		if (ret) {
			printf("failed to set rx queue stats mapping.\n");
			return;
		}
	}
}

void
set_xstats_hide_zero(uint8_t on_off)
{
	xstats_hide_zero = on_off;
}

void
set_record_core_cycles(uint8_t on_off)
{
	record_core_cycles = on_off;
}

void
set_record_burst_stats(uint8_t on_off)
{
	record_burst_stats = on_off;
}

static inline void
print_fdir_mask(struct rte_eth_fdir_masks *mask)
{
	printf("\n    vlan_tci: 0x%04x", rte_be_to_cpu_16(mask->vlan_tci_mask));

	if (fdir_conf.mode == RTE_FDIR_MODE_PERFECT_TUNNEL)
		printf(", mac_addr: 0x%02x, tunnel_type: 0x%01x,"
			" tunnel_id: 0x%08x",
			mask->mac_addr_byte_mask, mask->tunnel_type_mask,
			rte_be_to_cpu_32(mask->tunnel_id_mask));
	else if (fdir_conf.mode != RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		printf(", src_ipv4: 0x%08x, dst_ipv4: 0x%08x",
			rte_be_to_cpu_32(mask->ipv4_mask.src_ip),
			rte_be_to_cpu_32(mask->ipv4_mask.dst_ip));

		printf("\n    src_port: 0x%04x, dst_port: 0x%04x",
			rte_be_to_cpu_16(mask->src_port_mask),
			rte_be_to_cpu_16(mask->dst_port_mask));

		printf("\n    src_ipv6: 0x%08x,0x%08x,0x%08x,0x%08x",
			rte_be_to_cpu_32(mask->ipv6_mask.src_ip[0]),
			rte_be_to_cpu_32(mask->ipv6_mask.src_ip[1]),
			rte_be_to_cpu_32(mask->ipv6_mask.src_ip[2]),
			rte_be_to_cpu_32(mask->ipv6_mask.src_ip[3]));

		printf("\n    dst_ipv6: 0x%08x,0x%08x,0x%08x,0x%08x",
			rte_be_to_cpu_32(mask->ipv6_mask.dst_ip[0]),
			rte_be_to_cpu_32(mask->ipv6_mask.dst_ip[1]),
			rte_be_to_cpu_32(mask->ipv6_mask.dst_ip[2]),
			rte_be_to_cpu_32(mask->ipv6_mask.dst_ip[3]));
	}

	printf("\n");
}

static inline void
print_fdir_flex_payload(struct rte_eth_fdir_flex_conf *flex_conf, uint32_t num)
{
	struct rte_eth_flex_payload_cfg *cfg;
	uint32_t i, j;

	for (i = 0; i < flex_conf->nb_payloads; i++) {
		cfg = &flex_conf->flex_set[i];
		if (cfg->type == RTE_ETH_RAW_PAYLOAD)
			printf("\n    RAW:  ");
		else if (cfg->type == RTE_ETH_L2_PAYLOAD)
			printf("\n    L2_PAYLOAD:  ");
		else if (cfg->type == RTE_ETH_L3_PAYLOAD)
			printf("\n    L3_PAYLOAD:  ");
		else if (cfg->type == RTE_ETH_L4_PAYLOAD)
			printf("\n    L4_PAYLOAD:  ");
		else
			printf("\n    UNKNOWN PAYLOAD(%u):  ", cfg->type);
		for (j = 0; j < num; j++)
			printf("  %-5u", cfg->src_offset[j]);
	}
	printf("\n");
}

static char *
flowtype_to_str(uint16_t flow_type)
{
	struct flow_type_info {
		char str[32];
		uint16_t ftype;
	};

	uint8_t i;
	static struct flow_type_info flowtype_str_table[] = {
		{"raw", RTE_ETH_FLOW_RAW},
		{"ipv4", RTE_ETH_FLOW_IPV4},
		{"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
		{"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
		{"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
		{"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
		{"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
		{"ipv6", RTE_ETH_FLOW_IPV6},
		{"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
		{"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
		{"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
		{"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
		{"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
		{"l2_payload", RTE_ETH_FLOW_L2_PAYLOAD},
		{"port", RTE_ETH_FLOW_PORT},
		{"vxlan", RTE_ETH_FLOW_VXLAN},
		{"geneve", RTE_ETH_FLOW_GENEVE},
		{"nvgre", RTE_ETH_FLOW_NVGRE},
		{"vxlan-gpe", RTE_ETH_FLOW_VXLAN_GPE},
	};

	for (i = 0; i < RTE_DIM(flowtype_str_table); i++) {
		if (flowtype_str_table[i].ftype == flow_type)
			return flowtype_str_table[i].str;
	}

	return NULL;
}

#if defined(RTE_NET_I40E) || defined(RTE_NET_IXGBE)

static inline void
print_fdir_flex_mask(struct rte_eth_fdir_flex_conf *flex_conf, uint32_t num)
{
	struct rte_eth_fdir_flex_mask *mask;
	uint32_t i, j;
	char *p;

	for (i = 0; i < flex_conf->nb_flexmasks; i++) {
		mask = &flex_conf->flex_mask[i];
		p = flowtype_to_str(mask->flow_type);
		printf("\n    %s:\t", p ? p : "unknown");
		for (j = 0; j < num; j++)
			printf(" %02x", mask->mask[j]);
	}
	printf("\n");
}

static inline void
print_fdir_flow_type(uint32_t flow_types_mask)
{
	int i;
	char *p;

	for (i = RTE_ETH_FLOW_UNKNOWN; i < RTE_ETH_FLOW_MAX; i++) {
		if (!(flow_types_mask & (1 << i)))
			continue;
		p = flowtype_to_str(i);
		if (p)
			printf(" %s", p);
		else
			printf(" unknown");
	}
	printf("\n");
}

static int
get_fdir_info(portid_t port_id, struct rte_eth_fdir_info *fdir_info,
		    struct rte_eth_fdir_stats *fdir_stat)
{
	int ret = -ENOTSUP;

#ifdef RTE_NET_I40E
	if (ret == -ENOTSUP) {
		ret = rte_pmd_i40e_get_fdir_info(port_id, fdir_info);
		if (!ret)
			ret = rte_pmd_i40e_get_fdir_stats(port_id, fdir_stat);
	}
#endif
#ifdef RTE_NET_IXGBE
	if (ret == -ENOTSUP) {
		ret = rte_pmd_ixgbe_get_fdir_info(port_id, fdir_info);
		if (!ret)
			ret = rte_pmd_ixgbe_get_fdir_stats(port_id, fdir_stat);
	}
#endif
	switch (ret) {
	case 0:
		break;
	case -ENOTSUP:
		printf("\n FDIR is not supported on port %-2d\n",
			port_id);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
		break;
	}
	return ret;
}

void
fdir_get_infos(portid_t port_id)
{
	struct rte_eth_fdir_stats fdir_stat;
	struct rte_eth_fdir_info fdir_info;

	static const char *fdir_stats_border = "########################";

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	memset(&fdir_info, 0, sizeof(fdir_info));
	memset(&fdir_stat, 0, sizeof(fdir_stat));
	if (get_fdir_info(port_id, &fdir_info, &fdir_stat))
		return;

	printf("\n  %s FDIR infos for port %-2d     %s\n",
	       fdir_stats_border, port_id, fdir_stats_border);
	printf("  MODE: ");
	if (fdir_info.mode == RTE_FDIR_MODE_PERFECT)
		printf("  PERFECT\n");
	else if (fdir_info.mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN)
		printf("  PERFECT-MAC-VLAN\n");
	else if (fdir_info.mode == RTE_FDIR_MODE_PERFECT_TUNNEL)
		printf("  PERFECT-TUNNEL\n");
	else if (fdir_info.mode == RTE_FDIR_MODE_SIGNATURE)
		printf("  SIGNATURE\n");
	else
		printf("  DISABLE\n");
	if (fdir_info.mode != RTE_FDIR_MODE_PERFECT_MAC_VLAN
		&& fdir_info.mode != RTE_FDIR_MODE_PERFECT_TUNNEL) {
		printf("  SUPPORTED FLOW TYPE: ");
		print_fdir_flow_type(fdir_info.flow_types_mask[0]);
	}
	printf("  FLEX PAYLOAD INFO:\n");
	printf("  max_len:       %-10"PRIu32"  payload_limit: %-10"PRIu32"\n"
	       "  payload_unit:  %-10"PRIu32"  payload_seg:   %-10"PRIu32"\n"
	       "  bitmask_unit:  %-10"PRIu32"  bitmask_num:   %-10"PRIu32"\n",
		fdir_info.max_flexpayload, fdir_info.flex_payload_limit,
		fdir_info.flex_payload_unit,
		fdir_info.max_flex_payload_segment_num,
		fdir_info.flex_bitmask_unit, fdir_info.max_flex_bitmask_num);
	printf("  MASK: ");
	print_fdir_mask(&fdir_info.mask);
	if (fdir_info.flex_conf.nb_payloads > 0) {
		printf("  FLEX PAYLOAD SRC OFFSET:");
		print_fdir_flex_payload(&fdir_info.flex_conf, fdir_info.max_flexpayload);
	}
	if (fdir_info.flex_conf.nb_flexmasks > 0) {
		printf("  FLEX MASK CFG:");
		print_fdir_flex_mask(&fdir_info.flex_conf, fdir_info.max_flexpayload);
	}
	printf("  guarant_count: %-10"PRIu32"  best_count:    %"PRIu32"\n",
	       fdir_stat.guarant_cnt, fdir_stat.best_cnt);
	printf("  guarant_space: %-10"PRIu32"  best_space:    %"PRIu32"\n",
	       fdir_info.guarant_spc, fdir_info.best_spc);
	printf("  collision:     %-10"PRIu32"  free:          %"PRIu32"\n"
	       "  maxhash:       %-10"PRIu32"  maxlen:        %"PRIu32"\n"
	       "  add:	         %-10"PRIu64"  remove:        %"PRIu64"\n"
	       "  f_add:         %-10"PRIu64"  f_remove:      %"PRIu64"\n",
	       fdir_stat.collision, fdir_stat.free,
	       fdir_stat.maxhash, fdir_stat.maxlen,
	       fdir_stat.add, fdir_stat.remove,
	       fdir_stat.f_add, fdir_stat.f_remove);
	printf("  %s############################%s\n",
	       fdir_stats_border, fdir_stats_border);
}

#endif /* RTE_NET_I40E || RTE_NET_IXGBE */
