#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
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
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_net.h>
#include <rte_flow.h>

#include "testpmd.h"
#include "ecdc.h"

void ecdc_rx_packet(struct rte_mbuf  * pkt, struct fwd_stream *fs) {
    struct rte_ether_hdr *eth_h;
    //struct rte_ipv4_hdr *ip_h;
    uint16_t eth_type;
    fs->rx_packets++;
    eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    eth_type = RTE_BE_TO_CPU_16(eth_h->ether_type);

    if (eth_type == RTE_ETHER_TYPE_ARP) {
        fs->rx_etharp++;
    } else if (eth_type == RTE_ETHER_TYPE_IPV4) {
        fs->rx_ethip++;
    } else {
        fs->rx_ethoth++;
    }
}
