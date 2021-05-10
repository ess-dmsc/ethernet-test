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


int ecdc_eth_counters(struct rte_mbuf  * pkt, struct fwd_stream *fs) {
  struct rte_ether_hdr *eth_h;
  uint16_t eth_type;

  eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  eth_type = RTE_BE_TO_CPU_16(eth_h->ether_type);

  if (eth_type == RTE_ETHER_TYPE_ARP) {
      fs->rx_etharp++;
      return 0;
  } else if (eth_type == RTE_ETHER_TYPE_IPV4) {
      fs->rx_ethip++;
      return  1;
  } else {
      fs->rx_ethoth++;
      return 0;
  }
}

int ecdc_ip_counters(struct rte_mbuf  * pkt, struct fwd_stream *fs) {
  struct rte_ipv4_hdr *ip_h;
  ip_h = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  if (ip_h->next_proto_id == IPPROTO_UDP ) {
    fs->rx_ipudp++;
    return 1;
  } else {
    fs->rx_ipoth++;
    return 0;
  }
}


int ecdc_essdaq_counters(struct rte_mbuf  * pkt, struct fwd_stream *fs) {
  struct ess_hdr *ess_h;
  ess_h = rte_pktmbuf_mtod_offset(pkt, struct ess_hdr *,
    sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));

  if ((ess_h->CookieAndType & 0x00FFFFFF) != 0x535345) {
    fs->rx_udpoth++;
    return 0;
  } else {
    fs->rx_udpess++;
    return 1;
  }
}

void ecdc_rx_packet(struct rte_mbuf  * pkt, struct fwd_stream *fs) {
    fs->rx_packets++;
    fs->rx_bytes += pkt->pkt_len;

    if (ecdc_eth_counters(pkt, fs) == 0)
      return;

    if (ecdc_ip_counters(pkt, fs) == 0)
      return;

    ecdc_essdaq_counters(pkt, fs);

}
