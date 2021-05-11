


///
struct ess_hdr {
  uint8_t Padding;
  uint8_t Version;
  uint32_t CookieAndType;
  uint16_t TotalLength;
  uint8_t OutputQueue;
  uint8_t TimeSource;
  uint32_t PulseHigh;
  uint32_t PulseLow;
  uint32_t PrevPulseHigh;
  uint32_t PrevPulseLow;
  uint32_t SeqNum;
} __attribute__((packed));


///
int ecdc_eth_counters(struct rte_mbuf  * pkt, struct fwd_stream *fs);

///
int ecdc_ip_counters(struct rte_mbuf  * pkt, struct fwd_stream *fs);

///
int ecdc_essdaq_counters(struct rte_mbuf  * pkt, struct fwd_stream *fs);

///
void ecdc_rx_packet(struct rte_mbuf  * pkt, struct fwd_stream *fs);
