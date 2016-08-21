#include <pcap.h>
#include <libnet.h>

#include "http_inject.h"

#define PROMISCUOUS    1
#define NONPROMISCUOUS 0

#define IPPRO_TCP 6

#define MSG_LEN 7

/* fin */
enum fin { FORWARD_FIN, BACKWARD_FIN };

void checksum_ip(struct libnet_ipv4_hdr *ip) {
	u_short *p = (u_short *)ip;
	u_int sum = 0;
	ip->ip_sum = 0;

	/* ip: 10 */
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;

	ip->ip_sum = ~sum & 0xffff;
}

void checksum_tcp(struct libnet_ipv4_hdr* ip, struct libnet_tcp_hdr * tcp, u_int len){
	struct pseudo_h ph;
	u_short *p;
	u_int sum = 0;
	u_int count;

	tcp->th_sum = 0;

	ph.ip_dst = ip->ip_dst.s_addr;
	ph.ip_src = ip->ip_src.s_addr;
	ph.zero   = 0;
	ph.ip_p   = ip->ip_p;
	ph.ip_len = ip->ip_len - htons(sizeof(struct libnet_ipv4_hdr));

	/* tcp: 10+a */
	count = len >> 1;
	p = (u_short *)tcp;
	for (int i = 0; i < count; i++)
		sum += *p++;
	if (len % 2)
		sum += (u_int)*p;

	/* pseudo: 6 */
	p = (u_short *)&ph;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p++;
	sum += *p;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;

	tcp->th_sum = ~sum & 0xffff;
}

static void pcap_sendpacket_tcp(pcap_t *pd, u_char *pkt, const u_char *_pkt /*, enum fin fin */) {
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr  *tcp;
	char msg[MSG_LEN] = "blocked";

	/* copy */
	memcpy(pkt, _pkt, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);
	ip = (struct libnet_ipv4_hdr *)(pkt + LIBNET_ETH_H);
	tcp = (struct libnet_tcp_hdr *)((char *)ip + LIBNET_IPV4_H);
	memcpy((char *)tcp + LIBNET_TCP_H, msg, MSG_LEN);

	/* set */
	tcp->th_seq   = htonl(ntohl(tcp->th_seq) + ntohs(ip->ip_len) - LIBNET_IPV4_H - LIBNET_TCP_H);
	ip->ip_len    = htons(LIBNET_IPV4_H + LIBNET_TCP_H + MSG_LEN);
	tcp->th_flags = TH_FIN | TH_ACK;
	tcp->th_win   = 0;
	tcp->th_urp   = 0;

	/* checksum */
	checksum_ip(ip);
	checksum_tcp(ip, tcp, LIBNET_TCP_H + strlen(msg));

	/* send */
	pcap_inject(pd, pkt, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H + MSG_LEN);
}

void packet_inject(pcap_t *pd, u_char *pkt, const u_char *_pkt) {
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr     *ip;
	struct libnet_tcp_hdr      *tcp;

	eth = (struct libnet_ethernet_hdr *)_pkt;

	if (eth->ether_type != htons(ETHERTYPE_IP)) return;
	ip = (struct libnet_ipv4_hdr *)((char *)eth + LIBNET_ETH_H);

	if (ip->ip_len <= 40 || ip->ip_p != IPPRO_TCP) return;
	tcp = (struct libnet_tcp_hdr *)((char *)ip + ip->ip_hl * 4);

	const char *cp = (char *)tcp + LIBNET_TCP_H;
	if (memcmp(cp, "GET", 3)) return;

	pcap_sendpacket_tcp(pd, pkt, _pkt /*, FORWARD_FIN */);
}

int main() {
	pcap_t *pd;
	char *iface;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr hdr;
	const u_char *_pkt;
	u_char pkt[1460] = { 0 };

	iface = pcap_lookupdev(errbuf);
	if (iface == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	pd = pcap_open_live(iface, 65536, NONPROMISCUOUS, 0, errbuf);
	if (pd == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	for(;;) {
		_pkt = pcap_next(pd, &hdr);
		if (_pkt != NULL)
			packet_inject(pd, pkt, _pkt);
	}
	pcap_close(pd);

	return EXIT_SUCCESS;
}
