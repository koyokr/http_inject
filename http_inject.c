#include <pcap.h>
#include <libnet.h>

#include "http_inject.h"

#define PROMISCUOUS    1
#define NONPROMISCUOUS 0

#define IPPRO_TCP 6

#define MSG_LEN 7

static void checksum_ip(struct libnet_ipv4_hdr *ip) {
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
	sum += *p;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;

	ip->ip_sum = ~sum & 0xffff;
}

static void checksum_tcp(struct libnet_ipv4_hdr* ip, struct libnet_tcp_hdr * tcp, u_int len){
	struct pseudo_h ph;
	u_short *p;
	u_int count;
	u_int sum = 0;

	tcp->th_sum = 0;

	ph.ip_src = ip->ip_src.s_addr;
	ph.ip_dst = ip->ip_dst.s_addr;
	ph.zero   = 0;
	ph.ip_p   = IPPRO_TCP;
	ph.ip_len = htons(ntohs(ip->ip_len) - LIBNET_IPV4_H);

	/* tcp: 10+a */
	count = len >> 1;
	p = (u_short *)tcp;
	while (count--)
		sum += *p++;
	if (len % 2)
		sum += *p;

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

static void pcap_sendpacket_forward(pcap_t *pd, u_char *pkt, const u_char *_pkt, const char *msg) {
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr  *tcp;

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


static void pcap_sendpacket_backward(pcap_t *pd, u_char *pkt, const u_char *_pkt, const char *msg) {
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr  *tcp;

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

static int http_capture(const u_char *_pkt) {
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr     *ip;
	struct libnet_tcp_hdr      *tcp;

	eth = (struct libnet_ethernet_hdr *)_pkt;

	if (eth->ether_type != htons(ETHERTYPE_IP)) return 0;
	ip = (struct libnet_ipv4_hdr *)((char *)eth + LIBNET_ETH_H);

	if (ip->ip_len <= 40 || ip->ip_p != IPPRO_TCP) return 0;
	tcp = (struct libnet_tcp_hdr *)((char *)ip + ip->ip_hl * 4);

	const char *cp = (char *)tcp + tcp->th_off * 4;
	if (memcmp(cp, "GET", 3)) return 0;

	return 1;
}

int main() {
	pcap_t *pd;
	char *iface;
	char errbuf[PCAP_ERRBUF_SIZE];

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

	struct pcap_pkthdr *hdr;
	const u_char *_pkt;       /* receive packet */
	u_char pkt[1024] = { 0 }; /* send pakcet */
	char msg[MSG_LEN] = "blocked";
	enum fin { FORWARD_FIN, BACKWARD_FIN } fin = FORWARD_FIN;

	switch (fin) {
	case FORWARD_FIN:
		for(;;)
			if (pcap_next_ex(pd, &hdr, &_pkt) == 1)
				if (http_capture(_pkt) == 1)
					pcap_sendpacket_forward(pd, pkt, _pkt, msg);
		break;
	case BACKWARD_FIN:
		for(;;)
			if (pcap_next_ex(pd, &hdr, &_pkt) == 1)
				if (http_capture(_pkt) == 1)
					pcap_sendpacket_backward(pd, pkt, _pkt, msg);
		break;
	default:
		break;
	}

	pcap_close(pd);
	return EXIT_SUCCESS;
}
