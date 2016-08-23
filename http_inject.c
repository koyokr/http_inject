#ifdef _WIN32
#define HAVE_REMOTE
#include "pcap.h"
#include "win32/libnet.h"
#else
#include <pcap.h>
#include <libnet.h>
#endif

#include "http_inject.h"

#define PROMISCUOUS    1
#define NONPROMISCUOUS 0

#define IPPRO_TCP 6

#define LINK_REDIRECT "https://en.wikipedia.org/wiki/HTTP_302" /* REDIRECT LINK */
#define LINK_BLOCK    "gilgil.net"                             /* BLOCK LINK */
#define MSG_FORWARD   "blocked"
#define MSG_BACKWARD  "HTTP/1.1 302 Found\r\n" \
                      "Location: "LINK_REDIRECT"\r\n"

#define LINK_REDIRECT_LEN sizeof(LINK_REDIRECT) - 1
#define LINK_BLOCK_LEN    sizeof(LINK_BLOCK)    - 1
#define MSG_FORWARD_LEN   sizeof(MSG_FORWARD)   - 1
#define MSG_BACKWARD_LEN  sizeof(MSG_BACKWARD)  - 1

inline void swap8(uint8_t *a, uint8_t *b);
inline void swap16(uint16_t *a, uint16_t *b);
inline void swap32(uint32_t *a, uint32_t *b);
inline void swap48(void *a, void *b);
#ifdef _WIN32
inline void swap32l(ULONG *a, ULONG *b);
#else
#define swap32l(a, b) swap32(a, b)
#endif

void checksum_ip(struct libnet_ipv4_hdr *ip) {
	u_short *p = (u_short *)ip;
	u_int sum = 0;

	ip->ip_sum = 0;

	/* add ip data */
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

void checksum_tcp(const struct libnet_ipv4_hdr* ip, struct libnet_tcp_hdr * tcp, const u_int len){
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

	/* add tcp data */
	count = len >> 1;
	p = (u_short *)tcp;
	while (count--)
		sum += *p++;
	if (len % 2)
		sum += *p;

	/* add pseudo data */
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

void pcap_sendpacket_forward(u_char *pkt, const u_char *pkt_r, const u_char *msg, const u_short msg_len) {
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr  *tcp;

	/* copy */
	memcpy(pkt, pkt_r, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);
	ip = (struct libnet_ipv4_hdr *)(pkt + LIBNET_ETH_H);
	tcp = (struct libnet_tcp_hdr *)((char *)ip + LIBNET_IPV4_H);
	memcpy((char *)tcp + LIBNET_TCP_H, msg, msg_len);

	/* set */
	ip->ip_id    += 1;
	tcp->th_seq   = htonl(ntohl(tcp->th_seq) + ntohs(ip->ip_len) - LIBNET_IPV4_H - LIBNET_TCP_H); /* sequence number */
	ip->ip_len    = htons(LIBNET_IPV4_H + LIBNET_TCP_H + msg_len);
	tcp->th_flags = TH_FIN | TH_ACK;
	tcp->th_win   = 0;

	/* checksum */
	checksum_ip(ip);
	checksum_tcp(ip, tcp, LIBNET_TCP_H + msg_len);
}

void pcap_sendpacket_backward(u_char *pkt, const u_char *pkt_r, const u_char *msg, const u_short msg_len) {
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr     *ip;
	struct libnet_tcp_hdr      *tcp;

	/* copy */
	memcpy(pkt, pkt_r, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);
	eth = (struct libnet_ethernet_hdr *)pkt;
	ip = (struct libnet_ipv4_hdr *)(pkt + LIBNET_ETH_H);
	tcp = (struct libnet_tcp_hdr *)((char *)ip + LIBNET_IPV4_H);
	memcpy((char *)tcp + LIBNET_TCP_H, msg, msg_len);

	/* swap */
	swap48(eth->ether_dhost, eth->ether_shost);
	swap32l(&ip->ip_src.s_addr, &ip->ip_dst.s_addr);
	swap16(&tcp->th_sport, &tcp->th_dport);
	swap32(&tcp->th_seq, &tcp->th_ack);

	/* set */
	ip->ip_ttl    = 128; /* time to live */
	tcp->th_ack   = htonl(ntohl(tcp->th_ack) + ntohs(ip->ip_len) - LIBNET_IPV4_H - LIBNET_TCP_H); /* acknowlegment number */
	ip->ip_len    = htons(LIBNET_IPV4_H + LIBNET_TCP_H + msg_len);
	tcp->th_flags = TH_FIN | TH_ACK;
	tcp->th_win   = 0;

	/* checksum */
	checksum_ip(ip);
	checksum_tcp(ip, tcp, LIBNET_TCP_H + msg_len);
}

int http_capture(const u_char *pkt_r) {
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr     *ip;
	struct libnet_tcp_hdr      *tcp;

	/* ethernet header */
	eth = (struct libnet_ethernet_hdr *)pkt_r;

	/* ip header */
	if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;
	ip = (struct libnet_ipv4_hdr *)((char *)eth + LIBNET_ETH_H);

	/* tcp header */
	if (ntohs(ip->ip_len) <= 40 || ip->ip_p != IPPRO_TCP) return 0;
	tcp = (struct libnet_tcp_hdr *)((char *)ip + ip->ip_hl * 4);

	/* tcp data */
	const char *cp = (char *)tcp + tcp->th_off * 4;
	if (memcmp(cp, "GET", 3)) return 0;
	
	/* link filter
	while (*cp++ != '\r');
	while (*cp++ != ':');
	cp++;
	if (memcmp(cp, LINK_BLOCK, LINK_BLOCK_LEN)) return 0;
	*/

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
	const u_char *pkt_r;      /* receive packet */
	u_char pkt[1024] = { 0 }; /* send pakcet */
	u_char msg_forward[MSG_FORWARD_LEN+1] = MSG_FORWARD;          /* blocked message */
	u_char msg_backward[MSG_BACKWARD_LEN+1] = MSG_BACKWARD; /*  */

	for (;;)
		if (pcap_next_ex(pd, &hdr, &pkt_r) == 1)
			if (http_capture(pkt_r)) {
				/* backword fin */
				pcap_sendpacket_backward(pkt, pkt_r, msg_backward, MSG_BACKWARD_LEN);
				pcap_sendpacket(pd, pkt, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H + MSG_BACKWARD_LEN);

				/* forward fin */
				pcap_sendpacket_forward(pkt, pkt_r, msg_forward, MSG_FORWARD_LEN);
				pcap_sendpacket(pd, pkt, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H + MSG_FORWARD_LEN);

				/* printf("[*] Block \""LINK_BLOCK"\"\n"); */
				printf("[*] Redirect \""LINK_REDIRECT"\"\n");
			}

	//pcap_close(pd);
	return EXIT_SUCCESS;
}

inline void swap8(uint8_t *a, uint8_t *b) {
	uint8_t tmp = *a;
	*a = *b;
	*b = tmp;
}

inline void swap16(uint16_t *a, uint16_t *b) {
	uint16_t tmp = *a;
	*a = *b;
	*b = tmp;
}

inline void swap32(uint32_t *a, uint32_t *b) {
	uint32_t tmp = *a;
	*a = *b;
	*b = tmp;
}

inline void swap48(void *a, void *b) {
	uint8_t tmp[6];
	memcpy(tmp, a, 6);
	memcpy(a, b, 6);
	memcpy(b, tmp, 6);
}

#ifdef _WIN32
inline void swap32l(ULONG *a, ULONG *b) {
	ULONG tmp = *a;
	*a = *b;
	*b = tmp;
}
#endif
