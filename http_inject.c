#include <pcap.h>
#include <libnet.h>

#define PROMISCUOUS    0
#define NONPROMISCUOUS 1

#define IPPRO_TCP 6

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr     *ip;
	struct libnet_tcp_hdr      *tcp;
	static unsigned pkt_num = 0;

	pkt_num++;

	/* eth */
	eth = (struct libnet_ethernet_hdr *)pkt_data;

	/* ip */
	if (eth->ether_type != htons(ETHERTYPE_IP)) return;
	ip = (struct libnet_ipv4_hdr *)((uint8_t *)eth + LIBNET_ETH_H);
	if (ip->ip_len <= 40) return;

	/* tcp */
	if (ip->ip_p != IPPRO_TCP) return;
	tcp = (struct libnet_tcp_hdr *)((uint8_t *)ip + ip->ip_hl * 4);

	/* http */
	const uint8_t *cp, *get, *host;
	cp = (uint8_t *)tcp + tcp->th_off * 4;
	if (strncmp(cp, "GET", 3)) return;

	get = cp += 4;
	while (*cp != ' ') cp++;
	if (strncmp(cp+1, "HTTP", 4)) return;

	printf("%d.\n", pkt_num);
	printf("GET   %.*s\n", (int)(cp-get), get);

	while (*cp != '\r') cp++;
	host = cp += 8;
	while (*cp != '\r') cp++;

	printf("HOST: %.*s\n", (int)(cp-host), host);
}

int main() {
	pcap_t *pd;
	uint8_t *iface;
	uint8_t errbuf[PCAP_ERRBUF_SIZE];

	iface = pcap_lookupdev(errbuf);
	if (iface == NULL) { fprintf(stderr, "%s\n", errbuf); return EXIT_FAILURE; }

	pd = pcap_open_live(iface, 65536, NONPROMISCUOUS, 1, errbuf);
	if (pd == NULL) { fprintf(stderr, "%s\n", errbuf); return EXIT_FAILURE; }

	pcap_loop(pd, 0, packet_handler, NULL);
	pcap_close(pd);

	return EXIT_SUCCESS;
}
