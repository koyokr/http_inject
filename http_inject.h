#include <stdint.h>

struct pseudo_h {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t  zero;
	uint8_t  ip_p;
	uint16_t ip_len;
};
