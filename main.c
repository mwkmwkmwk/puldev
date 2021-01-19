#include "regs.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>

void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);

__asm__(
	".section start, \"ax\"\n"
	"b reset\n"
	"b und_handler\n"
	"b svc_handler\n"
	"b iabt_handler\n"
	"b dabt_handler\n"
	".word 0\n"
	"b handle_irq\n"
	"b fiq_handler\n"
	".text\n"
);

__asm__(
	"reset:\n"
	"cpsid aif, #0x11\n"
	"ldr sp, =stack_fiq_end\n"
	"cpsid aif, #0x12\n"
	"ldr sp, =stack_irq_end\n"
	"cpsid aif, #0x13\n"
	"ldr sp, =stack_svc_end\n"
	"cpsid aif, #0x17\n"
	"ldr sp, =stack_abt_end\n"
	"cpsid aif, #0x1b\n"
	"ldr sp, =stack_und_end\n"
	"cpsid aif, #0x1f\n"
	"ldr sp, =stack_end\n"
	"b main\n"
	".ltorg\n"
);

__asm__(
	"und_handler: b und_handler\n"
	"svc_handler: b svc_handler\n"
	"iabt_handler: b iabt_handler\n"
	"dabt_handler: b dabt_handler\n"
	"fiq_handler: b fiq_handler\n"
);

#if 0
__asm__(
	"irq_handler:\n"
	"push {r0, r1, r2, r3, r12, r14}\n"
	"bl handle_irq\n"
	"pop {r0, r1, r2, r3, r12, r14}\n"
	"subs pc, lr, #4\n"
);
#endif

__asm__(
	".globl memset\n"
	"memset:\n"
	"cmp r2, #0\n"
	"beq 1f\n"
	"mov r12, r0\n"
	"2:\n"
	"strb r1, [r0], #1\n"
	"subs r2, #1\n"
	"bne 2b\n"
	"mov r0, r12\n"
	"1:\n"
	"bx lr\n"
);

__asm__(
	".globl memcpy\n"
	"memcpy:\n"
	"cmp r2, #0\n"
	"beq 1f\n"
	"mov r12, r0\n"
	"2:\n"
	"ldrb r3, [r1], #1\n"
	"strb r3, [r0], #1\n"
	"subs r2, #1\n"
	"bne 2b\n"
	"mov r0, r12\n"
	"1:\n"
	"bx lr\n"
);

__asm__(
	".globl memcmp\n"
	"memcmp:\n"
	"mov r3, #0\n"
	"cmp r2, #0\n"
	"beq 1f\n"
	"2:\n"
	"ldrb r3, [r0], #1\n"
	"ldrb r12, [r1], #1\n"
	"subs r3, r12\n"
	"bne 1f\n"
	"subs r2, #1\n"
	"bne 2b\n"
	"1:\n"
	"mov r0, r3\n"
	"bx lr\n"
);

static inline void cpsid(void) {
	__asm__ volatile (
		"cpsid i\n"
	);
}

static inline void cpsie(void) {
	__asm__ volatile (
		"cpsie i\n"
	);
}

static inline void dmb(void) {
	__asm__ volatile (
		"dmb\n"
	);
}

static inline void dsb(void) {
	__asm__ volatile (
		"dsb\n"
	);
}

static inline void wfi(void) {
	__asm__ volatile (
		"wfi\n"
	);
}

extern volatile struct gem_desc {
	uint32_t addr;
	uint32_t attr;
} txring[0x80], rxring[0x80];

uint8_t otp_uniq[16];
uint8_t mac[6], srvmac[6];
uint8_t ip[4], srvip[4];
enum {
	NS_BOOTP,
	NS_ARP,
	NS_RST,
	NS_SYN,
	NS_READY,
} net_state = NS_BOOTP;

extern uint8_t rxdata[0x4000], txdata[0x2000], rxbuf[0x800], mixbuf[0x800];
static uint16_t *const mixbuf16 = (void *)mixbuf;
static uint32_t *const mixbuf32 = (void *)mixbuf;

int rxbpos = 0;
bool rxbact = 0;

int rxidx = 0, txidx = 0, txridx = 0, txused = 0;
static const int txdsize = 0x2000;
int txdput = 0, txdfree = 0x2000;
int retry_timer = 0;
int retry_reload = 0;

// tcp

extern uint8_t rxtcp[0x4000], txtcp[0x4000];
static const int rxtsize = 0x4000;
static const int txtsize = 0x4000;
uint32_t seq = 0, ack = 0;
uint32_t rxtget, rxtput, rxtfree = 0x4000, rxtused;
uint32_t rxwinsent = 0;
uint32_t txtget, txtput, txtfree = 0x4000, txtused, txtsent;
uint32_t txtwin = 0;
bool tcp_send_ack = false;
bool tcp_send_dat = false;
int tcp_sport = 666;

// uart1

bool uart_on = false;
extern uint8_t txuart[0x400];
static const int utxsize = 0x400;
uint32_t utxget, utxput, utxused, utxfree;
extern uint16_t rxuart[0x200];
static const int urxsize = 0x200;
uint32_t urxget, urxput, urxused, urxfree;

// wdt

int wdt = 30000;

void putc(char c) {
	*SWDT_RESTART = 0x1999;
	while (*UART0_SR & 0x10);
	*UART0_FIFO = c;
}

void printf(const char *fmt, ...) {
	char c;
	va_list va;
	va_start(va, fmt);
	while (c = *fmt++) {
		if (c == '\n') {
			putc('\r');
			putc('\n');
		} else if (c == '%') {
			c = *fmt++;
			int width = 0;
			while (c >= '0' && c <= '9') {
				width *= 10;
				width += c - '0';
				c++;
			}
			if (c == 'x') {
				uint32_t num = va_arg(va, uint32_t);
				for (int i = 0; i < 8; i++) {
					putc("0123456789abcdef"[num >> (7 - i) * 4 & 0xf]);
				}
			} else if (c == 'u' || c == 'd') {
				char buf[11];
				int pos = 0;
				uint32_t num = va_arg(va, uint32_t);
				do {
					buf[pos++] = '0' + num % 10;
					num /= 10;
				} while (num);
				while (pos)
					putc(buf[--pos]);
			} else {
				putc(c);
			}
		} else {
			putc(c);
		}
	}
	va_end(va);
}

void wr_be16(uint8_t *ptr, uint16_t num) {
	ptr[0] = num >> 8;
	ptr[1] = num;
}

void wr_be32(uint8_t *ptr, uint32_t num) {
	ptr[0] = num >> 24;
	ptr[1] = num >> 16;
	ptr[2] = num >> 8;
	ptr[3] = num;
}

uint16_t rd_be16(volatile uint8_t *ptr) {
	return ptr[0] << 8 | ptr[1];
}

uint32_t rd_be32(volatile uint8_t *ptr) {
	return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
}

uint32_t phyrd(uint32_t addr) {
	while (!(*GEM0_NWSR & 4));
	*GEM0_PHY = 0x60820000 | addr << 18;
	while (!(*GEM0_NWSR & 4));
	return *GEM0_PHY & 0xffff;
}

bool tx_packet_ex(uint8_t *pkt, size_t len, uint32_t txtoff, uint32_t txtlen) {
	while (txused) {
		dmb();
		uint32_t addr = txring[txridx].addr;
		uint32_t attr = txring[txridx].attr;
		dmb();
		if (!(attr & 0x80000000)) {
			//printf("TX RECLAIM FAIL %x %x %x\n", txridx, addr, attr);
			break;
		}
		while (1) {
			//printf("TX RECLAIM %x %x %x\n", txridx, addr, attr);
			txused--;
			txridx++;
			txridx &= 0x7f;
			if (addr >= (uint32_t)txdata && addr < (uint32_t)(txdata + txdsize)) {
				uint32_t olen = attr & 0x3fff;
				txdfree += olen;
				//printf("TX FREE +%x: %x\n", olen, txdfree);
			}
			if (attr & 0x8000)
				break;
			addr = txring[txridx].addr;
			attr = txring[txridx].attr;
			txring[txridx].attr = attr & 0x40000000 | 0x80000000;
		}
	}
	if (txdfree < len) {
		printf("TX no data space %x %x\n", txdfree, len);
		return false;
	}
	int descs = 0;
	if (txdput + len > txdsize) {
		descs = 2;
	} else {
		descs = 1;
	}
	if (txtlen) {
		if (txtoff + txtlen > txtsize)
			descs += 2;
		else
			descs += 1;
	}
	if (txused + descs > 0x80) {
		printf("TX no desc space %x %x\n", txused, descs);
		return false;
	}
	if (txdput + len > txdsize) {
		uint32_t ptr_a = (uint32_t)txdata + txdput;
		uint32_t ptr_b = (uint32_t)txdata;
		uint32_t size_a = txdsize - txdput;
		uint32_t size_b = txdput + len - txdsize;
		dmb();
		txring[txidx].addr = ptr_a;
		memcpy((void *)ptr_a, pkt, size_a);
		txring[(txidx + 1) & 0x7f].addr = ptr_b;
		memcpy((void *)ptr_b, pkt + size_a, size_b);
		dmb();
		uint32_t attr = size_a;
		if (txidx == 0x7f)
			attr |= 0x40000000;
		txring[txidx].attr = attr;
		txidx++;
		txidx &= 0x7f;
		attr = size_b;
		if (!txtlen)
			attr |= 0x8000;
		if (txidx == 0x7f)
			attr |= 0x40000000;
		txring[txidx].attr = attr;
		txidx++;
		txidx &= 0x7f;
		dmb();
		txdput = size_b;
		txdfree -= len;
		txused += 2;
	} else {
		uint32_t ptr_a = (uint32_t)txdata + txdput;
		dmb();
		txring[txidx].addr = ptr_a;
		memcpy((void *)ptr_a, pkt, len);
		dmb();
		uint32_t attr = len;
		if (!txtlen)
			attr |= 0x8000;
		if (txidx == 0x7f)
			attr |= 0x40000000;
		txring[txidx].attr = attr;
		txidx++;
		txidx &= 0x7f;
		dmb();
		txdput += len;
		if (txdput == txdsize)
			txdput = 0;
		txdfree -= len;
		txused += 1;
	}
	if (txtlen) {
		if (txtoff + txtlen > txtsize) {
			uint32_t ptr_a = (uint32_t)txtcp + txtoff;
			uint32_t ptr_b = (uint32_t)txtcp;
			uint32_t size_a = txtsize - txtoff;
			uint32_t size_b = txtlen - size_a;
			dmb();
			txring[txidx].addr = ptr_a;
			txring[(txidx + 1) & 0x7f].addr = ptr_b;
			dmb();
			uint32_t attr = size_a;
			if (txidx == 0x7f)
				attr |= 0x40000000;
			txring[txidx].attr = attr;
			txidx++;
			txidx &= 0x7f;
			attr = size_b;
			attr |= 0x8000;
			if (txidx == 0x7f)
				attr |= 0x40000000;
			txring[txidx].attr = attr;
			txidx++;
			txidx &= 0x7f;
			dmb();
			txused += 2;
		} else {
			uint32_t ptr_a = (uint32_t)txtcp + txtoff;
			dmb();
			txring[txidx].addr = ptr_a;
			dmb();
			uint32_t attr = txtlen;
			attr |= 0x8000;
			if (txidx == 0x7f)
				attr |= 0x40000000;
			txring[txidx].attr = attr;
			txidx++;
			txidx &= 0x7f;
			dmb();
			txused += 1;
		}
	}
	//printf("TX sending %x\n", txidx);
	// kick it!
	*GEM0_NWCTRL = 0x21c;
}

bool tx_packet(uint8_t *pkt, size_t len) {
	tx_packet_ex(pkt, len, 0, 0);
}

bool send_bootp(void) {
	char buf[14 + 20 + 8 + 300];
	uint8_t *ptr = buf;
	// eth header
	// to broadcast
	for (int i = 0; i < 6; i++)
		ptr[i] = 0xff;
	// from us
	memcpy(ptr+6, mac, 6);
	// ip
	wr_be16(ptr+12, 0x0800);
	ptr += 14;

	// IP header
	ptr[0] = 0x45;
	ptr[1] = 0; // DSCP
	wr_be16(ptr+2, 20 + 8 + 300);
	wr_be16(ptr+4, 0); // ID
	ptr[6] = 0; // fragmentation offset etc
	ptr[7] = 0;
	ptr[8] = 0x80; // TTL
	ptr[9] = 0x11; // protocol [UDP]
	wr_be16(ptr+10, 0); // checksum [hw-filled]
	// src ip
	for (int i = 0; i < 4; i++)
		ptr[12+i] = 0;
	// dst ip
	for (int i = 0; i < 4; i++)
		ptr[16+i] = 0xff;
	ptr += 20;

	// UDP header
	wr_be16(ptr+0, 68); // src port
	wr_be16(ptr+2, 67); // dst port
	wr_be16(ptr+4, 8 + 300); // length
	wr_be16(ptr+6, 0); // checksum [hw-filled]
	ptr += 8;

	// BOOTP packet
	ptr[0] = 0x01; // BOOTREQUEST
	ptr[1] = 0x01; // ethernet
	ptr[2] = 0x06; // mac length
	ptr[3] = 0x00; // hops
	memcpy(ptr+4, otp_uniq, 4); // xid
	wr_be16(ptr+8, 0); // seconds since boot [?]
	wr_be16(ptr+10, 0); // unused
	memset(ptr+12, 0, 16); // addresses [we don't know any]
	ptr += 28;
	memset(ptr, 0, 16);
	memcpy(ptr, mac, 6);
	ptr += 16;
	memset(ptr, 0, 256);
	return tx_packet(buf, sizeof buf);
}

bool send_srvarp(void) {
	char buf[14 + 28];
	uint8_t *ptr = buf;
	// eth header
	// to broadcast
	for (int i = 0; i < 6; i++)
		ptr[i] = 0xff;
	// from us
	memcpy(ptr+6, mac, 6);
	// arp
	wr_be16(ptr+12, 0x0806);
	ptr += 14;

	// ARP header
	wr_be16(ptr+0, 1);
	wr_be16(ptr+2, 0x800);
	ptr[4] = 6;
	ptr[5] = 4;
	wr_be16(ptr+6, 1);
	memcpy(ptr+8, mac, 6);
	memcpy(ptr+14, ip, 4);
	memset(ptr+18, 0, 6);
	memcpy(ptr+24, srvip, 4);
	return tx_packet(buf, sizeof buf);
}

void fill_ethip_tcp(uint8_t *ptr, uint16_t len) {
	// eth header
	// to srv
	memcpy(ptr+0, srvmac, 6);
	// from us
	memcpy(ptr+6, mac, 6);
	// ip
	wr_be16(ptr+12, 0x0800);
	ptr += 14;

	// IP header
	ptr[0] = 0x45;
	ptr[1] = 0; // DSCP
	wr_be16(ptr+2, 20 + len);
	wr_be16(ptr+4, 0); // ID
	ptr[6] = 0; // fragmentation offset etc
	ptr[7] = 0;
	ptr[8] = 0x80; // TTL
	ptr[9] = 6; // protocol [TCP]
	wr_be16(ptr+10, 0); // checksum [hw-filled]
	// src ip
	memcpy(ptr+12, ip, 4);
	// dst ip
	memcpy(ptr+16, srvip, 4);
	ptr += 20;
}

bool send_rst(void) {
	char buf[14 + 20 + 20];
	fill_ethip_tcp(buf, 20);
	uint8_t *ptr = buf + 20 + 14;

	// TCP header
	wr_be16(ptr+0, tcp_sport);
	wr_be16(ptr+2, 666);
	wr_be32(ptr+4, 0);
	wr_be32(ptr+8, 0);
	wr_be16(ptr+12, 0x5004);
	wr_be16(ptr+14, 0);
	wr_be16(ptr+16, 0);
	wr_be16(ptr+18, 0);

	return tx_packet(buf, sizeof buf);
}

bool send_syn(void) {
	char buf[14 + 20 + 20];
	fill_ethip_tcp(buf, 20);
	uint8_t *ptr = buf + 20 + 14;

	// TCP header
	wr_be16(ptr+0, tcp_sport);
	wr_be16(ptr+2, 666);
	wr_be32(ptr+4, -1); // seq
	wr_be32(ptr+8, 0); // ack
	wr_be16(ptr+12, 0x5002); // flags
	wr_be16(ptr+14, rxtsize); // window
	wr_be16(ptr+16, 0); // checksum
	wr_be16(ptr+18, 0); // urgent
	rxwinsent = rxtsize;

	return tx_packet(buf, sizeof buf);
}

bool send_tcp_ack(void) {
	char buf[14 + 20 + 20];
	fill_ethip_tcp(buf, 20);
	uint8_t *ptr = buf + 20 + 14;

	// TCP header
	wr_be16(ptr+0, tcp_sport);
	wr_be16(ptr+2, 666);
	wr_be32(ptr+4, seq); // seq
	wr_be32(ptr+8, ack); // ack
	wr_be16(ptr+12, 0x5010); // flags
	wr_be16(ptr+14, rxtfree); // window
	wr_be16(ptr+16, 0); // checksum
	wr_be16(ptr+18, 0); // urgent
	rxwinsent = rxtfree;

	return tx_packet(buf, sizeof buf);
}

int send_tcp_dat(uint32_t offset) {
	if (offset >= txtused)
		return 0;
	uint16_t dlen = txtused - offset;
	if (dlen > 1460)
		dlen = 1460;
	if (offset >= txtwin)
		return 0;
	if (dlen > txtwin - offset)
		dlen = txtwin - offset;
	char buf[14 + 20 + 20];
	fill_ethip_tcp(buf, 20 + dlen);
	uint8_t *ptr = buf + 20 + 14;

	// TCP header
	wr_be16(ptr+0, tcp_sport);
	wr_be16(ptr+2, 666);
	wr_be32(ptr+4, seq + offset); // seq
	wr_be32(ptr+8, ack); // ack
	wr_be16(ptr+12, 0x5010); // flags
	wr_be16(ptr+14, rxtfree); // window
	wr_be16(ptr+16, 0); // checksum
	wr_be16(ptr+18, 0); // urgent

	if (tx_packet_ex(buf, sizeof buf, (txtget + offset) % txtsize, dlen))
		return dlen;
	return 0;
}

void rx_ip_boot(uint32_t len) {
	if (len < 14 + 300 + 20 + 8)
		return;
	uint8_t *ptr = rxbuf + 14;
	if (ptr[0] != 0x45)
		return;
	uint16_t iplen = rd_be16(ptr + 2);
	if (iplen < 300 + 20 + 8)
		return;
	if (iplen + 14 > len)
		return;
	uint16_t flags = rd_be16(ptr + 6);
	if (flags & 0x3fff)
		return;
	if (ptr[9] != 0x11)
		return;

	uint8_t *udp = ptr + 20;
	uint16_t sport = rd_be16(udp+0);
	uint16_t dport = rd_be16(udp+2);
	uint16_t udplen = rd_be16(udp+4);
	if (udplen + 20 != iplen)
		return;
	if (sport != 67)
		return;
	if (dport != 68)
		return;

	uint8_t *bootp = udp + 8;
	if (bootp[0] != 2)
		return;
	if (bootp[1] != 1)
		return;
	if (bootp[2] != 6)
		return;
	if (memcmp(bootp+4, otp_uniq, 4))
		return;
	if (memcmp(bootp+28, mac, 6))
		return;
	memcpy(ip, bootp+16, 4);
	memcpy(srvip, bootp+20, 4);
	net_state = NS_ARP;
	printf("Got BOOTP! IP is %u.%u.%u.%u, srv is %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3], srvip[0], srvip[1], srvip[2], srvip[3]);
	retry_reload = 1;
	retry_timer = 2;
	send_srvarp();
}

void rx_ip(uint32_t len) {
	if (len < 14 + 20)
		return;
	uint8_t *ptr = rxbuf + 14;
	if (ptr[0] != 0x45)
		return;
	uint16_t iplen = rd_be16(ptr + 2);
	if (iplen < 20)
		return;
	if (iplen + 14 > len)
		return;
	uint16_t flags = rd_be16(ptr + 6);
	if (flags & 0x3fff)
		return;
	if (memcmp(ptr+16, ip, 4))
		return;
	uint8_t *next = ptr + 20;

	switch (ptr[9]) {
		case 1: {
			if (iplen < 24)
				return;
			if (next[0] == 8) {
				printf("ICMP request (us!)\n");
				memcpy(rxbuf, rxbuf+6, 6);
				memcpy(rxbuf+6, mac, 6);
				ptr[8] = 0x80;
				memcpy(ptr+16, ptr+12, 4);
				memcpy(ptr+12, ip, 4);
				next[0] = 0;
				next[2] = 0;
				next[3] = 0;
				if (iplen & 1) {
					next[iplen-20] = 0;
				}
				uint32_t chksum = 0;
				for (int i = 0; i < iplen - 20; i += 2) {
					chksum += rd_be16(next + i);
				}
				chksum %= 0xffff;
				chksum ^= 0xffff;
				wr_be16(next+2, chksum);
				tx_packet(rxbuf, len);
			} else {
				printf("RX ICMP %d\n", next[0]);
			}
		}
		break;
		case 6: {
			if (net_state < NS_SYN)
				return;
			if (iplen < 20 + 20)
				return;
			if (memcmp(ptr + 12, srvip, 4))
				return;
			if (rd_be16(next+0) != 666)
				return;
			if (rd_be16(next+2) != tcp_sport)
				return;
			uint32_t cur_seq = rd_be32(next+4);
			uint32_t cur_ack = rd_be32(next+8);
			uint16_t flags = rd_be16(next+12);
			uint16_t cur_win = rd_be16(next+14);
			int doff = flags >> 12;
			if (doff < 5 || iplen < 20 + doff * 4)
				return;
			int dlen = iplen - 20 - doff * 4;
			if (net_state == NS_SYN) {
				if (flags & 0x04) {
					printf("RST while SYN :(\n");
					return;
				}
				if (!(flags & 2))
					return;
				if (!(flags & 0x10))
					return;
				if (cur_ack != 0)
					return;
				printf("SYN-ACK!\n");
				ack = cur_seq + 1;
				txtwin = cur_win;
				net_state = NS_READY;
				tcp_send_ack = true;
				retry_reload = 0;
			} else {
				if (flags & 0x04) {
					printf("Whoops RST!\n");
					*PSS_RST_CTRL = 1;
					while(1) wfi();
				}
				if (!(flags & 0x10))
					return;
				if (cur_ack != seq) {
					uint32_t bump = cur_ack - seq;
					if (bump > txtused) {
						tcp_send_ack = true;
					} else {
						seq = cur_ack;
						if (bump > txtsent)
							txtsent = 0;
						else
							txtsent -= bump;
						txtused -= bump;
						txtfree += bump;
						txtget += bump;
						txtget %= txtsize;
						if (txtused && !txtsent && txtwin) {
							tcp_send_dat = true;
						}
						if (!txtused) {
							retry_reload = 0;
						} else if (!txtwin) {
							retry_reload = 256;
							retry_timer = 256;
						} else {
							retry_reload = 1;
							retry_timer = 2;
						}
					}
				}
				txtwin = cur_win;
				if (cur_seq == ack && dlen && rxtfree) {
					// printf("RX TCP DATA %x %x\n", rxtput, dlen);
					if (dlen > rxtfree)
						dlen = rxtfree;
					if (rxtput + dlen > rxtsize) {
						uint32_t size_a = rxtsize - rxtput;
						uint32_t size_b = dlen - size_a;
						memcpy(rxtcp + rxtput, next + doff * 4, size_a);
						memcpy(rxtcp, next + doff * 4 + size_a, size_b);
						rxtput = size_b;
					} else {
						memcpy(rxtcp + rxtput, next + doff * 4, dlen);
						rxtput += dlen;
						if (rxtput == rxtsize)
							rxtput = 0;
					}
					rxtfree -= dlen;
					rxtused += dlen;
					ack += dlen;
				}
				if (dlen)
					tcp_send_ack = true;
			}
		}
		break;
		default:
			printf("Unk proto %d\n", ptr[9]);
			break;
	}
}

void rx_arp(uint32_t len) {
	if (len < 14 + 28)
		return;
	uint8_t *ptr = rxbuf + 14;
	uint16_t htype = rd_be16(ptr+0);
	if (htype != 1)
		return;
	uint16_t ptype = rd_be16(ptr+2);
	if (ptype != 0x0800)
		return;
	if (ptr[4] != 6)
		return;
	if (ptr[5] != 4)
		return;
	uint16_t oper = rd_be16(ptr+6);
	if (oper == 1) {
		if (memcmp(ptr+24, ip, 4))
			return;
		printf("ARP request (us!)\n");
		// request
		char sbuf[14 + 28];
		uint8_t *sptr = sbuf;
		// eth header
		// to sender
		memcpy(sptr+0, ptr+8, 6);
		// from us
		memcpy(sptr+6, mac, 6);
		// arp
		wr_be16(sptr+12, 0x0806);
		sptr += 14;

		// ARP header
		wr_be16(sptr+0, 1);
		wr_be16(sptr+2, 0x800);
		sptr[4] = 6;
		sptr[5] = 4;
		wr_be16(sptr+6, 2);
		memcpy(sptr+8, mac, 6);
		memcpy(sptr+14, ip, 4);
		memcpy(sptr+18, ptr+8, 6);
		memcpy(sptr+24, ptr+14, 4);
		tx_packet(sbuf, sizeof sbuf);
	} else if (oper == 2) {
		if (memcmp(ptr+14, srvip, 4))
			return;
		printf("ARP reply (server!)\n");
		if (net_state == NS_ARP) {
			tcp_sport = 0x4000 + ((*PRIVT_CTR ^ *REBOOT_STATUS ^ *REBOOT_STATUS >> 24) & 0x7fff);
			memcpy(srvmac, ptr+8, 6);
			printf("MAC is %x:%x:%x:%x:%x:%x\n", srvmac[0], srvmac[1], srvmac[2], srvmac[3], srvmac[4], srvmac[5]);
			printf("TCP port is %d\n", tcp_sport);
			net_state = NS_RST;
			retry_reload = 1;
			retry_timer = 100;
			send_rst();
		}
	}
}

void rx_process(uint32_t len) {
	uint16_t type = rd_be16(rxbuf + 12);
	switch (type) {
		case 0x0800:
			if (net_state == NS_BOOTP)
				rx_ip_boot(len);
			else
				rx_ip(len);
			break;
		case 0x0806:
			if (net_state > NS_BOOTP) {
				rx_arp(len);
			}
			break;
		default:
			printf("Unk type %x\n", type);
			break;
	}
}

void do_uart_tx() {
	while (!(*UART1_SR & 0x10) && utxused) {
		*UART1_FIFO = txuart[utxget];
		utxused--;
		utxfree++;
		utxget++;
		if (utxget == utxsize)
			utxget = 0;
		*UART1_ISR = 0x408;
	}
	if (utxused)
		*UART1_IER = 0x408;
	else
		*UART1_IDR = 0x408;
}

void urxwr(uint16_t val) {
	if (urxfree) {
		rxuart[urxput++] = val;
		if (urxput == urxsize)
			urxput = 0;
		urxfree--;
		urxused++;
	} else {
		int prev = urxput - 1;
		if (urxput == 0)
			prev = urxsize - 1;
		rxuart[prev] = 0x100; // OVR
	}
}

void handle_uart(void) {
	uint32_t isr = *UART1_ISR;
	if (isr & 0x408)
		do_uart_tx();
	if (isr & 0x20) {
		*UART1_ISR = 0x20;
		urxwr(0x100); // OVR
	}
	if (isr & 0x40) {
		*UART1_ISR = 0x40;
		urxwr(0x200); // FRAMING
	}
	if (isr & 0x80) {
		*UART1_ISR = 0x80;
		urxwr(0x400); // PARITY
	}
	if (isr & 1) {
		*UART1_ISR = 1;
		int ctr = 64;
		while (!(*UART1_SR & 2) && ctr--) {
			urxwr(*UART1_FIFO);
		}
	}
}

void handle_gem(void) {
	if (*GEM0_ISR & 2) {
		*GEM0_ISR = 2;
		while (1) {
			dmb();
			uint32_t addr = rxring[rxidx].addr;
			if (!(addr & 1))
				break;
			dmb();
			uint32_t attr = rxring[rxidx].attr;
			uint32_t *ptr = (void *)(addr & ~3);
			if (attr & 0x4000) {
				rxbact = true;
				rxbpos = 0;
			}
			if (!rxbact) {
				printf("Ummm no act...\n");
			} else if (rxbpos == sizeof rxbuf) {
				printf("Ummm buf full...\n");
			} else {
				memcpy(rxbuf + rxbpos, ptr, 0x80);
				rxbpos += 0x80;
			}
			dmb();
			rxring[rxidx].addr = addr & ~1;
			rxidx++;
			rxidx &= 0x7f;
			if (attr & 0x8000) {
				// full packet!
				//printf("full pakige! %x %x\n", rxbpos, attr);
				rx_process(attr & 0x1fff);
				rxbact = false;
			}
		}
		if (tcp_send_dat) {
			int offs = txtsent;
			int cur = 0;
			while (cur = send_tcp_dat(offs))
				offs += cur;
			if (txtsent == offs)
				send_tcp_ack();
			txtsent = offs;
		} else if (tcp_send_ack) {
			send_tcp_ack();
		}
		tcp_send_dat = tcp_send_ack = false;
	}
}

void handle_privt(void) {
	*SWDT_RESTART = 0x1999;
	wdt--;
	if (!wdt) {
		// oh no.
		*PSS_RST_CTRL = 1;
	}
	if (retry_reload) {
		retry_timer--;
		if (!retry_timer) {
			printf("Retry %d\n", retry_reload);
			retry_timer = retry_reload;
			if (retry_reload < 128)
				retry_reload *= 2;
			switch (net_state) {
				case NS_BOOTP:
					send_bootp();
					break;
				case NS_ARP:
					send_srvarp();
					break;
				case NS_RST:
					net_state = NS_SYN;
					retry_reload = 1;
					retry_timer = 2;
					send_syn();
					break;
				case NS_SYN:
					send_syn();
					break;
				case NS_READY:
					txtsent = 0;
					int offs = 0;
					int cur = 0;
					while (cur = send_tcp_dat(offs))
						offs += cur;
					txtsent = offs;
					break;
				default:
					// XXX
					retry_reload = 0;
					break;
			}
		}
	}
}

__attribute__((interrupt)) void handle_irq(void) {
	uint32_t iar = *GIC_ICCIAR;
	int irqid = iar & 0x3ff;
	switch (irqid) {
		case 29:
			handle_privt();
			break;
		case 54:
			handle_gem();
			break;
		case 82:
			handle_uart();
			break;
		case 0x3ff:
			printf("Spurious IRQ\n");
			return;
		default:
			printf("Unknown IRQ %x\n", irqid);
			while(1) wfi();
	}
	*GIC_ICCEOIR = iar;
}

int recv(void *buf, size_t len) {
	uint8_t *dptr = buf;
	cpsid();
	dsb();
	while (len) {
		while (!rxtused) {
			wfi();
			cpsie();
			dsb();
			cpsid();
			dsb();
		}
		uint32_t cur = rxtused;
		if (cur > len)
			cur = len;
		if (cur > (rxtsize - rxtget))
			cur = rxtsize - rxtget;
		memcpy(dptr, rxtcp + rxtget, cur);
		len -= cur;
		dptr += cur;
		rxtget += cur;
		if (rxtget == rxtsize)
			rxtget = 0;
		rxtfree += cur;
		rxtused -= cur;
		if (rxtfree - rxwinsent > 0x1000)
			send_tcp_ack();
	}
	cpsie();
	dsb();
	return 0;
}

void do_tx() {
	int offs = txtsent;
	int cur = 0;
	while (cur = send_tcp_dat(offs))
		offs += cur;
	txtsent = offs;
}

int send(void *buf, size_t len) {
	uint8_t *sptr = buf;
	cpsid();
	dsb();
	while (len) {
		while (!txtfree) {
			do_tx();
			wfi();
			cpsie();
			dsb();
			cpsid();
			dsb();
		}
		uint32_t cur = txtfree;
		if (cur > len)
			cur = len;
		if (cur > (txtsize - txtput))
			cur = txtsize - txtput;
		memcpy(txtcp + txtput, sptr, cur);
		len -= cur;
		sptr += cur;
		txtput += cur;
		if (txtput == txtsize)
			txtput = 0;
		txtused += cur;
		txtfree -= cur;
	}
	do_tx();
	cpsie();
	dsb();
	return 0;
}

void uart_tx(uint8_t *buf, size_t len) {
	if (!uart_on)
		return;
	uint8_t *sptr = buf;
	cpsid();
	dsb();
	while (len) {
		while (!utxfree) {
			wfi();
			cpsie();
			dsb();
			cpsid();
			dsb();
		}
		uint32_t cur = utxfree;
		if (cur > len)
			cur = len;
		if (cur > (utxsize - utxput))
			cur = utxsize - utxput;
		memcpy(txuart + utxput, sptr, cur);
		len -= cur;
		sptr += cur;
		utxput += cur;
		if (utxput == utxsize)
			utxput = 0;
		utxused += cur;
		utxfree -= cur;
		do_uart_tx();
	}
	cpsie();
	dsb();
}

int cmd_rd8() {
	uint32_t addr;
	uint16_t len;
	uint8_t reply = 0x80;
	if (recv(&addr, sizeof addr)) return -1;
	if (recv(&len, sizeof len)) return -1;
	if (send(&reply, 1)) return -1;
	if (send(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x800)
			cur = 0x800;
		for (int i = 0; i < cur; i++)
			mixbuf[i] = *(volatile uint8_t *)(addr++);
		if (send(mixbuf, cur)) return -1;
		len -= cur;
	}
	return 0;
}

int cmd_rd16() {
	uint32_t addr;
	uint16_t len;
	uint8_t reply = 0x81;
	if (recv(&addr, sizeof addr)) return -1;
	if (recv(&len, sizeof len)) return -1;
	if (send(&reply, 1)) return -1;
	if (send(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x400)
			cur = 0x400;
		for (int i = 0; i < cur; i++) {
			mixbuf16[i] = *(volatile uint16_t *)addr;
			addr += 2;
		}
		if (send(mixbuf, cur * 2)) return -1;
		len -= cur;
	}
	return 0;
}

int cmd_rd32() {
	uint32_t addr;
	uint16_t len;
	uint8_t reply = 0x82;
	if (recv(&addr, sizeof addr)) return -1;
	if (recv(&len, sizeof len)) return -1;
	if (send(&reply, 1)) return -1;
	if (send(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x200)
			cur = 0x200;
		for (int i = 0; i < cur; i++) {
			mixbuf32[i] = *(volatile uint32_t *)addr;
			addr += 4;
		}
		if (send(mixbuf, cur * 4)) return -1;
		len -= cur;
	}
	return 0;
}

int cmd_wr8() {
	uint32_t addr;
	uint16_t len;
	if (recv(&addr, sizeof addr)) return -1;
	if (recv(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x800)
			cur = 0x800;
		if (recv(mixbuf, cur)) return -1;
		for (int i = 0; i < cur; i++)
			*(volatile uint8_t *)(addr++) = mixbuf[i];
		len -= cur;
	}
	uint8_t reply = 0x90;
	if (send(&reply, 1)) return -1;
	return 0;
}

int cmd_wr16() {
	uint32_t addr;
	uint16_t len;
	if (recv(&addr, sizeof addr)) return -1;
	if (recv(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x400)
			cur = 0x400;
		if (recv(mixbuf, cur * 2)) return -1;
		for (int i = 0; i < cur; i++) {
			*(volatile uint16_t *)addr = mixbuf16[i];
			addr += 2;
		}
		len -= cur;
	}
	uint8_t reply = 0x91;
	if (send(&reply, 1)) return -1;
	return 0;
}

int cmd_wr32() {
	uint32_t addr;
	uint16_t len;
	if (recv(&addr, sizeof addr)) return -1;
	if (recv(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x200)
			cur = 0x200;
		if (recv(mixbuf, cur * 4)) return -1;
		for (int i = 0; i < cur; i++) {
			*(volatile uint32_t *)addr = mixbuf32[i];
			addr += 4;
		}
		len -= cur;
	}
	uint8_t reply = 0x92;
	if (send(&reply, 1)) return -1;
	return 0;
}

int cmd_rddevc() {
	uint16_t len;
	uint8_t reply = 0x83;
	if (recv(&len, sizeof len)) return -1;
	if (send(&reply, 1)) return -1;
	if (send(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x200)
			cur = 0x200;
		*DEVC_DMA_SRC_ADDR = 0xffffffff;
		*DEVC_DMA_DST_ADDR = (uint32_t)mixbuf;
		*DEVC_DMA_SRC_LEN = cur ;
		*DEVC_DMA_DST_LEN = cur;
		while (!(*DEVC_STATUS & 0x30000000));
		printf("DEVC %x ", *DEVC_STATUS);
		*DEVC_STATUS = 0x30000000;
		printf("%x\n", *DEVC_STATUS);
		if (send(mixbuf, cur * 4)) return -1;
		len -= cur;
	}
	return 0;
}

int cmd_wrdevc() {
	uint16_t len;
	if (recv(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x200)
			cur = 0x200;
		if (recv(mixbuf, cur * 4)) return -1;
		*DEVC_DMA_SRC_ADDR = (uint32_t)mixbuf;
		*DEVC_DMA_DST_ADDR = 0xffffffff;
		*DEVC_DMA_SRC_LEN = cur;
		*DEVC_DMA_DST_LEN = cur ;
		while (!(*DEVC_STATUS & 0x30000000));
		//printf("DEVC %x ", *DEVC_STATUS);
		*DEVC_STATUS = 0x30000000;
		//printf("%x\n", *DEVC_STATUS);
		len -= cur;
	}
	uint8_t reply = 0x93;
	if (send(&reply, 1)) return -1;
	return 0;
}

int cmd_fpga_reset() {
	cpsid();
	dsb();
	*FPGA_RST_CTRL = 0xf;
	*LVL_SHFTR_EN = 0xa;
	*DEVC_MCTRL = 0;
	uint32_t ctrl = *DEVC_CTRL;
	ctrl |= 0x0c000000;
	ctrl &= ~0x02000000;
	*DEVC_CTRL = ctrl | 0x40000000;
	*DEVC_CTRL = ctrl & ~0x40000000;
	while (*DEVC_STATUS & 0x10);
	*DEVC_CTRL = ctrl | 0x40000000;
	while (!(*DEVC_STATUS & 0x10));

	// UART
	*UART_RST_CTRL = 0xa;
	uart_on = false;

	dsb();
	cpsie();
	dsb();

	uint8_t reply = 0xa0;
	if (send(&reply, 1)) return -1;
	return 0;
}

int cmd_fpga_boot() {
	uint8_t reply = 0xa1;
	if (*DEVC_STATUS & 0x400) {
		cpsid();
		dsb();

		*LVL_SHFTR_EN = 0xf;

		// UART
		*UART_RST_CTRL = 0x0;
		*UART1_CR = 0x12b; // reset & disable TX & RX, stop break
		*UART1_MR = 0x00000020; // 8 bits, no parity
		*UART1_IDR = 0xffffffff;
		*UART1_IER = 0x000000e1;
		*UART1_ISR = 0xffffffff;
		*UART1_BAUDGEN = 10;
		*UART1_BAUDDIV = 9;
		*UART1_RXWM = 1;
		*UART1_TXWM = 0x20;
		*UART1_MODEMCR = 0x3;
		*UART1_CR = 0x114; // start it
		utxput = utxget = utxused = 0;
		utxfree = utxsize;
		urxput = urxget = urxused = 0;
		urxfree = urxsize;
		uart_on = true;

		*FPGA_RST_CTRL = 0x0;

		dsb();
		cpsie();
		dsb();
	} else {
		reply = 0xe1;
	}
	if (send(&reply, 1)) return -1;
	return 0;
}

int cmd_uart_tx() {
	uint16_t len;
	if (recv(&len, sizeof len)) return -1;
	while (len) {
		uint16_t cur = len;
		if (cur > 0x200)
			cur = 0x200;
		if (recv(mixbuf, cur)) return -1;
		uart_tx(mixbuf, cur);
		len -= cur;
	}
	uint8_t reply = 0xb0;
	if (send(&reply, 1)) return -1;
	return 0;
}

void main() {
	// unlock SLCR
	*SLCR_UNLOCK = SLCR_UNLOCK_VAL;

	// clocks — PLLs
	// bypass all
	*ARM_PLL_CTRL |= 0x10;
	*DDR_PLL_CTRL |= 0x10;
	*IO_PLL_CTRL |= 0x10;
	// ARM PLL = 50MHz * 26 = 1300MHz
	*ARM_PLL_CFG = 12 << 4 | 2 << 8 | 375 << 12;
	*ARM_PLL_CTRL = 0x0001a010;
	*ARM_PLL_CTRL = 0x0001a011;
	*ARM_PLL_CTRL = 0x0001a010;
	// DDR PLL = 50MHz * 21 = 1050MHz
	*DDR_PLL_CFG = 12 << 4 | 2 << 8 | 475 << 12;
	*DDR_PLL_CTRL = 0x00015010;
	*DDR_PLL_CTRL = 0x00015011;
	*DDR_PLL_CTRL = 0x00015010;
	// IO PLL = 50MHz * 20 = 1000MHz
	*IO_PLL_CFG = 12 << 4 | 2 << 8 | 500 << 12;
	*IO_PLL_CTRL = 0x00014010;
	*IO_PLL_CTRL = 0x00014011;
	*IO_PLL_CTRL = 0x00014010;
	// wait for lock
	while ((*PLL_STATUS & 7) != 7);
	// disable bypass
	*ARM_PLL_CTRL = 0x0001a000;
	*DDR_PLL_CTRL = 0x00015000;
	*IO_PLL_CTRL = 0x00014000;

	// clocks
	*ARM_CLK_CTRL = 0x1f000200; // 1300MHz / 2 == 650MHz
	*DDR_CLK_CTRL = 0x0c200003;
	*DCI_CLK_CTRL = 0x00102000;
	*APER_CLK_CTRL = 0x00f00040; // GEM0, UART[01], GPIO, QSPI
	USB_CLK_CTRL[0] = 0x00102000;
	USB_CLK_CTRL[1] = 0x00102000;
	GEM_RXCLK_CTRL[0] = 0x00000001; // RX clock from MIO
	GEM_RXCLK_CTRL[1] = 0x00000000;
	GEM_CLK_CTRL[0] = 0x00100801; // 1000MHz / 8 == 125MHz
	GEM_CLK_CTRL[1] = 0x00102000;
	*SMC_CLK_CTRL = 0x00002000;
	*QSPI_CLK_CTRL = 0x00000501; // 1000MHz / 5 == 200MHz
	*SDIO_CLK_CTRL = 0x00002000;
	*UART_CLK_CTRL = 0x00000a03; // 1000MHz / 10 == 100MHz
	*SPI_CLK_CTRL = 0x00002000;
	*CAN_CLK_CTRL = 0x00102000;
	*CAN_MIOCLK_CTRL = 0x00000000;
	*DBG_CLK_CTRL = 0x00002000;
	*PCAP_CLK_CTRL = 0x00000501; // 1000MHz / 5 == 200MHz
	*TOPSW_CLK_CTRL = 1; // enable auto stop
	*FPGA0_CLK_CTRL = 0x00101400; // 1000MHz / 20 == 50MHz
	*FPGA1_CLK_CTRL = 0x00100a00; // 1000MHz / 10 == 100MHz
	*FPGA2_CLK_CTRL = 0x00100500; // 1000MHz / 5 == 200MHz
	*FPGA3_CLK_CTRL = 0x00100400; // 1000MHz / 4 == 250MHz
	*FPGA0_THR_CNT = 0;
	*FPGA1_THR_CNT = 0;
	*FPGA2_THR_CNT = 0;
	*FPGA3_THR_CNT = 0;
	*CLK_621_TRUE = 1;

	// resets
	*DDR_RST_CTRL = 1;
	*DMAC_RST_CTRL = 1;
	*USB_RST_CTRL = 0x33;
	*GEM_RST_CTRL = 0xf3;
	*SDIO_RST_CTRL = 0x33;
	*SPI_RST_CTRL = 0xf;
	*CAN_RST_CTRL = 0xf;
	*I2C_RST_CTRL = 0x3;
	*UART_RST_CTRL = 0xf;
	*GPIO_RST_CTRL = 0x1;
	*QSPI_RST_CTRL = 0x3;
	*SMC_RST_CTRL = 0x3;
	*A9_CPU_RST_CTRL = 2;
	// up the shit we need
	*GEM_RST_CTRL = 0xa2; // up
	*UART_RST_CTRL = 0x0; // up
	*GPIO_RST_CTRL = 0x0; // up
	*QSPI_RST_CTRL = 0x0; // up
	*DDR_RST_CTRL = 0; // up

	// SWDT on CPU clock
	*WDT_CLK_SEL = 0;

	// TrustZone — am I the villain now?
	TZ_OCM_RAM[0] = 0;
	TZ_OCM_RAM[1] = 0xffffffff;
	TZ_OCM_RAM[2] = 0;
	*TZ_DDR_RAM = 0;
	*TZ_DMA_NS = 0;
	*TZ_DMA_IRQ_NS = 0;
	*TZ_DMA_PERIPH_NS = 0;
	*TZ_GEM = 0;
	*TZ_SDIO = 0;
	*TZ_USB = 0;
	*TZ_FPGA_M = 3;
	*TZ_FPGA_AFI = 0xf;

	// MIO
	MIO_PIN[0] = 0x1601;
	MIO_PIN[1] = 0x602; // QSPI.CS
	MIO_PIN[2] = 0x602; // QSPI.IO
	MIO_PIN[3] = 0x602; // QSPI.IO
	MIO_PIN[4] = 0x602; // QSPI.IO
	MIO_PIN[5] = 0x602; // QSPI.IO
	MIO_PIN[6] = 0x602; // QSPI.LK
	MIO_PIN[7] = 0x601;
	MIO_PIN[8] = 0x602; // QSPI.FBCK
	MIO_PIN[9] = 0x1600; // ETH_RST_B
	MIO_PIN[10] = 0x1601; // ETH_INT_B
	MIO_PIN[11] = 0x1601; // OTG_OC
	MIO_PIN[12] = 0x1600; // AR_RST
	MIO_PIN[13] = 0x1601;
	MIO_PIN[14] = 0x6e1; // UART0.RX
	MIO_PIN[15] = 0x6e0; // UART0.TX

	MIO_PIN[16] = 0x802; // GEM0.TXCLK
	MIO_PIN[17] = 0x802; // GEM0.TXD0
	MIO_PIN[18] = 0x802; // GEM0.TXD1
	MIO_PIN[19] = 0x802; // GEM0.TXD2
	MIO_PIN[20] = 0x802; // GEM0.TXD3
	MIO_PIN[21] = 0x802; // GEM0.TXCTL
	MIO_PIN[22] = 0x803; // GEM0.RXCLK
	MIO_PIN[23] = 0x803; // GEM0.RXD0
	MIO_PIN[24] = 0x803; // GEM0.RXD1
	MIO_PIN[25] = 0x803; // GEM0.RXD2
	MIO_PIN[26] = 0x803; // GEM0.RXD3
	MIO_PIN[27] = 0x803; // GEM0.RXCTL

	MIO_PIN[28] = 0x1201; // USB0
	MIO_PIN[29] = 0x1201; // USB0
	MIO_PIN[30] = 0x1201; // USB0
	MIO_PIN[31] = 0x1201; // USB0
	MIO_PIN[32] = 0x1201; // USB0
	MIO_PIN[33] = 0x1201; // USB0
	MIO_PIN[34] = 0x1201; // USB0
	MIO_PIN[35] = 0x1201; // USB0
	MIO_PIN[36] = 0x1201; // USB0
	MIO_PIN[37] = 0x1201; // USB0
	MIO_PIN[38] = 0x1201; // USB0
	MIO_PIN[39] = 0x1201; // USB0

	MIO_PIN[40] = 0x1201; // SDIO0
	MIO_PIN[41] = 0x1201; // SDIO0
	MIO_PIN[42] = 0x1201; // SDIO0
	MIO_PIN[43] = 0x1201; // SDIO0
	MIO_PIN[44] = 0x1201; // SDIO0
	MIO_PIN[45] = 0x1201; // SDIO0
	MIO_PIN[46] = 0x1201; // OTG_RESETN
	MIO_PIN[47] = 0x1201; // SDIO0.CD
	MIO_PIN[48] = 0x1201;
	MIO_PIN[49] = 0x1201;
	MIO_PIN[50] = 0x1201; // HDMI I2C
	MIO_PIN[51] = 0x1201; // HDMI I2C

	MIO_PIN[52] = 0x1280; // MDIO0.CLK
	MIO_PIN[53] = 0x1280; // MDIO0.DATA

	*MIO_LOOPBACK = 0;

	// I'm not high.
	*OCM_CFG &= 0x10;

	*L2C_RAM = 0x00020202;

	*GPIOB_CTRL = 0x800;
	*GPIOB_CFG_CMOS18 = 0x0c301166;
	*GPIOB_CFG_CMOS33 = 0x0c301166;
	*GPIOB_CFG_HSTL = 0x0c750077;

	*REBOOT_STATUS += 0x1000000;

	// Private timer setup.
	*PRIVT_LOAD = 3250000;
	*PRIVT_CTL = 0x7;

	// GIC setup.
	*GIC_ICCICR = 0x17;
	*GIC_ICCPMR = 0xff;

	GIC_ICDISR[0] = 0;
	GIC_ICDISR[1] = 0;
	GIC_ICDISR[2] = 0;
	GIC_ICDICER[0] = 0xffffffff;
	GIC_ICDICER[1] = 0xffffffff;
	GIC_ICDICER[2] = 0xffffffff;
	for (int i = 0; i < 24; i++)
		GIC_ICDIPR[i] = 0;
	for (int i = 8; i < 24; i++)
		GIC_ICDIPTR[i] = 0x01010101;
	GIC_ICDICFR[1] = 0x7dc00000;
	GIC_ICDICFR[2] = 0x555d555f;
	GIC_ICDICFR[3] = 0x5555d555;
	GIC_ICDICFR[4] = 0x75555555;
	GIC_ICDICFR[5] = 0x57555555;
	// en 29, 54, 82
	GIC_ICDISER[0] = 0x20000000;
	GIC_ICDISER[1] = 0x00400000;
	GIC_ICDISER[2] = 0x00040000;
	// en everything
	*GIC_ICDDCR = 0x3;

	// UART0 setup.
	*UART0_CR = 0x12b; // reset & disable TX & RX, stop break
	*UART0_MR = 0x00000020; // 8 bits, no parity
	*UART0_IDR = 0xffffffff;
	*UART0_IER = 0x00000000;
	*UART0_ISR = 0xffffffff;
	*UART0_BAUDGEN = 124;
	*UART0_BAUDDIV = 6;
	*UART0_RXWM = 1;
	*UART0_TXWM = 0x20;
	*UART0_MODEMCR = 0x3;
	*UART0_CR = 0x114; // start it

	// Get the MAC.
	*QSPI_LCR = 0;
	*QSPI_LPBK = 0;
	*QSPI_CR = 0x8000fce7;
	*QSPI_DR = 0x04040404;
	*QSPI_RXWM = 1;
	*QSPI_ER = 1;
	*QSPI_CR = 0x8000f8e7;
	*QSPI_TXD = 0x0000204b;
	for (int i = 0; i < 15; i++)
		*QSPI_TXD = 0x00000000;
	*QSPI_CR = 0x8001f8e7;
	uint32_t words[0x10];
	for (int i = 0; i < 0x10; i++) {
		while (!(*QSPI_ISR & 0x10));
		while (!(*QSPI_ISR & 0x10));
		words[i] = *QSPI_RXD;
	}
	memcpy(otp_uniq, (char*)words + 5, 16);
	memcpy(mac, (char*)words + 0x25, 6);

	// Prepare descriptors.
	for (int i = 0; i < 0x80; i++) {
		rxring[i].addr = (uint32_t)(rxdata + i * 0x80) | (i == 0x7f ? 2 : 0);
		rxring[i].attr = 0;
		txring[i].addr = 0;
		txring[i].attr = 0x80000000 | (i == 0x7f ? 0x40000000 : 0);
	}

	// GEM0 setup.
	*GEM0_NWCTRL = 0x00000010;
	*GEM0_NWCFG = 0x000f0402;
	*GEM0_DMACR = 0x00020f10;
	*GEM0_RXQBASE = (uint32_t)rxring;
	*GEM0_TXQBASE = (uint32_t)txring;
	*GEM0_ISR = 0xffffffff;
	*GEM0_IDR = 0xffffffff;
	*GEM0_IER = 0x00000002;
	GEM0_LADDR1[0] = mac[0] | mac[1] << 8 | mac[2] << 16 | mac[3] << 24;
	GEM0_LADDR1[1] = mac[4] | mac[5] << 8;

#if 0
	for (int i = 0; i < 0x20; i++) {
		printf("PHY %x: %x\n", i, phyrd(i));
	}
#endif

	printf("Hello, world!\n");
	printf("I AM %x\n", *(volatile uint32_t *)0xf8000530);

	// Setup SWDT.
	*SWDT_CCR = 0x248 << 14 | 0x674 << 2 | 1;
	*SWDT_RESTART = 0x1999;
	*SWDT_ZMR = 0xabc1c3;

	// Start GEM0.
	*GEM0_NWCTRL = 0x3c;

restart:
	cpsid();
	dsb();

	net_state = NS_BOOTP;
	rxtget = rxtput = rxtused = 0;
	txtget = txtput = txtused = txtsent = 0;
	seq = ack = 0;
	txtfree = txtsize;
	rxtfree = rxtsize;
	send_bootp();
	retry_reload = 1;
	retry_timer = 2;

	// Main loop.
	while (1) {
		while (!rxtused && !urxused) {
			wfi();
			cpsie();
			dsb();
			cpsid();
			dsb();
		}
		bool do_uart = urxused != 0;
		if (do_uart) {
			int num = urxused;
			if (num + urxget > urxsize)
				num = urxsize - urxget;
			memcpy(mixbuf16, rxuart + urxget, num * 2);
			dsb();
			cpsie();
			dsb();

			uint8_t code = 0xb1;
			uint16_t len = num;
			if (send(&code, 1)) goto restart;
			if (send(&len, 2)) goto restart;
			if (send(mixbuf16, num * 2)) goto restart;

			dsb();
			cpsid();
			dsb();
			urxused -= num;
			urxfree += num;
			urxget += num;
			if (urxget == urxsize)
				urxget = 0;
		} else {
			dsb();
			cpsie();
			dsb();
			uint8_t cmd;
			if (recv(&cmd, 1))
				goto restart;
			switch (cmd) {
				case 0x00:
					if (cmd_rd8())
						goto restart;
					break;
				case 0x01:
					if (cmd_rd16())
						goto restart;
					break;
				case 0x02:
					if (cmd_rd32())
						goto restart;
					break;
				case 0x03:
					if (cmd_rddevc())
						goto restart;
					break;
				case 0x10:
					if (cmd_wr8())
						goto restart;
					break;
				case 0x11:
					if (cmd_wr16())
						goto restart;
					break;
				case 0x12:
					if (cmd_wr32())
						goto restart;
					break;
				case 0x13:
					if (cmd_wrdevc())
						goto restart;
					break;
				case 0x20:
					if (cmd_fpga_reset())
						goto restart;
					break;
				case 0x21:
					if (cmd_fpga_boot())
						goto restart;
					break;
				case 0x30:
					if (cmd_uart_tx())
						goto restart;
					break;
				case 0x40:
					*PSS_RST_CTRL = 1;
					break;
				case 0x41:
					wdt = 1500;
					break;
			}
			dsb();
			cpsid();
			dsb();
		}
	}
}
