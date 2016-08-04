#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <signal.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	/* uint32_t id = print_pkt(nfa); */
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);

	puts("entering callback");
	/* if ()
	 *	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	 * else
	 */	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void sig_handler(int signo) {
	exit(1);
}		

int main() {
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	signal(SIGINT, sig_handler);

	puts("opening library handle");
	h = nfq_open();

	puts("unbinding existing nf_queue handler for AF_INET (if any)");
	nfq_unbind_pf(h, AF_INET);

	puts("binding nfnetlink_queue as nf_queue handler for AF_INET");
	nfq_bind_pf(h, AF_INET);

	puts("binding this socket to queue '0'");
	qh = nfq_create_queue(h, 0, &cb, NULL);

	puts("setting copy_packet mode");
	nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

	fd = nfq_fd(h);

	while (1) {
		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0) {
			puts("pkt received");
			/* dump(buf, rv); */
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		else if (errno == ENOBUFS) {
			puts("losing packets!\n");
			continue;
		}
		puts("recv failed");
		break;
	}

	puts("unbinding from queue 0");
	nfq_destroy_queue(qh);

	puts("closing library handle");
	nfq_close(h);

	return 0;
}
