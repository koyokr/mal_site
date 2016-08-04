#include "struct.h"

bool filter_true = false;
pthread_t thread;
struct nfq_handle *h;
struct nfq_q_handle *qh;

bool filter(void *data);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

void *qthread() {
	puts("\npress enter key to exit~\n");
	getchar();

	puts("unbinding from queue 0");
	nfq_destroy_queue(qh);
	puts("closing library handle");
	nfq_close(h);

	exit(0);
}

void sig_handler(int signo) {
	pthread_cancel(thread);

	puts("\nunbinding from queue 0");
	nfq_destroy_queue(qh);
	puts("closing library handle");
	nfq_close(h);
	
	exit(1);
}

int main() {
	int fd, rv;
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

    pthread_create(&thread, NULL, qthread, NULL);
	pthread_detach(thread);
	
	while (true) {
		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0) {
			/* puts("pkt received"); */
			filter_true = filter(buf);
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

    pthread_cancel(thread);

	puts("\nunbinding from queue 0");
	nfq_destroy_queue(qh);
	puts("closing library handle");
	nfq_close(h);

	return 0;
}

bool filter(void *data) {
	uint8_t     *cp;
	struct ip   *ip;
	struct tcp  *tcp;
	struct http  http;

	ip = (struct ip *)((char *)data + 44);
	if (ip->ver != IPV4_VERSION) return false;
	if (ip->pro != PROTOCOL_TCP) return false;

	tcp = (struct tcp *)((char *)ip + ip->len_h * 4);
	http.get = (uint32_t *)((char *)tcp + tcp->off * 4);
	if (ntohs(ip->len_t) <= 40) return false;
	if (*http.get != STRING_GET) return false;

	cp = (uint8_t *)http.get;
	while (*cp++ != '\r');
	if (*cp++ != '\n') return false;

	http.host = cp += 6;
	while (*cp != '\r') cp++;
	*cp = '\0';
	printf("%s\n", http.host);

	return false;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	if (filter_true)
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}
