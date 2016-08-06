#include "struct.h"

bool filter = false;

void sig_handler(int signo) {
	exit(1);
}

void _close(struct nfq_handle *h, struct nfq_q_handle *qh) {
	puts("unbinding from queue 0");
	nfq_destroy_queue(qh);
	puts("closing library handle");
	nfq_close(h);
}

void *qthread(void *p) {
	struct thread_arg *arg = (struct thread_arg *)p;
	puts("[!] press enter key to exit~");
	/* Enter */
	getchar();
	_close(arg->h, arg->qh);
	exit(0);
}

#define BUF_SIZE 4096

int main() {
	int nfd, rv;
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	char buf[BUF_SIZE] __attribute__ ((aligned));

	/* Ctrl + C to exit(1) */
	signal(SIGINT, sig_handler);

	/* Preparations */
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
	nfd = nfq_fd(h);

	int fd;
	uint64_t fsize;

	/* Open mal_site1.dat: host list */
	fd = open("mal_site1.dat", O_RDONLY);
	fsize = fgetsize(&fd);
	char fbuf1[fsize];
	read(fd, fbuf1, fsize);
	close(fd);

	int w1, h1; /* width, height */
	w1 = getwidth(fbuf1);
	h1 = fsize / w1;
	fbuf1[w1-1] = '\0';
	char (*pbuf1)[w1] = (char (*)[w1])fbuf1;

	/* Open mal_site2.dat: get list */
	fd = open("mal_site2.dat", O_RDONLY);
	fsize = fgetsize(&fd);
	char fbuf2[fsize];
	read(fd, fbuf2, fsize);
	close(fd);

	int w2, h2, d2; /* width, height, depth */
	w2 = getwidth(fbuf2);
	h2 = getwidth_deep(fbuf2) / w2;
	d2 = fsize / (w2 * h2);
	fbuf2[w2*h2-1] = fbuf2[w2-1] = '\0';
	char (*pbuf2)[h2][w2] = (char (*)[h2][w2])fbuf2;

	/* Print mal_site1 */
	/* for (int i = 0; i < h1; i++) printf("%s\n", pbuf1[i]); */
	/* Print mal_site2 */
	/* for (int i = 0; i < d2; i++) { for (int j = 0; j < h2; j++) printf("[%d]%s  ", j, pbuf2[i][j]); printf("\n"); }; */

	/* Threading for exit */
	struct thread_arg arg = { h, qh };
	pthread_t thread;
	pthread_create(&thread, NULL, qthread, (void *)&arg);
	pthread_detach(thread);

	/* Receive packet */
	struct http http;
	char *tbuf;
	while (true) {
		rv = recv(nfd, buf, BUF_SIZE, 0);
		if (rv < 0)
			if (errno == ENOBUFS) {
				puts("losing packets");
				continue;
			}
			else {
				puts("recv failed");
				break;
			}

		/* Packet received */
		if (gethost(buf, &http)) /* http */
			if (bsearch(http.host, pbuf1, h1, w1, _strcmp)) /* filter host */
				if (tbuf = bsearch(http.host, pbuf2, d2, w2*h2, _strcmp)) /* host have get filter */
					if (bsearch(http.get, tbuf, h2, w2, _strcmp2)) filter = true; /* filter get */
					else filter = false;
				else filter = true;
			else filter = false;
		else filter = false;

		if (filter) printf("\x1b[31m[BLOCK]\x1b[0m %s %s\n", http.host, http.get);
		nfq_handle_packet(h, buf, rv);
	}

	pthread_cancel(thread);
	_close(h, qh);
	return 0;
}

/* Callback: nfq_create_queue() */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);

	if (filter)
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}
