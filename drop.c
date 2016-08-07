#include "struct.h"

bool filter = false;
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

void sig_handler(int signo) {
	exit(1);
}

void _close(struct nfq_handle *h, struct nfq_q_handle *qh, int fd, char *heap) {
	close(fd);
	free(heap);
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
	_close(arg->h, arg->qh, arg->fd, arg->heap);
	exit(0);
}

#define BUF_SIZE 4096
int main(int argc, char *argv[]) {
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

	/* Open top-1m */
	fd = open("top-1m", O_RDONLY);
	fsize = fgetsize(fd);
	char *p = (char *)malloc(fsize);
	read(fd, p, fsize);
	close(fd);

	int _w, _h; /* width, height */
	_w = getwidth(p);
	_h = fsize / _w;
	p[_w-1] = '\0';
	char (*pp)[_w] = (char (*)[_w])p;

	/* Open log */
	fd = open("log", O_WRONLY | O_APPEND | O_CREAT, 0664);

	/* Threading for exit */
	struct thread_arg arg = { h, qh, fd, p };
	pthread_t thread;
	pthread_create(&thread, NULL, qthread, (void *)&arg);
	pthread_detach(thread);

	/* Receive packet */
	struct http http;
	struct timespec start, end;
	float dtime;
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
		clock_gettime(CLOCK_MONOTONIC, &start);
		if (gethost(buf, &http)) { /* http */
			if (bsearch(http.host, pp, _h, _w, _strcmp)) filter = true;
			else filter = false;
			clock_gettime(CLOCK_MONOTONIC, &end);

			dtime = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec)/1000000000;
			printf("%.6fs elapsed.\n", dtime);
		} else filter = false;

		if (filter) {
			char tbuf[25+_w];
			sprintf(tbuf, "\x1b[31m[BLOCK]\x1b[0m %s\n", http.host);
			printf("%s", tbuf);
			write(fd, tbuf, strlen(tbuf));
		}
		nfq_handle_packet(h, buf, rv);
	}

	pthread_cancel(thread);
	_close(h, qh, fd, p);
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
