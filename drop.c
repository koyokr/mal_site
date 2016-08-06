#include "struct.h"

bool filter = false;

int _strlen(const char *str);
char *_strcpy(char *dst, const char *src);
bool _strstr_(const char *str, char *key);
int _strcmp(const void *a, const void *b);

void fgetlen(FILE *fp, int *line, int *hostlen, int *getlen);
bool gethost(void *data, struct http *http);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

inline void _close(struct nfq_handle *h, struct nfq_q_handle *qh) {
	puts("unbinding from queue 0");
	nfq_destroy_queue(qh);
	puts("closing library handle");
	nfq_close(h);
}

void *qthread(void *p) {
	struct thread_arg *arg = (struct thread_arg *)p;
	puts("[!] press enter key to exit~");
	while (true) {
		getchar();
		_close(arg->h, arg->qh);
		exit(0);
	}
}

void sig_handler(int signo) {
	exit(1);
}

int main() {
	int fd, rv;
	char buf[4096] __attribute__ ((aligned));
	struct nfq_handle *h;
	struct nfq_q_handle *qh;

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

	FILE *fp;
	fp = fopen("mal_site.txt", "r");

	int line, hostlen, getlen;
	fgetlen(fp, &line, &hostlen, &getlen);
	fseek(fp, 0, SEEK_SET);

	char site_host[line][hostlen+1];
	char site_get[line][getlen+1];
	for (int i = 0; i < line; i++) {
		char buf_temp[hostlen+getlen+2];
		char *p;
		p = buf_temp + 7;

		if (fgets(buf_temp, hostlen+getlen+2, fp) == NULL) break;
		buf_temp[_strlen(buf_temp)-1] = '\0';

		while (*p != '/' && *p != '\0') p++;
		if (*p == '\0') {
			site_get[i][0] = '/';
			site_get[i][1] = '\0';
		}
		else _strcpy(site_get[i], p);
		*p = '\0';
		_strcpy(site_host[i], buf_temp + 7);
	}
	fclose(fp);

	//qsort(site_host, line, hostlen+1, _strcmp);
	/* test */
	//for (int i = 0; i < line; i++) printf("%s %s\n", site_host[i], site_get[i]);

	struct thread_arg arg = { h, qh };
	pthread_t thread;
	pthread_create(&thread, NULL, qthread, (void *)&arg);
	pthread_detach(thread);

	struct http http;
	while (true) {
		char *buf_temp;
		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0) {
			/* puts("pkt received"); */
			if (gethost(buf, &http)) {
				buf_temp = bsearch(http.host, site_host, line, hostlen+1, _strcmp);
				if (buf_temp != NULL && _strstr_(http.get, site_get[(buf_temp-*site_host)/(hostlen+1)])) {
					printf("\x1b[31m[BLOCK]\x1b[0m %s %s\n", http.host, http.get);
					filter = true;
				}
				else filter = false;
			}
			else filter = false;
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
	_close(h, qh);
	return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);

	if (filter)
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}
