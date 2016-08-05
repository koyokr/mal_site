#include "struct.h"

bool filter = false;

int fgetline(FILE *fp);
int fgetlinelen(FILE *fp);

char *gethost(void *data);
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

int _strlen(const char *str) {
	int i;
	for (i = 0; str[i] != '\0'; i++);
	return i; 
}

char *_strcpy(char *dst, const char *src) {
	while (*src != '\0') *dst++ = *src++;
	*dst = '\0';
	return dst;
}

char *_strcat(char *dst, const char *src) {
	while (*dst != '\0') dst++;
	while (*src != '\0') *dst++ = *src++;
	*dst = '\0';
	return dst;
}

int _strcmp(const void *a, const void *b) {
	while (*(char *)a == *(char *)b && *(char *)a != '\0' && *(char *)b != '\0') {
		(char *)a++;
		(char *)b++;
	}
	return *(char *)a - *(char *)b;
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

	int line, linelen;
	line = fgetline(fp);
	fseek(fp, 0, SEEK_SET);
	linelen = fgetlinelen(fp) + 1;
	fseek(fp, 0, SEEK_SET);

	char site[line][linelen];
	for (int i = 0; i < line; i++) {
		char buf_temp[linelen];
		if (fgets(buf_temp, linelen, fp) == NULL) break;
		if (buf_temp[_strlen(buf_temp)-2] == '/')
			buf_temp[_strlen(buf_temp)-2] = '\0';
		else
			buf_temp[_strlen(buf_temp)-1] = '\0';
		_strcpy(site[i], buf_temp + 7);
	}
	fclose(fp);

	qsort(site, line, linelen, _strcmp);
	//bsearch(key, site, line, linelen, _strcmp);

	/* test */
	/*for (int i = 0; i < line; i++)
	 *	printf("%s\n", site[i]);
	 */

	struct thread_arg arg = { h, qh };
	pthread_t thread;
	pthread_create(&thread, NULL, qthread, (void *)&arg);
	pthread_detach(thread);

	char *host;
	while (true) {
		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0) {
			/* puts("pkt received"); */
			host = gethost(buf);
			if (host != NULL)
				if (bsearch(host, site, line, linelen, _strcmp) != NULL) {
					printf("\x1b[31m[BLOCK]\x1b[0m %s\n", host);
					filter = true;
				}
				else
					filter = false;
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

int fgetline(FILE *fp) {
	char buf[4096];
	char *p;
	int size;
	int i, line = 0;

	while (!feof(fp)) {
		size = fread(buf, 1, sizeof(buf), fp);
		for (i = 0, p = buf; p < buf+size; p++)
			if (*p == '\n') i++;
		line += i;
	}

	return line;	
}

int fgetlinelen(FILE *fp) {
	char buf[4096];
	char *p;
	int size;
	int i, linelen = 0;

	while (!feof(fp)) {
		size = fread(buf, 1, sizeof(buf), fp);
		for (i = 0, p = buf; p < buf+size; i++, p++)
			if (*p == '\n') {
				if (linelen < i) linelen = i;
				i = 0;
			}
	}

	return linelen;
}

char *gethost(void *data) {
	uint8_t     *p;
	struct ip   *ip;
	struct tcp  *tcp;
	struct http  http;

	ip = (struct ip *)((uint8_t *)data + 44);
	if (ip->ver != IPV4_VERSION) return NULL;
	if (ip->pro != PROTOCOL_TCP) return NULL;

	tcp = (struct tcp *)((uint8_t *)ip + ip->len_h * 4);
	http.get = (uint8_t *)tcp + tcp->off * 4;
	if (ntohs(ip->len_t) <= 40) return NULL;
	if (*(uint32_t *)http.get != STRING_GET) return NULL;

	p = http.get;
	while (*p++ != '\r');
	if (*p++ != '\n') return NULL;
	*(p-11) = '\0';

	http.host = p += 6;
	http.get += 4;
	while (*p != '\r') p++;
	*p = '\0';

	if (*(http.get+1) != '\0')
		_strcat(http.host, http.get);

	/* printf("%s\n", http.host); */

	return http.host;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);

	if (filter)
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}
