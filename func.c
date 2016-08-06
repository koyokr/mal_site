#include "struct.h"

/* Get file size */
uint64_t fgetsize(int *fd) {
	struct stat info;
	if (fstat(*fd, &info) != 0) {
		perror("fstat() error\n");
		exit(1);
	}
	return info.st_size;
}

/* Get file width for mal_site1, mal_site2 */
int getwidth(const char *buf) {
	int i = 0;
	while (buf[i++] != '\1');
	return i;
}

/* strcmp for bsearch */
int _strcmp(const void *a, const void *b) {
	return strcmp(a, b);
}

/* Get get, host */
#define NETFILTER_IP_INDEX 44
bool gethost(char *data, struct http *http) {
	uint8_t     *p;
	struct ip   *ip;
	struct tcp  *tcp;

	/* ip */
	ip = (struct ip *)((uint8_t *)data + NETFILTER_IP_INDEX);
	if (ip->ver != IPV4_VERSION) return false;
	if (ip->pro != PROTOCOL_TCP) return false;
	if (ntohs(ip->len_t) <= 40) return false;

	/* tcp */
	tcp = (struct tcp *)((uint8_t *)ip + ip->len_h * 4);

	/* http: get */
	p = (uint8_t *)tcp + tcp->off * 4;
	if (*(uint32_t *)p != STRING_GET) return false;

	while (*p++ != '\r');
	if (*p++ != '\n') return false;

	/* http: host */
	http->host = p += 6;
	while (*p != '\r') p++;
	*p = '\0';

	return true;
}
