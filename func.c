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

/* Get file width*height for mal_site2 */
int getwidth_deep(const char *buf) {
	int i = 0;
	while (buf[i++] != '\2');
	return i;
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

	/* http */
	http->get = (uint8_t *)tcp + tcp->off * 4;
	if (*(uint32_t *)http->get != STRING_GET) return false;

	/* get */
	p = http->get += 4;
	while (*p++ != '\r');
	if (*p++ != '\n') return false;
	*(p-11) = '\0';

	/* host */
	http->host = p += 6;
	while (*p != '\r') p++;
	*p = '\0';

	return true;
}

/* strcmp for bsearch() */
int _strcmp(const void *a, const void *b) {
	while (*(char *)a == *(char *)b && *(char *)a != '\0' && *(char *)b != '\0') {
		(char *)a++;
		(char *)b++;
	}
	return *(char *)a - *(char *)b;
}

/* Is not strcmp! function for bsearch() */
int _strcmp2(const void *str, const void *key) {
	while (*(char *)str == *(char *)key && *(char *)str != '\0') {
		(char *)str++;
		(char *)key++;
		if (*(char *)key == '\0') return 0;
	}
	return *(char *)str - *(char *)key;
}
