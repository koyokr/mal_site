#include "struct.h"

void fgetlen(FILE *fp, int *line, int *hostlen, int *getlen) {
	char buf[4096];
	char *p;
	int size;
	int i = 0, j = 0;
	*line = *hostlen = *getlen = 0;

	while (!feof(fp)) {
		size = fread(buf, 1, sizeof(buf), fp);
		for (p = buf + 7; p < buf + size; i++, p++) {
			if (*p == '/') {
				if (*hostlen < i && j == 0) {
					*hostlen = i;
				}
				j = i + 1;
			}
			else if (*p == '\n') {
				(*line)++;
				if (*hostlen < i && j == 0) {
					*hostlen = i;
				}
				if (*getlen < (i - j)) {
					*getlen = i - j;
				}
				p += 8;
				i = 0;
				j = 0;
			}
		}
	}
}

bool gethost(void *data, struct http *http) {
	uint8_t     *p;
	struct ip   *ip;
	struct tcp  *tcp;

	ip = (struct ip *)((uint8_t *)data + 44);
	if (ip->ver != IPV4_VERSION) return false;
	if (ip->pro != PROTOCOL_TCP) return false;

	tcp = (struct tcp *)((uint8_t *)ip + ip->len_h * 4);
	http->get = (uint8_t *)tcp + tcp->off * 4;
	if (ntohs(ip->len_t) <= 40) return false;
	if (*(uint32_t *)http->get != STRING_GET) return false;

	p = http->get;
	while (*p++ != '\r');
	if (*p++ != '\n') return false;
	*(p-11) = '\0';

	http->host = p += 6;
	http->get += 4;
	while (*p != '\r') p++;
	*p = '\0';

	return true;
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

bool _strstr_(const char *str, char *key) {
	while (*str == *key && *str != '\0') {
		str++;
		key++;
		if (*key == '\0') return true;
	}
	return false;
}

int _strcmp(const void *a, const void *b) {
	while (*(char *)a == *(char *)b && *(char *)a != '\0' && *(char *)b != '\0') {
		(char *)a++;
		(char *)b++;
	}
	return *(char *)a - *(char *)b;
}
