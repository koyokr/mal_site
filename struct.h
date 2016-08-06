#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <errno.h>
#include <signal.h>
#include <pthread.h>


struct thread_arg {
	struct nfq_handle   *h;
	struct nfq_q_handle *qh;
};

struct ip {
	uint8_t  len_h:4, ver:4; /* little endian */
#define IPV4_VERSION 4
	uint8_t  tos;
	uint16_t len_t;
	uint16_t id;
	uint16_t flag:3, off:13;
	uint8_t  ttl;
	uint8_t  pro;
#define PROTOCOL_TCP 6
	uint16_t sum;
	uint32_t ip_src;
	uint32_t ip_dst;
};

struct tcp {
	uint16_t port_src;
	uint16_t port_dst;
	uint32_t seq;
	uint32_t ack;
	uint8_t  resv:4, off:4; /* little endian */
	uint8_t  flag;
	uint16_t win;
	uint16_t sum;
	uint16_t urp;
};

#define STRING_GET 0x20544547 /* little endian */


uint64_t fgetsize(int *fd);
int getwidth(const char *buf);
int _strcmp(const void *a, const void *b);
bool gethost(char *data, char *host);
