#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <signal.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

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

struct http {
	uint32_t *get;
#define STRING_GET 0x20544547 /* little endian */
	uint8_t *host;
};
