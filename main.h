#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>
#include <stdint.h>

#define MAC_SIZE 8
#define IP_SIZE 4
typedef struct _TCP_PK{
    struct libnet_ethernet_hdr eth;
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;
    uint8_t data[16384];
}TCP_PK;