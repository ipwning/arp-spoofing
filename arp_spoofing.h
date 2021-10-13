#include <pcap.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <cstring>
#include <thread>
#include <signal.h>

typedef struct _eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
} eth_header;

typedef struct _arp {
    eth_header eth;
    uint16_t h_type;
    uint16_t p_type;
    uint8_t h_size;
    uint8_t p_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
    uint8_t padding[12];
} arp;

typedef struct _ip {
    eth_header eth;
    uint8_t ver:4;
    uint8_t h_len:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint8_t flags:3;
    uint16_t f_off:16;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sip;
    uint32_t dip;
    uint8_t pay[0x800];
} ip;

#define REQUEST     1
#define REPLY       2
#define RARP_REQ    3
#define RARP_REP    4
#define ARP         0x0806
#define IPv4        0x0800
#define ETH         1

int get_my_mac(char *_ifr_name, uint8_t *dst);

int get_my_ip(char *_ifr_name, uint32_t *my_ip);

void init_arp(arp* packet);

void set_arp(arp *packet, uint8_t *eth_smac, uint8_t *eth_dmac, uint16_t opcode, uint8_t *smac, uint32_t sip, uint8_t *dmac, uint32_t dip);

arp *resolve_target_arp(pcap_t* pcap, pcap_pkthdr **header, const uint8_t **data, arp*send);

void infecting_routine(pcap_t *pcap, int loop, arp **infecting);

void relay_routine(pcap_t *pcap, int loop, arp **infecting, 
                    uint32_t *sender_ip, uint8_t *my_mac, uint8_t **g_mac, uint32_t my_ip);

void handler();