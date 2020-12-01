#include "main.h"

void usage() {
    puts("syntax : tcp-block <interface> <pattern>");
    puts("sample : tcp-block ens33 \"Host: test.gilgil.net\"");
}

char pattern[128];
int pat_len;
pcap_t* handle;

int is_block(unsigned char* buf, int size) {
	// Using KMP Algorithm
	int fail[128] = { 0 };
	for(int i=1,j=0;i<pat_len;i++){
		while(j>0&&pattern[i]!=pattern[j])	j = fail[j-1];
		if(pattern[i] == pattern[j])	fail[i] = ++j;
	}

	for(int off=0,j=0;off<size;off++){
		while(j>0 && buf[off] != pattern[j])	j = fail[j-1];
		if(buf[off] == pattern[j]){
			if(j==pat_len-1){
				printf("Pattern is founded!\n");
                return 1;
			}
			else	j++;
		}
	}
	return 0;
}
/*
void send_arp_packet(uint8_t *ether_smac, uint8_t *ether_dmac, uint8_t *arp_sip, uint8_t *arp_smac, uint8_t *arp_tip, uint8_t *arp_tmac, uint8_t op){
    memcpy(packet.eth.ether_dhost, ether_dmac, MAC_SIZE);
    memcpy(packet.eth.ether_shost, ether_smac, MAC_SIZE);

    packet.eth.ether_type = htons(ETHERTYPE_ARP);
    packet.arp.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp.ar_pro = htons(PROTO_IPv4);
    packet.arp.ar_hln = MAC_SIZE;
    packet.arp.ar_pln = IP_SIZE;
    packet.arp.ar_op = htons(op);

    memcpy(packet.arp_.sip_addr, arp_sip, IP_SIZE);
    memcpy(packet.arp_.smac_addr, arp_smac, MAC_SIZE);
    memcpy(packet.arp_.tip_addr, arp_tip, IP_SIZE);
    memcpy(packet.arp_.tmac_addr, arp_tmac, MAC_SIZE);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(ARP_PK));
    
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}*/

void send_block_packet(TCP_PK packet){
    printf("SEND BLOCK PACKET!! %d bytes\n", ntohs(packet.ip.ip_len)+LIBNET_ETH_H);
    packet.tcp.th_seq += ntohs(packet.ip.ip_len);
    packet.tcp.th_flags |= TH_RST;
    pcap_inject(handle, reinterpret_cast<const u_char*>(&packet), ntohs(packet.ip.ip_len)+LIBNET_ETH_H);
    /*
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), ntohs(packet.ip.ip_len) + LIBNET_ETH_H);
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
    return;*/
}

int analyze(const u_char* packet, unsigned int length){
    printf("%d: %02x %02x %02x %02x\n", length, packet[0], packet[1], packet[2], packet[3]);
    TCP_PK pk_hdr;
    
    int offset = 0;
    int eth_size = LIBNET_ETH_H;
    memcpy(&(pk_hdr.eth), packet+offset, eth_size);

    offset += eth_size;
    if(offset >= length)    return 0;
    int ip_size = (packet[offset] & 0xf) << 2;
    memcpy(&(pk_hdr.ip), packet+offset, ip_size);

    if(pk_hdr.ip.ip_p != 0x06){
        //printf("not tcp packet\n");
        return 0;
    }

    offset += ip_size;
    if(offset >= length)    return 0;

    int tcp_size = (packet[offset+12] >> 4) << 2;
    memcpy(&(pk_hdr.tcp), packet+offset, tcp_size);

    offset += tcp_size;
    if(offset >= length)    return 0;

    int data_size = length-offset;
    memcpy(pk_hdr.data, packet+offset, data_size);
    if(is_block(pk_hdr.data, data_size)){
        send_block_packet(pk_hdr);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    memcpy(pattern, argv[2], sizeof(pattern));
    pat_len = strlen(pattern);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        analyze(packet, header->caplen);
    }
    
    pcap_close(handle);
}
