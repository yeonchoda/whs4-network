#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h" 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    
    struct ethheader *eth = (struct ethheader *)packet;
    
    if (ntohs(eth->ether_type) == 0x0800) { 
        
        
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
        
        
        int ip_header_len = ip->iph_ihl * 4;

        if (ip->iph_protocol == IPPROTO_TCP) {
            
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            
            int tcp_header_len = TH_OFF(tcp) * 4;

            int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = header->caplen - total_header_len;
            const u_char *payload = packet + total_header_len;

            printf("\n=========================================\n");
            
            printf("[Ethernet Header]\n");
            printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // [IP] IP 주소 출력
            printf("[IP Header]\n");
            printf("  Src IP : %s\n", inet_ntoa(ip->iph_sourceip));   
            printf("  Dst IP : %s\n", inet_ntoa(ip->iph_destip));    

            printf("[TCP Header]\n");
            printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

            printf("[HTTP Message (Payload)]\n");
            if (payload_len > 0) {
                for (int i = 0; i < payload_len; i++) {
                    if (isprint(payload[i]) || payload[i] == '\r' || payload[i] == '\n') {
                        putchar(payload[i]);
                    } else {
                        putchar('.'); 
                    }
                }
                printf("\n");
            } else {
                printf("  (No Application Data)\n");
            }
            printf("=========================================\n");
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    
    char filter_exp[] = "tcp port 80";
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }
    
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   
    return 0;
}
