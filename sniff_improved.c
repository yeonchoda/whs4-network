#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h" // 제공해주신 헤더 파일을 포함합니다.

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // 1. Ethernet Header 파싱
    struct ethheader *eth = (struct ethheader *)packet;

    // IPv4 패킷(0x0800)인 경우에만 진행
    if (ntohs(eth->ether_type) == 0x0800) { 
        
        // 2. IP Header 파싱
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
        
        // IP 헤더 크기 계산 (iph_ihl 값에 4를 곱함)
        int ip_header_len = ip->iph_ihl * 4;

        // 과제 조건: TCP 프로토콜(IPPROTO_TCP = 6)만 대상으로 진행
        if (ip->iph_protocol == IPPROTO_TCP) {
            
            // 3. TCP Header 파싱
            // 위치: 패킷 시작점 + 에더넷 헤더 크기 + IP 헤더 크기
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            
            // [중요] myheader.h에 정의된 TH_OFF 매크로를 사용하여 TCP 헤더 크기 계산
            // TH_OFF 매크로 결과(워드 단위)에 4를 곱해 실제 바이트 길이를 구합니다.
            int tcp_header_len = TH_OFF(tcp) * 4;

            // 4. HTTP Message (Application 데이터) 위치 및 크기 계산
            int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = header->caplen - total_header_len;
            const u_char *payload = packet + total_header_len;

            // ---- 결과 출력 ----
            printf("\n=========================================\n");
            
            // [Ethernet] MAC 주소 출력
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

            // [TCP] 포트 번호 출력 (`tcp_sport`, `tcp_dport` 반영 및 바이트 오더 변환)
            printf("[TCP Header]\n");
            printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // [HTTP Message] 출력
            printf("[HTTP Message (Payload)]\n");
            if (payload_len > 0) {
                for (int i = 0; i < payload_len; i++) {
                    // 출력 가능한 문자이거나 개행 문자인 경우에만 출력
                    if (isprint(payload[i]) || payload[i] == '\r' || payload[i] == '\n') {
                        putchar(payload[i]);
                    } else {
                        putchar('.'); // 깨지는 이진 데이터는 '.' 처리
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
    
    // 과제 조건: TCP protocol만 대상이므로 필터를 "tcp"로 설정
    char filter_exp[] = "tcp port 80";
    bpf_u_int32 net;

    // 네트워크 환경에 맞춰 인터페이스 이름 수정 필요 (ex: "enp0s3", "eth0" 또는 "any")
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // 필터 컴파일 및 적용
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // 패킷 캡처 루프 실행
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   
    return 0;
}