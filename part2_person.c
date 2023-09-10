#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_processor(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    
    ip_header = (struct ip*)(packet + 14);  // Skip Ethernet header

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    if (strcmp(source_ip, "131.144.126.118") == 0 || strcmp(dest_ip, "131.144.126.118") == 0) {
        tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));  // Skip IP header
        
        unsigned short src_port = ntohs(tcp_header->th_sport);
        unsigned short dst_port = ntohs(tcp_header->th_dport);

        printf("Source Port: %d\n", src_port);
        printf("Destination Port: %d\n", dst_port);

        // Calculate the sum of connection ports
        static unsigned long long total_port = 0;
        total_port += src_port + dst_port;
        printf("Sum of Connection Ports: %llu\n", total_port);
    }
}

int main(int arg_count, char *arg_values[]) {
    if (arg_count != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", arg_values[0]);
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;

    pcap_handle = pcap_open_offline(arg_values[1], error_buffer);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", error_buffer);
        return 1;
    }

    if (pcap_loop(pcap_handle, 0, packet_processor, NULL) < 0) {
        fprintf(stderr, "Error in pcap loop\n");
        return 1;
    }

    pcap_close(pcap_handle);
    return 0;
}