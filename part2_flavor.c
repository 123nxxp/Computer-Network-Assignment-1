#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

// Function to extract the host from an HTTP request
void extract_host(const char *http_data) {
    const char *host_prefix = "Host: ";
    const char *host_start = strstr(http_data, host_prefix);

    if (host_start) {
        host_start += strlen(host_prefix);
        const char *host_end = strchr(host_start, '\r');
        if (host_end) {
            int host_len = host_end - host_start;
            char host[host_len + 1];
            strncpy(host, host_start, host_len);
            host[host_len] = '\0';
            printf("Host: %s\n", host);
        }
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // Ethernet header is 14 bytes

    if (ip_header->ip_src.s_addr == inet_addr("127.0.0.1")) {
        if (ip_header->ip_p == IPPROTO_TCP) {  // Check for TCP traffic
            const u_char *tcp_payload = packet + 14 + (ip_header->ip_hl << 2) + (4 * (((struct tcphdr *)(((char *)ip_header) + (ip_header->ip_hl << 2)))->th_off));
            int tcp_payload_len = pkthdr->len - (14 + (ip_header->ip_hl << 2) + (4 * (((struct tcphdr *)(((char *)ip_header) + (ip_header->ip_hl << 2)))->th_off)));
            char tcp_data[tcp_payload_len + 1];
            strncpy(tcp_data, (const char *)tcp_payload, tcp_payload_len);
            tcp_data[tcp_payload_len] = '\0';

            if (strstr(tcp_data, "HTTP") != NULL) {  // Check if it's an HTTP packet
                extract_host(tcp_data);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    char *filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error in pcap_loop()\n");
        return 1;
    }

    pcap_close(handle);
    return 0;
}