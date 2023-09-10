#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PCAP_FILE "0.pcap"

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the .pcap file
    handle = pcap_open_offline(PCAP_FILE, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Start packet processing loop
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the .pcap file
    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    u_char *tcp_flags;

    ip_header = (struct ip *)(packet + 14); // Assuming Ethernet frames, adjust as needed
    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);
        tcp_flags = (u_char *)&tcp_header->th_flags;

        // Print the TCP flags
        printf("TCP Flags: ");
        if (*tcp_flags & TH_FIN) printf("FIN ");
        if (*tcp_flags & TH_SYN) printf("SYN ");
        if (*tcp_flags & TH_RST) printf("RST ");
        if (*tcp_flags & TH_PUSH) printf("PSH ");
        if (*tcp_flags & TH_ACK) printf("ACK ");
        if (*tcp_flags & TH_URG) printf("URG ");
        printf("\n");
    }
}
