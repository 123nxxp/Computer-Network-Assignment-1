#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Structure to represent a unique TCP connection
struct TCPConnection {
    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];
    uint16_t source_port;
    uint16_t destination_port;
};

// Compare function for TCP connections
int compare_connection(const void *a, const void *b) {
    const struct TCPConnection *conn_a = (const struct TCPConnection *)a;
    const struct TCPConnection *conn_b = (const struct TCPConnection *)b;

    int cmp = strcmp(conn_a->source_ip, conn_b->source_ip);
    if (cmp == 0) {
        cmp = conn_a->source_port - conn_b->source_port;
        if (cmp == 0) {
            cmp = strcmp(conn_a->destination_ip, conn_b->destination_ip);
            if (cmp == 0) {
                cmp = conn_a->destination_port - conn_b->destination_port;
            }
        }
    }
    return cmp;
}

int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;

    pcap_handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, error_buffer);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Error opening interface: %s\n", error_buffer);
        return 1;
    }

    struct TCPConnection connection_list[1024];  // Assuming a maximum of 1024 unique connections
    int connection_count = 0;

    while (true) {
        struct pcap_pkthdr packet_header;
        const u_char *packet_data = pcap_next(pcap_handle, &packet_header);

        if (packet_data == NULL) {
            continue;
        }

        struct ip *ip_packet_header = (struct ip *)(packet_data + 14);
        struct tcphdr *tcp_packet_header = (struct tcphdr *)(packet_data + 14 + ip_packet_header->ip_hl * 4);

        // Extract the connection
        struct TCPConnection current_connection;
        inet_ntop(AF_INET, &(ip_packet_header->ip_src), current_connection.source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_packet_header->ip_dst), current_connection.destination_ip, INET_ADDRSTRLEN);
        current_connection.source_port = ntohs(tcp_packet_header->th_sport);
        current_connection.destination_port = ntohs(tcp_packet_header->th_dport);

        // Check if the connection is already in the list
        bool connection_exists = false;
        for (int i = 0; i < connection_count; i++) {
            if (compare_connection(&connection_list[i], &current_connection) == 0) {
                connection_exists = true;
                break;
            }
        }

        if (!connection_exists) {
            // Add the new connection to the list
            connection_list[connection_count] = current_connection;
            connection_count++;

            // Print the connection information
            printf("Source IP: %s, Source Port: %d, Destination IP: %s, Destination Port: %d, Connection Count: %d\n",
                   current_connection.source_ip, current_connection.source_port,
                   current_connection.destination_ip, current_connection.destination_port, connection_count);
        }
    }

    pcap_close(pcap_handle);
    return 0;
}