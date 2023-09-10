#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

// Define a structure to store the mapping between ports and PIDs
struct PortPIDMap {
    int port;
    int pid;
};

// Define a hashmap to store the mappings
struct PortPIDMap portPIDMap[65536];

// Define the packet processing function
void processPacket(const u_char *packet, struct pcap_pkthdr packet_header) {
    // Extract the port and PID information from the packet and store it in the hashmap
    // You'll need to parse the packet header and extract the necessary information here.
    // This code will depend on your specific packet format.

    // Example code to extract source and destination ports from a TCP packet header:
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));
    
    int src_port = ntohs(tcp_header->th_sport);
    int dst_port = ntohs(tcp_header->th_dport);

    // Assuming you have extracted src_port and dst_port, you can map them to a PID.
    // You'll need to implement this part based on the information you can extract from the packet.
    
    // For example, you can use a simple logic to map the port to a PID:
    int pid = getpid(); // Replace this with actual PID extraction logic
    
    // Store the mapping in the hashmap
    portPIDMap[src_port].port = src_port;
    portPIDMap[src_port].pid = pid;
    portPIDMap[dst_port].port = dst_port;
    portPIDMap[dst_port].pid = pid;
}

int main() {
    // Initialize the hashmap
    memset(portPIDMap, 0, sizeof(portPIDMap));

    // Open the network interface for packet capture (you'll need to replace "eth0" with your interface name)
    char *dev = "wlp0s20f3";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Start capturing packets for 30 seconds
    time_t start_time = time(NULL);
    while (1) {
        struct pcap_pkthdr packet_header;
        const u_char *packet = pcap_next(handle, &packet_header);

        if (packet == NULL) {
            continue;
        }

        processPacket(packet, packet_header);

        // Check if 30 seconds have passed
        time_t current_time = time(NULL);
        if (current_time - start_time >= 30) {
            break;
        }
    }

    // Close the packet capture interface
    pcap_close(handle);

    // Print the list of unique ports used during packet capture
    printf("List of ports used during packet capture:\n");
    for (int i = 0; i < 65536; i++) {
        if (portPIDMap[i].port != 0) {
            printf("%d\n", portPIDMap[i].port);
        }
    }

    // Prompt the user to enter a port number and look up the corresponding PID
    while (1) {
        int port;
        printf("Enter a port number (or Ctrl+C to exit): ");
        if (scanf("%d", &port) != 1) {
            break;
        }

        // Look up the PID in the hashmap
        int pid = portPIDMap[port].pid;

        if (pid == 0) {
            printf("Port not found.\n");
        } else {
            printf("Process ID for port %d: %d\n", port, pid);
        }
    }

    return 0;
}
