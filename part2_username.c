#include <stdio.h>
#include <string.h>
#include <pcap.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    char *search_string = "username=secret";
    char *data = (char *)packet;
    int data_len = pkthdr->len;

    // Search for the search_string in the packet data
    for (int i = 0; i < data_len - strlen(search_string); i++) {
        if (strncmp(data + i, search_string, strlen(search_string)) == 0) {
            printf("Connection secret found in packet:\n");
            printf("%.*s\n", data_len - i, data + i);
            return;
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
