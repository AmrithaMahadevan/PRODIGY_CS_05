#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <iomanip>

// Callback function to handle packets
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *iph = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)

    // Print packet information
    std::cout << "Received packet at " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec 
              << " caplen=" << pkthdr->caplen << " len=" << pkthdr->len << std::endl;
    
    // Print IP addresses and protocol
    std::cout << "IP src=" << inet_ntoa(iph->ip_src) 
              << " dst=" << inet_ntoa(iph->ip_dst) 
              << " protocol=" << static_cast<int>(iph->ip_p) << std::endl;

    // Print payload data
    int ip_header_length = iph->ip_hl * 4;
    const u_char *payload = packet + 14 + ip_header_length; // Skip Ethernet and IP headers
    int payload_length = pkthdr->len - (14 + ip_header_length);

    if (payload_length > 0) {
        std::cout << "Payload: ";
        for (int i = 0; i < payload_length; ++i) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(payload[i]);
        }
        std::cout << std::endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDevs;
    pcap_if_t *device;

    // Get a list of devices
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Network devices found:" << std::endl;
    for (device = allDevs; device != nullptr; device = device->next) {
        std::cout << device->name 
                  << " [" << (device->description ? device->description : "No description available") 
                  << "]" << std::endl;
    }

    // Choose the first device
    device = allDevs;
    if (device == nullptr) {
        std::cerr << "No devices found." << std::endl;
        pcap_freealldevs(allDevs);
        return 1;
    }

    std::cout << "Using device: " << device->name << std::endl;

    // Open the device for packet capture
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        pcap_freealldevs(allDevs);
        return 1;
    }

    // Capture 10 packets
    pcap_loop(handle, 10, packetHandler, nullptr);

    // Clean up
    pcap_freealldevs(allDevs);
    pcap_close(handle);

    return 0;
}
