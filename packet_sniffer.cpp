#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <cstring>
#include "packet_structs.h"
#include "detection.h"

using namespace std;

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    const eth_header* eth = (eth_header*)packet;
    if (ntohs(eth->type) != 0x0800) return;

    const ip_header* ip = (ip_header*)(packet + sizeof(eth_header));
    u_char ip_header_len = (ip->ver_len & 0x0F) * 4;

    if (ip->protocol != 6) return; // Not TCP

    const tcp_header* tcp = (tcp_header*)(packet + sizeof(eth_header) + ip_header_len);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->src_addr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->dest_addr), dst_ip, INET_ADDRSTRLEN);

    cout << "[+] TCP Packet: " << src_ip << " → " << dst_ip
         << " | Src Port: " << ntohs(tcp->src_port)
         << " | Dst Port: " << ntohs(tcp->dest_port) << endl;

    detect_syn_scan(tcp, src_ip);
}

void start_sniffing() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    int i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error: " << errbuf << endl;
        return;
    }

    cout << "[*] Available Devices:" << endl;
    for (dev = alldevs; dev; dev = dev->next)
        cout << "  [" << i++ << "] " << dev->name << endl;

    cout << "Select device index: ";
    int choice;
    cin >> choice;

    dev = alldevs;
    for (int j = 0; j < choice && dev; j++) dev = dev->next;

    if (!dev) {
        cerr << "Invalid selection." << endl;
        pcap_freealldevs(alldevs);
        return;
    }

    pcap_t* handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Could not open device: " << errbuf << endl;
        return;
    }

    cout << "[*] Sniffing on: " << dev->name << endl;
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
}
