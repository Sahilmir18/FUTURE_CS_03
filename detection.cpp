#include "detection.h"
#include "logger.h"

void detect_syn_scan(const tcp_header* tcp, const std::string& src_ip) {
    bool syn = tcp->flags & 0x02;
    bool ack = tcp->flags & 0x10;
    if (syn && !ack) {
        log_alert("Possible SYN scan from " + src_ip);
    }
}
