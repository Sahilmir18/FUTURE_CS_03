#ifndef DETECTION_H
#define DETECTION_H

#include <string>
#include "packet_structs.h"

void detect_syn_scan(const tcp_header* tcp, const std::string& src_ip);

#endif
