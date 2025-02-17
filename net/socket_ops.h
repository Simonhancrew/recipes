#pragma once

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace recipes::utils {

const struct sockaddr *sockaddr_cast(const struct sockaddr_in6* addr);
void close(int fd);

} // namespace recipes::utils
