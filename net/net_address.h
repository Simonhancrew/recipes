#pragma once

#include "net/socket_ops.h"
#include <cstdint>
#include <string>


namespace recipes::utils {
class BufferView;
} // namespace recipes::utils

namespace recipes::transport {

class NetAddress {
public:
  explicit NetAddress(uint16_t port = 0, bool loopbackOnly = false,
                      bool ipv6 = false);
  NetAddress(const utils::BufferView &ip, uint16_t port, bool ipv6 = false);
  explicit NetAddress(const struct sockaddr_in &addr) : addr_(addr) {}
  explicit NetAddress(const struct sockaddr_in6 &addr) : addr6_(addr) {}
  int Family() const { return addr_.sin_family; }

  std::string ToIp() const;
  std::string ToIpPort() const;
  uint16_t Port() const;
  // default copy/assignment are Okay
  const struct sockaddr *GetSockAddr() const {
    return utils::sockaddr_cast(&addr6_);
  }
  void SetSockAddrInet6(const struct sockaddr_in6 &addr6) { addr6_ = addr6; }
  uint32_t Ipv4NetEndian() const;
  uint16_t PortNetEndian() const { return addr_.sin_port; }
  static bool Resolve(const utils::BufferView &hostname, NetAddress *result);
  void SetScopeId(uint32_t scope_id);

private:
  union {
    struct sockaddr_in addr_;
    struct sockaddr_in6 addr6_;
  };
};

} // namespace recipes::transport
