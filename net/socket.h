#pragma once

#include "net_address.h"

namespace recipes::transport {

class Socket {
public:
  explicit Socket(int fd) : fd_(fd) {}
  ~Socket();

  int Fd() const;
  bool GetTcpInfo(struct tcp_info *) const;
  bool GetTcpInfoString(char *buf, int len) const;
  void BindAddress(const NetAddress &localaddr);
  void Listen();
  int Accept(NetAddress *peeraddr);
  void ShutdownWrite();
  void SetTcpNoDelay(bool on);
  void SetReuseAddr(bool on);
  void SetReusePort(bool on);
  void SetKeepAlive(bool on);

private:
  int fd_;
};

} // namespace recipes::transport
