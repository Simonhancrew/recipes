#include "net/socket_ops.h"

namespace recipes::utils {

const struct sockaddr *sockaddr_cast(const struct sockaddr_in6 *addr) {
  return static_cast<const struct sockaddr *>(
      reinterpret_cast<const void *>(addr));
}

void close(int fd) {
#if defined(_WIN32)
  ::closesocket(fd);
#elif defined(__linux__)
  ::close(fd);
#endif
}

} // namespace recipes::utils
