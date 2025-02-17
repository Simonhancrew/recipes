#include "net/socket.h"

namespace recipes::transport {

Socket::~Socket() { utils::close(fd_); }

} // namespace recipes::transport