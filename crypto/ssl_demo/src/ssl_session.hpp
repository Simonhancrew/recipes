#pragma once

#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace ssl_demo {

enum class ClientType {
  kClient,
  kServer,
};

enum class SslVersion {
  kTls1_2,
  kTls1_3,
};

enum class SslError {
  kSuccess = 0,
  kInitializationFailed,
  kHandshakeFailed,
  kCertificateError,
  kIOError,
  kInvalidState,
  kMemoryError,
};

struct Config {
  Config();
  ClientType client_type;
  SslVersion min_ssl_version;
  SslVersion max_ssl_version;
  std::string server_name;
  std::string verify_server_name;
  std::vector<std::string> extra_verify_server_names;
  std::vector<std::string> user_cas;
  std::vector<std::string> cipher_suites;
};

class SSLSession;

using OnDecryptedData = std::function<std::size_t(const uint8_t*, std::size_t)>;
using OnEncryptedData = std::function<std::size_t(const uint8_t*, std::size_t)>;
using HandshakeDoneCallback = std::function<void(bool)>;

class SSLSerializer {
 public:
  static std::unique_ptr<SSLSerializer> Create(Config&& config);
  explicit SSLSerializer(Config&& config);
  ~SSLSerializer();

  SSLSerializer(const SSLSerializer&) = delete;
  SSLSerializer& operator=(const SSLSerializer&) = delete;
  SSLSerializer(SSLSerializer&&) = default;
  SSLSerializer& operator=(SSLSerializer&&) = default;

  void SetHandshakeDoneCallback(HandshakeDoneCallback handshake_done_callback);
  void SetOnDecryptedData(OnDecryptedData on_decrypted_data);
  void SetOnEncryptedData(OnEncryptedData on_encrypted_data);

  bool DoHandshake();
  std::size_t FillPlainData(const char* data, std::size_t size);
  bool FillEncryptedData(const char* data, std::size_t size);

  [[nodiscard]] bool IsHandshakeDone() const;
  [[nodiscard]] bool IsValid() const;
  [[nodiscard]] SslError GetLastError() const;
  [[nodiscard]] std::string GetLastErrorString() const;
  [[nodiscard]] int GetCertificateVerifyCode() const;

  bool PopOutgoingData();

 private:
  std::unique_ptr<SSLSession> ssl_session_;
};

}  // namespace ssl_demo
