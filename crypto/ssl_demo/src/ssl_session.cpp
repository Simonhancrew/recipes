#include "ssl_session.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <memory>
#include <mutex>
#include <sstream>

namespace ssl_demo {

namespace {

constexpr std::size_t kDefaultTlsRecordSize = 16 * 1024;

const std::unordered_map<SslVersion, int> kVersionMap = {
    {SslVersion::kTls1_2, TLS1_2_VERSION},
    {SslVersion::kTls1_3, TLS1_3_VERSION},
};

template <typename T, typename Deleter>
class ScopedResource {
 public:
  ScopedResource() : resource_(nullptr) {}
  explicit ScopedResource(T* resource) : resource_(resource) {}

  ~ScopedResource() {
    if (resource_) {
      Deleter()(resource_);
    }
  }

  T* get() const { return resource_; }
  T* release() {
    auto* tmp = resource_;
    resource_ = nullptr;
    return tmp;
  }

  explicit operator bool() const { return resource_ != nullptr; }

  ScopedResource(const ScopedResource&) = delete;
  ScopedResource& operator=(const ScopedResource&) = delete;

  ScopedResource(ScopedResource&& other) noexcept : resource_(other.resource_) {
    other.resource_ = nullptr;
  }

  ScopedResource& operator=(ScopedResource&& other) noexcept {
    if (this != &other) {
      if (resource_) {
        Deleter()(resource_);
      }
      resource_ = other.resource_;
      other.resource_ = nullptr;
    }
    return *this;
  }

 private:
  T* resource_;
};

struct SSLCTXDeleter {
  void operator()(SSL_CTX* ctx) const {
    if (ctx) SSL_CTX_free(ctx);
  }
};

struct SSLDeleter {
  void operator()(SSL* ssl) const {
    if (ssl) SSL_free(ssl);
  }
};

struct X509StoreDeleter {
  void operator()(X509_STORE* store) const {
    if (store) X509_STORE_free(store);
  }
};

struct X509Deleter {
  void operator()(X509* x509) const {
    if (x509) X509_free(x509);
  }
};

struct BIODeleter {
  void operator()(BIO* bio) const {
    if (bio) BIO_free(bio);
  }
};

using SSLContext = ScopedResource<SSL_CTX, SSLCTXDeleter>;
using SSLHandle = ScopedResource<SSL, SSLDeleter>;
using X509StoreHandle = ScopedResource<X509_STORE, X509StoreDeleter>;
using X509Handle = ScopedResource<X509, X509Deleter>;
using BIOHandle = ScopedResource<BIO, BIODeleter>;

}  // namespace

class Certificate {
 public:
  static std::unique_ptr<Certificate> CreateFromPemContent(
      const std::string& pem_content) {
    BIOHandle bio(BIO_new_mem_buf(pem_content.data(), pem_content.size()));
    if (!bio) {
      return nullptr;
    }

    X509* x509 = d2i_X509_bio(bio.get(), nullptr);
    if (!x509) {
      return nullptr;
    }

    return std::make_unique<Certificate>(x509);
  }

  explicit Certificate(X509* x509) : x509_(x509) {}

  [[nodiscard]] std::vector<uint8_t> Export() const {
    std::vector<uint8_t> result;
    BIOHandle bio(BIO_new(BIO_s_mem()));
    if (!bio) {
      return {};
    }

    if (i2d_X509_bio(bio.get(), x509_) <= 0) {
      return {};
    }

    result.resize(BIO_number_written(bio.get()));
    BIO_read(bio.get(), result.data(), result.size());
    return result;
  }

  ~Certificate() {
    if (x509_) {
      X509_free(x509_);
    }
  }

  Certificate(const Certificate&) = delete;
  Certificate& operator=(const Certificate&) = delete;
  Certificate(Certificate&&) = delete;
  Certificate& operator=(Certificate&&) = delete;

 private:
  X509* x509_{};
};

class SSLSession {
 public:
  explicit SSLSession(Config&& config) : config_(std::move(config)) {
    Initialize();
  }

  ~SSLSession() = default;

  SSLSession(const SSLSession&) = delete;
  SSLSession& operator=(const SSLSession&) = delete;

  SSLSession(SSLSession&&) = delete;
  SSLSession& operator=(SSLSession&&) = delete;

  void SetHandshakeDoneCallback(HandshakeDoneCallback handshake_done_callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    handshake_done_callback_ = std::move(handshake_done_callback);
  }

  void SetOnDecryptedData(OnDecryptedData on_decrypted_data) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_decrypted_data_ = std::move(on_decrypted_data);
  }

  void SetOnEncryptedData(OnEncryptedData on_encrypted_data) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_encrypted_data_ = std::move(on_encrypted_data);
  }

  bool DoHandshake() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValid()) {
      SetError(SslError::kInvalidState, "SSL session is not valid");
      return false;
    }

    auto ret = SSL_do_handshake(ssl_.get());
    if (ret == 1) {
      if (!handshake_done_) {
        handshake_done_ = true;
        cert_verify_code_ = SSL_get_verify_result(ssl_.get());
        NotifyHandshakeDone(true);
      }
      return true;
    }

    int err = SSL_get_error(ssl_.get(), ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      PopOutgoingData();
      return true;
    }

    cert_verify_code_ = SSL_get_verify_result(ssl_.get());
    SetError(SslError::kHandshakeFailed, GetSSLErrorString(err));
    NotifyHandshakeDone(false);
    return false;
  }

  std::size_t FillPlainData(const char* data, std::size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValid()) {
      SetError(SslError::kInvalidState, "SSL session is not valid");
      return 0;
    }

    if (!handshake_done_) {
      SetError(SslError::kInvalidState, "Handshake not completed");
      return 0;
    }

    std::size_t written = 0;
    while (size > 0) {
      auto write = SSL_write(ssl_.get(), data, size);
      if (write <= 0 && !BIO_ctrl_pending(wbio_.get())) {
        SetError(SslError::kIOError, "Failed to write plain data");
        return written;
      }

      if (!PopOutgoingData()) {
        SetError(SslError::kIOError, "Failed to pop outgoing data");
        return written;
      }

      if (write < 0) {
        write = 0;
      }
      size -= write;
      data += write;
      written += write;
    }
    return written;
  }

  bool FillEncryptedData(const char* data, std::size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValid()) {
      SetError(SslError::kInvalidState, "SSL session is not valid");
      return false;
    }

    std::size_t tot_write = 0;
    while (size > 0) {
      auto written = BIO_write(rbio_.get(), data, size);
      if (written <= 0) {
        SetError(SslError::kIOError, "Failed to write encrypted data");
        return false;
      }
      size -= written;
      data += written;
      tot_write += written;

      if (!handshake_done_) {
        if (!DoHandshake()) {
          return false;
        }
      } else {
        ProcessIncomingApplicationData();
      }
    }
    return true;
  }

  bool PopOutgoingData() {
    if (!IsValid()) {
      return false;
    }

    auto readable_wio_size = BIO_ctrl_pending(wbio_.get());
    if (readable_wio_size == 0) {
      return true;
    }

    bool retry = false;
    do {
      auto read =
          BIO_read(wbio_.get(), write_buffer_.data(), kDefaultTlsRecordSize);
      if (read > 0) {
        retry = false;
        NotifyOutgoingApplicationData(write_buffer_.data(), read);
        continue;
      }
      if (read < 0) {
        auto err = BIO_should_retry(wbio_.get());
        if (!retry && err != 0) {
          retry = true;
          continue;
        }
        return false;
      }
      return true;
    } while ((readable_wio_size = BIO_ctrl_pending(wbio_.get())) > 0);

    return true;
  }

  bool IsHandshakeDone() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return handshake_done_;
  }

  bool IsValid() const { return ssl_ && rbio_ && wbio_; }

  SslError GetLastError() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_error_;
  }

  std::string GetLastErrorString() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_error_string_;
  }

  int GetCertificateVerifyCode() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cert_verify_code_;
  }

 private:
  void Initialize() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

    bool is_client = config_.client_type == ClientType::kClient;

    ctx_ = SSLContext(
        SSL_CTX_new(is_client ? TLS_client_method() : TLS_server_method()));
    if (!ctx_) {
      SetError(SslError::kInitializationFailed, "Failed to create SSL context");
      return;
    }

    SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_PEER, nullptr);

    ssl_ = SSLHandle(SSL_new(ctx_.get()));
    if (!ssl_) {
      SetError(SslError::kInitializationFailed,
               "Failed to create SSL connection");
      return;
    }

    SSL_set_min_proto_version(ssl_.get(),
                              kVersionMap.at(config_.min_ssl_version));
    SSL_set_max_proto_version(ssl_.get(),
                              kVersionMap.at(config_.max_ssl_version));

    if (is_client) {
      SSL_set_connect_state(ssl_.get());
    } else {
      SSL_set_accept_state(ssl_.get());
    }

    if (!config_.cipher_suites.empty()) {
      std::string cipher_str;
      std::string sep;
      for (const auto& cipher : config_.cipher_suites) {
        cipher_str.append(sep).append(cipher);
        if (sep.empty()) {
          sep = ":";
        }
      }
      if (config_.cipher_suites.size() > 1) {
        cipher_str.append(":@STRENGTH");
      }
      SSL_set_cipher_list(ssl_.get(), cipher_str.data());
    }

    if (is_client && !config_.user_cas.empty()) {
      if (!SetupCertificateStore()) {
        return;
      }
    }

    if (!config_.server_name.empty()) {
      SSL_set_tlsext_host_name(ssl_.get(), config_.server_name.data());
    }

    if (!config_.verify_server_name.empty()) {
      auto* param = SSL_get0_param(ssl_.get());
      X509_VERIFY_PARAM_set1_host(param, config_.verify_server_name.data(),
                                  config_.verify_server_name.size());

      if (!config_.extra_verify_server_names.empty()) {
        for (const auto& hst : config_.extra_verify_server_names) {
          X509_VERIFY_PARAM_add1_host(param, hst.data(), hst.size());
        }
      }
    }

    rbio_ = BIOHandle(BIO_new(BIO_s_mem()));
    wbio_ = BIOHandle(BIO_new(BIO_s_mem()));
    if (!rbio_ || !wbio_) {
      SetError(SslError::kInitializationFailed, "Failed to create BIO");
      return;
    }

    SSL_set_bio(ssl_.get(), rbio_.get(), wbio_.get());

    rbio_.release();
    wbio_.release();

    handshake_done_ = false;
    cert_verify_code_ = X509_V_OK;
  }

  bool SetupCertificateStore() {
    store_ = X509StoreHandle(X509_STORE_new());
    if (!store_) {
      SetError(SslError::kInitializationFailed,
               "Failed to create certificate store");
      return false;
    }

    for (auto& cert : config_.user_cas) {
      auto cert_obj = Certificate::CreateFromPemContent(cert);
      if (!cert_obj) {
        continue;
      }

      auto buf = cert_obj->Export();
      if (buf.empty()) {
        continue;
      }

      BIOHandle fp(BIO_new_mem_buf(buf.data(), buf.size()));
      if (!fp) {
        continue;
      }

      X509* x509 = d2i_X509_bio(fp.get(), nullptr);
      if (!x509) {
        continue;
      }

      X509_STORE_add_cert(store_.get(), x509);
      X509_free(x509);
    }

    X509_STORE_set_flags(store_.get(), X509_V_FLAG_CHECK_SS_SIGNATURE);
    SSL_set0_verify_cert_store(ssl_.get(), store_.release());
    return true;
  }

  void ProcessIncomingApplicationData() {
    if (!handshake_done_) {
      return;
    }

    int byte_read = 0;
    int tot_read = 0;
    do {
      byte_read =
          SSL_read(ssl_.get(), read_buffer_.data(), kDefaultTlsRecordSize);
      if (byte_read <= 0) {
        break;
      }
      tot_read += byte_read;
      NotifyIncomingApplicationData(read_buffer_.data(), byte_read);
    } while (byte_read > 0);
  }

  void NotifyHandshakeDone(bool success) {
    if (handshake_done_callback_) {
      handshake_done_callback_(success);
    }
  }

  void NotifyIncomingApplicationData(const uint8_t* data, std::size_t size) {
    if (on_decrypted_data_) {
      on_decrypted_data_(data, size);
    }
  }

  std::size_t NotifyOutgoingApplicationData(const uint8_t* data,
                                            std::size_t size) {
    if (on_encrypted_data_) {
      return on_encrypted_data_(data, size);
    }
    return 0;
  }

  void SetError(SslError error, const std::string& message) const {
    last_error_ = error;
    last_error_string_ = message;
  }

  static std::string GetSSLErrorString(int err) {
    std::ostringstream oss;
    oss << "SSL error: " << err;
    return oss.str();
  }

  Config config_;
  SSLContext ctx_;
  SSLHandle ssl_;
  X509StoreHandle store_;
  BIOHandle rbio_;
  BIOHandle wbio_;
  mutable std::mutex mutex_;
  bool handshake_done_ = false;
  int64_t cert_verify_code_ = X509_V_OK;
  mutable SslError last_error_ = SslError::kSuccess;
  mutable std::string last_error_string_;
  HandshakeDoneCallback handshake_done_callback_;
  OnDecryptedData on_decrypted_data_;
  OnEncryptedData on_encrypted_data_;
  std::array<uint8_t, kDefaultTlsRecordSize> read_buffer_{};
  std::array<uint8_t, kDefaultTlsRecordSize> write_buffer_{};
};

Config::Config()
    : client_type(ClientType::kClient),
      min_ssl_version(SslVersion::kTls1_2),
      max_ssl_version(SslVersion::kTls1_3) {}

SSLSerializer::SSLSerializer(Config&& config)
    : ssl_session_(std::make_unique<SSLSession>(std::move(config))) {}

SSLSerializer::~SSLSerializer() = default;

std::unique_ptr<SSLSerializer> SSLSerializer::Create(Config&& config) {
  return std::make_unique<SSLSerializer>(std::move(config));
}

void SSLSerializer::SetHandshakeDoneCallback(
    HandshakeDoneCallback handshake_done_callback) {
  ssl_session_->SetHandshakeDoneCallback(std::move(handshake_done_callback));
}

void SSLSerializer::SetOnDecryptedData(OnDecryptedData on_decrypted_data) {
  ssl_session_->SetOnDecryptedData(std::move(on_decrypted_data));
}

void SSLSerializer::SetOnEncryptedData(OnEncryptedData on_encrypted_data) {
  ssl_session_->SetOnEncryptedData(std::move(on_encrypted_data));
}

bool SSLSerializer::DoHandshake() { return ssl_session_->DoHandshake(); }

std::size_t SSLSerializer::FillPlainData(const char* data, std::size_t size) {
  return ssl_session_->FillPlainData(data, size);
}

bool SSLSerializer::FillEncryptedData(const char* data, std::size_t size) {
  return ssl_session_->FillEncryptedData(data, size);
}

bool SSLSerializer::IsHandshakeDone() const {
  return ssl_session_->IsHandshakeDone();
}

bool SSLSerializer::IsValid() const { return ssl_session_->IsValid(); }

SslError SSLSerializer::GetLastError() const {
  return ssl_session_->GetLastError();
}

std::string SSLSerializer::GetLastErrorString() const {
  return ssl_session_->GetLastErrorString();
}

int SSLSerializer::GetCertificateVerifyCode() const {
  return ssl_session_->GetCertificateVerifyCode();
}

bool SSLSerializer::PopOutgoingData() {
  return ssl_session_->PopOutgoingData();
}

}  // namespace ssl_demo
