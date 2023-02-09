#include "session.h"

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <utility>

#include "http_request_parser.h"
#include "http_response_parser.h"
#include "logger.h"

using namespace boost;
using namespace std::placeholders;
using asio::ip::tcp;

namespace Proxy {

Session::Session(asio::io_context& io_context, tcp::socket&& client_socket,
                 const Server::RootCAInfo& root_ca_info,
                 Server::InterceptedSessionsQueue& intercepted_sessions_queue,
                 const Server::TInterceptCB& intercept_cb,
                 bool intercept_to_host_enabled,
                 bool intercept_to_client_enabled,
                 std::string host_interception_filter)
    : io_context(io_context),
      root_ca_info(root_ca_info),
      intercepted_sessions_queue(intercepted_sessions_queue),
      intercept_cb(intercept_cb),
      resolver(io_context),
      client_socket(std::move(client_socket)),
      remote_socket(io_context),
      request_parser(),
      intercept_to_host_enabled(intercept_to_host_enabled),
      intercept_to_client_enabled(intercept_to_client_enabled),
      host_interception_filter(host_interception_filter) {}

// Not in constructor because this->shared_from_this needs an initialized object
// before running
void Session::start() {
  // Must open a connection before set_option
  /*this->remote_socket.open(tcp::v4());
  this->remote_socket.set_option(tcp::no_delay(true));*/

  // auto [error, bytes_transferred] = co_await asio::async_read(
  //     this->client_socket, this->streambuf, asio::transfer_all(),
  //     asio::as_tuple(asio::use_awaitable));

  std::shared_ptr<std::vector<char>> buffer =
      std::make_shared<std::vector<char>>(BUFFER_SIZE);

  asio::async_read(this->client_socket, asio::buffer(*buffer),
                   asio::transfer_at_least(1),
                   std::bind(&Session::on_request_read,
                             this->shared_from_this(), _1, _2, buffer));
}

void Session::on_request_read(const system::error_code& error,
                              std::size_t bytes_transferred,
                              std::shared_ptr<std::vector<char>> buffer) {
  if (error && error != asio::error::eof) {
    LOG_ERROR << error.message();
    return;
  }

  if (bytes_transferred == 0) return;

  this->request_parser.process_chunk(buffer->data(), bytes_transferred);

  if (!this->request_parser.message_complete) {
    return asio::async_read(
        this->client_socket, asio::buffer(*buffer), asio::transfer_at_least(1),
        std::bind(&Session::on_request_read, this->shared_from_this(), _1, _2,
                  buffer));
  }

  LOG_DEBUG << "Target: " << this->request_parser.host.name << ":"
            << this->request_parser.host.port;

  // tcp::resolver::query query(this->request_parser.host.name,
  //     std::to_string(this->request_parser.host.port),
  //     asio::ip::resolver_query_base::numeric_service);

  this->resolver.async_resolve(
      this->request_parser.host.name,
      std::to_string(this->request_parser.host.port),
      std::bind(&Session::on_remote_resolve, this->shared_from_this(), _1, _2));
}

void Session::on_remote_resolve(const system::error_code& error,
                                tcp::resolver::iterator endpoint_iterator) {
  if (error) {
    LOG_ERROR << error.message();
    return;
  }

  asio::async_connect(
      this->remote_socket, std::move(endpoint_iterator),
      std::bind(&Session::on_remote_connect, this->shared_from_this(), _1));
}

void Session::on_remote_connect(const system::error_code& error) {
  if (error) {
    LOG_ERROR << error.message();
    return;
  }

  this->remote_host = this->request_parser.host.name + ":" +
                      std::to_string(this->request_parser.host.port);

  // SSL
  if (this->request_parser.method == "CONNECT") {
    std::string response = "HTTP/1.0 200 Connection established\r\n\r\n";
    this->client_socket.async_send(
        asio::buffer(response.data(), response.size()),
        std::bind(&Session::on_ssl_response_sent, this->shared_from_this(), _1,
                  _2));
  }
  // Not SSL
  else {
    // Skip reading the request from the client as we already have it
    const boost::system::error_code empty_error = boost::system::error_code();
    this->on_proxy_data_read(
        empty_error, this->request_parser.raw_message.size(),
        std::make_shared<HttpParser::HttpRequestParser>(),
        std::make_shared<std::vector<char>>(this->request_parser.raw_message),
        this->client_socket, this->remote_socket,
        this->intercept_to_host_enabled);

    this->proxy_data<tcp::socket, HttpParser::HttpResponseParser>(
        this->remote_socket, this->client_socket,
        this->intercept_to_client_enabled);
  }
}

void Session::on_ssl_response_sent(const system::error_code& error,
                                   std::size_t bytes_transferred) {
  if (error) {
    LOG_ERROR << error.message();
    return;
  }

  this->remote_ctx.emplace(asio::ssl::context::sslv23_client);

  this->remote_ctx->set_options(asio::ssl::context::no_compression);
  // ctx.set_options(asio::ssl::context::default_workarounds ||
  //                 asio::ssl::context::verify_none);

  this->remote_ctx->set_default_verify_paths();

  this->ssl_remote_socket.emplace(this->remote_socket, *this->remote_ctx);

  // Set SNI
  SSL_set_tlsext_host_name(this->ssl_remote_socket->native_handle(),
                           this->request_parser.host.name.c_str());

  this->ssl_remote_socket->async_handshake(
      asio::ssl::stream_base::client,
      std::bind(&Session::on_remote_handshake, this->shared_from_this(), _1));
}

void Session::on_remote_handshake(const system::error_code& error) {
  if (error) {
    LOG_ERROR << error.message();
    return;
  }

  X509* p_server_pub_cert =
      SSL_get_peer_certificate(this->ssl_remote_socket->native_handle());

  std::tuple<std::string, std::string> resigned_server_cert =
      this->resign_certificate(p_server_pub_cert,
                               this->request_parser.host.name);

  std::string p_cert_pub_str = std::get<0>(resigned_server_cert);
  std::string p_cert_key_str = std::get<1>(resigned_server_cert);

  this->client_ctx.emplace(asio::ssl::context::sslv23_server);

  /*SSL_CTX_set_options(ssl_context,
                      SSL_OP_NO_COMPRESSION | SSL_MODE_RELEASE_BUFFERS);*/

  this->client_ctx->set_options(asio::ssl::context::no_compression);

  // ctx.set_options(asio::ssl::context::default_workarounds |
  //                 asio::ssl::context::verify_none);

  this->client_ctx->use_certificate(
      asio::const_buffer(p_cert_pub_str.c_str(), p_cert_pub_str.length()),
      asio::ssl::context::file_format::pem);

  this->client_ctx->use_private_key(
      asio::const_buffer(p_cert_key_str.c_str(), p_cert_key_str.length()),
      asio::ssl::context::file_format::pem);

  this->ssl_client_socket.emplace(this->client_socket, *this->client_ctx);

  this->ssl_client_socket->async_handshake(
      asio::ssl::stream_base::server,
      std::bind(&Session::on_client_handshake, this->shared_from_this(), _1));
}

void Session::on_client_handshake(const system::error_code& error) {
  if (error) {
    LOG_ERROR << error.message();
    return;
  }

  this->proxy_data<asio::ssl::stream<tcp::socket&>,
                   HttpParser::HttpRequestParser>(
      this->ssl_client_socket.value(), this->ssl_remote_socket.value(),
      this->intercept_to_host_enabled);

  this->proxy_data<asio::ssl::stream<tcp::socket&>,
                   HttpParser::HttpResponseParser>(
      this->ssl_remote_socket.value(), this->ssl_client_socket.value(),
      this->intercept_to_client_enabled);
}

template <class T_stream, class T_parser>
void Session::proxy_data(T_stream& from, T_stream& to, bool intercept) {
  static_assert(std::is_base_of<HttpParser::HttpParser, T_parser>::value,
                "T_parser must extend HttpParser");

  std::shared_ptr<T_parser> parser = std::make_shared<T_parser>();
  std::shared_ptr<std::vector<char>> buffer =
      std::make_shared<std::vector<char>>(BUFFER_SIZE);

  asio::async_read(from, asio::buffer(*buffer), asio::transfer_at_least(1),
                   [self = this->shared_from_this(), parser, buffer, &from, &to,
                    intercept](auto&&... args) {
                     self->on_proxy_data_read<T_stream, T_parser>(
                         args..., parser, buffer, from, to, intercept);
                   });
}

template <class T_stream, class T_parser>
void Session::on_proxy_data_read(const system::error_code& error,
                                 std::size_t bytes_transferred,
                                 std::shared_ptr<T_parser> parser,
                                 std::shared_ptr<std::vector<char>> buffer,
                                 T_stream& from, T_stream& to, bool intercept) {
  if (error && error != asio::error::eof) {
    LOG_ERROR << error.message();
    return;
  }

  if (bytes_transferred == 0) return;

  try {
    parser->process_chunk(buffer->data(), bytes_transferred);
  } catch (std::exception& e) {
    LOG_ERROR << e.what();
  }

  if (!parser->message_complete) {
    return asio::async_read(from, asio::buffer(*buffer),
                            asio::transfer_at_least(1),
                            [self = this->shared_from_this(), parser, buffer,
                             &from, &to, intercept](auto&&... args) {
                              self->on_proxy_data_read<T_stream, T_parser>(
                                  args..., parser, buffer, from, to, intercept);
                            });
  }

  // Intercept only if content type is text
  if (parser->headers.count("content-type") > 0 &&
      parser->headers["content-type"].find("text/") == std::string::npos &&
      parser->headers["content-type"].find("application/") ==
          std::string::npos) {
    intercept = false;
  }

  // Intercept only if matches the intercept filter
  if (this->host_interception_filter != "" &&
      this->host_interception_filter != this->request_parser.host.name) {
    intercept = false;
  }

  std::vector<char> readable_message = parser->build(false);

  if (intercept && this->intercept_cb.has_value()) {
    std::function<void(T_stream&, const std::vector<char>&)>
        intercept_response_cb;
    intercept_response_cb = [self = this->shared_from_this()](
                                T_stream& to,
                                const std::vector<char>& altered_message) {
      auto final_message = std::make_shared<std::vector<char>>();
      T_parser altered_parser;
      altered_parser.process_chunk(altered_message.data(),
                                   altered_message.size(), false);
      *final_message = altered_parser.build();

      asio::async_write(
          to, asio::buffer(final_message->data(), final_message->size()),
          [self = self->shared_from_this(), final_message](auto&&... args) {
            self->on_proxy_data_sent(args...);
          });
      self->intercepted_sessions_queue.pop();

      if (!self->intercepted_sessions_queue.empty()) {
        auto next_intercepted_session =
            self->intercepted_sessions_queue.front();

        self->intercept_cb.value()(
            next_intercepted_session.http_message, self->remote_host,
            *next_intercepted_session.intercept_response_cb);
      }
    };

    Server::TInterceptResponseCB intercept_response_cb_bind =
        std::bind(intercept_response_cb, std::ref(to), _1);

    Server::InterceptedSession intercepted_session = {
        .session = this->shared_from_this(),
        .http_message = readable_message,
        .intercept_response_cb = std::make_shared<Server::TInterceptResponseCB>(
            intercept_response_cb_bind)};

    this->intercepted_sessions_queue.push(intercepted_session);

    if (this->intercepted_sessions_queue.size() == 1) {
      this->intercept_cb.value()(readable_message, this->remote_host,
                                 intercept_response_cb_bind);
    }

  } else {
    auto final_message = std::make_shared<std::vector<char>>();
    *final_message = parser->raw_message;
    asio::async_write(
        to, asio::buffer(final_message->data(), final_message->size()),
        [self = this->shared_from_this(), final_message](auto&&... args) {
          self->on_proxy_data_sent(args...);
        });
  }
}

void Session::on_proxy_data_sent(const system::error_code& error,
                                 std::size_t bytes_transferred) {
  if (error && error != asio::error::eof) {
    LOG_ERROR << error.message();
    return;
  }
}

// Session::~Session() {
//   LOG_INFO << "Count: " << ObjectCount::count;
//  if (this->ssl_client_socket.has_value()) {
//    SSL_CTX_free(this->remote_ctx->native_handle());
//    SSL_CTX_free(this->client_ctx->native_handle());
//  }
// }

void add_ext(X509* cert, X509* issuer_cert, X509_REQ* req_cert, int nid,
             const char* value) {
  X509_EXTENSION* ex = NULL;
  X509V3_CTX ctx;

  X509V3_set_ctx_nodb(&ctx);
  // X509V3_set_ctx(&ctx, cert, issuer_cert, NULL, NULL, 0);
  // X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  X509V3_set_ctx(&ctx, cert, NULL, NULL, NULL, 0);
  ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
}

int generate_set_random_serial(X509* crt) {
  /* Generates a 10 byte random serial number and sets in certificate. */
  unsigned char serial_bytes[10];
  if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
  serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
  BIGNUM* bn = BN_new();
  BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
  ASN1_INTEGER* serial = ASN1_INTEGER_new();
  BN_to_ASN1_INTEGER(bn, serial);

  X509_set_serialNumber(crt, serial);  // Set serial.

  ASN1_INTEGER_free(serial);
  BN_free(bn);
  return 1;
}

X509* Session::generate_cert(X509* p_server_cert, const char* hostname) {
  X509* p_generated_cert = nullptr;
  ASN1_INTEGER* p_serial_number = nullptr;
  X509_NAME* p_subject_name = nullptr;
  std::string san_dns;

  p_generated_cert = X509_new();

  X509_set_version(p_generated_cert, 2);

  // p_serial_number = X509_get_serialNumber(p_server_cert);
  // // p_serial_number = X509_get_serialNumber(this->p_ca_cert);
  // X509_set_serialNumber(p_generated_cert, p_serial_number);
  generate_set_random_serial(p_generated_cert);

  add_ext(p_generated_cert, this->root_ca_info.p_ca_cert, NULL, NID_key_usage,
          "dataEncipherment,keyEncipherment,digitalSignature");

  add_ext(p_generated_cert, this->root_ca_info.p_ca_cert, NULL,
          NID_ext_key_usage,
          "critical,codeSigning,1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2");

  //// san_dns = "DNS:" + std::string(hostname);
  san_dns = std::string(hostname);

  GENERAL_NAMES* gens = sk_GENERAL_NAME_new_null();
  GENERAL_NAME* gen_dns = GENERAL_NAME_new();
  ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
  ASN1_STRING_set(ia5, san_dns.data(), (int)san_dns.length());
  GENERAL_NAME_set0_value(gen_dns, GEN_DNS, ia5);
  sk_GENERAL_NAME_push(gens, gen_dns);
  X509_add1_ext_i2d(p_generated_cert, NID_subject_alt_name, gens, 0,
                    X509V3_ADD_DEFAULT);
  sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

  p_subject_name = X509_get_subject_name(p_server_cert);

  X509_set_issuer_name(p_generated_cert, p_subject_name);
  X509_set_subject_name(p_generated_cert, p_subject_name);

  X509_gmtime_adj(X509_get_notBefore(p_generated_cert), 0L);
  X509_gmtime_adj(X509_get_notAfter(p_generated_cert), 31536000L);

  if (0 >
      X509_set_pubkey(p_generated_cert, this->root_ca_info.p_resigned_key)) {
    printf("failed to set pkey\n");
    X509_free(p_generated_cert);
    p_generated_cert = nullptr;
    goto CLEANUP;
  }

  if (0 > EVP_PKEY_copy_parameters(this->root_ca_info.p_ca_pkey,
                                   this->root_ca_info.p_ca_key_pkey)) {
    printf("failed to copy parameters\n");
    X509_free(p_generated_cert);
    p_generated_cert = nullptr;
    goto CLEANUP;
  }

  X509_set_issuer_name(p_generated_cert,
                       X509_get_subject_name(this->root_ca_info.p_ca_cert));

  if (0 > X509_sign(p_generated_cert, this->root_ca_info.p_ca_key_pkey,
                    EVP_sha256())) {
    printf("failed to sign the certificate\n");
    X509_free(p_generated_cert);
    p_generated_cert = nullptr;
    goto CLEANUP;
  }

CLEANUP:
  ASN1_INTEGER_free(p_serial_number);
  X509_NAME_free(p_subject_name);
  return p_generated_cert;
}

std::tuple<std::string, std::string> Session::resign_certificate(
    X509* p_pub_certificate, std::string hostname) {
  BIO* p_cert_bio;
  BIO* p_key_bio;
  X509* p_resigned_cert_pub =
      this->generate_cert(p_pub_certificate, (char*)hostname.c_str());

  // Convert x509 to char*
  char p_cert_pub_str[4096];
  p_cert_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(p_cert_bio, p_resigned_cert_pub);
  size_t cert_length = BIO_number_written(p_cert_bio);
  p_cert_pub_str[cert_length] = 0;
  BIO_read(p_cert_bio, p_cert_pub_str, cert_length);

  // Convert RSA to char*
  char p_cert_key_str[4096];
  p_key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(p_key_bio, this->root_ca_info.p_resigned_key, NULL,
                           NULL, 0, NULL, NULL);

  size_t key_length = BIO_number_written(p_key_bio);
  p_cert_key_str[key_length] = 0;
  BIO_read(p_key_bio, p_cert_key_str, (int)key_length);

  BIO_free(p_cert_bio);
  BIO_free(p_key_bio);
  X509_free(p_resigned_cert_pub);

  return {p_cert_pub_str, p_cert_key_str};
}

}  // namespace Proxy