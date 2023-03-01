#include "session.h"

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <iostream>
#include <utility>

#include "boost/uuid/random_generator.hpp"
#include "cert.h"
#include "http_request_parser.h"
#include "http_response_parser.h"
#include "logger.h"

using namespace boost;
using namespace std::placeholders;
using asio::ip::tcp;

namespace Proxy {

Session::Session(
    asio::io_context& io_context, tcp::socket&& client_socket,
    const Cert::RootCAInfo& root_ca_info,
    Server::InterceptedSessions& intercepted_sessions_queue,
    Server::ResignedCertificatesCache& resigned_certificates_cache,
                 const std::optional<Server::TInterceptCB>& intercept_cb,
                 const bool& intercept_to_host_enabled,
                 const bool& intercept_to_client_enabled,
                 const std::string& host_interception_filter)
    : io_context(io_context),
      root_ca_info(root_ca_info),
      intercepted_sessions(intercepted_sessions_queue),
      resigned_certificates_cache(resigned_certificates_cache),
      intercept_cb(intercept_cb),
      resolver(io_context),
      client_socket(std::move(client_socket)),
      remote_socket(io_context),
      request_parser(),
      is_ssl(false),
      remote_host(),
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

  this->is_ssl = this->request_parser.method == "CONNECT";

  this->remote_host = {.name = this->request_parser.host.name,
                       .port = this->request_parser.host.port};

  LOG_DEBUG << "Target: " << this->remote_host.name << ":"
            << this->remote_host.port;

  // tcp::resolver::query query(this->request_parser.host.name,
  //     std::to_string(this->request_parser.host.port),
  //     asio::ip::resolver_query_base::numeric_service);

  this->resolver.async_resolve(
      this->remote_host.name, std::to_string(this->remote_host.port),
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

  if (this->is_ssl) {
    std::string response = "HTTP/1.0 200 Connection established\r\n\r\n";
    this->client_socket.async_send(
        asio::buffer(response.data(), response.size()),
        std::bind(&Session::on_ssl_response_sent, this->shared_from_this(), _1,
                  _2));
  } else {
    // Skip reading the request from the client (proxy_data) as we
    // already have it and call on_proxy_data_read directly
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

  SSL_CTX_set_options(this->remote_ctx->native_handle(),
                      SSL_OP_NO_COMPRESSION | SSL_MODE_RELEASE_BUFFERS |
                          SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

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

  // X509* p_server_pub_cert =
  //     SSL_get_peer_certificate(this->ssl_remote_socket->native_handle());

  const std::string& hostname = this->remote_host.name;

  Cert::CertInfo resigned_server_cert;

  // Check if the certificate is already in the cache
  if (this->resigned_certificates_cache.find(hostname) !=
      this->resigned_certificates_cache.end()) {
    // Get the certificate from the cache
    resigned_server_cert = this->resigned_certificates_cache[hostname];
  } else {
    resigned_server_cert =
        Cert::generate_certificate(this->root_ca_info, hostname);

    // Add the certificate to the cache
    this->resigned_certificates_cache[hostname] = resigned_server_cert;
  }

  std::string p_cert_pub_str = resigned_server_cert.cert;
  std::string p_cert_key_str = resigned_server_cert.key;

  this->client_ctx.emplace(asio::ssl::context::sslv23_server);

  SSL_CTX_set_options(this->remote_ctx->native_handle(),
                      SSL_OP_NO_COMPRESSION | SSL_MODE_RELEASE_BUFFERS |
                          SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
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

  // Save the request parser for later use
  // (might overwrite the HTTPS CONNECT parser)
  if constexpr (std::is_same_v<T_parser, HttpParser::HttpRequestParser>) {
    this->request_parser = *parser;
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
      this->remote_host.name.find(this->host_interception_filter) ==
          std::string::npos) {
    intercept = false;
  }

  std::vector<char> readable_message = parser->build(false);

  if (intercept && this->intercept_cb.has_value()) {
    std::function<void(uuids::uuid, T_stream&, const std::vector<char>&)>
        intercept_response_cb;
    intercept_response_cb = [self = this->shared_from_this(),
                             original_message_parser = parser,
                             original_message = readable_message](
                                uuids::uuid interception_id, T_stream& to,
                                const std::vector<char>& altered_message) {
      std::shared_ptr<std::vector<char>> final_message;
      // If the message was not altered,
      // send the original message instead of building it again
      if (false && original_message == altered_message) {
        final_message = std::make_shared<std::vector<char>>(
            original_message_parser->raw_message);
      } else {
      T_parser altered_parser;
      altered_parser.process_chunk(altered_message.data(),
                                   altered_message.size(), false);
        final_message =
            std::make_shared<std::vector<char>>(altered_parser.build());
      }

      asio::async_write(
          to, asio::buffer(final_message->data(), final_message->size()),
          [self = self->shared_from_this(), final_message](auto&&... args) {
            self->on_proxy_data_sent(args...);
          });

      auto it = std::find_if(self->intercepted_sessions.begin(),
                             self->intercepted_sessions.end(),
                             [&](auto intercepted_session) {
                               return intercepted_session.id == interception_id;
                             });

      if (it != self->intercepted_sessions.end()) {
        self->intercepted_sessions.erase(it);
      }
    };

    uuids::uuid id = uuids::random_generator()();

    Server::TInterceptResponseCB intercept_response_cb_bind =
        std::bind(intercept_response_cb, id, std::ref(to), _1);

    Server::RequestType request_type;
    if constexpr (std::is_same_v<T_parser, HttpParser::HttpRequestParser>) {
      request_type = Server::RequestType::HTTP_REQUEST;
    } else if constexpr (std::is_same_v<T_parser,
                                        HttpParser::HttpResponseParser>) {
      request_type = Server::RequestType::HTTP_RESPONSE;
    }
    Server::InterceptedSession intercepted_session = {
        .id = id,
        .session = this->shared_from_this(),
        .remote_host = this->remote_host,
        .request_type = request_type,
        .http_message = readable_message,
        .requested_at = std::chrono::system_clock::now(),
        .intercept_response_cb = std::make_shared<Server::TInterceptResponseCB>(
            intercept_response_cb_bind)};

    this->intercepted_sessions.push_back(intercepted_session);

    this->intercept_cb.value()();
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

}  // namespace Proxy