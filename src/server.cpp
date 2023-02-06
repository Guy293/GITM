#include <openssl/ssl.h>

#ifdef WIN32
#include <openssl/applink.c>
#endif

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <utility>

#include "http_request_parser.h"
#include "http_response_parser.h"
#include "logger.h"
#include "session.h"

using namespace boost;
using namespace std::placeholders;
using asio::ip::tcp;

namespace Proxy {

Server::Server(asio::io_context& io_context, tcp::endpoint& endpoint,
               const char* ca_path, const char* ca_key_path)
    : io_context(io_context),
      endpoint(endpoint),
      acceptor(io_context, endpoint),
      root_ca_info(),
      intercept_cb(),
      intercepted_sessions_queue() {
  FILE* p_ca_file;
  FILE* p_ca_key_file;

  this->root_ca_info.p_resigned_key = EVP_RSA_gen(2048);

  if ((p_ca_file = fopen(ca_path, "r")) == nullptr)
    throw std::runtime_error("Failed to open the ca file");

  if ((this->root_ca_info.p_ca_cert =
           PEM_read_X509(p_ca_file, NULL, 0, NULL)) == nullptr)
    throw std::runtime_error("Failed to X509 CA certificate");

  if ((this->root_ca_info.p_ca_pkey =
           X509_get_pubkey(this->root_ca_info.p_ca_cert)) == nullptr)
    throw std::runtime_error("Failed to get X509 CA pkey");

  if ((p_ca_key_file = fopen(ca_key_path, "r")) == nullptr)
    throw std::runtime_error("Failed to open the ca key file");

  if ((this->root_ca_info.p_ca_key_pkey = PEM_read_PrivateKey(
           p_ca_key_file, nullptr, nullptr, nullptr)) == nullptr)
    throw std::runtime_error("Failed to read the private key file");

  fclose(p_ca_file);
  fclose(p_ca_key_file);

  this->accept();
}

void Server::accept() {
  this->socket.emplace(io_context);

  this->acceptor.async_accept(*this->socket, [&](system::error_code error) {
    if (error && error != asio::error::eof) {
      LOG_ERROR << error.message();
      return;
    }

    std::shared_ptr<Session> session =
        std::make_shared<Session>(io_context, this, std::move(*this->socket),
                                  root_ca_info, this->intercept_cb);

    // LOG_INFO << "Count: " << ObjectCount::count;

    session->start();
    this->accept();
  });
}

void Server::set_intercept_cb(const TInterceptCB& intercept_cb) {
  this->intercept_cb = intercept_cb;
}

}  // namespace Proxy
