#pragma once

#include <openssl/ssl.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <chrono>
#include <iostream>
#include <thread>

namespace Proxy {
class Proxy {
 public:
  static const int CHUNK_SIZE = 8192;

  Proxy(const boost::asio::ip::tcp::endpoint& endpoint, const char* ca_path,
        const char* ca_key_path);

  void start();
  void stop();
  ~Proxy();

 private:
  std::thread* proxy_handler_thread;
  const boost::asio::ip::tcp::endpoint endpoint;
  EVP_PKEY* p_resigned_key;
  FILE* p_ca_file;
  X509* p_ca_cert;
  EVP_PKEY* p_ca_pkey;
  FILE* p_ca_key_file;
  EVP_PKEY* p_ca_key_pkey;
  void proxy_handler();
  void con_handler(boost::asio::io_context& io_context,
                   boost::asio::ip::tcp::socket* client_socket);
  X509* generate_cert(X509* p_server_cert, const char* hostname);
  std::tuple<std::string, std::string> resign_certificate(
      X509* p_pub_certificate, std::string hostname);
  template <class T_stream, class T_parser>
  static void proxy_data(T_stream& from, T_stream& to, bool intercept = false);
};

}  // namespace Proxy