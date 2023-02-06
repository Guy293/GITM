#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <optional>
#include <queue>

#include "http_request_parser.h"
#include "server.h"

// class Server;  // forward declaration

namespace Proxy {

class Session : public std::enable_shared_from_this<Session> {
 public:
  Session(boost::asio::io_context& io_context, Server* server,
          boost::asio::ip::tcp::socket&& client_socket,
          const Server::RootCAInfo& root_ca_info,
          std::optional<Server::TInterceptCB> intercept_cb);
  void start();
  //   ~Session();

 private:
  // static const int BUFFER_SIZE = 8192;

  void on_request_read(const boost::system::error_code& error,
                       std::size_t bytes_transferred,
                       std::shared_ptr<std::vector<char>> buffer);
  void on_remote_resolve(
      const boost::system::error_code& error,
      boost::asio::ip::tcp::resolver::iterator endpoint_iterator);
  void on_remote_connect(const boost::system::error_code& error);
  void on_none_ssl_response_sent(const boost::system::error_code& error,
                                 std::size_t bytes_transferred);
  void on_ssl_response_sent(const boost::system::error_code& error,
                            std::size_t bytes_transferred);
  void on_remote_handshake(const boost::system::error_code& error);
  void on_client_handshake(const boost::system::error_code& error);

  template <class T_stream, class T_parser>
  void proxy_data(T_stream& rom, T_stream& to, bool intercept = false);

  template <class T_stream, class T_parser>
  void on_proxy_data_read(const boost::system::error_code& error,
                          std::size_t bytes_transferred,
                          std::shared_ptr<T_parser> parser,
                          std::shared_ptr<std::vector<char>> buffer,
                          T_stream& from, T_stream& to, bool intercept);

  template <class T_stream, class T_parser>
  void on_intercept_cb_response(const std::vector<char>& altered_message,
                                T_stream& to);

  void on_proxy_data_sent(const boost::system::error_code& error,
                          std::size_t bytes_transferred,
                          std::shared_ptr<std::vector<char>> message);

  X509* generate_cert(X509* p_server_cert, const char* hostname);
  std::tuple<std::string, std::string> resign_certificate(
      X509* p_pub_certificate, std::string hostname);

  const Server::RootCAInfo root_ca_info;
  boost::asio::io_context& io_context;
  Server* server;
  std::optional<Server::TInterceptCB> intercept_cb;
  boost::asio::ip::tcp::resolver resolver;
  boost::asio::ip::tcp::socket client_socket;
  boost::asio::ip::tcp::socket remote_socket;
  HttpParser::HttpRequestParser request_parser;
  std::optional<boost::asio::ssl::context> remote_ctx;
  std::optional<boost::asio::ssl::context> client_ctx;
  std::optional<boost::asio::ssl::stream<boost::asio::ip::tcp::socket&>>
      ssl_remote_socket;
  std::optional<boost::asio::ssl::stream<boost::asio::ip::tcp::socket&>>
      ssl_client_socket;
  std::string remote_host;
  // boost::asio::streambuf streambuf;
  // std::vector<char> buffer;
};

}  // namespace Proxy