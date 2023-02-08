#pragma once

#define BUFFER_SIZE 8192

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <optional>
#include <queue>

#include "http_request_parser.h"

namespace Proxy {
class Session;

class Server {
 public:
  // typedef std::function<std::vector<char>(
  //     const std::vector<char>& http_message)>
  //     TInterceptCB;
  // typedef std::function<void( const std::vector<char>& http_message,
  // std::function<void(const std::vector<char>& altered_message)>)>
  // TInterceptCB;

  using TInterceptResponseCB =
      std::function<void(const std::vector<char>& altered_message)>;

  using TInterceptCB = std::function<void(
      const std::vector<char>& http_message, const std::string& remote_host,
      const TInterceptResponseCB& intercept_response_cb)>;

  struct RootCAInfo {
    EVP_PKEY* p_resigned_key;
    X509* p_ca_cert;
    EVP_PKEY* p_ca_pkey;
    EVP_PKEY* p_ca_key_pkey;
  };

  struct InterceptedSession {
    std::shared_ptr<Session> session;
    std::vector<char> http_message;
    std::shared_ptr<TInterceptResponseCB> intercept_response_cb;
  };

  using InterceptedSessionsQueue = std::queue<InterceptedSession>;

  Server(boost::asio::io_context& io_context,
         boost::asio::ip::tcp::endpoint& endpoint, const char* ca_path,
         const char* ca_key_path);

  void set_intercept_cb(const TInterceptCB& intercept_cb);

  void set_intercept_to_host_enabled(bool enabled);
  void set_intercept_to_client_enabled(bool enabled);
  void set_host_interception_filter(std::string host_filter);

  InterceptedSessionsQueue intercepted_sessions_queue;

 private:
  void accept();

  RootCAInfo root_ca_info;
  boost::asio::io_context& io_context;
  boost::asio::ip::tcp::endpoint endpoint;
  std::optional<TInterceptCB> intercept_cb;
  boost::asio::ip::tcp::acceptor acceptor;
  std::optional<boost::asio::ip::tcp::socket> socket;
  bool intercept_to_host_enabled;
  bool intercept_to_client_enabled;
  std::string host_interception_filter;
};

}  // namespace Proxy