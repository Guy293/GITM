#pragma once

#include <chrono>
#include <unordered_map>
#define BUFFER_SIZE 8192

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/uuid/uuid.hpp>
#include <optional>
#include <queue>

#include "cert.h"
#include "http_request_parser.h"
#include "http_response_parser.h"

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

  using TInterceptCB = std::function<void()>;

  using ResignedCertificatesCache =
      std::unordered_map<std::string, Cert::CertInfo>;

  enum RequestType { HTTP_REQUEST, HTTP_RESPONSE };

  struct InterceptedSession {
    boost::uuids::uuid id;  // Used for UI identification
    std::shared_ptr<Session> session;
    HttpParser::Host remote_host;
    RequestType request_type;
    std::vector<char> http_message;
    std::chrono::system_clock::time_point requested_at;
    std::shared_ptr<TInterceptResponseCB> intercept_response_cb;
  };

  using InterceptedSessions = std::vector<InterceptedSession>;

  Server(boost::asio::io_context& io_context,
         boost::asio::ip::tcp::endpoint& endpoint, const char* ca_path,
         const char* ca_key_path);

  void set_intercept_cb(const TInterceptCB& intercept_cb);

  void set_intercept_to_host_enabled(bool enabled);
  void set_intercept_to_client_enabled(bool enabled);
  void set_host_interception_filter(std::string host_filter);

  std::size_t get_intercepted_sessions_list_size() const;
  const InterceptedSession& get_intercepted_session(std::size_t index) const;
  const InterceptedSession& get_intercepted_session(
      const boost::uuids::uuid& id) const;

 private:
  void accept();

  Cert::RootCAInfo root_ca_info;
  boost::asio::io_context& io_context;
  boost::asio::ip::tcp::endpoint endpoint;
  std::optional<TInterceptCB> intercept_cb;
  boost::asio::ip::tcp::acceptor acceptor;
  std::optional<boost::asio::ip::tcp::socket> socket;
  InterceptedSessions intercepted_sessions;
  ResignedCertificatesCache resigned_certificates_cache;
  bool intercept_to_host_enabled;
  bool intercept_to_client_enabled;
  std::string host_interception_filter;
};

}  // namespace Proxy