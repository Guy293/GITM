// #include <vld.h>
#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <optional>
#include <queue>

#include "cert.h"
#include "http_parser/http_request_parser.h"
#include "server.h"

namespace Proxy {

class Session : public std::enable_shared_from_this<Session> {
   public:
    Session(boost::asio::io_context& io_context,
            boost::asio::ip::tcp::socket&& client_socket,
            const Cert::RootCAInfo& root_ca_info,
            Server::InterceptedSessions& intercepted_sessions_queue,
            Server::ResignedCertificatesCache& resigned_certificates_cache,
            const std::optional<Server::TInterceptCB>& intercept_cb,
            const bool& intercept_to_host_enabled,
            const bool& intercept_to_client_enabled,
            const std::string& host_interception_filter);
    void start();
    //   ~Session();

   private:
    // static const int BUFFER_SIZE = 8192;

    void on_request_read(const boost::system::error_code& error,
                         std::size_t bytes_transferred,
                         std::shared_ptr<std::vector<char>> buffer);
    void cert_file_response();
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

    void on_proxy_data_sent(const boost::system::error_code& error,
                            std::size_t bytes_transferred);

    const Cert::RootCAInfo& root_ca_info;
    boost::asio::io_context& io_context;
    Server::InterceptedSessions& intercepted_sessions;
    Server::ResignedCertificatesCache& resigned_certificates_cache;
    std::optional<Server::TInterceptCB> intercept_cb;
    boost::asio::ip::tcp::resolver resolver;
    boost::asio::ip::tcp::socket client_socket;
    boost::asio::ip::tcp::socket remote_socket;
    HttpParser::HttpRequestParser request_parser;
    HttpParser::Host remote_host;
    bool is_ssl;
    std::optional<boost::asio::ssl::context> remote_ctx;
    std::optional<boost::asio::ssl::context> client_ctx;
    std::optional<boost::asio::ssl::stream<boost::asio::ip::tcp::socket&>>
        ssl_remote_socket;
    std::optional<boost::asio::ssl::stream<boost::asio::ip::tcp::socket&>>
        ssl_client_socket;
    const bool& intercept_to_host_enabled;
    const bool& intercept_to_client_enabled;
    const std::string& host_interception_filter;
    // boost::asio::streambuf streambuf;
    // std::vector<char> buffer;
    Cert::CertInfo get_cert_for_hostname(const std::string& hostname);
};

}  // namespace Proxy