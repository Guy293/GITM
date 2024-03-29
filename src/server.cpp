#include "server.h"

#include <openssl/ssl.h>

#ifdef WIN32
#include <openssl/applink.c>
#endif

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <utility>

#include "cert.h"
#include "http_parser/http_request_parser.h"
#include "http_parser/http_response_parser.h"
#include "logger.h"
#include "session.h"

using namespace boost;
using namespace std::placeholders;
using asio::ip::tcp;

namespace Proxy {

Server::Server(asio::io_context& io_context, tcp::endpoint& endpoint,
               const Cert::CertInfo& root_ca_info)
    : io_context(io_context),
      endpoint(endpoint),
      acceptor(io_context, endpoint),
      root_ca_info(),
      intercept_cb(),
      intercepted_sessions(),
      resigned_certificates(),
      intercept_to_host_enabled(false),
      intercept_to_client_enabled(false) {
    // cert_key is the private key used to sign all certificates
    // We use the same one for all certificates for performance reasons
    this->root_ca_info.p_cert_key = EVP_RSA_gen(2048);

    // Load the root CA certificate and private key from strings
    BIO* bio;

    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, root_ca_info.pub.c_str());
    this->root_ca_info.p_ca_pub_cert =
        PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if ((this->root_ca_info.p_ca_pub_pkey =
             X509_get_pubkey(this->root_ca_info.p_ca_pub_cert)) == nullptr)
        throw std::runtime_error("Failed to get X509 CA pkey");

    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, root_ca_info.key.c_str());
    this->root_ca_info.p_ca_priv_pkey =
        PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    this->accept();
}

void Server::accept() {
    this->socket.emplace(io_context);

    this->acceptor.async_accept(*this->socket, [&](system::error_code error) {
        if (error && error != asio::error::eof) {
            LOG_ERROR << error.message();
            return;
        }

        std::shared_ptr<Session> session = std::make_shared<Session>(
            this->io_context, std::move(*this->socket), this->root_ca_info,
            this->intercepted_sessions, this->resigned_certificates,
            this->intercept_cb, this->intercept_to_host_enabled,
            this->intercept_to_client_enabled, this->host_interception_filter);

        // LOG_INFO << "Count: " << ObjectCount::count;

        session->start();
        this->accept();
    });
}

void Server::set_intercept_cb(const TInterceptCB& cb) {
    this->intercept_cb = cb;
}

void Server::set_intercept_to_host_enabled(bool enabled) {
    this->intercept_to_host_enabled = enabled;
}

void Server::set_intercept_to_client_enabled(bool enabled) {
    this->intercept_to_client_enabled = enabled;
}

void Server::set_host_interception_filter(const std::string& filter) {
    this->host_interception_filter = filter;
}

std::size_t Server::get_intercepted_sessions_list_size() const {
    return this->intercepted_sessions.size();
}

const Server::InterceptedSession& Server::get_intercepted_session(
    std::size_t index) const {
    if (index >= this->intercepted_sessions.size()) {
        throw std::out_of_range("Index out of range");
    }

    return this->intercepted_sessions.at(index);
}

const Server::InterceptedSession& Server::get_intercepted_session(
    const uuids::uuid& id) const {
    auto it = std::find_if(this->intercepted_sessions.begin(),
                           this->intercepted_sessions.end(),
                           [&](const InterceptedSession& intercepted_session) {
                               return intercepted_session.id == id;
                           });
    if (it == this->intercepted_sessions.end()) {
        throw std::out_of_range("Index out of range");
    }
    return *it;
}

void Server::forward_all_intercepted_sessions() {
    while (!this->intercepted_sessions.empty()) {
        auto session = this->get_intercepted_session(0);
        (*session.intercept_response_cb)(session.http_message);
    }
}

}  // namespace Proxy
