#include "old_proxy.h"

#include <openssl/ssl.h>

#ifdef WIN32
#include <openssl/applink.c>
#endif

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <fstream>
#include <iostream>
#include <thread>

#include "http_request_parser.h"
#include "http_response_parser.h"

using namespace boost;
using asio::ip::tcp;

namespace Proxy {

Proxy::Proxy(const tcp::endpoint& endpoint, const char* ca_path,
             const char* ca_key_path)
    : endpoint(endpoint), proxy_handler_thread(nullptr) {
  // Generating the key for every request leads to 100% cpu utilization
  this->p_resigned_key = EVP_RSA_gen(2048);

  if ((this->p_ca_file = fopen(ca_path, "r")) == nullptr)
    throw std::runtime_error("Failed to open the ca file");

  if ((this->p_ca_cert = PEM_read_X509(p_ca_file, NULL, 0, NULL)) == nullptr)
    throw std::runtime_error("Failed to X509 CA certificate");

  if ((this->p_ca_pkey = X509_get_pubkey(p_ca_cert)) == nullptr)
    throw std::runtime_error("Failed to get X509 CA pkey");

  if ((this->p_ca_key_file = fopen(ca_key_path, "r")) == nullptr)
    throw std::runtime_error("Failed to open the ca key file");

  if ((this->p_ca_key_pkey = PEM_read_PrivateKey(p_ca_key_file, nullptr,
                                                 nullptr, nullptr)) == nullptr)
    throw std::runtime_error("Failed to read the private key file");

  fclose(p_ca_file);
  fclose(p_ca_key_file);
};

void Proxy::proxy_handler() {
  asio::io_context* io_context = new asio::io_context();

  // tcp::tcp_connection::pointer new_connection =
  // tcp_connection::create(io_context_);
  tcp::socket socket(*io_context);
  tcp::acceptor acceptor(*io_context, endpoint);
  int a = 0;
  while (true) {
    try {
      tcp::socket* client_socket = new tcp::socket(*io_context);
      acceptor.accept(*client_socket);
      client_socket->set_option(
          tcp::no_delay(true));  // Must open a connection before set_option
      std::thread t = std::thread(&Proxy::con_handler, this,
                                  std::ref(*io_context), client_socket);

      t.detach();

    } catch (std::exception& e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

void Proxy::con_handler(boost::asio::io_context& io_context,
                        boost::asio::ip::tcp::socket* client_socket) {
  try {
    HttpParser::HttpRequestParser parser;
    char buffer[CHUNK_SIZE];
    system::error_code error;

    size_t length = client_socket->read_some(asio::buffer(buffer), error);

    if (error == asio::error::eof)
      return;  // Connection closed cleanly by peer.
    else if (error)
      throw system::system_error(error);

    // std::cout << "Bytes read: " << length << std::endl;
    //  if (len == 0) return;

    // std::cout << str << std::endl;

    parser.process_chunk(buffer, length);

    std::cout << "Target: " << parser.host.name << ":" << parser.host.port
              << std::endl;

    tcp::socket server_socket(io_context);
    server_socket.open(tcp::v4());  // Must open a connection before set_option
    server_socket.set_option(tcp::no_delay(true));

    auto server_endpoint =
        tcp::resolver(io_context)
            .resolve({parser.host.name, std::to_string(parser.host.port)});

    // SSL
    if (parser.method == "CONNECT") {
      asio::ssl::context ctx(asio::ssl::context::sslv23_client);
      // ctx.set_options(asio::ssl::context::default_workarounds |
      //                 asio::ssl::context::verify_none);
      ctx.set_default_verify_paths();

      asio::ssl::stream<tcp::socket&> ssl_server_socket(server_socket, ctx);

      SSL_set_tlsext_host_name(ssl_server_socket.native_handle(),
                               parser.host.name.c_str());  // SNI

      asio::connect(ssl_server_socket.next_layer(), server_endpoint);

      std::string response = "HTTP/1.0 200 Connection established\r\n\r\n";
      client_socket->send(asio::buffer(response));

      // Handshake as client
      ssl_server_socket.handshake(asio::ssl::stream_base::client);

      X509* p_server_pub_cert =
          SSL_get_peer_certificate(ssl_server_socket.native_handle());

      std::tuple<std::string, std::string> resigned_server_cert =
          this->resign_certificate(p_server_pub_cert, parser.host.name);

      std::string p_cert_pub_str = std::get<0>(resigned_server_cert);
      std::string p_cert_key_str = std::get<1>(resigned_server_cert);

      asio::ssl::context ctx2(asio::ssl::context::sslv23_server);
      // ctx.set_options(asio::ssl::context::default_workarounds |
      //                 asio::ssl::context::verify_none);

      ctx2.use_certificate(
          asio::const_buffer(p_cert_pub_str.c_str(), p_cert_pub_str.length()),
          asio::ssl::context::file_format::pem);

      ctx2.use_private_key(
          asio::const_buffer(p_cert_key_str.c_str(), p_cert_key_str.length()),
          asio::ssl::context::file_format::pem);

      asio::ssl::stream<tcp::socket&> ssl_client_socket(*client_socket, ctx2);

      ssl_client_socket.handshake(asio::ssl::stream_base::server);

      this->proxy_data<asio::ssl::stream<tcp::socket&>,
                       HttpParser::HttpRequestParser>(ssl_client_socket,
                                                      ssl_server_socket, false);
      this->proxy_data<asio::ssl::stream<tcp::socket&>,
                       HttpParser::HttpResponseParser>(
          ssl_server_socket, ssl_client_socket, false);

      // ssl_client_socket.shutdown();
      // ssl_server_socket.shutdown();

      // ssl_client_socket.shutdown();
      ssl_client_socket.next_layer().close();
      // ssl_server_socket.shutdown();
      ssl_server_socket.next_layer().close();
      delete client_socket;
      OPENSSL_thread_stop();
    }
    // Not SSL
    else {
      asio::connect(server_socket, server_endpoint);
      asio::write(server_socket, asio::buffer(buffer));

      this->proxy_data<tcp::socket, HttpParser::HttpResponseParser>(
          server_socket, *client_socket);
      delete client_socket;
    }
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
    OPENSSL_thread_stop();
  }
}

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

X509* Proxy::generate_cert(X509* p_server_cert, const char* hostname) {
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

  add_ext(p_generated_cert, p_ca_cert, NULL, NID_key_usage,
          "dataEncipherment,keyEncipherment,digitalSignature");

  add_ext(p_generated_cert, p_ca_cert, NULL, NID_ext_key_usage,
          "critical,codeSigning,1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2");

  //// san_dns = "DNS:" + std::string(hostname);
  san_dns = std::string(hostname);

  GENERAL_NAMES* gens = sk_GENERAL_NAME_new_null();
  GENERAL_NAME* gen_dns = GENERAL_NAME_new();
  ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
  ASN1_STRING_set(ia5, san_dns.data(), san_dns.length());
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

  if (0 > X509_set_pubkey(p_generated_cert, this->p_resigned_key)) {
    printf("failed to set pkey\n");
    X509_free(p_generated_cert);
    p_generated_cert = nullptr;
    goto CLEANUP;
  }

  if (0 > EVP_PKEY_copy_parameters(p_ca_pkey, p_ca_key_pkey)) {
    printf("failed to copy parameters\n");
    X509_free(p_generated_cert);
    p_generated_cert = nullptr;
    goto CLEANUP;
  }

  X509_set_issuer_name(p_generated_cert, X509_get_subject_name(p_ca_cert));

  if (0 > X509_sign(p_generated_cert, p_ca_key_pkey, EVP_sha256())) {
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

std::tuple<std::string, std::string> Proxy::resign_certificate(
    X509* p_pub_certificate, std::string hostname) {
  BIO* p_cert_bio;
  BIO* p_key_bio;
  X509* p_resigned_cert_pub =
      generate_cert(p_pub_certificate, (char*)hostname.c_str());

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
  PEM_write_bio_PrivateKey(p_key_bio, this->p_resigned_key, NULL, NULL, 0, NULL,
                           NULL);

  size_t key_length = BIO_number_written(p_key_bio);
  p_cert_key_str[key_length] = 0;
  BIO_read(p_key_bio, p_cert_key_str, key_length);

  BIO_free(p_cert_bio);
  BIO_free(p_key_bio);
  X509_free(p_resigned_cert_pub);

  return {p_cert_pub_str, p_cert_key_str};
}

// void Proxy::proxy_data(tcp::socket& from, tcp::socket& to, bool intercept) {
template <class T_stream, class T_parser>
void Proxy::proxy_data(T_stream& from, T_stream& to, bool intercept) {
  static_assert(std::is_base_of<HttpParser::HttpParser, T_parser>::value,
                "T_parser must extend HttpParser");
  T_parser parser;
  // std::unique_ptr<HttpParser::HttpParser> parser(
  //     dynamic_cast<HttpParser::HttpParser*>(
  //         new HttpParser::HttpRequestParser()));

  system::error_code error;

  std::vector<char> message;

  try {
    while (!parser.message_complete) {
      char buffer[CHUNK_SIZE];

      size_t length = from.read_some(asio::buffer(buffer), error);

      if (length == 0 || error == asio::error::eof)
        break;  // Connection closed cleanly by peer.
      else if (error)
        throw system::system_error(error);

      parser.process_chunk(buffer, length);
    }

    if (intercept && parser.body.find("ben gvir") != std::string::npos) {
      boost::replace_all(parser.body, "ben gvir", "begvir");
      message = parser.build();
    } else {
      message = parser.raw_message;
    }

    // if (intercept) {
    //   message = parser.build();
    // } else {
    //   message = parser.raw_message;
    // }

    // message = parser.build();

    // for (auto i : message) std::cout << i;

    // char buffer[CHUNK_SIZE];
    //  Intercept only if content type is text
    //  if (parser->headers.count("content-type") > 0 &&
    //     parser->headers["content-type"].find("text") != std::string::npos)
    //     {
    //
    // }

    asio::write(to, asio::buffer(message.data(), message.size()));

  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
    return;
  }
}

void Proxy::start() {
  std::thread t = std::thread(&Proxy::proxy_handler, this);
  this->proxy_handler_thread = &t;
  this->proxy_handler_thread->join();
}
//
// void Proxy::stop() {
//  if (proxy_handler_thread != NULL) {
//    proxy_handler_thread->detach();
//    proxy_handler_thread = NULL;
//  }
//}

Proxy::~Proxy() {
  if (this->p_resigned_key != nullptr) EVP_PKEY_free(this->p_resigned_key);
  if (this->p_ca_cert != nullptr) X509_free(this->p_ca_cert);
  if (this->p_ca_pkey != nullptr) EVP_PKEY_free(this->p_ca_pkey);
  if (this->p_ca_key_pkey != nullptr) EVP_PKEY_free(this->p_ca_key_pkey);

  //  if (proxy_handler_thread != nullptr) {
  //    proxy_handler_thread = nullptr;
  //  }
}

}  // namespace Proxy
