#pragma once

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <string>
#include <tuple>

namespace Proxy {

class Cert {
 public:
  struct RootCAInfo {
    EVP_PKEY* p_cert_key;
    X509* p_ca_pub_cert;
    EVP_PKEY* p_ca_pub_pkey;
    EVP_PKEY* p_ca_priv_pkey;
  };

  struct CertInfo {
    std::string cert;
    std::string key;
  };

  static Cert::CertInfo generate_certificate(
      const Cert::RootCAInfo& root_ca_info, const std::string& hostname);
  static Cert::CertInfo generate_root_certificate();

 private:
  static X509* generate_X509_cert(const Cert::RootCAInfo& root_ca_info,
                                  const std::string& hostname);
  static Cert::CertInfo X509_to_certinfo(X509* p_pub_cert,
                                         EVP_PKEY* p_private_key);
  static void add_ext(X509* cert, int nid, const char* value);
  static int generate_set_random_serial(X509* crt);
};

}  // namespace Proxy