#include "cert.h"

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace Proxy {

Cert::CertInfo Cert::generate_certificate(const Cert::RootCAInfo& root_ca_info,
                                          const std::string& hostname) {
  X509* p_pub_cert = Cert::generate_X509_cert(root_ca_info, hostname);

  Cert::CertInfo cert_info =
      Cert::X509_to_certinfo(p_pub_cert, root_ca_info.p_cert_key);

  X509_free(p_pub_cert);

  return cert_info;
}

X509* Cert::generate_X509_cert(const Cert::RootCAInfo& root_ca_info,
                               const std::string& hostname) {
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

  add_ext(p_generated_cert, NID_key_usage,
          "dataEncipherment,keyEncipherment,digitalSignature");

  add_ext(p_generated_cert, NID_ext_key_usage,
          "critical,codeSigning,1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2");

  // Set the subject alternative name (SAN) to the hostname
  GENERAL_NAMES* gens = sk_GENERAL_NAME_new_null();
  GENERAL_NAME* gen_dns = GENERAL_NAME_new();
  ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
  ASN1_STRING_set(ia5, hostname.data(), (int)hostname.length());
  GENERAL_NAME_set0_value(gen_dns, GEN_DNS, ia5);
  sk_GENERAL_NAME_push(gens, gen_dns);
  X509_add1_ext_i2d(p_generated_cert, NID_subject_alt_name, gens, 0,
                    X509V3_ADD_DEFAULT);
  sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

  p_subject_name = X509_NAME_new();
  X509_NAME_add_entry_by_txt(p_subject_name, "CN", MBSTRING_ASC,
                             (const unsigned char*)hostname.c_str(), -1, -1, 0);

  X509_set_subject_name(p_generated_cert, p_subject_name);

  X509_set_issuer_name(p_generated_cert,
                       X509_get_subject_name(root_ca_info.p_ca_pub_cert));

  X509_gmtime_adj(X509_get_notBefore(p_generated_cert), 0L);
  X509_gmtime_adj(X509_get_notAfter(p_generated_cert), 31536000L);

  if (0 > X509_set_pubkey(p_generated_cert, root_ca_info.p_cert_key)) {
    printf("failed to set pkey\n");
    X509_free(p_generated_cert);
    p_generated_cert = nullptr;
    goto CLEANUP;
  }

  if (0 > EVP_PKEY_copy_parameters(root_ca_info.p_ca_pub_pkey,
                                   root_ca_info.p_ca_priv_pkey)) {
    printf("failed to copy parameters\n");
    X509_free(p_generated_cert);
    p_generated_cert = nullptr;
    goto CLEANUP;
  }

  if (0 >
      X509_sign(p_generated_cert, root_ca_info.p_ca_priv_pkey, EVP_sha256())) {
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

Cert::CertInfo Cert::X509_to_certinfo(X509* p_pub_cert,
                                      EVP_PKEY* p_private_key) {
  BIO* p_cert_bio;
  BIO* p_key_bio;

  // Convert x509 to char*
  char p_cert_pub_str[4096];
  p_cert_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(p_cert_bio, p_pub_cert);
  size_t cert_length = BIO_number_written(p_cert_bio);
  p_cert_pub_str[cert_length] = 0;
  BIO_read(p_cert_bio, p_cert_pub_str, cert_length);

  // Convert RSA to char*
  char p_cert_key_str[4096];
  p_key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(p_key_bio, p_private_key, NULL, NULL, 0, NULL, NULL);

  size_t key_length = BIO_number_written(p_key_bio);
  p_cert_key_str[key_length] = 0;
  BIO_read(p_key_bio, p_cert_key_str, (int)key_length);

  BIO_free(p_cert_bio);
  BIO_free(p_key_bio);

  return {p_cert_pub_str, p_cert_key_str};
}
void Cert::add_ext(X509* cert, int nid, const char* value) {
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

int Cert::generate_set_random_serial(X509* crt) {
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

}  // namespace Proxy