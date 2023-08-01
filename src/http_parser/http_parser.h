#pragma once

#include <exception>
#include <map>
#include <streambuf>
#include <vector>

#include "../helper.h"

namespace HttpParser {

enum class TransferMethod { close, content_length, chunked };
using headers_t =
    std::map<std::string, std::string, Helper::case_insensitive_comp>;
/*enum HttpMethod {
  CONNECT,
  DELETE,
  GET,
  HEAD,
  OPTIONS,
  PATCH,
  POST,
  PUT,
  TRACE
};*/
// char* HttpMethods[] = {"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS",
//                        "PATCH",   "POST",   "PUT", "TRACE"}

// struct comsadp {
//   bool operator()(const std::string& lhs, const std::string& rhs) const {
//     return _stricmp(lhs.c_str(), rhs.c_str()) < 0;
//   }
// };
class HttpParser {
   public:
    HttpParser();
    void process_chunk(const char chunk[], size_t length,
                       bool body_encoded = true);
    std::vector<char> build(bool encode_body = true) const;
    std::vector<char> raw_message;
    headers_t headers;
    TransferMethod transfer_method;
    std::string http_version;
    std::vector<char> body;
    bool message_complete;

   private:
    std::vector<char> buffer;
    std::vector<char> chunk_body;
    int chunk_length_remaining;

    virtual std::string build_status_line() const = 0;
    virtual void parse_status_line(std::string status_line) = 0;
    virtual void parse_host(){};
    void decode_body_chunk();
    static TransferMethod realize_transfer_method(const headers_t& headers);
    static std::vector<char> compress_body(
        const headers_t& headers, const std::vector<char>& decompressed_body);
    static std::vector<char> compress_brotli(
        const std::vector<char>& decompressed_body);
    static std::vector<char> decompress_body(
        const headers_t& headers, const std::vector<char>& compressed_body);
    static std::vector<char> decompress_brotli(
        const std::vector<char>& compressed_body);
    std::vector<char> build_body(headers_t& build_headers) const;
};

class InvalidHttpException : public std::exception {
   private:
    const char* m_message;

   public:
    InvalidHttpException(const char* t_message) : m_message(t_message){};
};

}  // namespace HttpParser
