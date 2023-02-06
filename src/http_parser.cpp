#include "http_parser.h"

#include <brotli/decode.h>
#include <brotli/encode.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/format.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <cmath>
#include <vector>

#include "helper.h"

namespace HttpParser {

HttpParser::HttpParser()
    : raw_message(),
      headers(),
      transfer_method(TransferMethod::close),
      http_version(),
      body(),
      message_complete(false),
      buffer(),
      chunk_body(),
      chunk_length_remaining(-1) {}

void HttpParser::process_chunk(const char chunk[], size_t length,
                               bool body_encoded) {
  if (this->message_complete) {
    throw InvalidHttpException(
        "Tried to process chunk after message complete.");
  }

  this->raw_message.insert(this->raw_message.end(), chunk, chunk + length);
  this->buffer.insert(this->buffer.end(), chunk, chunk + length);

  // Read headers
  // If the transfer method is not type-close, it means that it was changed and
  // this is not the first chunk processed
  if (this->transfer_method == TransferMethod::close) {
    // Convert header lines only to str
    const char* crlf2 = "\r\n\r\n";
    auto it = std::search(this->buffer.begin(), this->buffer.end(), crlf2,
                          crlf2 + strlen(crlf2));

    if (it == this->buffer.end()) return;  // Headers doesn't end yet

    int i_headers_end = std::distance(this->buffer.begin(), it);

    std::string headers_str =
        std::string(this->buffer.begin(), this->buffer.begin() + i_headers_end);
    // std::size_t i_headers_end = headers_str.find("\r\n\r\n");

    std::vector<std::string> header_lines;
    boost::split(header_lines, headers_str.substr(0, i_headers_end),
                 boost::is_any_of("\r\n"), boost::token_compress_on);

    std::string status_line = header_lines[0];
    header_lines.erase(header_lines.begin());  // Skip status line
    this->parse_status_line(status_line);

    std::string name;
    std::string value;

    for (int i = 0; i < header_lines.size(); i++) {
      std::size_t i_split = header_lines[i].find(':');
      name = header_lines[i].substr(0, i_split);
      value = header_lines[i].substr(i_split + 2);
      this->headers[name] = value;
      // this->headers.insert(std::pair<std::string, std::string>(name, value));
    }

    this->parse_host();

    // The order is important
    //
    // "Messages must not include both a Content-Length header field
    // and a non-identity transfer-coding. If the message does include
    // a non-identity transfer-coding, the Content-Length must be ignored."
    //
    // - RFC 2616, Section 4.4
    if (this->headers.count("transfer-encoding") > 0)
      this->transfer_method = TransferMethod::chunked;
    else if (this->headers.count("content-length") > 0)
      this->transfer_method = TransferMethod::content_length;
    else
      this->transfer_method = TransferMethod::close;

    // Cut the headers from the chunk,
    // so if the message is chunked and the first body chunk
    // is in the same chunk as the header, the headers won't be
    // a part of the body.
    this->buffer.erase(this->buffer.begin(),
                       this->buffer.begin() + i_headers_end + 4);
  }

  if (!body_encoded) {
    // std::string headers_str = std::string(this->buffer.data());
    this->body = this->buffer;
    this->message_complete = true;
    return;
  }

  // RFC 2616, Section 4.4
  if (this->transfer_method == TransferMethod::close) {
    this->body = this->decompress_body(this->buffer);
    this->message_complete = true;
  } else if (this->transfer_method == TransferMethod::content_length) {
    int content_length = std::stoi(this->headers["content-length"]);

    if (content_length == 0) {
    }

    if (content_length == this->buffer.size()) {
      this->body = this->decompress_body(this->buffer);
      this->message_complete = true;
      return;
    }
  } else if (this->transfer_method == TransferMethod::chunked) {
    while (this->buffer.size() > 0) {
      // New chunk
      if (this->chunk_length_remaining == -1) {
        // Current chunk not finished
        if (this->buffer.size() < 2) return;

        // Skip first CRLF (after reading first chunk)
        if (this->buffer[0] == '\r' && this->buffer[1] == '\n')
          this->buffer.erase(this->buffer.begin(), this->buffer.begin() + 2);

        if (this->buffer.size() == 0) return;

        int i_length_end = -1;

        for (int i = 0; i < this->buffer.size() - 1; i++) {
          if (this->buffer[i] == '\r' && this->buffer[i + 1] == '\n') {
            i_length_end = i;
            break;
          }
        }

        // Chunk doesn't end yet
        if (i_length_end == -1) return;

        // Convert length hex to decimal
        std::string hex_length = std::string{
            this->buffer.begin(), this->buffer.begin() + i_length_end};
        this->chunk_length_remaining =
            (int)strtol(hex_length.c_str(), NULL, 16);

        this->buffer.erase(this->buffer.begin(),
                           this->buffer.begin() + i_length_end + 2);

        // End of message
        if (this->chunk_length_remaining == 0) {
          this->body = this->decompress_body(this->chunk_body);
          this->message_complete = true;
          return;
        }
      }
      // Read current chunk
      if (chunk_length_remaining > 0) {
        int i_data_end =
            std::min(this->chunk_length_remaining, (int)this->buffer.size());

        this->chunk_body.insert(this->chunk_body.end(), this->buffer.begin(),
                                buffer.begin() + i_data_end);

        this->buffer.erase(this->buffer.begin(),
                           this->buffer.begin() + i_data_end);

        this->chunk_length_remaining -= i_data_end;

        // End of chunk
        if (this->chunk_length_remaining == 0)
          this->chunk_length_remaining = -1;
      }
    }
  }
}

std::vector<char> HttpParser::build(bool encode_body) const {
  const std::string CLRF = "\r\n";

  std::vector<char> build_buffer = std::vector<char>();
  std::vector<char> build_body;
  std::map<std::string, std::string, Helper::case_insensitive_comp>
      build_headers(
          this->headers);  // Copy headers in case we need to change them

  // Build status line
  std::string status_line = this->build_status_line() + CLRF;
  Helper::vector_insert(&build_buffer, &status_line);

  // Build body
  if (!this->body.empty()) {
    if (!encode_body) {
      Helper::vector_insert(&build_body, &this->body);
    } else {
      std::vector<char> compressed_body = this->compress_body(this->body);

      if (this->transfer_method == TransferMethod::content_length) {
        build_headers["content-length"] = compressed_body.size();
        Helper::vector_insert(&build_body, &compressed_body);

      } else if (this->transfer_method == TransferMethod::chunked) {
        const size_t CHUNK_SIZE = 1024;

        for (int i = 1; i <= ceil((double)compressed_body.size() / CHUNK_SIZE);
             i++) {
          int current_index = (i - 1) * CHUNK_SIZE;

          int current_chunk_length =
              std::min(CHUNK_SIZE, compressed_body.size() - current_index);

          // Append length
          std::string hex_length =
              (boost::format("%x") % current_chunk_length).str() + CLRF;
          std::copy(hex_length.begin(), hex_length.end(),
                    std::back_inserter(build_body));

          // Append data
          build_body.insert(
              build_body.end(), compressed_body.begin() + current_index,
              compressed_body.begin() + current_index + current_chunk_length);

          // Append data end CLRF
          std::copy(CLRF.begin(), CLRF.end(), std::back_inserter(build_body));
        }

        // Chunk stream end
        std::string stream_end = '0' + CLRF + CLRF;
        std::copy(stream_end.begin(), stream_end.end(),
                  std::back_inserter(build_body));
      }
    }
  }

  // Build headers
  for (auto const& h : build_headers) {
    std::string header = h.first + ": " + h.second + "\r\n";
    Helper::vector_insert(&build_buffer, &header);
  }
  Helper::vector_insert(&build_buffer, &CLRF);

  // Insert body after headers
  Helper::vector_insert(&build_buffer, &build_body);

  return build_buffer;
}

std::vector<char> HttpParser::compress_body(
    const std::vector<char>& decompressed_body) const {
  auto encoding_header = this->headers.find("content-encoding");

  // // Return a vector of /0 if body is empty
  if (decompressed_body.empty()) {
    std::vector<char> compressed_body;
    // compressed_body.push_back('\0');
    return compressed_body;
  }

  // Return decompressed body if no encoding header
  if (encoding_header == this->headers.end()) {
    std::vector<char> compressed_body;
    Helper::vector_insert(&compressed_body, &decompressed_body);
    return compressed_body;
  }

  std::string compress_algo = this->headers.find("content-encoding")->second;

  if (compress_algo == "br") {
    const uint8_t* c_str = (uint8_t*)decompressed_body.data();
    size_t compressed_size =
        BrotliEncoderMaxCompressedSize(decompressed_body.size());
    uint8_t* p_compressed_buffer = (uint8_t*)malloc(compressed_size);

    BROTLI_BOOL result = BrotliEncoderCompress(
        BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
        decompressed_body.size(), c_str, &compressed_size, p_compressed_buffer);

    std::vector<char> compressed_body(p_compressed_buffer,
                                      p_compressed_buffer + compressed_size);
    free(p_compressed_buffer);

    if (result != BROTLI_TRUE) {
      throw std::runtime_error("Error compressing brotli body");
    }

    return compressed_body;

  } else if (compress_algo == "gzip" || compress_algo == "deflate") {
    std::vector<char> compressed_body;
    boost::iostreams::filtering_ostream stream;

    if (compress_algo == "gzip") {
      stream.push(boost::iostreams::gzip_compressor());
    } else if (compress_algo == "deflate") {
      stream.push(boost::iostreams::zlib_compressor());
    }
    stream.push(boost::iostreams::back_inserter(compressed_body));
    stream << decompressed_body.data();

    boost::iostreams::close(stream);

    return compressed_body;
  } else {
    throw std::runtime_error("Couldn't detect compression: " + compress_algo);
  }
}

std::vector<char> HttpParser::decompress_body(
    const std::vector<char>& compressed_body) const {
  // // Return a vector of /0 if body is empty
  if (compressed_body.empty()) {
    std::vector<char> decompressed_body;
    // decompressed_body.push_back('\0');
    return decompressed_body;
  }

  if (this->headers.find("content-encoding") == this->headers.end())
    return compressed_body;

  std::string compress_algo = this->headers.find("content-encoding")->second;

  if (compress_algo == "br") {
    std::unique_ptr<BrotliDecoderState, decltype(&BrotliDecoderDestroyInstance)>
        state(BrotliDecoderCreateInstance(nullptr, nullptr, nullptr),
              BrotliDecoderDestroyInstance);

    BrotliDecoderResult result = BROTLI_DECODER_RESULT_ERROR;

    std::vector<char> out;
    const size_t chunk_size = 1 << 16;
    std::vector<std::uint8_t> buffer(chunk_size, 0);

    size_t available_in = compressed_body.size();
    const std::uint8_t* next_in =
        reinterpret_cast<const std::uint8_t*>(compressed_body.data());
    size_t available_out = buffer.size();
    std::uint8_t* next_out = buffer.data();

    while (true) {
      result = BrotliDecoderDecompressStream(
          state.get(), &available_in, &next_in, &available_out, &next_out, 0);

      if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT ||
          result == BROTLI_DECODER_RESULT_SUCCESS) {
        out.insert(out.end(), buffer.begin(),
                   buffer.begin() + std::distance(buffer.data(), next_out));

        if (result == BROTLI_DECODER_RESULT_SUCCESS) return out;

        available_out = buffer.size();
        next_out = buffer.data();
      } else if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
        throw std::runtime_error(
            "Brotli decompressing failed: Input corrupted");
      } else {
        if (result == BROTLI_DECODER_RESULT_ERROR) {
          std::string detail =
              BrotliDecoderErrorString(BrotliDecoderGetErrorCode(state.get()));
          throw std::runtime_error("Brotli decompressing failed: " + detail);
        }
        throw std::runtime_error("Brotli decompressing failed");
      }
    }
  } else if (compress_algo == "gzip" || compress_algo == "deflate") {
    std::vector<char> decompressed_body;
    boost::iostreams::filtering_ostream stream;

    if (compress_algo == "gzip")
      stream.push(boost::iostreams::gzip_decompressor());
    else if (compress_algo == "deflate")
      stream.push(boost::iostreams::zlib_decompressor());

    stream.push(boost::iostreams::back_inserter(decompressed_body));
    boost::iostreams::write(stream, &compressed_body[0],
                            compressed_body.size());
    boost::iostreams::close(stream);

    //    if (decompressed_body.empty()) return "";

    return decompressed_body;
  } else {
    throw std::runtime_error("Couldn't detect compression: " + compress_algo);
  }
}

}  // namespace HttpParser
