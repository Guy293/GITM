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

#include "../helper.h"

const std::string CRLF = "\r\n";
const std::string DOUBLE_CRLF = CRLF + CRLF;

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
    // If the transfer method is "close" it always means we're currently reading
    // the first (and possibly the last) chunk
    if (this->transfer_method == TransferMethod::close) {
        // Return if headers doesn't end yet
        auto header_end_it =
            std::search(this->buffer.begin(), this->buffer.end(),
                        DOUBLE_CRLF.begin(), DOUBLE_CRLF.end());
        if (header_end_it == this->buffer.end()) return;

        long long headers_end_i =
            std::distance(this->buffer.begin(), header_end_it);

        std::string headers_str = std::string(
            this->buffer.begin(), this->buffer.begin() + headers_end_i);

        std::vector<std::string> header_lines;
        boost::split(header_lines, headers_str, boost::is_any_of("\r\n"),
                     boost::token_compress_on);

        // Remove status line from headers
        std::string status_line = header_lines[0];
        header_lines.erase(header_lines.begin());
        this->parse_status_line(status_line);

        for (const auto& header_line : header_lines) {
            std::size_t split_i = header_line.find(':');
            std::string name = header_line.substr(0, split_i);
            std::string value = header_line.substr(split_i + 2);
            this->headers[name] = value;
        }

        // Parse host after we read headers
        this->parse_host();

        this->transfer_method =
            HttpParser::realize_transfer_method(this->headers);

        // Cut the headers from the chunk,
        // so if the message is chunked and the first body chunk
        // is in the same chunk as the header, the headers won't be
        // a part of the body.
        this->buffer.erase(
            this->buffer.begin(),
            this->buffer.begin() + headers_end_i + DOUBLE_CRLF.size());
    }

    if (!body_encoded) {
        // std::string headers_str = std::string(this->buffer.data());
        this->body = this->buffer;
        this->message_complete = true;
        return;
    }

    decode_body_chunk();
}

void HttpParser::decode_body_chunk() {  // RFC 2616, Section 4.4
    if (transfer_method == TransferMethod::close) {
        body = decompress_body(headers, buffer);
        message_complete = true;
    } else if (transfer_method == TransferMethod::content_length) {
        int content_length = std::stoi(headers["content-length"]);

        // if (content_length == 0) {
        // }

        if (content_length == buffer.size()) {
            body = decompress_body(headers, buffer);
            message_complete = true;
            return;
        }
    } else if (transfer_method == TransferMethod::chunked) {
        while (!buffer.empty()) {
            // New chunk (remaining length is -1)
            if (chunk_length_remaining == -1) {
                // Current chunk not finished
                if (buffer.size() < 2) return;

                // Skip first CRLF (after reading first chunk)
                if (buffer[0] == '\r' && buffer[1] == '\n')
                    buffer.erase(buffer.begin(), buffer.begin() + 2);

                if (buffer.empty()) return;

                int i_length_end = -1;

                for (int i = 0; i < buffer.size() - 1; i++) {
                    if (buffer[i] == '\r' && buffer[i + 1] == '\n') {
                        i_length_end = i;
                        break;
                    }
                }

                // Chunk doesn't end yet
                if (i_length_end == -1) return;

                // Convert length hex to decimal
                std::string hex_length =
                    std::string{buffer.begin(), buffer.begin() + i_length_end};
                chunk_length_remaining =
                    (int)strtol(hex_length.c_str(), nullptr, 16);

                buffer.erase(buffer.begin(), buffer.begin() + i_length_end + 2);

                // End of message
                if (chunk_length_remaining == 0) {
                    body = decompress_body(headers, chunk_body);
                    message_complete = true;
                    return;
                }
            }
            // Read current chunk
            if (chunk_length_remaining > 0) {
                int i_data_end =
                    std::min(chunk_length_remaining, (int)buffer.size());

                chunk_body.insert(chunk_body.end(), buffer.begin(),
                                  buffer.begin() + i_data_end);

                buffer.erase(buffer.begin(), buffer.begin() + i_data_end);

                chunk_length_remaining -= i_data_end;

                // End of chunk
                if (chunk_length_remaining == 0) chunk_length_remaining = -1;
            }
        }
    }
}

TransferMethod HttpParser::realize_transfer_method(const headers_t& headers) {
    // The order is important
    //
    // "Messages must not include both a Content-Length header field
    // and a non-identity transfer-coding. If the message does include
    // a non-identity transfer-coding, the Content-Length must be ignored."
    //
    // - RFC 2616, Section 4.4
    if (headers.contains("transfer-encoding")) {
        return TransferMethod::chunked;
    } else if (headers.contains("content-length")) {
        return TransferMethod::content_length;
    } else {
        return TransferMethod::close;
    }
}

std::vector<char> HttpParser::build(bool encode_body) const {
    std::vector<char> build_buffer = std::vector<char>();
    std::vector<char> build_body_data;
    std::map<std::string, std::string, Helper::case_insensitive_comp>
        build_headers(
            this->headers);  // Copy headers in case we need to change them

    // Build status line
    std::string status_line = this->build_status_line() + CRLF;
    Helper::vector_insert(&build_buffer, &status_line);

    // Build body
    if (!this->body.empty()) {
        if (!encode_body) {
            Helper::vector_insert(&build_body_data, &this->body);
        } else {
            build_body_data = build_body(build_headers);
        }
    }

    // Build headers
    for (auto const& h : build_headers) {
        std::string header = h.first + ": " + h.second + CRLF;
        Helper::vector_insert(&build_buffer, &header);
    }
    Helper::vector_insert(&build_buffer, &CRLF);

    // Insert body after headers
    Helper::vector_insert(&build_buffer, &build_body_data);

    return build_buffer;
}
std::vector<char> HttpParser::build_body(headers_t& build_headers) const {
    std::vector<char> build_body;
    std::vector<char> compressed_body = compress_body(headers, body);

    if (transfer_method == TransferMethod::content_length) {
        build_headers["content-length"] =
            std::to_string(compressed_body.size());
        Helper::vector_insert(&build_body, &compressed_body);

    } else if (transfer_method == TransferMethod::chunked) {
        constexpr size_t CHUNK_SIZE = 1024;

        for (size_t i = 1;
             i <= ceil((double)compressed_body.size() / CHUNK_SIZE); i++) {
            size_t current_index = (i - 1) * CHUNK_SIZE;

            int current_chunk_length =
                std::min(CHUNK_SIZE, compressed_body.size() - current_index);

            // Append length
            std::string hex_length =
                (boost::format("%x") % current_chunk_length).str() + CRLF;
            std::copy(hex_length.begin(), hex_length.end(),
                      std::back_inserter(build_body));

            // Append data
            build_body.insert(
                build_body.end(), compressed_body.begin() + current_index,
                compressed_body.begin() + current_index + current_chunk_length);

            // Append data end CRLF
            std::copy(CRLF.begin(), CRLF.end(), std::back_inserter(build_body));
        }

        // Chunk stream end
        const std::string stream_end = '0' + CRLF + CRLF;
        std::copy(stream_end.begin(), stream_end.end(),
                  std::back_inserter(build_body));
    }

    return build_body;
}

std::vector<char> HttpParser::compress_body(
    const headers_t& headers, const std::vector<char>& decompressed_body) {
    // Return an empty vector if body is empty
    if (decompressed_body.empty()) {
        return decompressed_body;
    }

    std::string compress_algo;
    try {
        compress_algo = headers.at("content-encoding");
    } catch (const std::out_of_range& ex) {
        // Return decompressed body if no encoding header
        return decompressed_body;
    }

    if (compress_algo == "br") {
        return compress_brotli(decompressed_body);

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
        throw std::runtime_error("Couldn't detect compression: " +
                                 compress_algo);
    }
}
std::vector<char> HttpParser::compress_brotli(
    const std::vector<char>& decompressed_body) {
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
}

std::vector<char> HttpParser::decompress_body(
    const headers_t& headers, const std::vector<char>& compressed_body) {
    // // Return a vector of /0 if body is empty
    if (compressed_body.empty()) {
        std::vector<char> decompressed_body;
        // decompressed_body.push_back('\0');
        return decompressed_body;
    }

    if (headers.find("content-encoding") == headers.end())
        return compressed_body;

    std::string compress_algo = headers.find("content-encoding")->second;

    if (compress_algo == "br") {
        return decompress_brotli(compressed_body);

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

        return decompressed_body;
    } else {
        throw std::runtime_error("Couldn't detect compression: " +
                                 compress_algo);
    }
}
std::vector<char> HttpParser::decompress_brotli(
    const std::vector<char>& compressed_body) {
    std::unique_ptr<BrotliDecoderState, decltype(&BrotliDecoderDestroyInstance)>
        state(BrotliDecoderCreateInstance(nullptr, nullptr, nullptr),
              BrotliDecoderDestroyInstance);

    BrotliDecoderResult result = BROTLI_DECODER_RESULT_ERROR;

    std::vector<char> out;
    const size_t chunk_size = 1 << 16;
    std::vector<uint8_t> buffer(chunk_size, 0);

    size_t available_in = compressed_body.size();
    const uint8_t* next_in =
        reinterpret_cast<const uint8_t*>(compressed_body.data());
    size_t available_out = buffer.size();
    uint8_t* next_out = buffer.data();

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
                std::string detail = BrotliDecoderErrorString(
                    BrotliDecoderGetErrorCode(state.get()));
                throw std::runtime_error("Brotli decompressing failed: " +
                                         detail);
            }
            throw std::runtime_error("Brotli decompressing failed");
        }
    }
}

}  // namespace HttpParser
