#include "http_request_parser.h"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <vector>

namespace HttpParser {

std::string HttpRequestParser::build_status_line() const {
    return this->method + ' ' + this->target_uri + ' ' + this->http_version;
}

void HttpRequestParser::parse_status_line(std::string t_status_line) {
    std::vector<std::string> status_line_tokens;
    boost::split(status_line_tokens, t_status_line, boost::is_any_of(" "),
                 boost::token_compress_on);

    this->method = status_line_tokens[0];
    this->target_uri = status_line_tokens[1];
    this->http_version = status_line_tokens[2];
}

void HttpRequestParser::parse_host() {
    std::string hostname = this->target_uri;

    std::size_t i_protocol = hostname.find("://");
    if (i_protocol != std::string::npos)
        hostname = hostname.substr(i_protocol + 3);

    std::size_t i_path = hostname.find("/");
    if (i_path != std::string::npos) hostname = hostname.substr(0, i_path);

    std::size_t i_port = hostname.find(":");
    if (i_port != std::string::npos) {
        this->host.name = hostname.substr(0, i_port);
        this->host.port = std::stoi(hostname.substr(i_port + 1));
    } else {
        this->host.name = hostname;
        this->host.port = 80;
    }
}

}  // namespace HttpParser