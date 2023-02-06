#include "http_response_parser.h"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <vector>

namespace HttpParser {

std::string HttpResponseParser::build_status_line() const {
  return this->http_version + ' ' + this->status;
}

void HttpResponseParser::parse_status_line(std::string t_status_line) {
  std::size_t i_split = t_status_line.find(" ");

  this->http_version = t_status_line.substr(0, i_split);
  this->status = t_status_line.substr(i_split + 1);
}

}  // namespace HttpParser