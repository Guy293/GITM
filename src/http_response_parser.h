#pragma once

#include "http_parser.h"

namespace HttpParser {
class HttpResponseParser : public HttpParser {
 public:
  std::string status;

 private:
  virtual std::string build_status_line() const;
  virtual void parse_status_line(std::string t_status_line);
};

}  // namespace HttpParser