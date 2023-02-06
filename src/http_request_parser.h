#pragma once

#include "http_parser.h"

namespace HttpParser {

struct Host {
  std::string name;
  int port;
};

class HttpRequestParser : public HttpParser {
 public:
  std::string method;
  std::string target_uri;
  Host host;

 private:
  virtual std::string build_status_line() const;
  virtual void parse_status_line(std::string t_status_line);
  virtual void parse_host();
};

}  // namespace HttpParser