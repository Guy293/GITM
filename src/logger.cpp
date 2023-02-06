#include "logger.h"

#include <boost/log/expressions.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace expr = boost::log::expressions;
namespace sinks = boost::log::sinks;

BOOST_LOG_GLOBAL_LOGGER_INIT(my_logger, logger_t) {
  logger_t lg;

  logging::add_common_attributes();

  // logging::value_ref<std::string> fullpath = expr::attr<std::string>("File");

  logging::add_console_log(
      std::clog,
      boost::log::keywords::format =
          (expr::stream
           << expr::format_date_time<boost::posix_time::ptime>("TimeStamp",
                                                               "%H:%M:%S")
           << " ["
           << expr::attr<boost::log::trivial::severity_level>("Severity")
           << "]: " /*<< expr::attr<std::string>("Function")* << ":"*/
           << expr::attr<std::string>("File") << ":" << expr::attr<int>("Line")
           << ": " << expr::smessage));

  logging::core::get()->set_filter(logging::trivial::severity >=
                                   logging::trivial::debug);

  return lg;
}
