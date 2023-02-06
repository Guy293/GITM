#pragma once

#define BOOST_USE_WINAPI_VERSION BOOST_WINAPI_VERSION_WIN7

#include <string.h>

#include <boost/log/attributes.hpp>
#include <boost/log/core.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/manipulators/add_value.hpp>

#ifdef WIN32
#define CURRENT_FILENAME strrchr("\\" __FILE__, '\\') + 1
#else
#define CURRENT_FILENAME strrchr("/" __FILE__, '/') + 1
#endif

#define CUSTOM_LOG(log_, sv)                                         \
  BOOST_LOG_SEV(log_, sv) << boost::log::add_value("Line", __LINE__) \
                          << boost::log::add_value("File", CURRENT_FILENAME)
//<< boost::log::add_value("Function", BOOST_CURRENT_FUNCTION)

#define LOG_DEBUG CUSTOM_LOG(my_logger::get(), boost::log::trivial::debug)
#define LOG_INFO CUSTOM_LOG(my_logger::get(), boost::log::trivial::info)
#define LOG_WARN CUSTOM_LOG(my_logger::get(), boost::log::trivial::warning)
#define LOG_ERROR CUSTOM_LOG(my_logger::get(), boost::log::trivial::error)

// Narrow-char thread-safe logger.
typedef boost::log::sources::severity_logger_mt<
    boost::log::trivial::severity_level>
    logger_t;

// declares a global logger with a custom initialization
BOOST_LOG_GLOBAL_LOGGER(my_logger, logger_t);