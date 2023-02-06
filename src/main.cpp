#include <boost/asio.hpp>
#include <iostream>
#include <thread>

#include "logger.h"
// #include "proxy.h"
#include <QApplication>

#include "mainwindow.h"
#include "server.h"

using namespace boost;

int main(int argc, char** argv) {
  // asio::ip::address_v4 address = asio::ip::make_address_v4("127.0.0.1");
  // asio::ip::tcp::endpoint endpoint = asio::ip::tcp::endpoint(address, 8080);
  asio::ip::tcp::endpoint endpoint =
      asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 8080);

  const char* ca_path = "./cert.crt";
  const char* ca_key_path = "./cert.key";
  LOG_INFO << "Starting proxy";

  //   try {
  asio::io_context io_context;
  Proxy::Server server(io_context, endpoint, ca_path, ca_key_path);
  std::thread t([&]() { io_context.run(); });
  t.detach();

  QApplication app(argc, argv);

  GUI::MainWindow w(nullptr, server);

  w.show();

  return QApplication::exec();
  //   } catch (std::exception& e) {
  //     LOG_ERROR << e.what();
  //   }
}