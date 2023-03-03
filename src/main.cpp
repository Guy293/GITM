#include <qapplication.h>

#include <QSettings>

#include <QApplication>
#include <QSettings>
#include <boost/asio.hpp>
#include <iostream>
#include <thread>

#include "cert.h"
#include "logger.h"
#include "mainwindow.h"
#include "server.h"

using namespace boost;

int main(int argc, char** argv) {
  // asio::ip::address_v4 address = asio::ip::make_address_v4("127.0.0.1");
  // asio::ip::tcp::endpoint endpoint = asio::ip::tcp::endpoint(address, 8080);
  asio::ip::tcp::endpoint endpoint =
      asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 8080);

  QSettings settings("settings.ini", QSettings::IniFormat);

  Proxy::Cert::CertInfo ca_cert_info;

  // Generate root certificate if it doesn't exist
  if (settings.value("cert_pub").isNull() ||
      settings.value("cert_priv").isNull()) {
    ca_cert_info = Proxy::Cert::generate_root_certificate();
    settings.setValue("cert_pub", ca_cert_info.pub.c_str());
    settings.setValue("cert_priv", ca_cert_info.key.c_str());
  } else {
    ca_cert_info.pub = settings.value("cert_pub").toString().toStdString();
    ca_cert_info.key = settings.value("cert_priv").toString().toStdString();
  }

  LOG_INFO << "Starting proxy";

  //   try {
  asio::io_context io_context;
  Proxy::Server server(io_context, endpoint, ca_cert_info);
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