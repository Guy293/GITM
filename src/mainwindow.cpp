#include "mainwindow.h"

#include <boost/asio.hpp>

#include "logger.h"
// #include "proxy.h"

#include "mainwindow.h"
#include "server.h"
#include "ui_mainwindow.h"

using namespace boost;
using namespace std::placeholders;

namespace GUI {
MainWindow::MainWindow(QWidget* parent, Proxy::Server& server)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      server(server),
      intercept_response_cb() {
  ui->setupUi(this);

  QObject::connect(this, &MainWindow::session_intercepted, this,
                   &MainWindow::set_editor);

  this->ui->interceptingRemote->setText("Remote: ");

  server.set_intercept_cb(
      std::bind(&MainWindow::intercept_cb, this, _1, _2, _3));
}

void MainWindow::intercept_cb(
    const std::vector<char>& http_message, std::string remote_host,
    const Proxy::Server::TInterceptResponseCB& intercept_response_cb) {
  this->intercept_response_cb = intercept_response_cb;

  emit this->session_intercepted(http_message, remote_host);
}

void MainWindow::showEvent(QShowEvent* event) { QWidget::showEvent(event); }

void MainWindow::set_editor(const std::vector<char>& http_message,
                            const std::string& remote_host) {
  ui->plainTextEdit->setEnabled(true);
  ui->sendButton->setEnabled(true);

  ui->plainTextEdit->setPlainText(
      QString::fromUtf8(http_message.data(), http_message.size()));

  this->ui->interceptingRemote->setText(QString("Remote: ") +
                                        QString::fromStdString(remote_host));
}

void MainWindow::on_sendButton_clicked() {
  if (this->intercept_response_cb.has_value()) {
    QByteArray intercepted_message =
        this->ui->plainTextEdit->toPlainText().toUtf8();

    // Add carriage return (\r) to every line feed (\n) to make it a valid HTTP
    intercepted_message.replace("\n", "\r\n");

    this->ui->plainTextEdit->clear();
    this->ui->plainTextEdit->setEnabled(false);
    this->ui->sendButton->setEnabled(false);

    //     auto session = this->server.intercepted_sessions_queue.front();
    auto intercept_response_cb = this->intercept_response_cb.value();
    this->intercept_response_cb.reset();

    intercept_response_cb(std::vector<char>(intercepted_message.begin(),
                                            intercepted_message.end()));

    //     (*session.intercept_response_cb)(std::vector<char>(
    //         intercepted_message.begin(), intercepted_message.end()));

    //     if (!this->server.intercepted_sessions_queue.empty()) {
    //       //       auto session_2 =
    //       this->server.intercepted_sessions_queue.front();
    //       //       this->intercept_response_cb =
    //       session.intercept_response_cb; emit
    //       this->editor_changed(session.http_message);
    //     }
  }
}

MainWindow::~MainWindow() { delete ui; }

}  // namespace GUI
