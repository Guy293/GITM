#include "mainwindow.h"

#include <qabstractitemmodel.h>
#include <qlistwidget.h>
#include <qobject.h>

#include <boost/asio.hpp>
#include <boost/uuid/nil_generator.hpp>

#include "http_highlighter.h"
#include "logger.h"
#include "mainwindow.h"
#include "pending_sessions_list_model.h"
#include "server.h"
#include "ui_mainwindow.h"

using namespace boost;
using namespace std::placeholders;

namespace GUI {
MainWindow::MainWindow(QWidget* parent, Proxy::Server& server)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      server(server),
      // current_intercepting_session_index(0)
      current_intercepting_session_id(boost::uuids::nil_uuid()) {
  ui->setupUi(this);

  QObject::connect(this, &MainWindow::session_intercepted_signal, this,
                   &MainWindow::on_new_intercpeted_session);
  HttpHighlighter* highlighter =
      new HttpHighlighter(ui->plainTextEdit->document());

  this->ui->interceptingRemote->setText("Remote: ");
  this->ui->plainTextEdit->setEnabled(false);
  this->ui->sendButton->setEnabled(false);

  QAbstractItemModel* model = new GUI::PendingRequestsListModel(this->server);
  this->ui->interceptionQueueListView->setModel(model);

  QObject::connect(this->ui->interceptionQueueListView, &QListView::clicked,
                   this, &MainWindow::on_session_queue_clicked);

  server.set_intercept_cb(std::bind(&MainWindow::intercept_cb, this));
}

void MainWindow::intercept_cb() { emit this->session_intercepted_signal(); }

void MainWindow::set_editor_session(
    const Proxy::Server::InterceptedSession& intercepted_session) {
  this->ui->plainTextEdit->setPlainText(
      QString::fromUtf8(intercepted_session.http_message.data(),
                        intercepted_session.http_message.size()));

  this->ui->interceptingRemote->setText(
      QString("Remote: ") +
      QString::fromStdString(
          intercepted_session.remote_host.name + ":" +
          std::to_string(intercepted_session.remote_host.port)));

  this->ui->plainTextEdit->setEnabled(true);
  this->ui->sendButton->setEnabled(true);
}

void MainWindow::showEvent(QShowEvent* event) { QWidget::showEvent(event); }

void MainWindow::on_new_intercpeted_session() {
  this->ui->interceptionQueueListView->model()->dataChanged(
      this->ui->interceptionQueueListView->model()->index(0, 0),
      this->ui->interceptionQueueListView->model()->index(
          this->ui->interceptionQueueListView->model()->rowCount(), 0));

  // Select the first session if there is no current session selected
  if (this->ui->plainTextEdit->toPlainText().isEmpty()) {
    QModelIndex first_index =
        this->ui->interceptionQueueListView->model()->index(0, 0);
    this->ui->interceptionQueueListView->setCurrentIndex(first_index);
    this->on_session_queue_clicked(first_index);
  }
}

void MainWindow::on_session_queue_clicked(const QModelIndex& index) {
  auto intercepted_session = this->server.get_intercepted_session(index.row());
  this->current_intercepting_session_id = intercepted_session.id;
  this->set_editor_session(intercepted_session);
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
    this->ui->interceptingRemote->setText("Remote: ");

  auto current_intercepting_session = this->server.get_intercepted_session(
      this->current_intercepting_session_id);

  auto intercept_response_cb =
      *current_intercepting_session.intercept_response_cb;

    intercept_response_cb(std::vector<char>(intercepted_message.begin(),
                                            intercepted_message.end()));

  this->ui->interceptionQueueListView->model()->dataChanged(
      this->ui->interceptionQueueListView->model()->index(0, 0),
      this->ui->interceptionQueueListView->model()->index(
          this->ui->interceptionQueueListView->model()->rowCount(), 0));

  // Select the next session in the queue
  int current_index = this->ui->interceptionQueueListView->currentIndex().row();
  int next_index_int = current_index - 1;
  if (next_index_int < 0) {
    next_index_int = 0;
  }
  QModelIndex next_index =
      this->ui->interceptionQueueListView->model()->index(next_index_int, 0);
  if (next_index.isValid()) {
    this->ui->interceptionQueueListView->setCurrentIndex(next_index);
    this->on_session_queue_clicked(next_index);
  }
}

void MainWindow::on_interceptToClientCheckBox_toggled(bool checked) {
  this->server.set_intercept_to_client_enabled(checked);
}

void MainWindow::on_interceptToHostCheckBox_toggled(bool checked) {
  this->server.set_intercept_to_host_enabled(checked);
}

void MainWindow::on_hostFilterLineEdit_textEdited(const QString& arg1) {
  this->server.set_host_interception_filter(arg1.toStdString());
}

MainWindow::~MainWindow() { delete ui; }

}  // namespace GUI
