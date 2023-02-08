#pragma once
#include <QMainWindow>

#include "server.h"
#include "session.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

namespace GUI {
class MainWindow : public QMainWindow {
  Q_OBJECT
 protected:
  virtual void showEvent(QShowEvent* event);

 public:
  explicit MainWindow(QWidget* parent, Proxy::Server& server);
  ~MainWindow() override;

 public slots:
  void set_editor(const std::vector<char>& http_message,
                  const std::string& remote_host);
  void on_sendButton_clicked();
  void on_interceptToClientCheckBox_toggled(bool checked);
  void on_interceptToHostCheckBox_toggled(bool checked);
  void on_hostFilterLineEdit_textEdited(const QString& arg1);

 signals:
  void session_intercepted(const std::vector<char>& http_message,
                           const std::string& remote_host);

 private:
  void intercept_cb(
      const std::vector<char>& http_message, std::string remote_host,
      const Proxy::Server::TInterceptResponseCB& intercept_response_cb);

  Ui::MainWindow* ui;
  Proxy::Server& server;
  std::optional<Proxy::Server::TInterceptResponseCB> intercept_response_cb;
};
}  // namespace GUI
