#pragma once
#include <QMainWindow>
#include <boost/uuid/uuid.hpp>

#include "server.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

namespace GUI {
class MainWindow : public QMainWindow {
    Q_OBJECT

   public:
    explicit MainWindow(QWidget* parent, Proxy::Server& server);
    ~MainWindow() override;

   public slots:
    void on_new_intercpeted_session();
    void on_session_queue_clicked(const QModelIndex& index);
    void on_sendButton_clicked();
    void on_dropButton_clicked();
    void on_sendAllButton_clicked();
    void on_interceptToClientCheckBox_toggled(bool checked);
    void on_interceptToHostCheckBox_toggled(bool checked);
    void on_hostFilterLineEdit_textEdited(const QString& arg1);

   signals:
    void session_intercepted_signal();

   private:
    void update_interception_queue_list_view();
    void select_session_index_from_queue(int next_index_int);
    void handle_send(bool drop_session = false);
    void set_editor_session(
        const Proxy::Server::InterceptedSession& intercepted_session);

    void intercept_cb();

    Ui::MainWindow* ui;
    Proxy::Server& server;
    boost::uuids::uuid current_intercepting_session_id;
};
}  // namespace GUI
