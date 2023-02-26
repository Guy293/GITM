#include "pending_sessions_list_model.h"

#include <qvariant.h>

#include <chrono>

#include "session.h"

namespace GUI {

PendingRequestsListModel::PendingRequestsListModel(Proxy::Server& server)
    : QAbstractListModel(), server(server) {}

int PendingRequestsListModel::rowCount(const QModelIndex& parent) const {
  return this->server.get_intercepted_sessions_list_size();
}

QVariant PendingRequestsListModel::data(const QModelIndex& index,
                                        int role) const {
  if (!index.isValid()) {
    return QVariant();
  }

  if (index.row() >= this->server.get_intercepted_sessions_list_size()) {
    return QVariant();
  }

  if (role == Qt::DisplayRole) {
    // return QVariant("test");
    auto intercepted_session =
        this->server.get_intercepted_session(index.row());

    std::string full_host =
        intercepted_session.remote_host.name + ":" +
        std::to_string(intercepted_session.remote_host.port).c_str();

    // Convert to "HH:MM:SS"
    auto requested_at =
        std::chrono::system_clock::to_time_t(intercepted_session.requested_at);
    char time_buffer[9];
    std::strftime(time_buffer, sizeof(time_buffer), "%H:%M:%S",
                  std::localtime(&requested_at));

    std::string requested_at_str = "[" + std::string(time_buffer) + "]";

    if (intercepted_session.request_type ==
        Proxy::Server::RequestType::HTTP_REQUEST) {
      return QVariant(
          QString::fromStdString(requested_at_str + " -> " + full_host));
    } else {
      return QVariant(
          QString::fromStdString(requested_at_str + " <- " + full_host));
    }
  }
  return QVariant();
}

}  // namespace GUI