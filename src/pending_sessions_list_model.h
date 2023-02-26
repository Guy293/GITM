#pragma once

#include <QAbstractListModel>
#include <boost/uuid/uuid.hpp>

#include "server.h"

namespace GUI {
class PendingRequestsListModel : public QAbstractListModel {
  Q_OBJECT

 public:
  PendingRequestsListModel(Proxy::Server& server);

  // QAbstractItemModel interface
  int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  QVariant data(const QModelIndex& index,
                int role = Qt::DisplayRole) const override;

 private:
  Proxy::Server& server;
};
}  // namespace GUI