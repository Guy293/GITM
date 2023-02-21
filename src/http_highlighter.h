#pragma once

#include <QList>
#include <QRegularExpression>
#include <QSyntaxHighlighter>
#include <QTextBlock>
#include <QTextBlockUserData>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QTextFormat>
#include <QTextLayout>
#include <QTextOption>

namespace GUI {
class HttpHighlighter : public QSyntaxHighlighter {
  Q_OBJECT

 public:
  HttpHighlighter(QTextDocument* parent = nullptr);

 protected:
  void highlightBlock(const QString& text) override;

 private:
  struct HighlightingRule {
    QRegularExpression pattern;
    QTextCharFormat format;
    int line_number = -1;
  };
  std::list<HighlightingRule> highlighting_rules;
};
}  // namespace GUI
