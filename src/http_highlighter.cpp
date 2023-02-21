#include "http_highlighter.h"

#include <QRegularExpression>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QTextLayout>
#include <QTextOption>

namespace GUI {
HttpHighlighter ::HttpHighlighter(QTextDocument* parent)
    : QSyntaxHighlighter(parent) {
  QTextCharFormat base_format;
  base_format.setFontPointSize(12);

  const QString request_status_line_pattern =
      QStringLiteral("^[A-Z]+ (.+ HTTP\\/\\d.\\d)");
  QTextCharFormat request_status_line_format(base_format);
  request_status_line_format.setFontWeight(QFont::Bold);
  request_status_line_format.setForeground(Qt::blue);
  HighlightingRule request_status_line_rule;
  request_status_line_rule.pattern =
      QRegularExpression(request_status_line_pattern);
  request_status_line_rule.format = request_status_line_format;
  request_status_line_rule.line_number = 0;
  highlighting_rules.push_back(request_status_line_rule);

  // const QString response_status_line_pattern = QStringLiteral("^[A-Z]+ [\\S]+
  // HTTP\\/\\d.\\d");
  const QString response_status_line_pattern =
      QStringLiteral("^HTTP\\/\\d.\\d \\d+ .*");
  QTextCharFormat response_status_line_format(base_format);
  response_status_line_format.setFontWeight(QFont::Bold);
  response_status_line_format.setForeground(Qt::blue);
  HighlightingRule response_status_line_rule;
  response_status_line_rule.pattern =
      QRegularExpression(response_status_line_pattern);
  response_status_line_rule.format = response_status_line_format;
  response_status_line_rule.line_number = 0;
  highlighting_rules.push_back(response_status_line_rule);

  const QString methods_pattern = QStringLiteral(
      "\\bGET\\b|\\bPOST\\b|\\bPUT\\b|\\bDELETE\\b|\\bHEAD\\b|\\bOPTIONS\\b|"
      "\\bTRACE\\b|\\bCONNECT\\b");
  QTextCharFormat method_format(base_format);
  method_format.setFontWeight(QFont::Bold);
  method_format.setForeground(Qt::darkGreen);
  HighlightingRule method_rule;
  method_rule.pattern = QRegularExpression(methods_pattern);
  method_rule.format = method_format;
  method_rule.line_number = 0;
  highlighting_rules.push_back(method_rule);

  const QString HTTP_version_pattern = QStringLiteral("HTTP\\/\\d.\\d");
  QTextCharFormat http_version_format(base_format);
  http_version_format.setFontWeight(QFont::Bold);
  http_version_format.setForeground(Qt::darkGreen);
  HighlightingRule http_version_rule;
  http_version_rule.pattern = QRegularExpression(HTTP_version_pattern);
  http_version_rule.format = http_version_format;
  http_version_rule.line_number = 0;
  highlighting_rules.push_back(http_version_rule);

  const QString header_line_pattern = QStringLiteral("^[A-Z-a-z0-9-]+: .*");
  QTextCharFormat header_line_format(base_format);
  header_line_format.setFontItalic(true);
  header_line_format.setForeground(Qt::darkBlue);
  HighlightingRule header_line_rule;
  header_line_rule.pattern = QRegularExpression(header_line_pattern);
  header_line_rule.format = header_line_format;

  highlighting_rules.push_back(header_line_rule);

  const QString header_key_pattern = QStringLiteral("^[A-Za-z0-9\\-]+:");
  QTextCharFormat header_key_format(base_format);
  header_key_format.setFontWeight(QFont::Bold);
  header_key_format.setForeground(Qt::darkBlue);
  HighlightingRule header_key_rule;
  header_key_rule.pattern = QRegularExpression(header_key_pattern);
  header_key_rule.format = header_key_format;
  highlighting_rules.push_back(header_key_rule);
}

void HttpHighlighter::highlightBlock(const QString& text) {
  QTextCharFormat body_format;
  body_format.setForeground(Qt::black);
  body_format.setFontPointSize(12);
  setFormat(0, text.length(), body_format);

  for (const HighlightingRule& rule : std::as_const(highlighting_rules)) {
    if (rule.line_number != -1 &&
        rule.line_number != currentBlock().blockNumber()) {
      continue;
    }

    QRegularExpressionMatchIterator matchIterator =
        rule.pattern.globalMatch(text);
    while (matchIterator.hasNext()) {
      QRegularExpressionMatch match = matchIterator.next();
      setFormat(match.capturedStart(), match.capturedLength(), rule.format);
    }
  }
}

}  // namespace GUI
