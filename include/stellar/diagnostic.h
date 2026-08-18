#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace stellar::v0_1 {
struct Point { std::size_t offset{}; std::size_t line{1}; std::size_t column{1}; };
struct Span { Point start{}; Point end{}; };
struct SecondarySpan { std::string file; Span span{}; std::string label; };
struct Diagnostic {
  std::string code;
  std::string severity{"error"};
  std::string message;
  std::string file;
  Span span{};
  std::string help;
  std::vector<SecondarySpan> secondary_spans;
};
std::string diagnostic_json(const Diagnostic& diagnostic);
std::string diagnostic_human(const Diagnostic& diagnostic);
std::string json_escape(const std::string& value);
}
