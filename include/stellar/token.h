#pragma once

#include "diagnostic.h"
#include <string>
#include <vector>

namespace stellar::v0_1 {
enum class TokenKind { identifier, number, string_value, dot, chevron, left_crescent, right_crescent, wave, angular, colon, comma, operator_token, end };
struct Token { TokenKind kind{}; std::string value; Span span{}; };
inline constexpr std::size_t max_tokens = 16384;
bool lex(const std::string& file, const std::string& source, std::vector<Token>& tokens, Diagnostic& error);
}
