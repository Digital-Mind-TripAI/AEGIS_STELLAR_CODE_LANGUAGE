#pragma once

#include "token.h"
#include <vector>

namespace stellar::v0_1 {
struct Statement { std::vector<Token> tokens; Span span{}; };
struct Program { std::vector<Statement> statements; Span span{}; };
inline constexpr std::size_t max_statements = 2048;
bool parse_skeleton(const std::string& file, const std::vector<Token>& tokens, Program& program, Diagnostic& error);
}
