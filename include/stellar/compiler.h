#pragma once

#include "ast.h"
#include "source.h"

namespace stellar::v0_1 {
bool check_source(const Source& source, Program& program, Diagnostic& error);
std::string format_program(const Program& program);
}
