#pragma once

#include "diagnostic.h"
#include <filesystem>
#include <string>

namespace stellar::v0_1 {
inline constexpr std::size_t max_source_bytes = 262144;
struct Source { std::filesystem::path path; std::string display_path; std::string text; };
bool load_source(const std::filesystem::path& path, Source& source, Diagnostic& error);
Point end_point(const std::string& text);
}
