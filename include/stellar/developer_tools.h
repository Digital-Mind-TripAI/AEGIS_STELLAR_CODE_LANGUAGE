#pragma once
#include "diagnostic.h"
#include <filesystem>
#include <string>

namespace stellar::v0_1 {
bool inspect_developer_view(const std::filesystem::path& target, const std::string& view, std::string& output, Diagnostic& error);
bool test_package_without_execution(const std::filesystem::path& manifest, std::string& output, Diagnostic& error);
bool create_or_verify_bundle(const std::filesystem::path& manifest, const std::filesystem::path& schema_root,
  const std::filesystem::path& output, const std::filesystem::path& verify, std::string& response, Diagnostic& error);
}
