#pragma once

#include "diagnostic.h"
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace stellar::v0_1 {
struct PackageManifest {
  std::string schema, name, version, target, profile, entry;
  std::vector<std::string> modules, relics, capabilities;
};
struct PackageInspection {
  std::string canonical_manifest, integrity;
  std::map<std::string, std::string> module_hashes;
};
bool inspect_manifest(const std::filesystem::path& path, PackageInspection& result, Diagnostic& error);
bool write_lock(const std::filesystem::path& manifest_path, const PackageInspection& result, Diagnostic& error);
bool verify_lock(const std::filesystem::path& manifest_path, const PackageInspection& result, Diagnostic& error);
std::string inspection_json(const PackageInspection& result);
std::string sha256_text(const std::string& text);
}
