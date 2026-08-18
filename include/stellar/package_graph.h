#pragma once

#include "diagnostic.h"
#include <filesystem>
#include <string>
#include <vector>

namespace stellar::v0_1 {
struct PackageGraphAnalysis {
  std::string json;
  std::string dependency_lock;
  struct NativeModule {
    std::string id;
    std::string object_name;
    std::string assembly;
    std::string trace_json;
    std::vector<std::string> defined_symbols;
    std::vector<std::string> undefined_symbols;
  };
  std::vector<NativeModule> native_modules;
  std::string native_plan;
};

// Resolves and type-checks a package without emitting objects, linking, loading,
// or executing native code.
bool analyze_package_graph(const std::filesystem::path& manifest, PackageGraphAnalysis& analysis, Diagnostic& error, bool native_lowering = false);
bool write_dependency_lock(const std::filesystem::path& manifest, const PackageGraphAnalysis& analysis, Diagnostic& error);
bool verify_dependency_lock(const std::filesystem::path& manifest, const PackageGraphAnalysis& analysis, Diagnostic& error);
bool write_native_package_plan(const std::filesystem::path& manifest, const std::filesystem::path& output,
  const PackageGraphAnalysis& analysis, Diagnostic& error);
}
