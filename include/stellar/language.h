#pragma once

#include "diagnostic.h"
#include "source.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace stellar::v0_1 {
struct TypedAnalysis { std::string json; };

// Parses and type-checks the bounded v0.1 language core. This produces evidence
// only; it does not emit, link, load, or execute native code.
bool analyze_typed_source(const Source& source, TypedAnalysis& analysis, Diagnostic& error);
bool is_typed_v0_1_source(const Source& source);

struct NativeModuleLowering {
  std::string assembly;
  std::string trace_json;
  std::vector<std::string> defined_symbols;
  std::vector<std::string> undefined_symbols;
};

// Lowers an already package-resolved, capability-free typed module. External
// names and exported names come from the verified package graph; source cannot
// inject assembly, symbols, flags, paths, or capabilities.
bool lower_typed_native_module(const Source& source, const std::string& module,
  const std::map<std::string,std::string>& external_symbols,
  const std::set<std::string>& exported_names,
  NativeModuleLowering& lowering, Diagnostic& error);
}
