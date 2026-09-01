#pragma once

#include "diagnostic.h"
#include "token.h"
#include <cstddef>
#include <string>
#include <vector>

namespace stellar::v0_1 {

// Public, declaration-only representation of a relational flow.  The main
// typed-language parser currently owns integration with the broader Unit
// model; this type is the stable seam for moving the flow grammar out of the
// monolithic parser without changing its accepted syntax.
struct RelationalFlowCondition {
  std::string metric;
  std::string op;
  std::string value;
  Span span{};
};

struct RelationalFlowNode {
  std::string id;
  std::string type;
  Span span{};
};

struct RelationalFlowEdge {
  std::string id;
  std::string relation;
  std::string from;
  std::string to;
  long long order{};
  std::vector<RelationalFlowCondition> conditions;
  Span span{};
};

struct RelationalFlow {
  std::string name;
  std::string kind;
  std::vector<RelationalFlowNode> nodes;
  std::vector<RelationalFlowEdge> edges;
  std::string state;
  std::vector<std::string> shortfalls;
  std::vector<std::string> gap_pauses;
  Span span{};
};

// Validate the graph invariants independently of parser/container concerns.
// This is passive: it emits no effects, capabilities, or execution request.
bool validate_relational_flow(const RelationalFlow& flow,
  Diagnostic& error, const std::string& file);

} // namespace stellar::v0_1
