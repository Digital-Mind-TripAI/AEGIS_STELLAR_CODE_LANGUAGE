#include "stellar/relational_flow.h"
#include <cmath>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>

namespace stellar::v0_1 {
namespace {
[[noreturn]] void reject(Diagnostic& error, const std::string& file,
  const std::string& code, const std::string& message, const Span& span,
  const std::string& help) {
  error = {code, "error", message, file, span, help};
  throw std::runtime_error(code);
}
}

bool validate_relational_flow(const RelationalFlow& flow, Diagnostic& error,
  const std::string& file) {
  try {
    if (flow.nodes.empty() || flow.edges.empty())
      reject(error, file, "S6301", "relational-flow requires at least one node and edge",
        flow.span, "declare a bounded passive graph");
    if (flow.state != "declared" && flow.state != "paused" && flow.state != "closed")
      reject(error, file, "S6301", "invalid relational-flow state", flow.span,
        "use declared, paused, or closed");
    std::set<std::string> nodes;
    for (const auto& node : flow.nodes) {
      if (!nodes.insert(node.id).second)
        reject(error, file, "S6302", "duplicate relational-flow node", node.span,
          "use a unique node identifier");
      if (node.type != "element" && node.type != "orb" && node.type != "field-layer" && node.type != "tether")
        reject(error, file, "S6301", "invalid relational-flow node type", node.span,
          "use element, orb, field-layer, or tether");
    }
    std::set<std::string> edges;
    std::set<long long> orders;
    std::map<std::string, std::vector<std::string>> graph;
    for (const auto& edge : flow.edges) {
      if (!edges.insert(edge.id).second)
        reject(error, file, "S6302", "duplicate relational-flow edge", edge.span,
          "use a unique edge identifier");
      if (edge.relation != "supports" && edge.relation != "observes" &&
          edge.relation != "contains" && edge.relation != "tethers")
        reject(error, file, "S6301", "invalid relational-flow edge relation", edge.span,
          "use supports, observes, contains, or tethers");
      if (!nodes.contains(edge.from) || !nodes.contains(edge.to))
        reject(error, file, "S6303", "relational-flow edge endpoint is unresolved", edge.span,
          "reference declared flow nodes");
      if (edge.order < 1 || !orders.insert(edge.order).second)
        reject(error, file, "S6302", "duplicate or invalid relational-flow edge order", edge.span,
          "use each positive order once");
      for (const auto& condition : edge.conditions) {
        if (condition.metric != "eq" && condition.metric != "drift" &&
            condition.metric != "capture" && condition.metric != "witness")
          reject(error, file, "S6301", "invalid flow condition metric", condition.span,
            "use eq, drift, capture, or witness");
        if (condition.op != ">=" && condition.op != "<=" && condition.op != "==")
          reject(error, file, "S6301", "invalid relational-flow condition operator", condition.span,
            "use >=, <=, or ==");
        if (condition.metric == "witness") {
          if (condition.value != "true" && condition.value != "false")
            reject(error, file, "S6301", "witness condition must be boolean", condition.span,
              "use true or false");
        } else {
          try {
            const double value = std::stod(condition.value);
            if (!std::isfinite(value) || value < 0.0 || value > 1.0) throw std::runtime_error("range");
          } catch (...) {
            reject(error, file, "S6301", "flow condition must be a finite value from 0 through 1",
              condition.span, "use a bounded numeric value");
          }
        }
      }
      graph[edge.from].push_back(edge.to);
    }
    std::set<std::string> visiting, done;
    std::function<void(const std::string&)> visit = [&](const std::string& id) {
      if (visiting.contains(id)) reject(error, file, "S6304",
        "relational-flow graph must be acyclic", flow.span,
        "remove the cycle from the passive graph");
      if (done.contains(id)) return;
      visiting.insert(id);
      for (const auto& next : graph[id]) visit(next);
      visiting.erase(id);
      done.insert(id);
    };
    for (const auto& node : flow.nodes) visit(node.id);
    return true;
  } catch (...) { return false; }
}
}
