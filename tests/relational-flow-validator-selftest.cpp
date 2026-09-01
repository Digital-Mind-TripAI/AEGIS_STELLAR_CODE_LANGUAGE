#include "stellar/relational_flow.h"
#include <cassert>

using namespace stellar::v0_1;

int main() {
  RelationalFlow flow;
  flow.name = "signal-path";
  flow.kind = "relational";
  flow.state = "declared";
  flow.nodes = {{"source", "element"}, {"sink", "orb"}};
  flow.edges = {{"observe", "observes", "source", "sink", 1, {}, {}}};
  Diagnostic error;
  assert(validate_relational_flow(flow, error, "selftest.stellar"));

  flow.edges[0].to = "missing";
  assert(!validate_relational_flow(flow, error, "selftest.stellar"));
  assert(error.code == "S6303");
  return 0;
}
