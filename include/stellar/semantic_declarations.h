#pragma once

#include "stellar/relational_flow.h"
#include "stellar/token.h"
#include <string>
#include <utility>
#include <vector>

namespace stellar::v0_1 {

struct ElementDecl { std::string name; std::string kind; std::vector<std::pair<std::string,std::string>> metadata; Span span{}; };
struct OrbDecl { std::string name; std::string kind; std::vector<std::string> elements; Span span{}; };
struct HarmonicDecl { std::string name; std::string kind; std::vector<std::pair<std::string,std::string>> parameters; Span span{}; };
struct TotemDecl { std::string name; std::string kind; std::string parent; std::vector<std::string> children; std::vector<std::string> shortfalls; Span span{}; };
struct ActuatorDecl { std::string name; std::string kind; std::string target; std::string totem; std::string shortfall; std::string authorization; Span span{}; };
struct GapPauseDecl { std::string pause_id; std::string reason; long long timeout_ms{}; std::string resume; std::string abort; Span span{}; };
struct FieldLayerDecl { std::string name; std::string kind; std::string orb; std::string target; std::string state; Span span{}; };
using RelationalFlowDecl = RelationalFlow;

// Parses only the passive semantic declaration forms. The caller owns the
// token cursor and remains responsible for struct/function declarations.
class SemanticDeclarationParser {
 public:
  SemanticDeclarationParser(const std::string& file, const std::vector<Token>& tokens, Diagnostic& error, std::size_t& at)
      : file_(file), tokens_(tokens), error_(error), at_(at) {}
  ElementDecl element();
  OrbDecl orb();
  HarmonicDecl harmonic();
  TotemDecl totem();
  ActuatorDecl actuator();
  GapPauseDecl gap_pause();
  FieldLayerDecl field();
  RelationalFlowDecl flow();
 private:
  const std::string& file_; const std::vector<Token>& tokens_; Diagnostic& error_; std::size_t& at_;
  const Token& peek(std::size_t n=0) const;
  Token take();
  [[noreturn]] void fail(std::string code, std::string message, Span span, std::string help);
  Token identifier(const char* help="provide an identifier");
  Token expect(TokenKind kind, const char* message);
  long long integer_literal(const std::string& code, const char* help);
};
}
