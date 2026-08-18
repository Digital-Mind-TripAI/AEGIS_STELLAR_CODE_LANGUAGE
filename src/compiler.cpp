#include "stellar/compiler.h"
#include "stellar/language.h"

namespace stellar::v0_1 {
bool check_source(const Source& source, Program& program, Diagnostic& error) {
  if (is_typed_v0_1_source(source)) { TypedAnalysis ignored; if (!analyze_typed_source(source, ignored, error)) return false; }
  std::vector<Token> tokens;
  return lex(source.display_path,source.text,tokens,error)&&parse_skeleton(source.display_path,tokens,program,error);
}

std::string format_program(const Program& program) {
  std::string out;
  for(const auto& statement:program.statements){
    for(std::size_t i=0;i<statement.tokens.size();++i){const auto& t=statement.tokens[i];if(i&&t.kind!=TokenKind::colon&&t.kind!=TokenKind::comma)out+=' ';out+=t.value;}
    out+='\n';
  }
  return out;
}
}
