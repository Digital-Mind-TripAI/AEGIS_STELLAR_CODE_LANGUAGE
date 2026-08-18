#include "stellar/ast.h"

namespace stellar::v0_1 {
bool parse_skeleton(const std::string& file, const std::vector<Token>& tokens, Program& program, Diagnostic& error) {
  std::size_t depth=0, start=0;
  for(std::size_t i=0;i+1<tokens.size();++i){
    if(tokens[i].kind==TokenKind::left_crescent) ++depth;
    if(tokens[i].kind==TokenKind::right_crescent){if(depth==0){error={"S1004","error","unmatched right crescent",file,tokens[i].span,"remove it or open a scope first"};return false;}--depth;}
    if(tokens[i].kind==TokenKind::dot && depth==0){if(i==start){error={"S1005","error","empty statement",file,tokens[i].span,"remove the terminator or add a declaration"};return false;} Statement s; s.tokens.assign(tokens.begin()+static_cast<std::ptrdiff_t>(start),tokens.begin()+static_cast<std::ptrdiff_t>(i+1));s.span={tokens[start].span.start,tokens[i].span.end};program.statements.push_back(std::move(s));start=i+1;if(program.statements.size()>max_statements){error={"S0006","error","source exceeds the 2048-statement limit",file,tokens[i].span,"split the package into bounded modules"};return false;}}
  }
  const Token& eof=tokens.back();
  if(depth!=0){error={"S1006","error","unclosed crescent scope",file,eof.span,"close the scope with ')'"};return false;}
  if(start+1<tokens.size()){error={"S1001","error","expected statement terminator '·'",file,eof.span,"terminate the statement with '·' (ASCII ';' is accepted)"};return false;}
  program.span=program.statements.empty()?eof.span:Span{program.statements.front().span.start,eof.span.end}; return true;
}
}
