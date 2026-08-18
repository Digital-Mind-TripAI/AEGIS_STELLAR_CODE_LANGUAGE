#include "stellar/token.h"
#include <cctype>

namespace stellar::v0_1 {
bool lex(const std::string& file, const std::string& source, std::vector<Token>& out, Diagnostic& error) {
  Point p{0,1,1};
  auto advance = [&](std::size_t bytes = 1) { for (std::size_t j=0;j<bytes;++j) { const char c=source[p.offset++]; if(c=='\n'){++p.line;p.column=1;}else ++p.column; } };
  auto emit = [&](TokenKind kind, std::string value, Point start) { out.push_back({kind,std::move(value),{start,p}}); return out.size() <= max_tokens; };
  while (p.offset < source.size()) {
    const unsigned char c = static_cast<unsigned char>(source[p.offset]);
    if (std::isspace(c)) { advance(); continue; }
    const Point start = p;
    if (p.offset+1 < source.size() && static_cast<unsigned char>(source[p.offset])==0xc2 && static_cast<unsigned char>(source[p.offset+1])==0xb7) { p.offset+=2;++p.column; if(!emit(TokenKind::dot,"·",start)) break; continue; }
    if (p.offset+2 < source.size() && static_cast<unsigned char>(source[p.offset])==0xe2 && static_cast<unsigned char>(source[p.offset+1])==0x80 && static_cast<unsigned char>(source[p.offset+2])==0xba) { p.offset+=3;++p.column; if(!emit(TokenKind::chevron,"›",start)) break; continue; }
    TokenKind kind{}; std::string value; bool punctuation=true;
    switch(c) { case ';':kind=TokenKind::dot;value="·";break; case '>':kind=TokenKind::chevron;value="›";break; case '(':kind=TokenKind::left_crescent;value="(";break; case ')':kind=TokenKind::right_crescent;value=")";break; case '~':kind=TokenKind::wave;value="~";break; case '/':kind=TokenKind::angular;value="/";break; case ':':kind=TokenKind::colon;value=":";break; case ',':kind=TokenKind::comma;value=",";break; default:punctuation=false; }
    if (punctuation) { advance(); if(!emit(kind,value,start)) break; continue; }
    if (c=='"') { advance(); std::string v="\""; while(p.offset<source.size() && source[p.offset]!='"' && source[p.offset]!='\n'){v+=source[p.offset];advance();} if(p.offset>=source.size()||source[p.offset]!='"'){error={"S1003","error","unterminated string literal",file,{start,p},"close the string with a double quote"};return false;} v+='"';advance();emit(TokenKind::string_value,v,start);continue; }
    if (std::isdigit(c) || (c=='-' && p.offset+1<source.size() && std::isdigit(static_cast<unsigned char>(source[p.offset+1])))) { std::string v; std::size_t dots=0; if(c=='-'){v+='-';advance();} while(p.offset<source.size() && (std::isdigit(static_cast<unsigned char>(source[p.offset]))||source[p.offset]=='.')){if(source[p.offset]=='.')++dots;v+=source[p.offset];advance();} if(dots>1||(!v.empty()&&v.back()=='.')){error={"S1002","error","malformed numeric literal",file,{start,p},"use an integer or one finite decimal point"};return false;} emit(TokenKind::number,v,start);continue; }
    if (std::isalpha(c)||c=='_') { std::string v; while(p.offset<source.size()){const unsigned char x=static_cast<unsigned char>(source[p.offset]);if(!(std::isalnum(x)||x=='_'||x=='-'||x=='.'))break;v+=static_cast<char>(x);advance();}emit(TokenKind::identifier,v,start);continue; }
    error={"S1002","error","unexpected source character",file,{start,p},"use the stellar-lab-v0 token profile"}; return false;
  }
  if(out.size()>max_tokens){error={"S0005","error","source exceeds the 16384-token limit",file,{p,p},"split the package into bounded modules"};return false;}
  out.push_back({TokenKind::end,"",{p,p}}); return true;
}
}
