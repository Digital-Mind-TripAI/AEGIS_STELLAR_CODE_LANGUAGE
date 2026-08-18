#include "stellar/diagnostic.h"
#include <sstream>

namespace stellar::v0_1 {
namespace { std::string stage(const std::string& code){if(code.size()<2)return"unknown";switch(code[1]){case'0':return"source";case'1':return"lex-parse";case'2':return"type";case'3':return"layout-control";case'4':return"module-relic";case'5':return"package-integrity";case'6':return"lower-link";case'7':return"developer-tooling-security";default:return"unknown";}} }
std::string json_escape(const std::string& value) {
  std::ostringstream out;
  for (const unsigned char c : value) {
    switch (c) {
      case '\\': out << "\\\\"; break; case '"': out << "\\\""; break;
      case '\n': out << "\\n"; break; case '\r': out << "\\r"; break; case '\t': out << "\\t"; break;
      default: if (c < 0x20) { const char* h = "0123456789abcdef"; out << "\\u00" << h[c >> 4] << h[c & 15]; } else out << static_cast<char>(c);
    }
  }
  return out.str();
}

std::string diagnostic_json(const Diagnostic& d) {
  std::ostringstream o;
  o << "{\"code\":\"" << json_escape(d.code) << "\",\"severity\":\"" << json_escape(d.severity)
    << "\",\"message\":\"" << json_escape(d.message) << "\",\"file\":\"" << json_escape(d.file)
    << "\",\"span\":{\"start\":{\"offset\":" << d.span.start.offset << ",\"line\":" << d.span.start.line << ",\"column\":" << d.span.start.column
    << "},\"end\":{\"offset\":" << d.span.end.offset << ",\"line\":" << d.span.end.line << ",\"column\":" << d.span.end.column
    << "}},\"primarySpan\":{\"start\":{\"offset\":" << d.span.start.offset << ",\"line\":" << d.span.start.line << ",\"column\":" << d.span.start.column
    << "},\"end\":{\"offset\":" << d.span.end.offset << ",\"line\":" << d.span.end.line << ",\"column\":" << d.span.end.column
    << "}},\"secondarySpans\":[";
  for(std::size_t i=0;i<d.secondary_spans.size();++i){if(i)o<<',';const auto&s=d.secondary_spans[i];o<<"{\"file\":\""<<json_escape(s.file)<<"\",\"label\":\""<<json_escape(s.label)<<"\",\"span\":{\"start\":{\"offset\":"<<s.span.start.offset<<",\"line\":"<<s.span.start.line<<",\"column\":"<<s.span.start.column<<"},\"end\":{\"offset\":"<<s.span.end.offset<<",\"line\":"<<s.span.end.line<<",\"column\":"<<s.span.end.column<<"}}}";}
  o << "],\"stage\":\""<<stage(d.code)<<"\",\"help\":\"" << json_escape(d.help) << "\"}";
  return o.str();
}

std::string diagnostic_human(const Diagnostic& d) {
  std::ostringstream o;
  o << d.file << ':' << d.span.start.line << ':' << d.span.start.column << ": " << d.severity << '[' << d.code << "]: " << d.message;
  if (!d.help.empty()) o << "\n  help: " << d.help;
  for(const auto&secondary:d.secondary_spans)o<<"\n  note: "<<secondary.file<<':'<<secondary.span.start.line<<':'<<secondary.span.start.column<<": "<<secondary.label;
  return o.str();
}
}
