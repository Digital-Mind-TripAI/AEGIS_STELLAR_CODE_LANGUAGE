#include "stellar/source.h"
#include <fstream>
#include <iterator>

namespace stellar::v0_1 {
static bool valid_utf8(const std::string& s) {
  for (std::size_t i = 0; i < s.size();) {
    const auto c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) { ++i; continue; }
    std::size_t n = 0; unsigned int cp = 0;
    if ((c & 0xe0) == 0xc0) { n = 2; cp = c & 0x1f; if (cp == 0) return false; }
    else if ((c & 0xf0) == 0xe0) { n = 3; cp = c & 0x0f; }
    else if ((c & 0xf8) == 0xf0) { n = 4; cp = c & 0x07; }
    else return false;
    if (i + n > s.size()) return false;
    for (std::size_t j = 1; j < n; ++j) { const auto x = static_cast<unsigned char>(s[i+j]); if ((x & 0xc0) != 0x80) return false; cp = (cp << 6) | (x & 0x3f); }
    if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    i += n;
  }
  return true;
}

Point end_point(const std::string& text) {
  Point p{0,1,1};
  for (const char c : text) { ++p.offset; if (c == '\n') { ++p.line; p.column = 1; } else ++p.column; }
  return p;
}

bool load_source(const std::filesystem::path& path, Source& source, Diagnostic& error) {
  const auto display = std::filesystem::absolute(path).generic_string();
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) { error = {"S0004", "error", "source file could not be read", display, {}, "provide an existing regular file"}; return false; }
  if (size > max_source_bytes) { error = {"S0001", "error", "source exceeds the 262144-byte limit", display, {}, "split the package into bounded modules"}; return false; }
  std::ifstream in(path, std::ios::binary);
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (text.find('\0') != std::string::npos) { error = {"S0002", "error", "source contains a NUL byte", display, {}, "remove binary data from the source file"}; return false; }
  if (!valid_utf8(text)) { error = {"S0003", "error", "source is not well-formed UTF-8", display, {}, "encode Stellar source as UTF-8 without a byte-order mark"}; return false; }
  source = {std::filesystem::absolute(path), display, std::move(text)};
  return true;
}
}
