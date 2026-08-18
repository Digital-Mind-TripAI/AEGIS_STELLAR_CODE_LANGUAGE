#pragma once

#include <array>
#include <string_view>

namespace stellar::v0_1 {
inline constexpr std::array<std::string_view, 6> fixed_width_types{"bool", "i32", "i64", "u32", "u64", "f64"};
inline constexpr std::size_t max_modules = 128;
inline constexpr std::size_t max_functions = 4096;
inline constexpr std::size_t max_loop_bound = 65536;
}
