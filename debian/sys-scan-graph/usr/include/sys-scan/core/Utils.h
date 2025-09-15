#pragma once
#include <string>
#include <vector>
#include <optional>

namespace sys_scan {
namespace utils {
    std::vector<std::string> read_lines(const std::string& path);
    std::optional<std::string> read_file(const std::string& path, size_t max_bytes = 1<<20);
    bool is_world_writable(const std::string& path);
    std::string trim(const std::string& s);
    std::string read_file_trim(const std::string& path);
}
}
