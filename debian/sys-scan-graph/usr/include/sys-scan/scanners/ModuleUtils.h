#pragma once
#include <string>
namespace sys_scan {
std::string decompress_xz_bounded(const std::string& full);
std::string decompress_gz_bounded(const std::string& full);
}
