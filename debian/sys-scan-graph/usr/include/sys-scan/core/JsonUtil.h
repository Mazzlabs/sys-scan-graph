// JSON utility helpers (escaped string + ISO8601 time)
#pragma once
#include <string>
#include <chrono>
namespace sys_scan { namespace jsonutil {
std::string escape(const std::string& s);
std::string time_to_iso(std::chrono::system_clock::time_point tp);
} }
