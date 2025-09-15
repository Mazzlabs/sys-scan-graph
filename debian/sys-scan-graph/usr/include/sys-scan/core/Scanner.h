#pragma once
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <optional>
#include <map>
#include "Severity.h"

namespace sys_scan {

struct Finding {
    std::string id;
    std::string title;
    Severity severity = Severity::Info;
    std::string description;
    std::map<std::string, std::string> metadata; // flexible key/value pairs
    int base_severity_score = 0; // static mapping from severity; final holistic risk computed downstream
    bool operational_error = false; // true if this represents scanner operational failure, not a security issue
};

struct ScanResult {
    std::string scanner_name;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::vector<Finding> findings;
};

class Report; // fwd
struct ScanContext; // fwd

class Scanner {
public:
    virtual ~Scanner() = default;
    virtual std::string name() const = 0;
    virtual std::string description() const = 0;
    virtual void scan(ScanContext& context) = 0; // Updated to accept ScanContext
};

using ScannerPtr = std::unique_ptr<Scanner>; 

}
