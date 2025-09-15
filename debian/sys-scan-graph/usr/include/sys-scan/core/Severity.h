#pragma once
#include <string>
#include <cstdint>

namespace sys_scan {

enum class Severity : uint8_t {
    Info = 0,
    Low,
    Medium,
    High,
    Critical,
    Error
};

// Map enum to canonical lowercase string
inline const char* severity_to_string(Severity s){
    switch(s){
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
        case Severity::Error: return "error";
    }
    return "info";
}

// Parse (lenient) string to enum, default info
inline Severity severity_from_string(const std::string& in){
    std::string s; s.reserve(in.size());
    for(char c: in){ s.push_back((char)tolower((unsigned char)c)); }
    if(s=="info") return Severity::Info;
    if(s=="low") return Severity::Low;
    if(s=="medium") return Severity::Medium;
    if(s=="high") return Severity::High;
    if(s=="critical") return Severity::Critical;
    if(s=="error") return Severity::Error;
    return Severity::Info;
}

inline int severity_rank_enum(Severity s){ return static_cast<int>(s); }
inline int severity_rank(const std::string& s){ return severity_rank_enum(severity_from_string(s)); }

// Simple numeric risk score mapping (placeholder for future weighting)
inline int severity_risk_score(Severity s){
    switch(s){
        case Severity::Info: return 10;
        case Severity::Low: return 30;
        case Severity::Medium: return 50;
        case Severity::High: return 70;
        case Severity::Critical: return 90;
        case Severity::Error: return 80; // internal error severity separate from security criticality
    }
    return 10;
}

}
