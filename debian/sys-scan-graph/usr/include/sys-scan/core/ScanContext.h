#pragma once
#include "Config.h"
// #include "Report.h"  // Remove to break circular dependency
#include <memory>
#include <string>
#include <vector>
#include <chrono>

namespace sys_scan {

class Report; // Forward declaration to break circular dependency

/**
 * ScanContext - Shared context for all scanners
 * 
 * This struct encapsulates all shared state that scanners need access to,
 * eliminating global state and improving testability through dependency injection.
 */
struct ScanContext {
    // Core dependencies
    const Config& config;           // Configuration (read-only reference)
    Report& report;                 // Report for findings (mutable reference)
    
    // Optional shared state (can be extended as needed)
    std::string hostname;           // System hostname
    std::string scan_id;            // Unique scan identifier
    std::chrono::system_clock::time_point scan_start_time; // When scan began
    
    // Constructor
    ScanContext(const Config& cfg, Report& rep) 
        : config(cfg), report(rep) {
        // Initialize optional state
        scan_start_time = std::chrono::system_clock::now();
        
        // Generate scan ID (simple timestamp-based for now)
        auto now = std::chrono::system_clock::to_time_t(scan_start_time);
        scan_id = "scan_" + std::to_string(now);
    }
    
    // Copy constructor (shallow copy of references)
    ScanContext(const ScanContext& other) = default;
    
    // Assignment operator
    ScanContext& operator=(const ScanContext& other) = delete;
};

} // namespace sys_scan