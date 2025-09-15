#pragma once
#include "Scanner.h"
#include <mutex>
#include <map>

namespace sys_scan {

struct Config; // forward declaration to avoid heavy include

enum class WarnCode {
    DecompressFail,
    ParamUnreadable,
    ProcUnreadableStatus,
    ProcUnreadableCmdline,
    ProcExeSymlinkUnreadable,
    NetFileUnreadable,
    WalkError,
    MountsUnreadable,
    Generic
};

class Report {
public:
    void start_scanner(const std::string& name);
    void add_finding(const std::string& scanner, Finding finding);
    // Directly add a completed ScanResult (used by composite scanners)
    void add_result(ScanResult result);
    void end_scanner(const std::string& name);
    // Warning / error side channels (non-security collection issues)
    void add_warning(const std::string& scanner, WarnCode code, const std::string& detail="");
    void add_warning(const std::string& scanner, const std::string& message){ add_warning(scanner, WarnCode::Generic, message); }
    void add_error(const std::string& scanner, const std::string& message);

    // Attach active configuration for filtering and rule application
    void attach_config(const Config& cfg) { std::lock_guard<std::mutex> lock(mutex_); cfg_ = &cfg; }

    const std::vector<ScanResult>& results() const { return results_; }
    const std::vector<std::pair<std::string,std::string>>& warnings() const { return warnings_; }
    const std::vector<std::pair<std::string,std::string>>& errors() const { return errors_; }
    // Thread-safe aggregate counts
    size_t total_findings() const;
private:
    std::vector<ScanResult> results_;
    std::vector<std::pair<std::string,std::string>> warnings_; // (scanner, jsonified structured warning)
    std::vector<std::pair<std::string,std::string>> errors_;
    std::vector<std::pair<std::string,std::string>> partial_warnings_; // structured partial failure warnings
    std::map<std::string, std::map<std::string,std::string>> compliance_summary_; // standard -> metrics (stringified)
    mutable std::mutex mutex_;
    const Config* cfg_ = nullptr; // active configuration for this report instance
public:
    const std::map<std::string,std::map<std::string,std::string>>& compliance_summary() const { return compliance_summary_; }
    void set_compliance_metric(const std::string& standard, const std::string& key, const std::string& value){ std::lock_guard<std::mutex> lock(mutex_); compliance_summary_[standard][key]=value; }
    void add_partial_warning(const std::string& scanner, const std::string& message){ std::lock_guard<std::mutex> lock(mutex_); partial_warnings_.emplace_back(scanner, message); }
    const std::vector<std::pair<std::string,std::string>>& partial_warnings() const { return partial_warnings_; }
};

}
