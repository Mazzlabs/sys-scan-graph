#pragma once
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include "Severity.h"
#include "Scanner.h"

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

struct ComplianceControlResult {
    std::string standard;      // e.g. pci_dss_4_0
    std::string control_id;    // e.g. 3.4
    std::string requirement;   // human readable description
    Severity severity = Severity::Info; // inherent severity / rating
    bool passed = false;
    bool not_applicable = false;
    std::string rationale; // failure or NA explanation
};

struct ComplianceStandardSummary {
    int total_controls = 0;
    int passed = 0;
    int failed = 0;
    int not_applicable = 0;
    double score = 0.0; // passed / (passed+failed)
};

class ComplianceScanner : public Scanner {
protected:
    struct ComplianceCheck {
        std::string standard;        // "pci_dss_4_0", "hipaa_security_rule" ...
        std::string control_id;      // "3.4", "164.312(a)(1)"
        std::string requirement;     // Human readable
        Severity severity;           // Impact of failing the control
        std::function<bool()> test;  // Executed at scan time
        std::function<bool()> applicable; // optional gating (defaults true)
    };
    std::vector<ComplianceCheck> checks_;
public:
    virtual ~ComplianceScanner() = default;
    virtual void register_checks() = 0;
    void scan(ScanContext& context) override;
};

class PCIComplianceScanner : public ComplianceScanner {
public:
    std::string name() const override { return "pci_compliance"; }
    std::string description() const override { return "PCI-DSS 4.0 selected technical controls"; }
    void register_checks() override;
};

// Aggregated evaluation after all compliance scanners (placeholder for future engine)
struct ComplianceEvaluation {
    std::vector<ComplianceControlResult> controls;
    std::map<std::string, ComplianceStandardSummary> summary_by_standard;
};

}
