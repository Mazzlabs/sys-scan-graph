#ifndef SYS_SCAN_EBPF_SCANNER_H
#define SYS_SCAN_EBPF_SCANNER_H

#include "../core/Scanner.h"
#include <memory>
#include <set>
#include <optional>
#include <string>

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

class EbpfScanner : public Scanner {
public:
    std::string name() const override;
    std::string description() const override;
    void scan(ScanContext& context) override;

private:
    // Runtime eBPF feature detection
    bool is_ebpf_available() const;

    // Alternative detection structures
    struct ProcessInfo {
        pid_t pid;
        pid_t ppid;
        std::string comm;
        std::string cmdline;
    };

    // Alternative detection methods
    void scan_proc_filesystem(ScanContext& context, int duration);
    std::optional<std::set<pid_t>> get_running_pids();
    std::optional<ProcessInfo> get_process_info(pid_t pid);
};

// Factory
std::unique_ptr<Scanner> make_ebpf_scanner();

} // namespace sys_scan

#endif // SYS_SCAN_EBPF_SCANNER_H
