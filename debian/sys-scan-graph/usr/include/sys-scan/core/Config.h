#pragma once
#include <string>
#include <vector>
#include <optional>

namespace sys_scan {

struct Config {
    std::vector<std::string> enable_scanners; // if non-empty, only these
    std::vector<std::string> disable_scanners;
    std::string output_file = ""; // output file path
    std::string min_severity = ""; // none means all
    std::string fail_on_severity = ""; // exit non-zero if any finding >= this
    bool pretty = false;
    bool all_processes = false;
    std::vector<std::string> world_writable_dirs;
    std::vector<std::string> world_writable_exclude; // substring patterns
    int max_processes = 0; // 0 = unlimited after filtering
    int max_sockets = 0; // 0 = unlimited
    bool compact = false; // inverse of pretty; if both false default pretty output currently
    bool network_debug = false; // dump raw lines if parsing issues
    bool network_listen_only = false; // only include LISTEN TCP sockets (and UDP equivalents)
    std::string network_proto = ""; // "tcp" | "udp" | empty=both
    std::vector<std::string> network_states; // filter TCP states if non-empty
    // IOC tuning
    std::vector<std::string> ioc_allow; // substrings or prefixes that downgrade env-only IOC severity
    bool modules_summary_only = false; // if true, emit single summary with counts and notable modules
    // Extended tuning
    std::string ioc_allow_file = ""; // file with newline-delimited allowlist patterns (comments starting with #)
    int fail_on_count = -1; // if >=0, exit non-zero if total findings >= this; -1 means not set
    bool process_hash = false; // hash process executable (SHA256) if OpenSSL available
    bool process_inventory = false; // list every process as finding (otherwise only anomalies via IOC scanner)
    bool modules_anomalies_only = false; // only emit unsigned / out-of-tree module findings
    // SUID expected baseline management
    std::vector<std::string> suid_expected_add; // user-specified additional expected SUID paths
    std::string suid_expected_file = ""; // file containing newline-delimited expected SUID paths
    // Output formatting extensions
    bool canonical = false; // RFC 8785 JCS canonical JSON
    bool ndjson = false; // newline-delimited findings mode
    bool sarif = false; // SARIF output mode
    bool parallel = false; // execute scanners in parallel
    int parallel_max_threads = 0; // 0 = hardware_concurrency
    bool hardening = false; // enable additional hardening / attack-surface scanners
    bool containers = false; // enable container / namespace awareness & findings
    std::string container_id_filter = ""; // if non-empty, limit process/network findings to this container id
    bool modules_hash = false; // hash kernel module files (SHA256) when analyzing anomalies (OpenSSL only)
    bool ioc_env_trust = false; // correlate LD_* env vars with executable trust (signed/known path heuristics)
    bool ioc_exec_trace = false; // enable short-lived process execve trace (eBPF) run-to-completion sampling
    int ioc_exec_trace_seconds = 0; // duration to run exec trace (0=default 3s) when enabled
    bool network_advanced = false; // enable advanced network analytics (external exposure, fanout aggregation)
    int network_fanout_threshold = 100; // total connections threshold for fanout alert
    int network_fanout_unique_threshold = 50; // unique remote IP threshold
    bool fs_hygiene = false; // enable advanced filesystem hygiene checks (PATH dir ww, setuid interpreters, setcap binaries, dangling suid hardlinks)
    int fs_world_writable_limit = 0; // if >0, cap number of world-writable file findings (noise control)
    bool integrity = false; // enable integrity/package verification checks
    bool integrity_ima = false; // include IMA measurement statistics
    bool integrity_pkg_verify = false; // attempt dpkg/rpm verify
    int integrity_pkg_limit = 200; // limit number of detailed mismatch findings (summary beyond)
    bool integrity_pkg_rehash = false; // recompute SHA256 for mismatched package files (OpenSSL only)
    int integrity_pkg_rehash_limit = 50; // max files to rehash to control cost
    // Rule engine
    bool rules_enable = false; // enable rule enrichment
    std::string rules_dir = ""; // directory containing rule definition files
    bool rules_allow_legacy = false; // if false, fail hard on unsupported rule_version
    // PII suppression flags
    bool no_user_meta = false;     // suppress user/uid/euid/gid/egid fields
    bool no_cmdline_meta = false;  // suppress process command line
    bool no_hostname_meta = false; // suppress hostname
    // Integrity & provenance
    bool sign_gpg = false; // after writing output file, produce detached ascii-armored signature
    std::string sign_gpg_key = ""; // key id / fingerprint / email for gpg --detach-sign -u
    bool drop_priv = false; // drop Linux capabilities early
    bool keep_cap_dac = false; // retain CAP_DAC_READ_SEARCH when dropping
    bool seccomp = false; // apply seccomp sandbox after initialization
    bool seccomp_strict = false; // if true, failure to apply seccomp is fatal
    std::string write_env_file = ""; // path to write .env style file (binary hash, version, commit)
    // Compliance
    bool compliance = false; // enable compliance scanners
    std::vector<std::string> compliance_standards; // subset selection (empty=all registered)
    bool fast_scan = false;        // skip heavy scanners (modules, integrity, ebpf) for quick triage
    bool timings = false;          // include per-scanner timing metrics in output meta
};

Config& config();
void set_config(const Config& c);

int severity_rank(const std::string& sev); // compatibility wrapper (enum implemented in Severity.h)

}
