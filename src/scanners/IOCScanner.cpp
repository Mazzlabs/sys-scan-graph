#include "IOCScanner.h"
#include <cctype>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <sys/stat.h>
#include "../core/Config.h"
#include "../core/Report.h"
#include "../core/ScanContext.h"
#include "../core/Utils.h"

namespace sys_scan {

// Fast PID validation
static inline bool is_valid_pid(const char* str, int* pid_out = nullptr) {
    if (!str || !*str) return false;
    char* endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0' || val <= 0 || val > INT_MAX) return false;
    if (pid_out) *pid_out = static_cast<int>(val);
    return true;
}

// Data structures to encapsulate string arrays and reduce string-heavy arguments
struct IOCPatterns {
    static constexpr const char* suspicious_names[] = {
        "kworker", "cryptominer", "xmrig", "minerd", "kthreadd", "malware", "bot"
    };
    static constexpr const char* world_writable_dirs[] = {"/tmp", "/dev/shm", "/var/tmp", "/home"};
    static constexpr const char* environment_vars[] = {"LD_PRELOAD=", "LD_LIBRARY_PATH="};

    static constexpr size_t suspicious_count = sizeof(suspicious_names) / sizeof(suspicious_names[0]);
    static constexpr size_t ww_dirs_count = sizeof(world_writable_dirs) / sizeof(world_writable_dirs[0]);
    static constexpr size_t env_vars_count = sizeof(environment_vars) / sizeof(environment_vars[0]);
};

struct IOCScanConfig {
    std::string proc_path;
    size_t max_hits;

    IOCScanConfig(const Config& cfg) : max_hits(500) {
        proc_path = cfg.test_root.empty() ? "/proc" : cfg.test_root + "/proc";
    }
};

// Fast file reading with fixed buffer
static ssize_t read_file_to_buffer(const char* path, char* buffer, size_t buffer_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    ssize_t total_read = 0;
    while (total_read < static_cast<ssize_t>(buffer_size)) {
        ssize_t bytes_read = read(fd, buffer + total_read, buffer_size - total_read);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }
    close(fd);
    return total_read;
}

// Batch file operations to reduce system calls
struct ProcessFiles {
    char cmdline[4096];
    char exe_target[PATH_MAX];
    char environ[2048];
    ssize_t cmdline_len, exe_len, environ_len;

    bool read_all(const char* proc_base, int pid) {
        char path_buf[64];
        snprintf(path_buf, sizeof(path_buf), "%s/%d/cmdline", proc_base, pid);
        cmdline_len = read_file_to_buffer(path_buf, cmdline, sizeof(cmdline) - 1);
        if (cmdline_len > 0) cmdline[cmdline_len] = '\0';

        snprintf(path_buf, sizeof(path_buf), "%s/%d/exe", proc_base, pid);
        exe_len = readlink(path_buf, exe_target, sizeof(exe_target) - 1);
        if (exe_len > 0) exe_target[exe_len] = '\0';

        snprintf(path_buf, sizeof(path_buf), "%s/%d/environ", proc_base, pid);
        environ_len = read_file_to_buffer(path_buf, environ, sizeof(environ) - 1);
        if (environ_len > 0) environ[environ_len] = '\0';

        return cmdline_len > 0;
    }
};

// Memory-efficient process info
struct ProcessInfo {
    int pid;
    uint8_t flags;  // 1=pattern_match, 2=deleted_exe, 4=world_writable, 8=env_issue
    char exe_key[256];
    char cmd_sample[128];

    void set_exe_key(const char* exe, size_t len) {
        size_t copy_len = std::min(len, sizeof(exe_key) - 1);
        memcpy(exe_key, exe, copy_len);
        exe_key[copy_len] = '\0';
    }

    void set_cmd_sample(const char* cmd, size_t len) {
        size_t copy_len = std::min(len, sizeof(cmd_sample) - 1);
        memcpy(cmd_sample, cmd, copy_len);
        cmd_sample[copy_len] = '\0';
    }
};

// Fast directory reading
static size_t list_proc_pids(const char* proc_path, int* pid_buffer, size_t max_pids) {
    DIR* dir = opendir(proc_path);
    if (!dir) return 0;

    size_t count = 0;
    struct dirent* entry;
    while (count < max_pids && (entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        int pid;
        if (is_valid_pid(entry->d_name, &pid)) {
            pid_buffer[count++] = pid;
        }
    }
    closedir(dir);
    return count;
}

// Check if buffer contains a pattern
static bool buffer_contains_pattern(const char* buffer, size_t buffer_len, const char* pattern) {
    size_t pattern_len = strlen(pattern);
    if (buffer_len < pattern_len) return false;

    for (size_t k = 0; k <= buffer_len - pattern_len; ++k) {
        if (memcmp(buffer + k, pattern, pattern_len) == 0) {
            return true;
        }
    }
    return false;
}

// Check if path starts with any world-writable directory
static bool is_world_writable_path(const char* path) {
    for (size_t j = 0; j < IOCPatterns::ww_dirs_count; ++j) {
        if (strncmp(path, IOCPatterns::world_writable_dirs[j], strlen(IOCPatterns::world_writable_dirs[j])) == 0) {
            return true;
        }
    }
    return false;
}

// Analyze cmdline for suspicious patterns and world-writable paths
static void analyze_cmdline(const ProcessFiles& files, bool& pattern_match, bool& ww_path) {
    if (files.cmdline_len <= 0) return;

    // Check for suspicious patterns
    for (size_t j = 0; j < IOCPatterns::suspicious_count && !pattern_match; ++j) {
        if (buffer_contains_pattern(files.cmdline, files.cmdline_len, IOCPatterns::suspicious_names[j])) {
            pattern_match = true;
        }
    }

    // Check for world-writable paths
    for (size_t j = 0; j < IOCPatterns::ww_dirs_count && !ww_path; ++j) {
        if (buffer_contains_pattern(files.cmdline, files.cmdline_len, IOCPatterns::world_writable_dirs[j])) {
            ww_path = true;
        }
    }
}

// Analyze executable for issues
static void analyze_executable(const ProcessFiles& files, bool& deleted_exe, bool& ww_exe) {
    if (files.exe_len <= 0) return;

    deleted_exe = strstr(files.exe_target, "(deleted)") != nullptr;
    if (!ww_exe) {
        ww_exe = is_world_writable_path(files.exe_target);
    }
}

// Analyze environment variables for suspicious patterns
static void analyze_environment(const ProcessFiles& files, bool& env_issue) {
    if (files.environ_len <= 0) return;

    for (size_t j = 0; j < IOCPatterns::env_vars_count && !env_issue; ++j) {
        if (buffer_contains_pattern(files.environ, files.environ_len, IOCPatterns::environment_vars[j])) {
            env_issue = true;
        }
    }
}

// Analyze a single process for IOCs
static bool analyze_process_iocs(int pid, const std::string& proc_path, ProcessInfo& info) {
    ProcessFiles files;
    if (!files.read_all(proc_path.c_str(), pid)) return false;

    bool pattern_match = false;
    bool ww_path = false;
    bool deleted_exe = false;
    bool ww_exe = false;
    bool env_issue = false;

    // Analyze different aspects
    analyze_cmdline(files, pattern_match, ww_path);
    analyze_executable(files, deleted_exe, ww_exe);
    analyze_environment(files, env_issue);

    // Return false if no issues found
    if (!pattern_match && !ww_path && !deleted_exe && !ww_exe && !env_issue) {
        return false;
    }

    // Populate process info
    info.pid = pid;
    info.flags = 0;
    if (pattern_match || ww_path) info.flags |= 1;
    if (deleted_exe) info.flags |= 2;
    if (ww_exe) info.flags |= 4;
    if (env_issue) info.flags |= 8;

    // Set exe key
    if (files.exe_len > 0) {
        info.set_exe_key(files.exe_target, files.exe_len);
    } else if (files.cmdline_len > 0) {
        const char* end = (const char*)memchr(files.cmdline, '\0', files.cmdline_len);
        size_t len = end ? (end - files.cmdline) : files.cmdline_len;
        info.set_exe_key(files.cmdline, std::min(len, sizeof(info.exe_key) - 1));
    }

    // Set command sample
    if (files.cmdline_len > 0) {
        info.set_cmd_sample(files.cmdline, files.cmdline_len);
    }

    return true;
}

// Scan all processes for IOCs
static size_t scan_processes_for_iocs(const IOCScanConfig& config, ProcessInfo proc_info[], size_t max_hits) {
    const size_t MAX_PROCESSES = 2000;
    int pid_buffer[MAX_PROCESSES];
    size_t pid_count = list_proc_pids(config.proc_path.c_str(), pid_buffer, MAX_PROCESSES);

    size_t hit_count = 0;

    for (size_t i = 0; i < pid_count && hit_count < max_hits; ++i) {
        int pid = pid_buffer[i];
        if (analyze_process_iocs(pid, config.proc_path, proc_info[hit_count])) {
            ++hit_count;
        }
    }

    return hit_count;
}

// Create finding from process info
static Finding create_ioc_finding(const ProcessInfo& info) {
    Finding f;
    f.id = std::string(info.exe_key) + ":" + std::to_string(info.pid);
    f.title = "Process IOC Detected";

    // Determine severity and description
    if (info.flags & 2) {  // deleted exe
        f.severity = Severity::Critical;
        f.description = "Process with deleted executable: " + std::string(info.exe_key);
    } else if (info.flags & 4) {  // world writable exe
        f.severity = Severity::High;
        f.description = "Process with world-writable executable: " + std::string(info.exe_key);
    } else if (info.flags & 8) {  // env issue
        f.severity = Severity::Medium;
        f.description = "Process with suspicious environment: " + std::string(info.exe_key);
    } else {
        f.severity = Severity::Low;
        f.description = "Process with suspicious patterns: " + std::string(info.exe_key);
    }

    // Add metadata
    f.metadata["pid"] = std::to_string(info.pid);
    f.metadata["command"] = std::string(info.cmd_sample);

    if (info.flags & 1) f.metadata["pattern_match"] = "true";
    if (info.flags & 2) f.metadata["deleted_executable"] = "true";
    if (info.flags & 4) f.metadata["world_writable_executable"] = "true";
    if (info.flags & 8) f.metadata["environment_issue"] = "true";

    return f;
}

// Generate findings from process info
static void generate_ioc_findings(const ProcessInfo proc_info[], size_t hit_count, ScanContext& context) {
    for (size_t i = 0; i < hit_count; ++i) {
        Finding f = create_ioc_finding(proc_info[i]);
        context.report.add_finding("ioc", std::move(f));
    }
}

void IOCScanner::scan(ScanContext& context) {
    // Start scanner
    context.report.start_scanner(name());

    // Create scan configuration
    IOCScanConfig config(context.config);

    // Allocate process info array (fixed size to avoid VLA)
    const size_t MAX_HITS = 500;
    ProcessInfo proc_info[MAX_HITS];

    // Scan processes for IOCs
    size_t hit_count = scan_processes_for_iocs(config, proc_info, MAX_HITS);

    // Generate findings
    generate_ioc_findings(proc_info, hit_count, context);

    // End scanner
    context.report.end_scanner(name());
}

}
