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

// Fast PID validation using integer conversion
static inline bool is_valid_pid(const char* str, int* pid_out = nullptr) {
    if (!str || !*str) return false;
    char* endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0' || val <= 0 || val > INT_MAX) return false;
    if (pid_out) *pid_out = static_cast<int>(val);
    return true;
}

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

void IOCScanner::scan(ScanContext& context) {
    const auto& cfg = context.config;

    // Start scanner
    context.report.start_scanner(name());
    // Constants - no runtime allocations
    static const char* suspicious_names[] = {
        "kworker", "cryptominer", "xmrig", "minerd", "kthreadd", "malware", "bot"
    };
    static const char* ww_dirs[] = {"/tmp", "/dev/shm", "/var/tmp", "/home"};
    static const char* env_vars[] = {"LD_PRELOAD=", "LD_LIBRARY_PATH="};

    const size_t suspicious_count = sizeof(suspicious_names) / sizeof(suspicious_names[0]);
    const size_t ww_dirs_count = sizeof(ww_dirs) / sizeof(ww_dirs[0]);
    const size_t env_vars_count = sizeof(env_vars) / sizeof(env_vars[0]);

    // Fixed limits for memory control
    const size_t MAX_PROCESSES = 2000;
    const size_t MAX_HITS = 500;

    int pid_buffer[MAX_PROCESSES];
    ProcessInfo proc_info[MAX_HITS];
    size_t hit_count = 0;

    // Use test_root if set
    std::string proc_path = cfg.test_root.empty() ? "/proc" : cfg.test_root + "/proc";

    // Fast directory scan
    size_t pid_count = list_proc_pids(proc_path.c_str(), pid_buffer, MAX_PROCESSES);

    // Process each PID
    for (size_t i = 0; i < pid_count && hit_count < MAX_HITS; ++i) {
        int pid = pid_buffer[i];

        ProcessFiles files;
        if (!files.read_all(proc_path.c_str(), pid)) continue;

        // Analyze patterns
        bool pattern_match = false;
        bool ww_path = false;
        bool deleted_exe = false;
        bool ww_exe = false;
        bool env_issue = false;

        // Check cmdline
        if (files.cmdline_len > 0) {
            // Check for suspicious patterns
            for (size_t j = 0; j < suspicious_count; ++j) {
                const char* pattern = suspicious_names[j];
                size_t pattern_len = strlen(pattern);
                if (files.cmdline_len >= pattern_len) {
                    // Search for pattern in cmdline buffer up to cmdline_len
                    for (size_t k = 0; k <= files.cmdline_len - pattern_len; ++k) {
                        if (memcmp(files.cmdline + k, pattern, pattern_len) == 0) {
                            pattern_match = true;
                            break;
                        }
                    }
                }
                if (pattern_match) break;
            }
            // Check for world-writable paths
            for (size_t j = 0; j < ww_dirs_count; ++j) {
                const char* pattern = ww_dirs[j];
                size_t pattern_len = strlen(pattern);
                if (files.cmdline_len >= pattern_len) {
                    // Search for pattern in cmdline buffer up to cmdline_len
                    for (size_t k = 0; k <= files.cmdline_len - pattern_len; ++k) {
                        if (memcmp(files.cmdline + k, pattern, pattern_len) == 0) {
                            ww_path = true;
                            break;
                        }
                    }
                }
                if (ww_path) break;
            }
        }

        // Check exe
        if (files.exe_len > 0) {
            deleted_exe = strstr(files.exe_target, "(deleted)") != nullptr;
            if (!ww_exe) {
                for (size_t j = 0; j < ww_dirs_count; ++j) {
                    if (strncmp(files.exe_target, ww_dirs[j], strlen(ww_dirs[j])) == 0) {
                        ww_exe = true;
                        break;
                    }
                }
            }
        }

        // Check environment
        if (files.environ_len > 0) {
            for (size_t j = 0; j < env_vars_count; ++j) {
                const char* pattern = env_vars[j];
                size_t pattern_len = strlen(pattern);
                if (files.environ_len >= pattern_len) {
                    // Search for pattern in environ buffer up to environ_len
                    for (size_t k = 0; k <= files.environ_len - pattern_len; ++k) {
                        if (memcmp(files.environ + k, pattern, pattern_len) == 0) {
                            env_issue = true;
                            break;
                        }
                    }
                }
                if (env_issue) break;
            }
        }

        // Store if suspicious
        if (pattern_match || ww_path || deleted_exe || ww_exe || env_issue) {
            ProcessInfo& info = proc_info[hit_count++];
            info.pid = pid;

            // Set flags
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
        }
    }

    // Generate findings
    for (size_t i = 0; i < hit_count; ++i) {
        const ProcessInfo& info = proc_info[i];

        Finding f;
        f.id = std::string(info.exe_key) + ":" + std::to_string(info.pid);
        f.title = "Process IOC Detected";

        // Determine severity
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

        context.report.add_finding(this->name(), std::move(f));
    }

    // End scanner
    context.report.end_scanner(name());
}

}
