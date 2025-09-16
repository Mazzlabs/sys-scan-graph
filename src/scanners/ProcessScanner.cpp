#include "ProcessScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/ScanContext.h"  // Added ScanContext include
#include "../core/Logging.h"
#include <unordered_map>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#include <sys/stat.h>
#include <pwd.h>
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

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

// Check if a string is a valid hex string of given length
static bool is_valid_hex_string(const char* str, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (!isxdigit(str[i])) return false;
    }
    return true;
}

// Extract container ID from hex string
static bool extract_hex_container_id(const char* ptr, size_t remaining_len, size_t hex_len, char* out_id, size_t out_size) {
    if (remaining_len < hex_len || !is_valid_hex_string(ptr, hex_len)) return false;

    size_t copy_len = (hex_len >= 12) ? 12 : hex_len;
    if (copy_len >= out_size) return false;

    memcpy(out_id, ptr, copy_len);
    out_id[copy_len] = '\0';
    return true;
}

// Ultra-fast container ID extraction (no allocations)
static bool extract_container_id_lean(const char* cgroup_data, size_t len, char* out_id, size_t out_size) {
    if (out_size < 13) return false;  // Need at least 12 chars + null

    const char* ptr = cgroup_data;
    const char* end = cgroup_data + len;

    while (ptr < end - 32) {  // Need at least 32 chars
        if (isxdigit(*ptr)) {
            size_t remaining_len = end - ptr;

            // Try 64-char hex string first
            if (extract_hex_container_id(ptr, remaining_len, 64, out_id, out_size)) {
                return true;
            }

            // Try 32-char hex string
            if (extract_hex_container_id(ptr, remaining_len, 32, out_id, out_size)) {
                return true;
            }
        }
        ++ptr;
    }
    return false;
}

// Parse a single field (Uid or Gid) from status data
static bool parse_field_lean(const char* status_data, size_t len, const char* field_name, char* out_buf, size_t out_size) {
    const char* ptr = status_data;
    const char* end = status_data + len;
    size_t field_len = strlen(field_name);

    while (ptr < end) {
        if (strncmp(ptr, field_name, field_len) == 0) {
            ptr += field_len;
            while (ptr < end && (*ptr == ' ' || *ptr == '\t')) ++ptr;
            const char* start = ptr;
            while (ptr < end && isdigit(*ptr)) ++ptr;
            size_t val_len = ptr - start;
            if (val_len > 0 && val_len < out_size) {
                memcpy(out_buf, start, val_len);
                out_buf[val_len] = '\0';
                return true;
            }
        }

        // Move to next line
        while (ptr < end && *ptr != '\n') ++ptr;
        if (ptr < end) ++ptr;
    }
    return false;
}

// Ultra-fast UID/GID parsing (reduced parameters)
static bool parse_uid_gid_lean(const char* status_data, size_t len, char* uid_buf, size_t uid_size, char* gid_buf, size_t gid_size) {
    bool found_uid = parse_field_lean(status_data, len, "Uid:", uid_buf, uid_size);
    bool found_gid = parse_field_lean(status_data, len, "Gid:", gid_buf, gid_size);
    return found_uid && found_gid;
}

// Ultra-fast SHA256 with pre-allocated hex buffer
static bool fast_sha256_lean(const char* filepath, char* hash_out) {
#ifdef SYS_SCAN_HAVE_OPENSSL
    int fd = open(filepath, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        close(fd);
        return false;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        return false;
    }

    char buffer[4096];  // Smaller buffer for better cache performance
    ssize_t bytes_read;
    size_t total_read = 0;
    const size_t MAX_READ = 128 * 1024;  // Reduced limit for speed

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0 && total_read < MAX_READ) {
        EVP_DigestUpdate(ctx, buffer, bytes_read);
        total_read += bytes_read;
    }
    close(fd);

    unsigned char md[32];
    unsigned int mdlen = 0;
    if (EVP_DigestFinal_ex(ctx, md, &mdlen) == 1 && mdlen == 32) {
        // Pre-computed hex table for speed
        static const char hex_chars[] = "0123456789abcdef";
        for (unsigned i = 0; i < 32; ++i) {
            hash_out[i * 2] = hex_chars[md[i] >> 4];
            hash_out[i * 2 + 1] = hex_chars[md[i] & 0xF];
        }
        hash_out[64] = '\0';
        EVP_MD_CTX_free(ctx);
        return true;
    }

    EVP_MD_CTX_free(ctx);
    return false;
#else
    strcpy(hash_out, "(disabled)");
    return true;
#endif
}

// Fast directory listing
static size_t list_proc_pids(int* pid_buffer, size_t max_pids) {
    DIR* dir = opendir("/proc");
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

// Build container ID mapping for container-aware scanning
static size_t build_container_mapping(const int* pid_buffer, size_t pid_count,
                                    char container_map[][13], int* container_pids, size_t max_containers) {
    size_t container_count = 0;

    for (size_t i = 0; i < pid_count && container_count < max_containers; ++i) {
        int pid = pid_buffer[i];
        char cgroup_path[64];
        snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%d/cgroup", pid);

        char cgroup_data[2048];
        ssize_t len = read_file_to_buffer(cgroup_path, cgroup_data, sizeof(cgroup_data) - 1);
        if (len > 0) {
            cgroup_data[len] = '\0';
            if (extract_container_id_lean(cgroup_data, len, container_map[container_count], 13)) {
                container_pids[container_count] = pid;
                container_count++;
            }
        }
    }

    return container_count;
}

// Read process status and cmdline files
static bool read_process_files(int pid, char* status_data, size_t status_size,
                              std::string& cmd, const std::string& scanner_name, ScanContext& context) {
    // Read status file
    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);

    ssize_t status_len = read_file_to_buffer(status_path, status_data, status_size - 1);
    if (status_len <= 0) {
        context.report.add_warning(scanner_name, WarnCode::ProcUnreadableStatus, status_path);
        return false;
    }
    status_data[status_len] = '\0';

    // Read cmdline file
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

    char cmd_buffer[4096];
    ssize_t cmd_len = read_file_to_buffer(cmdline_path, cmd_buffer, sizeof(cmd_buffer) - 1);
    if (cmd_len > 0) {
        cmd_buffer[cmd_len] = '\0';
        cmd = cmd_buffer;
    } else {
        context.report.add_warning(scanner_name, WarnCode::ProcUnreadableCmdline, cmdline_path);
    }

    return true;
}

// Check if process should be included based on filtering rules
static bool should_include_process(const std::string& cmd, bool all_processes,
                                 const char container_map[][13], const int* container_pids,
                                 size_t container_count, int pid,
                                 const std::string& container_id_filter) {
    // Basic filtering
    if (cmd.empty() && !all_processes) return false;
    if (!all_processes && !cmd.empty() && cmd.front() == '[' && cmd.back() == ']') return false;

    // Container filtering
    if (!container_id_filter.empty()) {
        bool found_match = false;
        for (size_t j = 0; j < container_count; ++j) {
            if (container_pids[j] == pid && strcmp(container_map[j], container_id_filter.c_str()) == 0) {
                found_match = true;
                break;
            }
        }
        if (!found_match) return false;
    }

    return true;
}

// Parse UID and GID from status data
static void parse_process_uid_gid(const char* status_data, size_t status_len,
                                uid_t& uid_val, gid_t& gid_val) {
    char uid_buf[16], gid_buf[16];
    uid_buf[0] = gid_buf[0] = '\0';

    parse_uid_gid_lean(status_data, status_len, uid_buf, sizeof(uid_buf), gid_buf, sizeof(gid_buf));

    if (uid_buf[0]) uid_val = static_cast<uid_t>(strtoul(uid_buf, nullptr, 10));
    if (gid_buf[0]) gid_val = static_cast<gid_t>(strtoul(gid_buf, nullptr, 10));
}

// Analyze process executable and compute hash
static void analyze_process_exe(int pid, std::map<std::string, std::string>& metadata,
                              const std::string& scanner_name, ScanContext& context) {
    char exe_path[64];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

    char exe_link_path[PATH_MAX];
    ssize_t exe_len = readlink(exe_path, exe_link_path, sizeof(exe_link_path) - 1);
    if (exe_len > 0) {
        exe_link_path[exe_len] = '\0';
        metadata["exe_path"] = exe_link_path;

        char hash_buffer[65];
        if (fast_sha256_lean(exe_link_path, hash_buffer)) {
            metadata["sha256"] = hash_buffer;
        } else {
            metadata["sha256"] = "(error)";
        }
    } else {
        context.report.add_warning(scanner_name, WarnCode::ProcExeSymlinkUnreadable, exe_path);
    }
}

// Build process finding with metadata
static Finding build_process_finding(int pid, const std::string& cmd, uid_t uid_val, gid_t gid_val,
                                   const char container_map[][13], const int* container_pids,
                                   size_t container_count, bool no_user_meta, bool containers) {
    Finding f;
    f.id = std::to_string(pid);
    f.title = "Process " + f.id;
    f.severity = Severity::Info;
    f.description = cmd.empty() ? "(no cmdline)" : cmd;

    if (!no_user_meta) {
        f.metadata["uid"] = std::to_string(uid_val);
        f.metadata["gid"] = std::to_string(gid_val);
    }

    if (containers) {
        for (size_t j = 0; j < container_count; ++j) {
            if (container_pids[j] == pid) {
                f.metadata["container_id"] = container_map[j];
                break;
            }
        }
    }

    return f;
}

void ProcessScanner::scan(ScanContext& context) {
    const size_t MAX_PROCESSES = 5000;
    int pid_buffer[MAX_PROCESSES];
    size_t emitted = 0;

    // Get list of PIDs
    size_t pid_count = list_proc_pids(pid_buffer, MAX_PROCESSES);

    // Build container mapping if needed
    char container_map[2000][13];
    int container_pids[2000];
    size_t container_count = 0;

    if (context.config.containers) {
        container_count = build_container_mapping(pid_buffer, pid_count, container_map, container_pids, 2000);
    }

    bool inventory = context.config.process_inventory;

    // Process each PID
    for (size_t i = 0; i < pid_count; ++i) {
        int pid = pid_buffer[i];

        // Read process files
        char status_data[2048];
        std::string cmd;
        if (!read_process_files(pid, status_data, sizeof(status_data), cmd, this->name(), context)) {
            continue;
        }

        // Check filtering rules
        if (!should_include_process(cmd, context.config.all_processes, container_map, container_pids,
                                  container_count, pid, context.config.container_id_filter)) {
            continue;
        }

        if (context.config.max_processes > 0 && emitted >= (size_t)context.config.max_processes) break;

        // Parse UID/GID
        uid_t uid_val = 0;
        gid_t gid_val = 0;
        parse_process_uid_gid(status_data, strlen(status_data), uid_val, gid_val);

        if (inventory) {
            // Build process finding
            Finding f = build_process_finding(pid, cmd, uid_val, gid_val, container_map, container_pids,
                                            container_count, context.config.no_user_meta, context.config.containers);

            // Add exe analysis if requested
            if (context.config.process_hash) {
                analyze_process_exe(pid, f.metadata, this->name(), context);
            }

            context.report.add_finding(this->name(), std::move(f));
            ++emitted;
        }
    }
}

}
