#include "NetworkScanner.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/ScanContext.h"
#include "../core/Severity.h"
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <iomanip>
#include <string>
#include <tuple>
#include <regex>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#include <sys/stat.h>
#include <filesystem>
#include <vector>
#include <sys/types.h>
#include <cstdlib>
#include <climits>
#include <cerrno>

namespace fs = std::filesystem;

namespace sys_scan {

// Lean network scanning constants
static const size_t MAX_SOCKETS_LEAN = 1000;
static const size_t MAX_PATH_LEN_LEAN = 512;  // Increased from 256 for better path handling
static const size_t MAX_INODE_LEN_LEAN = 32;  // Increased from 16 for better safety margin

// Forward declarations for helper functions
static const char* tcp_state_lean(const char* st);
static bool hex_ip_to_v4_lean(const char* hex_ip, char* out_ip, size_t out_size);
static bool hex_ip6_to_str_lean(const char* hex_ip, char* out_ip, size_t out_size);
static size_t find_inode_lean(const char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN], size_t count, const char* inode);
static bool state_allowed_lean(const char* st, const Config& config);
static Severity classify_tcp_severity_lean(const char* state, unsigned port, const char* exe);
static Severity classify_udp_severity_lean(unsigned port, const char* exe);
static Severity escalate_exposed_lean(Severity current, const char* state, const char* lip);

// Fanout aggregation struct
struct FanoutAgg { size_t total=0; std::unordered_set<std::string> remote_ips; unsigned privileged_listen=0; unsigned wildcard_listen=0; };

// Full-file line-by-line reader for /proc/net/* files (handles files larger than buffer)
static void parse_proc_net_file(const char* path, Report& report, const char* proto,
                               const char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN], const char pid_map[MAX_SOCKETS_LEAN][16],
                               const char exe_map[MAX_SOCKETS_LEAN][MAX_PATH_LEN_LEAN], const char container_map[MAX_SOCKETS_LEAN][13],
                               size_t inode_count, size_t& emitted,
                               std::unordered_map<std::string, FanoutAgg>* fanout, const Config& config,
                               bool is_tcp = true) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        report.add_warning(proto, WarnCode::NetFileUnreadable, path);
        return;
    }

    char line[512];  // Larger buffer for lines
    bool is_ipv6 = strstr(path, (is_tcp ? "tcp6" : "udp6")) != nullptr;
    bool header_skipped = false;

    while (fgets(line, sizeof(line), fp) && emitted < (size_t)config.max_sockets) {
        // Skip header line
        if (!header_skipped) {
            header_skipped = true;
            continue;
        }

        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
            len--;
        }
        if (len == 0) continue;

        // Quick filter for colon
        if (!strchr(line, ':')) continue;

        // Tokenize line (space/tab separated, thread-safe)
        char* tokens[20];
        int token_count = 0;
        char* saveptr;
        char* tok = strtok_r(line, " \t", &saveptr);
        while (tok && token_count < 20) {
            tokens[token_count++] = tok;
            tok = strtok_r(nullptr, " \t", &saveptr);
        }

        if (token_count < (is_tcp ? 10 : 9)) continue;

        // Extract fields
        char* local = tokens[1];
        char* rem = is_tcp ? tokens[2] : nullptr;
        char* st = is_tcp ? tokens[3] : nullptr;
        char* uid_s = tokens[is_tcp ? 7 : 6];
        char* inode_s = tokens[is_tcp ? 9 : 8];

        // Parse addresses and ports
        char* colon1 = strchr(local, ':');
        if (!colon1) continue;

        *colon1 = '\0';
        char* lport_hex = colon1 + 1;

        char* rport_hex = nullptr;
        if (is_tcp && rem) {
            char* colon2 = strchr(rem, ':');
            if (!colon2) continue;
            *colon2 = '\0';
            rport_hex = colon2 + 1;
        }

        // Convert hex ports to decimal
        unsigned lport = strtoul(lport_hex, nullptr, 16);
        unsigned rport = is_tcp && rport_hex ? strtoul(rport_hex, nullptr, 16) : 0;

        if (lport == 0 && (!is_tcp || rport == 0)) continue;

        const char* state_str = is_tcp ? tcp_state_lean(st) : "UDP";

        if (is_tcp) {
            if (config.network_listen_only && strcmp(state_str, "LISTEN") != 0) continue;
            if (!state_allowed_lean(state_str, config)) continue;
        }

        // Convert IPs
        char lip[40] = "", rip[40] = "";
        if (is_ipv6) {
            hex_ip6_to_str_lean(local, lip, sizeof(lip));
            if (is_tcp && rem) hex_ip6_to_str_lean(rem, rip, sizeof(rip));
        } else {
            hex_ip_to_v4_lean(local, lip, sizeof(lip));
            if (is_tcp && rem) hex_ip_to_v4_lean(rem, rip, sizeof(rip));
        }

        // Create finding
        Finding f;
        char id_buf[64];
        snprintf(id_buf, sizeof(id_buf), "%s:%u:%s", proto, lport, inode_s);
        f.id = id_buf;

        char title_buf[64];
        if (is_tcp) {
            snprintf(title_buf, sizeof(title_buf), "%s %s %u", proto, state_str, lport);
        } else {
            snprintf(title_buf, sizeof(title_buf), "%s port %u", proto, lport);
        }
        f.title = title_buf;

        f.severity = Severity::Info;
        f.description = is_tcp ? "TCP socket" : "UDP socket";

        f.metadata["protocol"] = is_tcp ? "tcp" : "udp";
        if (is_tcp) f.metadata["state"] = state_str;
        if (!config.no_user_meta) f.metadata["uid"] = uid_s;
        f.metadata["lport"] = std::to_string(lport);
        if (is_tcp) f.metadata["rport"] = std::to_string(rport);
        f.metadata["inode"] = inode_s;
        f.metadata["lip"] = lip;
        if (is_tcp) f.metadata["rip"] = rip;

        // Lookup inode in lean arrays
        size_t inode_idx = find_inode_lean(inode_map, inode_count, inode_s);
        if (inode_idx != SIZE_MAX && inode_idx < inode_count) {
            if (pid_map[inode_idx][0]) f.metadata["pid"] = pid_map[inode_idx];
            if (exe_map[inode_idx][0]) f.metadata["exe"] = exe_map[inode_idx];
            if (container_map[inode_idx][0]) f.metadata["container_id"] = container_map[inode_idx];
        }

        // Container filtering
        if (config.containers && !config.container_id_filter.empty()) {
            auto it = f.metadata.find("container_id");
            if (it == f.metadata.end() || it->second != config.container_id_filter) continue;
        }

        // Severity classification
        const char* exe_str = f.metadata.count("exe") ? f.metadata["exe"].c_str() : "";
        Severity sev;
        if (is_tcp) {
            sev = classify_tcp_severity_lean(state_str, lport, exe_str);
            f.severity = escalate_exposed_lean(sev, state_str, lip);
        } else {
            sev = classify_udp_severity_lean(lport, exe_str);
            f.severity = sev;
        }

        // Wildcard/privileged annotations for TCP
        if (is_tcp && strcmp(state_str, "LISTEN") == 0) {
            // Check for wildcard addresses (aligned with converter output)
            bool wildcard = false;
            if (is_ipv6) {
                // IPv6: check for all-zero expanded form (converter never emits "::")
                wildcard = (strcmp(lip, "0000:0000:0000:0000:0000:0000:0000:0000") == 0);
            } else {
                // IPv4: check for 0.0.0.0
                wildcard = (strcmp(lip, "0.0.0.0") == 0);
            }
            if (wildcard) f.metadata["wildcard_listen"] = "true";
            if (lport < 1024) f.metadata["privileged_port"] = "true";
        }

        report.add_finding(proto, std::move(f));

        // Fanout aggregation for TCP
        if (is_tcp && config.network_advanced && fanout && strcmp(state_str, "ESTABLISHED") == 0 && inode_idx != SIZE_MAX && inode_idx < inode_count) {
            const char* pid_str = pid_map[inode_idx];
            auto& agg = (*fanout)[pid_str];
            agg.total++;

            char remote_ip[40];
            if (is_ipv6) {
                hex_ip6_to_str_lean(rem, remote_ip, sizeof(remote_ip));
            } else {
                hex_ip_to_v4_lean(rem, remote_ip, sizeof(remote_ip));
            }
            agg.remote_ips.insert(remote_ip);
        }

        ++emitted;
    }

    fclose(fp);
}

// State filtering with case-insensitive comparison
static bool state_allowed_lean(const char* st, const Config& config) {
    if (config.network_states.empty()) return true;
    for (const auto& allowed : config.network_states) {
        // Case-insensitive comparison for state filtering
        if (strcasecmp(st, allowed.c_str()) == 0) return true;
    }
    return false;
}

// Ultra-fast container ID extraction (no allocations) with stricter cgroup parsing
static bool extract_container_id_lean(const char* cgroup_data, size_t len, char* out_id, size_t out_size) {
    if (out_size < 13) return false;  // Need at least 12 chars + null

    const char* ptr = cgroup_data;
    const char* end = cgroup_data + len;

    // Known container runtime markers for stricter parsing
    static const char* markers[] = {
        "docker-", "containerd-", "crio-", "podman-", "lxc-", "kubepods"
    };

    while (ptr < end - 32) {  // Need at least 32 chars
        // Check for known container runtime markers first
        bool has_marker = false;
        for (const char* marker : markers) {
            size_t marker_len = strlen(marker);
            if (ptr + marker_len < end && strncmp(ptr, marker, marker_len) == 0) {
                has_marker = true;
                break;
            }
        }

        if (!has_marker && !isxdigit(*ptr)) {
            ++ptr;
            continue;
        }

        // Check for 64-char hex string
        bool is_64_char = true;
        for (int i = 0; i < 64 && ptr + i < end; ++i) {
            if (!isxdigit(ptr[i])) {
                is_64_char = false;
                break;
            }
        }
        if (is_64_char && ptr + 64 <= end) {
            memcpy(out_id, ptr, 12);
            out_id[12] = '\0';
            return true;
        }

        // Check for 32-char hex string
        bool is_32_char = true;
        for (int i = 0; i < 32 && ptr + i < end; ++i) {
            if (!isxdigit(ptr[i])) {
                is_32_char = false;
                break;
            }
        }
        if (is_32_char && ptr + 32 <= end) {
            memcpy(out_id, ptr, 12);
            out_id[12] = '\0';
            return true;
        }
        ++ptr;
    }
    return false;
}

// Fast PID validation
static inline bool is_valid_pid(const char* str, int* pid_out = nullptr) {
    if (!str || !*str) return false;
    char* endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0' || val <= 0 || val > INT_MAX) return false;
    if (pid_out) *pid_out = static_cast<int>(val);
    return true;
}

// Fast file reading with fixed buffer (EINTR-safe)
static ssize_t read_file_to_buffer(const char* path, char* buffer, size_t buffer_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return -1;

    ssize_t total_read = 0;
    while (total_read < static_cast<ssize_t>(buffer_size)) {
        ssize_t bytes_read;
        do {
            bytes_read = read(fd, buffer + total_read, buffer_size - total_read);
        } while (bytes_read == -1 && errno == EINTR);

        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }
    close(fd);
    return total_read;
}

// Ultra-fast inode map building (lean version)
static size_t build_inode_map_lean(char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN], char pid_map[MAX_SOCKETS_LEAN][16], char exe_map[MAX_SOCKETS_LEAN][MAX_PATH_LEN_LEAN], char container_map[MAX_SOCKETS_LEAN][13], size_t max_entries, const Config& config) {
    DIR* dir = opendir("/proc");
    if (!dir) return 0;

    size_t count = 0;
    struct dirent* entry;
    while (count < max_entries && (entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        int pid;
        if (!is_valid_pid(entry->d_name, &pid)) continue;

        // Build paths
        char proc_path[128];  // Increased from 64 for better path handling
        char cgroup_path[128];  // Increased from 64 for better path handling
        char exe_path[128];  // Increased from 64 for better path handling
        char fd_path[128];  // Increased from 64 for better path handling
        snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
        snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%d/cgroup", pid);
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);

        // Read container ID if containers enabled
        char container_id[13] = "";
        if (config.containers) {
            char cgroup_data[2048];
            ssize_t len = read_file_to_buffer(cgroup_path, cgroup_data, sizeof(cgroup_data) - 1);
            if (len > 0) {
                cgroup_data[len] = '\0';
                extract_container_id_lean(cgroup_data, len, container_id, sizeof(container_id));
            }
        }

        // Read exe symlink
        char exe_buf[512];  // Increased from 256 for better path handling
        ssize_t exe_len = readlink(exe_path, exe_buf, sizeof(exe_buf) - 1);
        if (exe_len > 0) {
            exe_buf[exe_len] = '\0';
        } else {
            exe_buf[0] = '\0';
        }

        // Process fd directory
        DIR* fd_dir = opendir(fd_path);
        if (fd_dir) {
            struct dirent* fd_entry;
            while (count < max_entries && (fd_entry = readdir(fd_dir)) != nullptr) {
                if (fd_entry->d_name[0] == '.') continue;

                char fd_link_path[512];  // Increased from 128 for better path handling
                snprintf(fd_link_path, sizeof(fd_link_path), "/proc/%d/fd/%s", pid, fd_entry->d_name);

                char target[128];  // Increased from 64 for better path handling
                ssize_t target_len = readlink(fd_link_path, target, sizeof(target) - 1);
                if (target_len <= 0) continue;

                target[target_len] = '\0';

                // Check if it's a socket
                const char* socket_prefix = "socket:[";
                if (strncmp(target, socket_prefix, strlen(socket_prefix)) != 0) continue;

                // Extract inode number
                const char* bracket_start = strchr(target, '[');
                const char* bracket_end = strchr(target, ']');
                if (!bracket_start || !bracket_end || bracket_start >= bracket_end) continue;

                size_t inode_len = bracket_end - bracket_start - 1;
                if (inode_len >= sizeof(inode_map[0]) - 1) continue;  // Leave room for null terminator

                memcpy(inode_map[count], bracket_start + 1, inode_len);
                inode_map[count][inode_len] = '\0';

                // Store associated data
                snprintf(pid_map[count], sizeof(pid_map[0]), "%d", pid);
                if (exe_len > 0 && exe_len < sizeof(exe_map[0])) {
                    memcpy(exe_map[count], exe_buf, exe_len + 1);
                } else {
                    exe_map[count][0] = '\0';
                }
                if (container_id[0] && strlen(container_id) < sizeof(container_map[0])) {
                    memcpy(container_map[count], container_id, strlen(container_id) + 1);
                } else {
                    container_map[count][0] = '\0';
                }

                count++;
            }
            closedir(fd_dir);
        }
    }
    closedir(dir);
    return count;
}

// Ultra-fast hex IP conversion (no string allocations)
static bool hex_ip_to_v4_lean(const char* hex_ip, char* out_ip, size_t out_size) {
    if (!hex_ip || strlen(hex_ip) < 8 || out_size < 16) return false;

    unsigned int b1 = 0, b2 = 0, b3 = 0, b4 = 0;
    char byte_str[3] = {0};

    // Parse each byte (2 hex chars = 1 byte)
    memcpy(byte_str, hex_ip + 6, 2); byte_str[2] = '\0'; b1 = strtoul(byte_str, nullptr, 16);
    memcpy(byte_str, hex_ip + 4, 2); byte_str[2] = '\0'; b2 = strtoul(byte_str, nullptr, 16);
    memcpy(byte_str, hex_ip + 2, 2); byte_str[2] = '\0'; b3 = strtoul(byte_str, nullptr, 16);
    memcpy(byte_str, hex_ip + 0, 2); byte_str[2] = '\0'; b4 = strtoul(byte_str, nullptr, 16);

    snprintf(out_ip, out_size, "%u.%u.%u.%u", b1, b2, b3, b4);
    return true;
}

static bool hex_ip6_to_str_lean(const char* hex_ip, char* out_ip, size_t out_size) {
    if (!hex_ip || strlen(hex_ip) < 32 || out_size < 40) return false;

    char* out = out_ip;
    for (int i = 0; i < 8; ++i) {
        if (i > 0) {
            *out++ = ':';
            if (out - out_ip >= (ssize_t)out_size) return false;
        }
        memcpy(out, hex_ip + i * 4, 4);
        out += 4;
        if (out - out_ip >= (ssize_t)out_size) return false;
    }
    *out = '\0';
    return true;
}

// Ultra-fast TCP state lookup
static const char* tcp_state_lean(const char* st) {
    static const struct { const char* hex; const char* name; } states[] = {
        {"01", "ESTABLISHED"}, {"02", "SYN_SENT"}, {"03", "SYN_RECV"},
        {"04", "FIN_WAIT1"}, {"05", "FIN_WAIT2"}, {"06", "TIME_WAIT"},
        {"07", "CLOSE"}, {"08", "CLOSE_WAIT"}, {"09", "LAST_ACK"},
        {"0A", "LISTEN"}, {"0B", "CLOSING"}
    };

    for (size_t i = 0; i < sizeof(states)/sizeof(states[0]); ++i) {
        if (strcmp(st, states[i].hex) == 0) {
            return states[i].name;
        }
    }
    return st;
}

// Ultra-fast severity classification
static Severity classify_tcp_severity_lean(const char* state, unsigned port, const char* exe) {
    if (strcmp(state, "LISTEN") == 0) {
        if (port == 22 || port == 23 || port == 2323) return Severity::Medium;
        if (port == 0) return Severity::Low;
        if (port < 1024) {
            // Common services
            if (port == 80 || port == 443 || port == 53 || port == 25 ||
                port == 110 || port == 995 || port == 143 || port == 993) {
                return Severity::Low;
            }
            return Severity::Medium;
        }
    }
    return Severity::Info;
}

static Severity classify_udp_severity_lean(unsigned port, const char* exe) {
    // DNS is common and low-risk
    if (port == 53) return Severity::Low;

    // Sensitive UDP services that should be flagged
    if (port == 161 || port == 162) return Severity::Medium;  // SNMP
    if (port == 1900) return Severity::Medium;  // SSDP/UPnP
    if (port == 5353) return Severity::Low;  // mDNS
    if (port == 67 || port == 68) return Severity::Low;  // DHCP (common infrastructure)

    // Privileged ports (except common services above)
    if (port < 1024 && port != 123) return Severity::Medium;  // NTP is common

    return Severity::Info;
}

// Ultra-fast escalation for exposed listeners
static Severity escalate_exposed_lean(Severity current, const char* state, const char* lip) {
    if (strcmp(state, "LISTEN") != 0) return current;

    // Check for loopback addresses
    if (strncmp(lip, "127.", 4) == 0 ||
        strcmp(lip, "::1") == 0 ||
        strcmp(lip, "0000:0000:0000:0000:0000:0000:0000:0001") == 0 ||
        strcmp(lip, "127.0.0.1") == 0 ||
        strcmp(lip, "127.0.0.53") == 0 ||
        strcmp(lip, "127.0.0.54") == 0) {
        return current;
    }

    // Escalate one level for exposed listeners
    static const Severity order[] = {Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical};
    for (size_t i = 0; i < sizeof(order)/sizeof(order[0]) - 1; ++i) {
        if (current == order[i]) {
            return order[i + 1];
        }
    }
    return current;
}

// Ultra-fast inode lookup in lean arrays
static size_t find_inode_lean(const char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN], size_t count, const char* inode) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(inode_map[i], inode) == 0) {
            return i;
        }
    }
    return SIZE_MAX;
}

// Ultra-fast TCP parsing (lean version)
static void parse_tcp_lean(const char* path, Report& report, const char* proto,
                          const char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN], const char pid_map[MAX_SOCKETS_LEAN][16],
                          const char exe_map[MAX_SOCKETS_LEAN][MAX_PATH_LEN_LEAN], const char container_map[MAX_SOCKETS_LEAN][13],
                          size_t inode_count, size_t& emitted,
                          std::unordered_map<std::string, FanoutAgg>* fanout, const Config& config) {
    parse_proc_net_file(path, report, proto, inode_map, pid_map, exe_map, container_map, inode_count, emitted, fanout, config, true);
}

// Ultra-fast UDP parsing (lean version)
static void parse_udp_lean(const char* path, Report& report, const char* proto,
                          const char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN], const char pid_map[MAX_SOCKETS_LEAN][16],
                          const char exe_map[MAX_SOCKETS_LEAN][MAX_PATH_LEN_LEAN], const char container_map[MAX_SOCKETS_LEAN][13],
                          size_t inode_count, size_t& emitted,
                          std::unordered_map<std::string, FanoutAgg>* fanout, const Config& config) {
    parse_proc_net_file(path, report, proto, inode_map, pid_map, exe_map, container_map, inode_count, emitted, fanout, config, false);
}

void NetworkScanner::scan(ScanContext& context) {
    const Config& config = context.config;
    Report& report = context.report;

    // Lean network scanning implementation
    size_t emitted = 0;

    // Build inode-to-process mapping (lean arrays)
    char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN] = {};
    char pid_map[MAX_SOCKETS_LEAN][16] = {};
    char exe_map[MAX_SOCKETS_LEAN][MAX_PATH_LEN_LEAN] = {};
    char container_map[MAX_SOCKETS_LEAN][13] = {};

    size_t inode_count = 0;

    // Scan /proc for socket inodes
    if (config.network_advanced) {
        inode_count = build_inode_map_lean(inode_map, pid_map, exe_map, container_map, MAX_SOCKETS_LEAN, config);
    }

    // Parse TCP sockets
    bool scan_tcp = config.network_proto.empty() || config.network_proto == "tcp";
    if (scan_tcp) {
        size_t before_tcp = emitted;
        parse_tcp_lean("/proc/net/tcp", report, "tcp", inode_map, pid_map, exe_map, container_map, inode_count, emitted, nullptr, config);
        parse_tcp_lean("/proc/net/tcp6", report, "tcp6", inode_map, pid_map, exe_map, container_map, inode_count, emitted, nullptr, config);

        // Add truncation warning if we hit the limit
        if (emitted >= (size_t)config.max_sockets && before_tcp < emitted) {
            char warn_msg[128];
            snprintf(warn_msg, sizeof(warn_msg), "TCP socket scan truncated at %d sockets (max_sockets limit)", config.max_sockets);
            report.add_warning("tcp", WarnCode::NetFileUnreadable, warn_msg);
        }
    }

    // Parse UDP sockets
    bool scan_udp = config.network_proto.empty() || config.network_proto == "udp";
    if (scan_udp) {
        size_t before_udp = emitted;
        parse_udp_lean("/proc/net/udp", report, "udp", inode_map, pid_map, exe_map, container_map, inode_count, emitted, nullptr, config);
        parse_udp_lean("/proc/net/udp6", report, "udp6", inode_map, pid_map, exe_map, container_map, inode_count, emitted, nullptr, config);

        // Add truncation warning if we hit the limit
        if (emitted >= (size_t)config.max_sockets && before_udp < emitted) {
            char warn_msg[128];
            snprintf(warn_msg, sizeof(warn_msg), "UDP socket scan truncated at %d sockets (max_sockets limit)", config.max_sockets);
            report.add_warning("udp", WarnCode::NetFileUnreadable, warn_msg);
        }
    }
}

} // namespace sys_scan
