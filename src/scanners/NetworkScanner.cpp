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

// Parse and validate line tokens from /proc/net/* files
static bool parse_net_line_tokens(const char* line, char* tokens[], int max_tokens, bool is_tcp) {
    // Remove trailing newline
    size_t len = strlen(line);
    if (len > 0 && line[len-1] == '\n') {
        ((char*)line)[len-1] = '\0';
        len--;
    }
    if (len == 0) return false;

    // Quick filter for colon
    if (!strchr(line, ':')) return false;

    // Tokenize line (space/tab separated, thread-safe)
    int token_count = 0;
    char* saveptr;
    char* tok = strtok_r((char*)line, " \t", &saveptr);
    while (tok && token_count < max_tokens) {
        tokens[token_count++] = tok;
        tok = strtok_r(nullptr, " \t", &saveptr);
    }

    return token_count >= (is_tcp ? 10 : 9);
}

// Extract addresses and ports from tokenized line
static bool extract_address_port_info(char* tokens[], bool is_tcp, unsigned& lport, unsigned& rport, char*& local, char*& rem) {
    local = tokens[1];
    rem = is_tcp ? tokens[2] : nullptr;

    // Parse addresses and ports
    char* colon1 = strchr(local, ':');
    if (!colon1) return false;

    *colon1 = '\0';
    char* lport_hex = colon1 + 1;

    char* rport_hex = nullptr;
    if (is_tcp && rem) {
        char* colon2 = strchr(rem, ':');
        if (!colon2) return false;
        *colon2 = '\0';
        rport_hex = colon2 + 1;
    }

    // Convert hex ports to decimal
    lport = strtoul(lport_hex, nullptr, 16);
    rport = is_tcp && rport_hex ? strtoul(rport_hex, nullptr, 16) : 0;

    return lport != 0 && (!is_tcp || rport != 0);
}

// Convert IP addresses from hex to string format
static void convert_ip_addresses(const char* local, const char* rem, bool is_ipv6, bool is_tcp,
                               char* lip, size_t lip_size, char* rip, size_t rip_size) {
    if (is_ipv6) {
        hex_ip6_to_str_lean(local, lip, lip_size);
        if (is_tcp && rem) hex_ip6_to_str_lean(rem, rip, rip_size);
    } else {
        hex_ip_to_v4_lean(local, lip, lip_size);
        if (is_tcp && rem) hex_ip_to_v4_lean(rem, rip, rip_size);
    }
}

// Check if socket should be filtered based on configuration
static bool should_filter_socket(bool is_tcp, const char* state_str, const Config& config,
                               const char* lip, const char* container_id) {
    if (is_tcp) {
        if (config.network_listen_only && strcmp(state_str, "LISTEN") != 0) return true;
        if (!state_allowed_lean(state_str, config)) return true;
    }

    // Container filtering
    if (config.containers && !config.container_id_filter.empty()) {
        if (!container_id || strcmp(container_id, config.container_id_filter.c_str()) != 0) {
            return true;
        }
    }

    return false;
}

// Create finding from parsed socket information
static void create_socket_finding(Report& report, const char* proto, bool is_tcp, const char* state_str,
                                unsigned lport, unsigned rport, const char* lip, const char* rip,
                                const char* inode_s, const char* pid_str, const char* exe_str,
                                const char* container_id, const Config& config) {
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
    if (!config.no_user_meta) f.metadata["uid"] = "";  // Will be set from tokens if available
    f.metadata["lport"] = std::to_string(lport);
    if (is_tcp) f.metadata["rport"] = std::to_string(rport);
    f.metadata["inode"] = inode_s;
    f.metadata["lip"] = lip;
    if (is_tcp) f.metadata["rip"] = rip;

    if (pid_str && *pid_str) f.metadata["pid"] = pid_str;
    if (exe_str && *exe_str) f.metadata["exe"] = exe_str;
    if (container_id && *container_id) f.metadata["container_id"] = container_id;

    // Severity classification
    Severity sev;
    if (is_tcp) {
        sev = classify_tcp_severity_lean(state_str, lport, exe_str ? exe_str : "");
        f.severity = escalate_exposed_lean(sev, state_str, lip);
    } else {
        sev = classify_udp_severity_lean(lport, exe_str ? exe_str : "");
        f.severity = sev;
    }

    // Wildcard/privileged annotations for TCP
    if (is_tcp && strcmp(state_str, "LISTEN") == 0) {
        bool wildcard = false;
        if (strstr(proto, "6")) {  // IPv6
            wildcard = (strcmp(lip, "0000:0000:0000:0000:0000:0000:0000:0000") == 0);
        } else {  // IPv4
            wildcard = (strcmp(lip, "0.0.0.0") == 0);
        }
        if (wildcard) f.metadata["wildcard_listen"] = "true";
        if (lport < 1024) f.metadata["privileged_port"] = "true";
    }

    report.add_finding(proto, std::move(f));
}

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

        // Parse line tokens
        char* tokens[20];
        if (!parse_net_line_tokens(line, tokens, 20, is_tcp)) continue;

        // Extract address and port information
        unsigned lport, rport;
        char* local, *rem;
        if (!extract_address_port_info(tokens, is_tcp, lport, rport, local, rem)) continue;

        const char* state_str = is_tcp ? tcp_state_lean(tokens[3]) : "UDP";

        // Convert IP addresses
        char lip[40] = "", rip[40] = "";
        convert_ip_addresses(local, rem, is_ipv6, is_tcp, lip, sizeof(lip), rip, sizeof(rip));

        // Lookup inode in lean arrays
        size_t inode_idx = find_inode_lean(inode_map, inode_count, tokens[is_tcp ? 9 : 8]);
        const char* inode_s = tokens[is_tcp ? 9 : 8];
        const char* pid_str = (inode_idx != SIZE_MAX && inode_idx < inode_count) ? pid_map[inode_idx] : "";
        const char* exe_str = (inode_idx != SIZE_MAX && inode_idx < inode_count) ? exe_map[inode_idx] : "";
        const char* container_id = (inode_idx != SIZE_MAX && inode_idx < inode_count) ? container_map[inode_idx] : "";

        // Check if socket should be filtered
        if (should_filter_socket(is_tcp, state_str, config, lip, container_id)) continue;

        // Create and add finding
        create_socket_finding(report, proto, is_tcp, state_str, lport, rport, lip, rip,
                            inode_s, pid_str, exe_str, container_id, config);

        // Fanout aggregation for TCP
        if (is_tcp && config.network_advanced && fanout && strcmp(state_str, "ESTABLISHED") == 0 && inode_idx != SIZE_MAX && inode_idx < inode_count) {
            const char* remote_ip = is_ipv6 ? rip : rip;
            (*fanout)[pid_str].total++;
            (*fanout)[pid_str].remote_ips.insert(remote_ip);
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
// Check if position has a known container runtime marker
static bool has_container_marker(const char* ptr, const char* end, const char* const* markers, size_t marker_count) {
    for (size_t i = 0; i < marker_count; ++i) {
        size_t marker_len = strlen(markers[i]);
        if (ptr + marker_len < end && strncmp(ptr, markers[i], marker_len) == 0) {
            return true;
        }
    }
    return false;
}

// Check if string of given length is all hex digits
static bool is_valid_hex_string(const char* ptr, size_t len, const char* end) {
    if (ptr + len > end) return false;
    for (size_t i = 0; i < len; ++i) {
        if (!isxdigit(ptr[i])) return false;
    }
    return true;
}

// Extract container ID from position if valid hex string found
static bool extract_container_id_from_position(const char* ptr, const char* end, char* out_id, size_t out_size) {
    // Check for 64-char hex string first (full container ID)
    if (is_valid_hex_string(ptr, 64, end)) {
        memcpy(out_id, ptr, 12);
        out_id[12] = '\0';
        return true;
    }

    // Check for 32-char hex string (short container ID)
    if (is_valid_hex_string(ptr, 32, end)) {
        memcpy(out_id, ptr, 12);
        out_id[12] = '\0';
        return true;
    }

    return false;
}

// Extract container ID from cgroup data (lean version)
static bool extract_container_id_lean(const char* cgroup_data, size_t len, char* out_id, size_t out_size) {
    if (out_size < 13) return false;  // Need at least 12 chars + null

    const char* ptr = cgroup_data;
    const char* end = cgroup_data + len;

    // Known container runtime markers for stricter parsing
    static const char* markers[] = {
        "docker-", "containerd-", "crio-", "podman-", "lxc-", "kubepods"
    };
    static const size_t marker_count = sizeof(markers) / sizeof(markers[0]);

    while (ptr < end - 32) {  // Need at least 32 chars for shortest valid ID
        // Check for known container runtime markers first
        if (!has_container_marker(ptr, end, markers, marker_count) && !isxdigit(*ptr)) {
            ++ptr;
            continue;
        }

        // Try to extract container ID from current position
        if (extract_container_id_from_position(ptr, end, out_id, out_size)) {
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

// Build standard proc file paths for a given PID
static void build_proc_paths(int pid, char* proc_path, size_t proc_size,
                           char* cgroup_path, size_t cgroup_size,
                           char* exe_path, size_t exe_size,
                           char* fd_path, size_t fd_size) {
    snprintf(proc_path, proc_size, "/proc/%d", pid);
    snprintf(cgroup_path, cgroup_size, "/proc/%d/cgroup", pid);
    snprintf(exe_path, exe_size, "/proc/%d/exe", pid);
    snprintf(fd_path, fd_size, "/proc/%d/fd", pid);
}

// Read container ID from cgroup file
static bool read_container_id(int pid, const Config& config, char* container_id, size_t container_size) {
    if (!config.containers || container_size < 13) return false;

    char cgroup_path[128];
    char cgroup_data[2048];

    build_proc_paths(pid, nullptr, 0, cgroup_path, sizeof(cgroup_path), nullptr, 0, nullptr, 0);

    ssize_t len = read_file_to_buffer(cgroup_path, cgroup_data, sizeof(cgroup_data) - 1);
    if (len > 0) {
        cgroup_data[len] = '\0';
        return extract_container_id_lean(cgroup_data, len, container_id, container_size);
    }
    return false;
}

// Read executable path from /proc/[pid]/exe symlink
static bool read_exe_path(int pid, char* exe_buf, size_t exe_size) {
    char exe_path[128];
    build_proc_paths(pid, nullptr, 0, nullptr, 0, exe_path, sizeof(exe_path), nullptr, 0);

    ssize_t exe_len = readlink(exe_path, exe_buf, exe_size - 1);
    if (exe_len > 0) {
        exe_buf[exe_len] = '\0';
        return true;
    }
    exe_buf[0] = '\0';
    return false;
}

// Process socket file descriptors for a given PID
static size_t process_socket_fds(int pid, const char* exe_buf, const char* container_id,
                                char inode_map[MAX_SOCKETS_LEAN][MAX_INODE_LEN_LEAN],
                                char pid_map[MAX_SOCKETS_LEAN][16],
                                char exe_map[MAX_SOCKETS_LEAN][MAX_PATH_LEN_LEAN],
                                char container_map[MAX_SOCKETS_LEAN][13],
                                size_t start_count, size_t max_entries) {
    char fd_path[128];
    build_proc_paths(pid, nullptr, 0, nullptr, 0, nullptr, 0, fd_path, sizeof(fd_path));

    DIR* fd_dir = opendir(fd_path);
    if (!fd_dir) return start_count;

    size_t count = start_count;
    struct dirent* fd_entry;

    while (count < max_entries && (fd_entry = readdir(fd_dir)) != nullptr) {
        if (fd_entry->d_name[0] == '.') continue;

        char fd_link_path[512];
        snprintf(fd_link_path, sizeof(fd_link_path), "/proc/%d/fd/%s", pid, fd_entry->d_name);

        char target[128];
        ssize_t target_len = readlink(fd_link_path, target, sizeof(target) - 1);
        if (target_len <= 0) continue;

        target[target_len] = '\0';

        // Check if it's a socket and extract inode
        const char* socket_prefix = "socket:[";
        if (strncmp(target, socket_prefix, strlen(socket_prefix)) != 0) continue;

        const char* bracket_start = strchr(target, '[');
        const char* bracket_end = strchr(target, ']');
        if (!bracket_start || !bracket_end || bracket_start >= bracket_end) continue;

        size_t inode_len = bracket_end - bracket_start - 1;
        if (inode_len >= sizeof(inode_map[0]) - 1) continue;

        // Store inode and associated data
        memcpy(inode_map[count], bracket_start + 1, inode_len);
        inode_map[count][inode_len] = '\0';

        snprintf(pid_map[count], sizeof(pid_map[0]), "%d", pid);

        if (exe_buf && *exe_buf && strlen(exe_buf) < sizeof(exe_map[0])) {
            memcpy(exe_map[count], exe_buf, strlen(exe_buf) + 1);
        } else {
            exe_map[count][0] = '\0';
        }

        if (container_id && *container_id && strlen(container_id) < sizeof(container_map[0])) {
            memcpy(container_map[count], container_id, strlen(container_id) + 1);
        } else {
            container_map[count][0] = '\0';
        }

        count++;
    }

    closedir(fd_dir);
    return count;
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

        // Read container ID and exe path
        char container_id[13] = "";
        char exe_buf[512] = "";

        read_container_id(pid, config, container_id, sizeof(container_id));
        read_exe_path(pid, exe_buf, sizeof(exe_buf));

        // Process socket file descriptors
        count = process_socket_fds(pid, exe_buf, container_id, inode_map, pid_map, exe_map, container_map, count, max_entries);
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
// Check if TCP port is considered sensitive
static bool is_sensitive_tcp_port(unsigned port) {
    return port == 22 || port == 23 || port == 2323;
}

// Check if TCP port is a common service
static bool is_common_service_port(unsigned port) {
    return port == 80 || port == 443 || port == 53 || port == 25 ||
           port == 110 || port == 995 || port == 143 || port == 993;
}

// Classify severity for TCP ports in LISTEN state
static Severity classify_listen_port_severity(unsigned port) {
    if (is_sensitive_tcp_port(port)) return Severity::Medium;
    if (port == 0) return Severity::Low;
    if (port < 1024) {
        if (is_common_service_port(port)) return Severity::Low;
        return Severity::Medium;
    }
    return Severity::Info;
}

// Ultra-fast severity classification for TCP
static Severity classify_tcp_severity_lean(const char* state, unsigned port, const char* exe) {
    if (strcmp(state, "LISTEN") == 0) {
        return classify_listen_port_severity(port);
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
