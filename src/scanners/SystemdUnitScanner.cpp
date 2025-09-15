#include "SystemdUnitScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cctype>

namespace sys_scan {

// Ultra-lean constants (reduced to prevent stack overflow)
#define MAX_SYSTEMD_UNITS_LEAN 1000
#define MAX_PATH_LEN_LEAN 256
#define MAX_LINE_LEN_LEAN 512
#define MAX_KEY_VALUE_PAIRS_LEAN 50
#define MAX_SERVICE_FILES_LEAN 500

// Ultra-lean unit data structure
struct UnitDataLean {
    char name[MAX_PATH_LEN_LEAN];
    char kv_keys[MAX_KEY_VALUE_PAIRS_LEAN][MAX_LINE_LEN_LEAN];
    char kv_values[MAX_KEY_VALUE_PAIRS_LEAN][MAX_LINE_LEN_LEAN];
    int kv_count;
};

// Service file batch structure
struct ServiceBatch {
    char filenames[MAX_SERVICE_FILES_LEAN][MAX_PATH_LEN_LEAN];
    int file_count;
};

// Fast string operations with safety checks
static inline void trim_string_lean(char* str) {
    if (!str || !*str) return;
    size_t len = strlen(str);
    if (len == 0) return;

    char* end = str + len - 1;
    while (end > str && (*end == ' ' || *end == '\r' || *end == '\n' || *end == '\t')) {
        *end = '\0';
        end--;
    }
    char* start = str;
    while (*start == ' ' || *start == '\t') start++;
    if (start != str) {
        size_t new_len = strlen(start);
        memmove(str, start, new_len + 1);
    }
}

static inline bool string_equal_lean(const char* a, const char* b) {
    return strcmp(a, b) == 0;
}

static inline bool string_contains_lean(const char* haystack, const char* needle) {
    return strstr(haystack, needle) != NULL;
}

static inline char* string_copy_lean(char* dest, const char* src, size_t max_len) {
    if (!dest || !src || max_len == 0) return dest;
    size_t len = strlen(src);
    if (len >= max_len) len = max_len - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
    return dest;
}

// Fast file reading to fixed buffer with safety
static inline ssize_t read_file_to_buffer_lean(int fd, char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return -1;

    ssize_t total_read = 0;
    ssize_t bytes_read;
    while (total_read < (ssize_t)buffer_size - 1 &&
           (bytes_read = read(fd, buffer + total_read, buffer_size - total_read - 1)) > 0) {
        total_read += bytes_read;
    }
    buffer[total_read] = '\0'; // Ensure null termination
    return total_read;
}

// Ultra-fast unit file parsing with safety checks
static void parse_unit_lean(const char* buffer, UnitDataLean* unit) {
    if (!buffer || !unit || !*buffer) return;

    unit->kv_count = 0;
    const char* line_start = buffer;
    const char* buffer_end = buffer + strlen(buffer);

    while (line_start < buffer_end && unit->kv_count < MAX_KEY_VALUE_PAIRS_LEAN) {
        const char* line_end = line_start;
        while (line_end < buffer_end && *line_end != '\n' && *line_end != '\r') line_end++;

        // Skip empty lines and comments
        if (line_start == line_end || *line_start == '#' || *line_start == ';') {
            line_start = line_end + 1;
            if (line_start < buffer_end && *line_start == '\n') line_start++;
            continue;
        }

        // Find '='
        const char* eq_pos = line_start;
        while (eq_pos < line_end && *eq_pos != '=') eq_pos++;

        if (eq_pos >= line_end) {
            line_start = line_end + 1;
            if (line_start < buffer_end && *line_start == '\n') line_start++;
            continue;
        }

        // Extract key and value with bounds checking
        size_t key_len = eq_pos - line_start;
        size_t val_len = line_end - eq_pos - 1;

        if (key_len >= MAX_LINE_LEN_LEAN) key_len = MAX_LINE_LEN_LEAN - 1;
        if (val_len >= MAX_LINE_LEN_LEAN) val_len = MAX_LINE_LEN_LEAN - 1;

        // Copy key
        memcpy(unit->kv_keys[unit->kv_count], line_start, key_len);
        unit->kv_keys[unit->kv_count][key_len] = '\0';
        trim_string_lean(unit->kv_keys[unit->kv_count]);

        // Copy value
        memcpy(unit->kv_values[unit->kv_count], eq_pos + 1, val_len);
        unit->kv_values[unit->kv_count][val_len] = '\0';
        trim_string_lean(unit->kv_values[unit->kv_count]);

        unit->kv_count++;
        line_start = line_end + 1;
        if (line_start < buffer_end && *line_start == '\n') line_start++;
    }
}

// Batch collect service files
static int collect_service_files_batch(const char* dir_path, ServiceBatch* batch) {
    if (!dir_path || !batch) return 0;

    DIR* dir = opendir(dir_path);
    if (!dir) return 0;

    struct dirent* entry;
    batch->file_count = 0;

    while ((entry = readdir(dir)) != NULL && batch->file_count < MAX_SERVICE_FILES_LEAN) {
        if (entry->d_name[0] == '.') continue;
        if (!string_contains_lean(entry->d_name, ".service")) continue;

        string_copy_lean(batch->filenames[batch->file_count], entry->d_name, MAX_PATH_LEN_LEAN);
        batch->file_count++;
    }

    closedir(dir);
    return batch->file_count;
}

// Check if unit has ExecStart (is a service)
static inline bool unit_has_exec_start(const UnitDataLean* unit) {
    if (!unit) return false;
    for (int i = 0; i < unit->kv_count; i++) {
        if (string_equal_lean(unit->kv_keys[i], "ExecStart")) {
            return true;
        }
    }
    return false;
}

// Find key value in unit
static inline const char* find_unit_value(const UnitDataLean* unit, const char* key) {
    if (!unit || !key) return NULL;
    for (int i = 0; i < unit->kv_count; i++) {
        if (string_equal_lean(unit->kv_keys[i], key)) {
            return unit->kv_values[i];
        }
    }
    return NULL;
}

void SystemdUnitScanner::scan(ScanContext& context){
    if(!context.config.hardening) return;

    // Start scanner
    context.report.start_scanner(name());

    // Use heap allocation to avoid stack overflow
    UnitDataLean* units = new (std::nothrow) UnitDataLean[MAX_SYSTEMD_UNITS_LEAN];
    ServiceBatch* service_batch = new (std::nothrow) ServiceBatch[1];
    char* file_buffer = new (std::nothrow) char[8192];

    if (!units || !service_batch || !file_buffer) {
        // Memory allocation failed
        delete[] units;
        delete[] service_batch;
        delete[] file_buffer;
        return;
    }

    // Initialize
    memset(units, 0, sizeof(UnitDataLean) * MAX_SYSTEMD_UNITS_LEAN);
    memset(service_batch, 0, sizeof(ServiceBatch));
    memset(file_buffer, 0, 8192);

    // Standard systemd directories (or test root)
    std::string systemd_dirs[3];
    if (!context.config.test_root.empty()) {
        // Use test root for testing
        systemd_dirs[0] = context.config.test_root + "/etc/systemd/system";
        systemd_dirs[1] = context.config.test_root + "/usr/lib/systemd/system";
        systemd_dirs[2] = context.config.test_root + "/lib/systemd/system";
    } else {
        // Use system paths for production
        systemd_dirs[0] = "/etc/systemd/system";
        systemd_dirs[1] = "/usr/lib/systemd/system";
        systemd_dirs[2] = "/lib/systemd/system";
    }
    const int dir_count = 3;

    int total_units = 0;

    // Single-pass collection and processing
    for (int d = 0; d < dir_count && total_units < MAX_SYSTEMD_UNITS_LEAN; d++) {
        const std::string& dir_path = systemd_dirs[d];

        // Check if directory exists
        struct stat st;
        if (stat(dir_path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        // Collect service files
        if (collect_service_files_batch(dir_path.c_str(), service_batch) == 0) continue;

        // Process each service file
        for (int f = 0; f < service_batch->file_count && total_units < MAX_SYSTEMD_UNITS_LEAN; f++) {
            const char* filename = service_batch->filenames[f];

            // Build full path with bounds checking
            char full_path[MAX_PATH_LEN_LEAN];
            const char* dir_path_cstr = dir_path.c_str();
            size_t dir_len = strlen(dir_path_cstr);
            size_t name_len = strlen(filename);

            if (dir_len + 1 + name_len >= MAX_PATH_LEN_LEAN - 1) continue; // Prevent buffer overflow

            memcpy(full_path, dir_path_cstr, dir_len);
            full_path[dir_len] = '/';
            memcpy(full_path + dir_len + 1, filename, name_len);
            full_path[dir_len + 1 + name_len] = '\0';

            // Read file
            int fd = open(full_path, O_RDONLY);
            if (fd == -1) continue;

            ssize_t bytes_read = read_file_to_buffer_lean(fd, file_buffer, 8192);
            close(fd);

            if (bytes_read <= 0) continue;

            // Parse unit
            UnitDataLean* unit = &units[total_units];
            string_copy_lean(unit->name, filename, MAX_PATH_LEN_LEAN);
            parse_unit_lean(file_buffer, unit);

            // Only keep if it has ExecStart (is a service)
            if (unit_has_exec_start(unit)) {
                total_units++;
            }
        }
    }

    // Hardening recommendations (static array for speed)
    struct RecLean {
        const char* key;
        const char* expect;
        Severity sev;
        const char* bad_desc;
        const char* good_desc;
    };

    static const RecLean recs[] = {
        {"NoNewPrivileges", "yes", Severity::Medium, "NoNewPrivileges not set to yes", "NoNewPrivileges enforced"},
        {"PrivateTmp", "yes", Severity::Low, "PrivateTmp not enabled", "PrivateTmp enabled"},
        {"ProtectSystem", "strict", Severity::Medium, "ProtectSystem not strict", "ProtectSystem strict"},
        {"ProtectHome", "read-only", Severity::Low, "ProtectHome not read-only", "ProtectHome read-only"},
        {"CapabilityBoundingSet", "", Severity::Low, "CapabilityBoundingSet not present (no reduction)", "CapabilityBoundingSet present"},
        {"RestrictNamespaces", "yes", Severity::Low, "RestrictNamespaces not enabled", "RestrictNamespaces enabled"},
        {"RestrictSUIDSGID", "yes", Severity::Low, "RestrictSUIDSGID not enabled", "RestrictSUIDSGID enabled"},
        {"ProtectKernelModules", "yes", Severity::Low, "ProtectKernelModules not enabled", "ProtectKernelModules enabled"},
        {"ProtectKernelTunables", "yes", Severity::Low, "ProtectKernelTunables not enabled", "ProtectKernelTunables enabled"},
        {"ProtectControlGroups", "yes", Severity::Low, "ProtectControlGroups not enabled", "ProtectControlGroups enabled"},
        {"MemoryDenyWriteExecute", "yes", Severity::Low, "MemoryDenyWriteExecute not enabled", "MemoryDenyWriteExecute enabled"},
        {"RestrictRealtime", "yes", Severity::Low, "RestrictRealtime not enabled", "RestrictRealtime enabled"},
        {"LockPersonality", "yes", Severity::Low, "LockPersonality not enabled", "LockPersonality enabled"},
    };

    const int rec_count = sizeof(recs) / sizeof(recs[0]);

    // Generate findings with ultra-fast lookups
    for (int u = 0; u < total_units; u++) {
        const UnitDataLean* unit = &units[u];

        for (int r = 0; r < rec_count; r++) {
            const RecLean* rec = &recs[r];
            const char* value = find_unit_value(unit, rec->key);

            bool present = (value != NULL);
            bool good = false;

            if (present) {
                if (strlen(rec->expect) == 0) {
                    good = true; // presence only requirement
                } else if (string_equal_lean(value, rec->expect)) {
                    good = true;
                } else if (string_equal_lean(rec->key, "ProtectSystem") &&
                          string_equal_lean(value, "full")) {
                    // Special case for ProtectSystem
                    good = false;
                }
            }

            Finding f;
            char id_buf[512];
            char title_buf[512];

            // Build ID and title
            strcpy(id_buf, "systemd:");
            strcat(id_buf, rec->key);
            strcat(id_buf, ":");
            strcat(id_buf, unit->name);

            strcpy(title_buf, unit->name);
            strcat(title_buf, " ");
            strcat(title_buf, rec->key);

            f.id = id_buf;
            f.title = title_buf;
            f.metadata["unit"] = unit->name;
            f.metadata["key"] = rec->key;
            if (present) f.metadata["value"] = value;
            f.metadata["expected"] = rec->expect;

            if (good) {
                f.severity = Severity::Info;
                f.description = rec->good_desc;
            } else {
                f.severity = rec->sev;
                f.description = present ? rec->bad_desc :
                               std::string(rec->bad_desc) + " (missing)";
            }

            context.report.add_finding(name(), std::move(f));
        }
    }

    // Clean up heap allocations
    delete[] units;
    delete[] service_batch;
    delete[] file_buffer;

    // End scanner
    context.report.end_scanner(name());
}

}
