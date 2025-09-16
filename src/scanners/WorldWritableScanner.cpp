#include "WorldWritableScanner.h"
#include "../core/Report.h"
#include "../core/ScanContext.h"
#include "../core/Utils.h"
#include "../core/Config.h"
#include <sys/stat.h>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#ifdef __linux__
#include <sys/types.h>
#include <sys/xattr.h>
#endif

namespace sys_scan {

// Ultra-lean constants
static const size_t MAX_FILES_LEAN = 5000;
static const size_t MAX_PATH_LEN_LEAN = 256;
static const size_t MAX_INODES_LEAN = 1000;
static const size_t MAX_PATHS_PER_INODE = 3;

// Ultra-fast single-pass file batch structure
struct FileBatch {
    char paths[MAX_FILES_LEAN][MAX_PATH_LEN_LEAN];
    struct stat stats[MAX_FILES_LEAN];
    char shebangs[MAX_FILES_LEAN][128];
    bool has_suid[MAX_FILES_LEAN];
    bool has_caps[MAX_FILES_LEAN];
    bool is_world_writable[MAX_FILES_LEAN];
    size_t count;
};

// Ultra-fast inode tracking for hardlink detection
struct InodeEntry {
    ino_t inode;
    char paths[MAX_PATHS_PER_INODE][MAX_PATH_LEN_LEAN];
    size_t path_count;
};

// Check if file should be excluded based on patterns
static bool is_file_excluded(const char* filepath, const std::vector<std::string>& exclude_patterns) {
    for (const auto& pat : exclude_patterns) {
        if (strstr(filepath, pat.c_str()) != nullptr) {
            return true;
        }
    }
    return false;
}

// Process world-writable file findings
static void process_world_writable_file(const char* filepath, ScanContext& context, int ww_limit, size_t* ww_count) {
    if (*ww_count >= static_cast<size_t>(ww_limit) && ww_limit > 0) return;

    Finding f;
    f.id = filepath;
    f.title = "World-writable file";
    f.severity = Severity::Medium;
    f.description = "File is world writable";

    // Adjust severity based on path
    if (strstr(filepath, "/tmp/") != nullptr) {
        f.severity = Severity::Low;
    } else if (strstr(filepath, ".so") != nullptr || strstr(filepath, "/bin/") != nullptr) {
        f.severity = Severity::High;
    }

    context.report.add_finding("world_writable", std::move(f));
    ++(*ww_count);
}

// Check if file is a SUID interpreter
static bool is_suid_interpreter(const char* filepath, const char* shebang, bool has_suid,
                               const char* interpreters[], size_t interpreter_count) {
    if (!has_suid) return false;

    const char* filename = strrchr(filepath, '/');
    filename = filename ? filename + 1 : filepath;

    // Check filename first
    for (size_t j = 0; j < interpreter_count; ++j) {
        if (strcmp(filename, interpreters[j]) == 0) {
            return true;
        }
    }

    // Check shebang if needed
    if (shebang[0] == '#') {
        for (size_t j = 0; j < interpreter_count; ++j) {
            if (strstr(shebang, interpreters[j]) != nullptr) {
                return true;
            }
        }
    }

    return false;
}

// Process SUID interpreter finding
static void process_suid_interpreter(const char* filepath, ScanContext& context) {
    Finding f;
    f.id = filepath;
    f.title = "Setuid interpreter";
    f.severity = Severity::Critical;
    f.description = "Setuid shell or script interpreter";
    f.metadata["rule"] = "setuid_interpreter";
    context.report.add_finding("world_writable", std::move(f));
}

// Process file capabilities finding
static void process_file_capabilities(const char* filepath, const struct stat* st, bool has_caps, ScanContext& context) {
    if (!has_caps || (st->st_mode & S_ISUID)) return;

    Finding f;
    f.id = filepath;
    f.title = "File capabilities binary";
    f.severity = Severity::Medium;
    f.description = "Binary has file capabilities set";
    f.metadata["rule"] = "file_capability";
    context.report.add_finding("world_writable", std::move(f));
}

// Track inode for hardlink detection
static void track_inode_for_hardlinks(const char* filepath, const struct stat* st, bool has_suid,
                                     InodeEntry* inode_entries, size_t* inode_count) {
    if (!has_suid || *inode_count >= MAX_INODES_LEAN) return;

    ino_t inode = st->st_ino;

    // Find existing inode entry
    size_t entry_idx = SIZE_MAX;
    for (size_t j = 0; j < *inode_count; ++j) {
        if (inode_entries[j].inode == inode) {
            entry_idx = j;
            break;
        }
    }

    // Create new entry if needed
    if (entry_idx == SIZE_MAX) {
        entry_idx = *inode_count;
        inode_entries[entry_idx].inode = inode;
        inode_entries[entry_idx].path_count = 0;
        ++(*inode_count);
    }

    // Add path if space available
    if (entry_idx < *inode_count && inode_entries[entry_idx].path_count < MAX_PATHS_PER_INODE) {
        size_t path_idx = inode_entries[entry_idx].path_count;
        strncpy(inode_entries[entry_idx].paths[path_idx], filepath, MAX_PATH_LEN_LEAN - 1);
        inode_entries[entry_idx].paths[path_idx][MAX_PATH_LEN_LEAN - 1] = '\0';
        ++inode_entries[entry_idx].path_count;
    }
}

// Process a single file in the batch
static void process_single_file(const FileBatch* batch, size_t index, ScanContext& context,
                               const std::vector<std::string>& exclude_patterns,
                               int ww_limit, size_t* ww_count,
                               const char* interpreters[], size_t interpreter_count,
                               InodeEntry* inode_entries, size_t* inode_count) {
    const char* filepath = batch->paths[index];

    // Skip excluded files
    if (is_file_excluded(filepath, exclude_patterns)) return;

    // World-writable check
    if (batch->is_world_writable[index]) {
        process_world_writable_file(filepath, context, ww_limit, ww_count);
    }

    // SUID interpreter check
    if (is_suid_interpreter(filepath, batch->shebangs[index], batch->has_suid[index],
                           interpreters, interpreter_count)) {
        process_suid_interpreter(filepath, context);
    }

    // File capabilities check
    process_file_capabilities(filepath, &batch->stats[index], batch->has_caps[index], context);

    // Track inodes for hardlink detection
    track_inode_for_hardlinks(filepath, &batch->stats[index], batch->has_suid[index],
                             inode_entries, inode_count);
}

// Ultra-fast batch file processor (refactored)
static void process_file_batch_lean(FileBatch* batch, ScanContext& context,
                                   const std::vector<std::string>& exclude_patterns,
                                   int ww_limit, size_t* ww_count,
                                   const char* interpreters[], size_t interpreter_count,
                                   InodeEntry* inode_entries, size_t* inode_count) {

    for (size_t i = 0; i < batch->count; ++i) {
        process_single_file(batch, i, context, exclude_patterns, ww_limit, ww_count,
                           interpreters, interpreter_count, inode_entries, inode_count);
    }
}

// Build full file path from directory and filename
static bool build_file_path(const char* dir_path, const char* filename, char* out_path, size_t max_len) {
    size_t dir_len = strlen(dir_path);
    size_t name_len = strlen(filename);

    if (dir_len + 1 + name_len >= max_len) return false;

    memcpy(out_path, dir_path, dir_len);
    out_path[dir_len] = '/';
    memcpy(out_path + dir_len + 1, filename, name_len + 1);
    return true;
}

// Check if file has capabilities set
static bool check_file_capabilities(const char* filepath) {
#ifdef __linux__
    ssize_t cap_len = getxattr(filepath, "security.capability", nullptr, 0);
    return cap_len > 0;
#else
    return false;
#endif
}

// Read shebang from file
static void read_file_shebang(const char* filepath, char* shebang_buffer, size_t buffer_size) {
    shebang_buffer[0] = '\0';

    int fd = open(filepath, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return;

    ssize_t bytes_read = read(fd, shebang_buffer, buffer_size - 1);
    close(fd);

    if (bytes_read > 0) {
        shebang_buffer[bytes_read] = '\0';

        // Null terminate at newline
        char* newline = strchr(shebang_buffer, '\n');
        if (newline) *newline = '\0';
    }
}

// Process a single directory entry
static bool process_directory_entry(const char* dir_path, const char* filename,
                                   char* filepath, struct stat* st, char* shebang,
                                   bool* has_suid, bool* is_world_writable, bool* has_caps) {
    // Build full path
    if (!build_file_path(dir_path, filename, filepath, MAX_PATH_LEN_LEAN)) {
        return false;
    }

    // Get file stats
    if (lstat(filepath, st) != 0) {
        return false;
    }

    // Only process regular files
    if (!S_ISREG(st->st_mode)) {
        return false;
    }

    // Set flags
    *has_suid = (st->st_mode & S_ISUID) != 0;
    *is_world_writable = (st->st_mode & S_IWOTH) != 0;
    *has_caps = check_file_capabilities(filepath);

    // Read shebang for SUID files only
    if (*has_suid) {
        read_file_shebang(filepath, shebang, 128);
    } else {
        shebang[0] = '\0';
    }

    return true;
}

// Ultra-fast single-pass directory scanner (refactored)
static size_t scan_directory_batch_lean(const char* dir_path, FileBatch* batch,
                                       size_t max_files, size_t start_idx) {
    DIR* dir = opendir(dir_path);
    if (!dir) return 0;

    size_t count = 0;

    while (count < max_files) {
        struct dirent* entry = readdir(dir);
        if (!entry) break;

        if (entry->d_name[0] == '.') continue;  // Skip hidden files

        size_t current_idx = start_idx + count;

        if (process_directory_entry(dir_path, entry->d_name,
                                  batch->paths[current_idx],
                                  &batch->stats[current_idx],
                                  batch->shebangs[current_idx],
                                  &batch->has_suid[current_idx],
                                  &batch->is_world_writable[current_idx],
                                  &batch->has_caps[current_idx])) {
            ++count;
        }
    }

    closedir(dir);
    return count;
}

// Scan default directories and process files
static void scan_default_directories(ScanContext& context, FileBatch* batch,
                                    InodeEntry* inode_entries, size_t* inode_count,
                                    const char* interpreters[], size_t interpreter_count,
                                    size_t* total_files, size_t* ww_count) {
    // Directories to scan
    const char* scan_dirs[] = {"/usr/bin", "/bin", "/usr/local/bin", "/etc", "/var"};
    const size_t scan_dir_count = sizeof(scan_dirs) / sizeof(scan_dirs[0]);

    // Single-pass directory scanning
    for (size_t d = 0; d < scan_dir_count && *total_files < MAX_FILES_LEAN; ++d) {
        size_t files_added = scan_directory_batch_lean(scan_dirs[d], batch, MAX_FILES_LEAN - *total_files, *total_files);
        *total_files += files_added;
    }

    batch->count = *total_files;

    // Process all files in single batch
    process_file_batch_lean(batch, context, context.config.world_writable_exclude,
                           context.config.fs_world_writable_limit, ww_count,
                           interpreters, interpreter_count, inode_entries, inode_count);
}

// Scan additional directories from configuration
static void scan_additional_directories(ScanContext& context, InodeEntry* inode_entries, size_t* inode_count,
                                       const char* interpreters[], size_t interpreter_count,
                                       size_t* total_files, size_t* ww_count) {
    for (const auto& extra_dir : context.config.world_writable_dirs) {
        if (*total_files >= MAX_FILES_LEAN) break;

        FileBatch* extra_batch = new FileBatch();
        size_t extra_files = scan_directory_batch_lean(extra_dir.c_str(), extra_batch,
                                                      MAX_FILES_LEAN - *total_files, 0);
        extra_batch->count = extra_files;

        if (extra_files > 0) {
            process_file_batch_lean(extra_batch, context, context.config.world_writable_exclude,
                                   context.config.fs_world_writable_limit, ww_count,
                                   interpreters, interpreter_count, inode_entries, inode_count);
            *total_files += extra_files;
        }
        delete extra_batch;
    }
}

// Check PATH directories for world-writability
static void check_path_directories_world_writable(ScanContext& context) {
    const char* path_env = getenv("PATH");
    if (!path_env) return;

    const char* path_ptr = path_env;
    char path_seg[MAX_PATH_LEN_LEAN];

    while (*path_ptr) {
        // Extract path segment
        const char* colon = strchr(path_ptr, ':');
        size_t seg_len = colon ? (size_t)(colon - path_ptr) : strlen(path_ptr);

        if (seg_len > 0 && seg_len < sizeof(path_seg)) {
            memcpy(path_seg, path_ptr, seg_len);
            path_seg[seg_len] = '\0';

            struct stat st;
            if (stat(path_seg, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (st.st_mode & S_IWOTH) {
                    Finding f;
                    f.id = path_seg;
                    f.title = "World-writable PATH directory";
                    f.severity = Severity::High;
                    f.description = "Executable search path directory is world-writable";
                    f.metadata["rule"] = "path_dir_world_writable";
                    context.report.add_finding("world_writable", std::move(f));
                }
            }
        }

        if (!colon) break;
        path_ptr = colon + 1;
    }
}

// Check if inode entry has both system and suspect paths
static bool has_system_and_suspect_paths(const InodeEntry& entry) {
    const char* suspect_roots[] = {"/tmp", "/var/tmp", "/dev/shm"};
    const size_t suspect_count = sizeof(suspect_roots) / sizeof(suspect_roots[0]);

    bool has_system = false;
    bool has_suspect = false;

    for (size_t j = 0; j < entry.path_count; ++j) {
        const char* path = entry.paths[j];

        if (strncmp(path, "/usr/bin/", 10) == 0 ||
            strncmp(path, "/bin/", 5) == 0 ||
            strncmp(path, "/usr/sbin/", 11) == 0) {
            has_system = true;
        }

        for (size_t k = 0; k < suspect_count; ++k) {
            if (strncmp(path, suspect_roots[k], strlen(suspect_roots[k])) == 0) {
                has_suspect = true;
                break;
            }
        }
    }

    return has_system && has_suspect;
}

// Create finding for dangling SUID hardlink
static void create_dangling_suid_finding(const InodeEntry& entry, ScanContext& context) {
    Finding f;
    f.id = std::string(entry.paths[0]) + ":dangling_suid_link";
    f.title = "Dangling SUID hardlink";
    f.severity = Severity::High;
    f.description = "SUID binary hardlinked into temporary/untrusted location";
    f.metadata["rule"] = "dangling_suid_hardlink";

    std::string all_paths;
    for (size_t j = 0; j < entry.path_count; ++j) {
        if (j > 0) all_paths += ",";
        all_paths += entry.paths[j];
    }
    f.metadata["paths"] = all_paths;

    context.report.add_finding("world_writable", std::move(f));
}

// Detect dangling SUID hardlinks
static void detect_dangling_suid_hardlinks(InodeEntry* inode_entries, size_t inode_count, ScanContext& context) {
    for (size_t i = 0; i < inode_count; ++i) {
        const auto& entry = inode_entries[i];
        if (entry.path_count < 2) continue;

        if (has_system_and_suspect_paths(entry)) {
            create_dangling_suid_finding(entry, context);
        }
    }
}

void WorldWritableScanner::scan(ScanContext& context) {
    // Interpreter list
    const char* interpreters[] = {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby"};
    const size_t interpreter_count = sizeof(interpreters) / sizeof(interpreters[0]);

    // Single batch for all files
    FileBatch* batch = new FileBatch();
    InodeEntry inode_entries[MAX_INODES_LEAN] = {};
    size_t inode_count = 0;
    size_t total_files = 0;
    size_t ww_count = 0;

    // Scan default directories
    scan_default_directories(context, batch, inode_entries, &inode_count,
                           interpreters, interpreter_count, &total_files, &ww_count);

    // Scan additional directories from config
    scan_additional_directories(context, inode_entries, &inode_count,
                              interpreters, interpreter_count, &total_files, &ww_count);

    delete batch;

    if (!context.config.fs_hygiene) return;  // Advanced checks gated

    // Check PATH directories for world-writability
    check_path_directories_world_writable(context);

    // Detect dangling SUID hardlinks
    detect_dangling_suid_hardlinks(inode_entries, inode_count, context);
}

}
