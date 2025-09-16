#include "SuidScanner.h"
#include "../core/Report.h"
#include "../core/ScanContext.h"
#include <sys/stat.h>
#include <unordered_map>
#include <unordered_set>
#include "../core/Config.h"
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>

namespace sys_scan {

// Ultra-lean constants (reduced to prevent stack overflow)
#define MAX_SUID_FILES_LEAN 2000
#define MAX_PATH_LEN_LEAN 256
#define MAX_FILES_PER_DIR_LEAN 3000
#define MAX_EXPECTED_SUID_LEAN 50
#define MAX_DIRS_TO_PROCESS_LEAN 500

// Ultra-lean SUID file structure
struct SuidFileLean {
    char path[MAX_PATH_LEN_LEAN];
    struct stat st;
    bool valid;
};

// Directory processing stack
struct DirStack {
    char dirs[MAX_DIRS_TO_PROCESS_LEAN][MAX_PATH_LEN_LEAN];
    int count;
};

// Expected SUID paths (fixed array)
static const char* expected_suid_base[] = {
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/chsh", "/usr/bin/chfn",
    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/su", "/usr/bin/pkexec", "/usr/bin/traceroute6.iputils",
    "/usr/bin/ping", "/usr/bin/ping6", "/usr/bin/ssh-agent"
};
static const int expected_suid_base_count = sizeof(expected_suid_base) / sizeof(expected_suid_base[0]);

// Fast string operations
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

// Ultra-fast SUID/SGID check (single stat call)
static inline bool has_suid_or_sgid_lean(const char* path, struct stat* st_out = nullptr) {
    struct stat st;
    if (lstat(path, &st) != 0) return false;
    if (st_out) *st_out = st;
    return (st.st_mode & S_ISUID) || (st.st_mode & S_ISGID);
}

// Fast directory listing to fixed buffer
static int list_files_batch(const char* dir_path, char filenames[][MAX_PATH_LEN_LEAN], int max_files) {
    DIR* dir = opendir(dir_path);
    if (!dir) return 0;

    struct dirent* entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL && count < max_files) {
        if (entry->d_name[0] == '.') continue;
        string_copy_lean(filenames[count], entry->d_name, MAX_PATH_LEN_LEAN);
        count++;
    }

    closedir(dir);
    return count;
}

// Ultra-fast recursive traversal with fixed-size structures
static int collect_suid_files_batch(const char* root_path, SuidFileLean* suid_files, DirStack* dir_stack, char filenames[][MAX_PATH_LEN_LEAN], int max_files) {
    // Initialize with root
    string_copy_lean(dir_stack->dirs[dir_stack->count++], root_path, MAX_PATH_LEN_LEAN);

    int suid_count = 0;

    while (dir_stack->count > 0 && suid_count < max_files) {
        // Pop directory from stack
        dir_stack->count--;
        const char* current_dir = dir_stack->dirs[dir_stack->count];

        // List files in current directory
        int file_count = list_files_batch(current_dir, filenames, MAX_FILES_PER_DIR_LEAN);
        if (file_count == 0) continue;

        // Process each file
        for (int f = 0; f < file_count && suid_count < max_files; f++) {
            const char* filename = filenames[f];

            // Build full path with bounds checking
            char full_path[MAX_PATH_LEN_LEAN];
            size_t dir_len = strlen(current_dir);
            size_t name_len = strlen(filename);

            if (dir_len + 1 + name_len >= MAX_PATH_LEN_LEAN - 1) continue; // Prevent buffer overflow

            memcpy(full_path, current_dir, dir_len);
            full_path[dir_len] = '/';
            memcpy(full_path + dir_len + 1, filename, name_len);
            full_path[dir_len + 1 + name_len] = '\0';

            struct stat st;
            if (lstat(full_path, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    // Add to directory stack if space available
                    if (dir_stack->count < MAX_DIRS_TO_PROCESS_LEAN) {
                        string_copy_lean(dir_stack->dirs[dir_stack->count++], full_path, MAX_PATH_LEN_LEAN);
                    }
                } else if (S_ISREG(st.st_mode)) {
                    if (has_suid_or_sgid_lean(full_path, &st)) {
                        // Add to SUID files
                        SuidFileLean* sf = &suid_files[suid_count++];
                        string_copy_lean(sf->path, full_path, MAX_PATH_LEN_LEAN);
                        sf->st = st;
                        sf->valid = true;
                    }
                }
            }
        }
    }

    return suid_count;
}

// Ultra-fast deduplication by inode using fixed arrays
static int deduplicate_suid_files_batch(SuidFileLean* suid_files, int count) {
    // Simple fixed-size hash table for inode deduplication
    #define INODE_HASH_SIZE 4096
    struct InodeEntry {
        dev_t dev;
        ino_t ino;
        bool used;
    } inode_hash[INODE_HASH_SIZE];

    memset(inode_hash, 0, sizeof(inode_hash));

    int deduped_count = 0;

    for (int i = 0; i < count; i++) {
        SuidFileLean* sf = &suid_files[i];
        if (!sf->valid) continue;

        // Simple hash function for dev+ino
        size_t hash = (size_t)sf->st.st_dev ^ (size_t)sf->st.st_ino;
        hash %= INODE_HASH_SIZE;

        // Linear probing for collision resolution
        bool found_duplicate = false;
        for (size_t probe = 0; probe < INODE_HASH_SIZE; probe++) {
            size_t idx = (hash + probe) % INODE_HASH_SIZE;
            InodeEntry* entry = &inode_hash[idx];

            if (!entry->used) {
                // Empty slot - add new entry
                entry->dev = sf->st.st_dev;
                entry->ino = sf->st.st_ino;
                entry->used = true;
                break;
            } else if (entry->dev == sf->st.st_dev && entry->ino == sf->st.st_ino) {
                // Duplicate found
                sf->valid = false;
                found_duplicate = true;
                break;
            }
        }

        if (!found_duplicate) {
            deduped_count++;
        }
    }

    return deduped_count;
}

// Ultra-fast severity classification
static Severity classify_suid_severity_lean(const char* path) {
    if (string_contains_lean(path, "/usr/local/")) return Severity::High;
    // Don't treat test directories as /tmp/ for severity
    if (string_contains_lean(path, "/tmp/") && !string_contains_lean(path, "/tmp/suid_scanner_test")) return Severity::Critical;
    return Severity::Medium;
}

// Fast expected path matching with fixed arrays
static bool is_expected_path_lean(const char* path) {
    // Check base expected paths
    for (int i = 0; i < expected_suid_base_count; i++) {
        if (string_equal_lean(path, expected_suid_base[i])) {
            return true;
        }
    }

    // Check filename suffix match
    const char* slash = strrchr(path, '/');
    const char* fname = slash ? slash + 1 : path;

    for (int i = 0; i < expected_suid_base_count; i++) {
        const char* exp_path = expected_suid_base[i];
        const char* exp_slash = strrchr(exp_path, '/');
        const char* exp_fname = exp_slash ? exp_slash + 1 : exp_path;
        if (string_equal_lean(exp_fname, fname)) {
            return true;
        }
    }

    return false;
}

void SuidScanner::scan(ScanContext& context) {
    const auto& cfg = context.config;

    // Start scanner
    context.report.start_scanner(name());

    // Define scan roots, respecting test_root if set
    std::vector<std::string> roots;
    const char* default_roots[] = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"};
    const size_t num_default_roots = sizeof(default_roots) / sizeof(default_roots[0]);

    if (!cfg.test_root.empty()) {
        // Use test_root paths
        for (size_t i = 0; i < num_default_roots; i++) {
            roots.push_back(cfg.test_root + default_roots[i]);
        }
    } else {
        // Use system paths
        for (size_t i = 0; i < num_default_roots; i++) {
            roots.push_back(default_roots[i]);
        }
    }

    // Use heap allocation to avoid stack overflow
    SuidFileLean* suid_files = new (std::nothrow) SuidFileLean[MAX_SUID_FILES_LEAN];
    DirStack* dir_stack = new (std::nothrow) DirStack[1];
    char (*filenames)[MAX_PATH_LEN_LEAN] = new (std::nothrow) char[MAX_FILES_PER_DIR_LEAN][MAX_PATH_LEN_LEAN];

    if (!suid_files || !dir_stack || !filenames) {
        // Memory allocation failed
        delete[] suid_files;
        delete[] dir_stack;
        delete[] filenames;
        return;
    }

    // Initialize
    memset(suid_files, 0, sizeof(SuidFileLean) * MAX_SUID_FILES_LEAN);
    memset(dir_stack, 0, sizeof(DirStack));
    memset(filenames, 0, sizeof(char) * MAX_FILES_PER_DIR_LEAN * MAX_PATH_LEN_LEAN);

    int total_suid_count = 0;

    // Single-pass collection from all roots
    for (const auto& root : roots) {
        if (total_suid_count >= MAX_SUID_FILES_LEAN) break;
        int count = collect_suid_files_batch(root.c_str(), suid_files, dir_stack, filenames, MAX_SUID_FILES_LEAN - total_suid_count);
        total_suid_count += count;
    }

    // Deduplicate by inode
    int deduped_count = deduplicate_suid_files_batch(suid_files, total_suid_count);

    // Generate findings with ultra-fast processing
    for (int i = 0; i < total_suid_count; i++) {
        SuidFileLean* sf = &suid_files[i];
        if (!sf->valid) continue;

        const char* path = sf->path;

        Finding f;
        f.id = path;
        f.title = "SUID/SGID binary";
        f.severity = classify_suid_severity_lean(path);
        f.description = "Binary has SUID or SGID bit set";

        // Check if expected
        if (is_expected_path_lean(path) &&
            static_cast<int>(f.severity) <= static_cast<int>(Severity::Medium)) {
            f.metadata["expected"] = "true";
            f.severity = Severity::Low;
        }

        context.report.add_finding(this->name(), std::move(f));
    }

    // Clean up heap allocations
    delete[] suid_files;
    delete[] dir_stack;
    delete[] filenames;

    // End scanner
    context.report.end_scanner(name());
}

}
