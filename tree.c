// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

// Forward declaration (implemented in object.c)
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

typedef struct {
    uint32_t mode;
    ObjectID hash;
    char path[512];
} TreeIndexEntry;

// Recursive builder for one tree level rooted at prefix ("" for root).
static int write_tree_level(const TreeIndexEntry *entries, int entry_count,
                            const char *prefix, ObjectID *tree_id_out) {
    Tree tree;
    tree.count = 0;

    char subdirs[MAX_TREE_ENTRIES][256];
    int subdir_count = 0;
    size_t prefix_len = strlen(prefix);

    for (int i = 0; i < entry_count; i++) {
        const TreeIndexEntry *ie = &entries[i];
        if (strncmp(ie->path, prefix, prefix_len) != 0) continue;

        const char *rest = ie->path + prefix_len;
        if (*rest == '\0') continue;

        const char *slash = strchr(rest, '/');
        if (!slash) {
            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            if (strlen(rest) >= sizeof(tree.entries[tree.count].name)) return -1;

            tree.entries[tree.count].mode = ie->mode;
            tree.entries[tree.count].hash = ie->hash;
            snprintf(tree.entries[tree.count].name,
                     sizeof(tree.entries[tree.count].name), "%s", rest);
            tree.count++;
        } else {
            size_t dlen = (size_t)(slash - rest);
            if (dlen == 0 || dlen >= sizeof(subdirs[0])) return -1;

            int exists = 0;
            for (int j = 0; j < subdir_count; j++) {
                if (strncmp(subdirs[j], rest, dlen) == 0 && subdirs[j][dlen] == '\0') {
                    exists = 1;
                    break;
                }
            }
            if (!exists) {
                if (subdir_count >= MAX_TREE_ENTRIES) return -1;
                memcpy(subdirs[subdir_count], rest, dlen);
                subdirs[subdir_count][dlen] = '\0';
                subdir_count++;
            }
        }
    }

    for (int i = 0; i < subdir_count; i++) {
        if (tree.count >= MAX_TREE_ENTRIES) return -1;

        char child_prefix[1024];
        int n = snprintf(child_prefix, sizeof(child_prefix), "%s%s/", prefix, subdirs[i]);
        if (n < 0 || (size_t)n >= sizeof(child_prefix)) return -1;

        ObjectID child_id;
        if (write_tree_level(entries, entry_count, child_prefix, &child_id) != 0) return -1;

        tree.entries[tree.count].mode = MODE_DIR;
        tree.entries[tree.count].hash = child_id;
        size_t subdir_name_len = strlen(subdirs[i]);
        if (subdir_name_len >= sizeof(tree.entries[tree.count].name)) return -1;
        memcpy(tree.entries[tree.count].name, subdirs[i], subdir_name_len + 1);
        tree.count++;
    }

    // Empty trees are valid objects: raw tree payload length is 0.
    if (tree.count == 0) {
        return object_write(OBJ_TREE, "", 0, tree_id_out);
    }

    void *raw = NULL;
    size_t raw_len = 0;
    if (tree_serialize(&tree, &raw, &raw_len) != 0) return -1;

    int rc = object_write(OBJ_TREE, raw, raw_len, tree_id_out);
    free(raw);
    return rc;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
int tree_from_index(ObjectID *id_out) {
    if (!id_out) return -1;

    TreeIndexEntry entries[MAX_INDEX_ENTRIES];
    int entry_count = 0;

    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) {
        if (errno != ENOENT) return -1;
        // No index yet: write and return an empty root tree.
        return object_write(OBJ_TREE, "", 0, id_out);
    }

    char line[2048];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (entry_count >= MAX_INDEX_ENTRIES) {
            fclose(f);
            return -1;
        }

        unsigned int mode;
        char hash_hex[HASH_HEX_SIZE + 1];
        unsigned long long mtime_ignored;
        unsigned int size_ignored;
        char path[512];

        int parsed = sscanf(line, "%o %64s %llu %u %511[^\n]",
                            &mode, hash_hex, &mtime_ignored, &size_ignored, path);
        if (parsed != 5) {
            fclose(f);
            return -1;
        }

        entries[entry_count].mode = mode;
        if (hex_to_hash(hash_hex, &entries[entry_count].hash) != 0) {
            fclose(f);
            return -1;
        }
        snprintf(entries[entry_count].path, sizeof(entries[entry_count].path), "%s", path);
        entry_count++;
    }
    fclose(f);

    return write_tree_level(entries, entry_count, "", id_out);
}