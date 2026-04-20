// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <errno.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    if (!data && len != 0) return -1;

    const char *type_str = NULL;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob"; break;
        case OBJ_TREE:   type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) return -1;

    size_t object_len = (size_t)header_len + 1 + len;
    unsigned char *object = malloc(object_len);
    if (!object) return -1;

    memcpy(object, header, (size_t)header_len + 1);
    if (len > 0) memcpy(object + header_len + 1, data, len);

    ObjectID id;
    compute_hash(object, object_len, &id);
    if (id_out) *id_out = id;

    if (object_exists(&id)) {
        free(object);
        return 0;
    }

    if (mkdir(OBJECTS_DIR, 0755) != 0 && errno != EEXIST) {
        free(object);
        return -1;
    }

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);

    char shard_dir[1024];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    if (mkdir(shard_dir, 0755) != 0 && errno != EEXIST) {
        free(object);
        return -1;
    }

    char final_path[512];
    object_path(&id, final_path, sizeof(final_path));

    char tmp_path[1024];
    const char tmp_suffix[] = "/.tmpXXXXXX";
    size_t shard_len = strlen(shard_dir);
    if (shard_len + sizeof(tmp_suffix) > sizeof(tmp_path)) {
        free(object);
        return -1;
    }
    memcpy(tmp_path, shard_dir, shard_len);
    memcpy(tmp_path + shard_len, tmp_suffix, sizeof(tmp_suffix));

    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(object);
        return -1;
    }

    int rc = -1;
    if (fchmod(fd, 0644) != 0) goto cleanup;

    size_t written = 0;
    while (written < object_len) {
        ssize_t n = write(fd, object + written, object_len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            goto cleanup;
        }
        written += (size_t)n;
    }

    if (fsync(fd) != 0) goto cleanup;
    if (close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    if (rename(tmp_path, final_path) != 0) goto cleanup;

    int dirfd = open(shard_dir, O_RDONLY | O_DIRECTORY);
    if (dirfd >= 0) {
        fsync(dirfd);
        close(dirfd);
    }

    rc = 0;

cleanup:
    if (fd >= 0) {
        close(fd);
        unlink(tmp_path);
    } else if (rc != 0) {
        unlink(tmp_path);
    }
    free(object);
    return rc;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (!id || !type_out || !data_out || !len_out) return -1;

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    long file_size_long = ftell(f);
    if (file_size_long < 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    size_t file_size = (size_t)file_size_long;
    unsigned char *buf = malloc(file_size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t read_len = fread(buf, 1, file_size, f);
    fclose(f);
    if (read_len != file_size) {
        free(buf);
        return -1;
    }

    unsigned char *nul = memchr(buf, '\0', file_size);
    if (!nul) {
        free(buf);
        return -1;
    }

    size_t header_len = (size_t)(nul - buf);
    char *header = malloc(header_len + 1);
    if (!header) {
        free(buf);
        return -1;
    }
    memcpy(header, buf, header_len);
    header[header_len] = '\0';

    char *space = strchr(header, ' ');
    if (!space) {
        free(header);
        free(buf);
        return -1;
    }
    *space = '\0';
    const char *size_str = space + 1;

    ObjectType parsed_type;
    if (strcmp(header, "blob") == 0) {
        parsed_type = OBJ_BLOB;
    } else if (strcmp(header, "tree") == 0) {
        parsed_type = OBJ_TREE;
    } else if (strcmp(header, "commit") == 0) {
        parsed_type = OBJ_COMMIT;
    } else {
        free(header);
        free(buf);
        return -1;
    }

    char *endptr = NULL;
    unsigned long declared_size_ul = strtoul(size_str, &endptr, 10);
    if (endptr == size_str || *endptr != '\0') {
        free(header);
        free(buf);
        return -1;
    }

    size_t declared_size = (size_t)declared_size_ul;
    size_t data_len = file_size - header_len - 1;
    if (declared_size != data_len) {
        free(header);
        free(buf);
        return -1;
    }

    ObjectID computed;
    compute_hash(buf, file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(header);
        free(buf);
        return -1;
    }

    void *data = malloc(data_len);
    if (!data && data_len != 0) {
        free(header);
        free(buf);
        return -1;
    }
    if (data_len > 0) memcpy(data, nul + 1, data_len);

    *type_out = parsed_type;
    *data_out = data;
    *len_out = data_len;

    free(header);
    free(buf);
    return 0;
}
