///////////////////////////////////////////////////////////////////////
// COMP1521 25T2 --- Assignment 2: `titanic', a simple file synchroniser
// <https://cgi.cse.unsw.edu.au/~cs1521/25T2/assignments/ass2/index.html>
//
// Written by Danny Sun (z5691331) on 21/07/2025.
//
// A file synchronisation tool that creates and applies index files to
// efficiently update files between a sender and receiver.
//
// 2025-07-20   v1.0    Team COMP1521 <cs1521 at cse.unsw.edu.au>


#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "titanic.h"

// Additional elements
#define READ_WRITE_PERMISSIONS 0666
#define ALL_PERMISSIONS 0777

mode_t parse_mode(uint8_t *mode);


/// @brief Create a TABI file from an array of pathnames.
/// @param out_pathname A path to where the new TABI file should be created.
/// @param in_pathnames An array of strings containing, in order, the files
//                      that should be placed in the new TABI file.
/// @param num_in_pathnames The length of the `in_pathnames` array. In
///                         subset 5, when this is zero, you should include
///                         everything in the current directory.

void stage_1(char *out_pathname, char *in_pathnames[], size_t num_in_pathnames) {

    FILE *file = fopen(out_pathname, "wb");

    // Write the magic number for TABI file
    fputc(TYPE_A_MAGIC[0], file);
    fputc(TYPE_A_MAGIC[1], file);
    fputc(TYPE_A_MAGIC[2], file);
    fputc(TYPE_A_MAGIC[3], file);

    fputc(num_in_pathnames, file);

    // Process each pathname
    for (size_t i = 0; i < num_in_pathnames; i++) {
        struct stat info;
        if (stat(in_pathnames[i], &info) != 0) {
            perror("Failed to retrieve information");
            exit(1);
        }

        // Read and write pathname length
        size_t len = strlen(in_pathnames[i]);
        fputc(len & 0xFF, file);
        fputc((len >> MATCH_BYTE_BITS) & 0xFF, file);
        fwrite(in_pathnames[i], 1, len, file);

        // Read and write number of blocks in the file
        size_t num_blocks = number_of_blocks_in_file(info.st_size);
        fputc(num_blocks & 0xFF, file);
        fputc((num_blocks) >> MATCH_BYTE_BITS & 0xFF, file);
        fputc((num_blocks) >> (MATCH_BYTE_BITS * 2) & 0xFF, file);

        // Open the input file for reading
        FILE *input_file = fopen(in_pathnames[i], "rb");
        if (input_file == NULL) {
            perror("Failed to open file");
            exit(1);
        }

        unsigned char buffer[BLOCK_SIZE];

        // Process each block in the file
        for (size_t j = 0; j < num_blocks; j++) {
            size_t bytes_read = fread(buffer, 1, BLOCK_SIZE, input_file);

            // Check for read error
            if (bytes_read == 0 && ferror(input_file)) {
                perror("Failed to read bytes");
                exit(1);
            }

            // Write hash as 8-byte little-endian integer
            uint64_t hash = hash_block((char *)buffer, bytes_read);
            for (int k = 0; k < HASH_SIZE ; k++) {
                fputc(hash >> (k * MATCH_BYTE_BITS) & 0xFF, file);
            }
        }

        fclose(input_file);
    }

    fclose(file);
}


/// @brief Create a TBBI file from a TABI file.
/// @param out_pathname A path to where the new TBBI file should be created.
/// @param in_pathname A path to where the existing TABI file is located.

void stage_2(char *out_pathname, char *in_pathname) {

    FILE *read_file = fopen(in_pathname, "rb");
    FILE *write_file = fopen(out_pathname, "wb");

    // Check if either file failed to open
    if (read_file == NULL || write_file == NULL) {
        perror("Failed to open file(s)");
        exit(1);
    }

    // Validate the magic number from the TABI file
    uint8_t magic[MAGIC_SIZE];
    if (fread(magic, 1, MAGIC_SIZE, read_file) != MAGIC_SIZE ||
        magic[0] != TYPE_A_MAGIC[0] || magic[1] != TYPE_A_MAGIC[1] ||
        magic[2] != TYPE_A_MAGIC[2] || magic[3] != TYPE_A_MAGIC[3]) {
        perror("Bad magic");
        exit(1);
    }

    fputc(TYPE_B_MAGIC[0], write_file);
    fputc(TYPE_B_MAGIC[1], write_file);
    fputc(TYPE_B_MAGIC[2], write_file);
    fputc(TYPE_B_MAGIC[3], write_file);

    // Read the number of records
    int c = fgetc(read_file);
    if (c == EOF) {
        perror("Failed to read number of records");
        exit(1);
    }
    uint8_t num_records = (uint8_t)c;
    if (num_records == 0) {
        perror("Invalid records");
        exit(1);
    }
    fputc(num_records, write_file);

    size_t records_processed = 0;

    // Process each record in the TABI file
    for (size_t j = 0; j < num_records; j++) {
        struct stat info;
        uint16_t pathname_length;
        char *pathname;
        uint32_t num_blocks;

        // Read 2-byte pathname length (little-endian)
        uint8_t len_bytes[PATHNAME_LEN_SIZE];
        if (fread(len_bytes, 1, PATHNAME_LEN_SIZE, read_file)
            != PATHNAME_LEN_SIZE) {
            perror("Failed to read pathname length");
            exit(1);
        }
        pathname_length = len_bytes[0] | (len_bytes[1] << MATCH_BYTE_BITS);
        fwrite(len_bytes, 1, PATHNAME_LEN_SIZE, write_file);

        // Read pathname
        pathname = malloc(pathname_length + 1);
        if (pathname == NULL) {
            perror("malloc failed");
            exit(1);
        }
        if (fread(pathname, 1, pathname_length, read_file)
            != pathname_length) {
            perror("Failed to read pathname");
            exit(1);
        }
        fwrite(pathname, 1, pathname_length, write_file);
        pathname[pathname_length] = '\0';

        // Read 3-byte number of blocks (little-endian)
        uint8_t block_bytes[NUM_BLOCKS_SIZE];
        if (fread(block_bytes, 1, NUM_BLOCKS_SIZE, read_file)
            != NUM_BLOCKS_SIZE) {
            perror("Failed to read number of blocks");
            exit(1);
        }
        num_blocks = block_bytes[0] | (block_bytes[1] << MATCH_BYTE_BITS) |
            (block_bytes[2] << (MATCH_BYTE_BITS * 2));
        fwrite(block_bytes, 1, NUM_BLOCKS_SIZE, write_file);

        // Calculate how many bytes are needed to store 1 bit per block
        size_t match_bytes = num_tbbi_match_bytes(num_blocks);
        uint8_t *matches = calloc(match_bytes, 1); // All bits start at 0
        if (matches == NULL) {
            perror("calloc failed");
            exit(1);
        }

        // Try to open receiver's version of the file
        int has_file;
        if (stat(pathname, &info) == 0) {
            has_file = 1;
        } else {
            has_file = 0;
        }
        FILE *recv_file;
        if (has_file) {
            recv_file = fopen(pathname, "rb");
        } else {
            recv_file = NULL;
        }

        // Loop through all blocks
        for (uint32_t k = 0; k < num_blocks; k++) {
            // Read 8-byte hash from TABI
            uint8_t hash_bytes[HASH_SIZE];
            if (fread(hash_bytes, 1, HASH_SIZE, read_file) != HASH_SIZE) {
                perror("Failed to read TABI hash");
                exit(1);
            }

            if (recv_file) {
                unsigned char buf[BLOCK_SIZE];
                size_t bytes_read = fread(buf, 1, BLOCK_SIZE, recv_file);

                if (bytes_read == 0 && ferror(recv_file)) {
                    perror("Failed to read receiver block");
                    exit(1);
                }

                // Convert TABI hash bytes to uint64_t
                uint64_t tabi_hash = 0;
                for (int b = 0; b < HASH_SIZE; b++) {
                    tabi_hash |=
                        ((uint64_t)hash_bytes[b]) << (b * MATCH_BYTE_BITS);
                }

                uint64_t local_hash = hash_block((char *)buf, bytes_read);

                if (tabi_hash == local_hash) {
                    matches[k / MATCH_BYTE_BITS] |= (
                        1 << (MATCH_BYTE_BITS - 1 - (k % MATCH_BYTE_BITS)));
                }
            }
        }

        // Write matches bitfield to output
        fwrite(matches, 1, match_bytes, write_file);

        records_processed++;
        free(matches);
        free(pathname);
        if (recv_file) {
            fclose(recv_file);
        }
    }

    // Verify all expected records were processed
    if (records_processed < num_records) {
        perror("Insufficient number of records in TABI file");
        exit(1);
    }

    // Check for extra data by attempting to read one more byte
    int extra_byte = fgetc(read_file);
    if (extra_byte != EOF) {
        perror("Extra data in TABI file");
        exit(1);
    }

    fclose(read_file);
    fclose(write_file);
}


/// @brief Create a TCBI file from a TBBI file.
/// @param out_pathname A path to where the new TCBI file should be created.
/// @param in_pathname A path to where the existing TBBI file is located.

void stage_3(char *out_pathname, char *in_pathname) {

    // Open the TBBI input file and TCBI output file
    FILE *read_file = fopen(in_pathname, "rb");
    FILE *write_file = fopen(out_pathname, "wb");

    if (read_file == NULL || write_file == NULL) {
        perror("Failed to open file(s)");
        exit(1);
    }

    // Validate the magic number from the TBBI file
    uint8_t magic[MAGIC_SIZE];
    if (fread(magic, 1, MAGIC_SIZE, read_file) != MAGIC_SIZE ||
        magic[0] != TYPE_B_MAGIC[0] || magic[1] != TYPE_B_MAGIC[1] ||
        magic[2] != TYPE_B_MAGIC[2] || magic[3] != TYPE_B_MAGIC[3]) {
        perror("Bad magic");
        exit(1);
    }

    // Write the magic number for the TCBI file
    fputc(TYPE_C_MAGIC[0], write_file);
    fputc(TYPE_C_MAGIC[1], write_file);
    fputc(TYPE_C_MAGIC[2], write_file);
    fputc(TYPE_C_MAGIC[3], write_file);

    int c = fgetc(read_file);
    if (c == EOF) {
        perror("Failed to read number of records");
        exit(1);
    }
    uint8_t num_records = (uint8_t)c;
    if (num_records == 0) {
        perror("Invalid records");
        exit(1);
    }
    fputc(num_records, write_file);

    // Process each record in the TBBI file
    for (uint8_t j = 0; j < num_records; j++) {
        struct stat info;

        uint16_t pathname_length;
        char *pathname;
        uint32_t file_size;

        // Read 2-byte pathname length (little-endian)
        uint8_t len_bytes[PATHNAME_LEN_SIZE];
        if (fread(len_bytes, 1, PATHNAME_LEN_SIZE, read_file)
            != PATHNAME_LEN_SIZE) {
            perror("Failed to read pathname length");
            exit(1);
        }
        pathname_length = len_bytes[0] | (len_bytes[1] << MATCH_BYTE_BITS);
        fwrite(len_bytes, 1, PATHNAME_LEN_SIZE, write_file);

        // Read pathname
        pathname = malloc(pathname_length + 1);
        if (pathname == NULL) {
            perror("malloc failed");
            exit(1);
        }
        if (fread(pathname, 1, pathname_length, read_file)
            != pathname_length) {
            perror("Failed to read pathname");
            exit(1);
        }
        fwrite(pathname, 1, pathname_length, write_file);
        pathname[pathname_length] = '\0';

        // Write mode
        if (stat(pathname, &info) == -1) {
            perror("Failed to retrieve mode");
            exit(1);
        } else {
            uint8_t mode[MODE_SIZE];
            if (S_ISREG(info.st_mode)) {
                mode[0] = '-';
            } else {
                if (S_ISDIR(info.st_mode)) {
                    mode[0] = 'd';
                } else {
                    mode[0] = '?';
                }
            }
            if (info.st_mode & S_IRUSR) {
                mode[1] = 'r';
            } else {
                mode[1] = '-';
            }
            if (info.st_mode & S_IWUSR) {
                mode[2] = 'w';
            } else {
                mode[2] = '-';
            }
            if (info.st_mode & S_IXUSR) {
                mode[3] = 'x';
            } else {
                mode[3] = '-';
            }
            if (info.st_mode & S_IRGRP) {
                mode[4] = 'r';
            } else {
                mode[4] = '-';
            }
            if (info.st_mode & S_IWGRP) {
                mode[5] = 'w';
            } else {
                mode[5] = '-';
            }
            if (info.st_mode & S_IXGRP) {
                mode[6] = 'x';
            } else {
                mode[6] = '-';
            }
            if (info.st_mode & S_IROTH) {
                mode[7] = 'r';
            } else {
                mode[7] = '-';
            }
            if (info.st_mode & S_IWOTH) {
                mode[8] = 'w';
            } else {
                mode[8] = '-';
            }
            if (info.st_mode & S_IXOTH) {
                mode[9] = 'x';
            } else {
                mode[9] = '-';
            }
            fwrite(mode, 1, MODE_SIZE, write_file);
        }

        // Write file size
        file_size = (uint32_t)info.st_size;
        fwrite(&file_size, 1, FILE_SIZE_SIZE, write_file);

        // Number of updates
        uint8_t num_blocks_bytes[NUM_BLOCKS_SIZE];
        if (fread(num_blocks_bytes, 1, NUM_BLOCKS_SIZE, read_file)
            != NUM_BLOCKS_SIZE) {
            perror("Failed to read number of blocks");
            exit(1);
        }
        uint32_t num_blocks = num_blocks_bytes[0] |
            (num_blocks_bytes[1] << MATCH_BYTE_BITS) |
            (num_blocks_bytes[2] << (MATCH_BYTE_BITS * 2));
        size_t expected_blocks = number_of_blocks_in_file(file_size);
        if (num_blocks != expected_blocks && file_size > 0) {
            perror("Inconsistent number of blocks");
            exit(1);
        }

        size_t matches_size = num_tbbi_match_bytes(num_blocks);
        uint8_t *matches = NULL;
        if (matches_size > 0) {
            matches = malloc(matches_size);
            if (matches == NULL) {
                perror("malloc failed for matches");
                exit(1);
            }
            if (fread(matches, 1, matches_size, read_file) != matches_size) {
                perror("Failed to read matches");
                free(matches);
                exit(1);
            }

            // Validate padding in last byte (right-padded with 0s)
            if (num_blocks % MATCH_BYTE_BITS != 0) {
                uint8_t last_byte = matches[matches_size - 1];
                int padding_bits = MATCH_BYTE_BITS -
                    (num_blocks % MATCH_BYTE_BITS);
                uint8_t mask = (1 << padding_bits) - 1;
                if ((last_byte & mask) != 0) {
                    perror("Invalid padding in matches field");
                    free(matches);
                    exit(1);
                }
            }
        }

        // Count non-padding 0 bits for number of updates
        uint32_t num_updates = 0;
        for (size_t i = 0; i < matches_size; i++) {
            uint8_t byte = matches[i];
            int bits_to_check;

            if (i == matches_size - 1) {
                if (num_blocks % MATCH_BYTE_BITS) {
                    bits_to_check = num_blocks % MATCH_BYTE_BITS;
                } else {
                    bits_to_check = MATCH_BYTE_BITS;
                }
            } else {
                bits_to_check = MATCH_BYTE_BITS;
            }

            for (int bit_pos = 0; bit_pos < bits_to_check; bit_pos++) {
                int bit = MATCH_BYTE_BITS - 1 - bit_pos;
                if (!(byte & (1 << bit))) {
                    num_updates++;
                }
            }
        }

        // Write number of updates (3 bytes, little-endian)
        uint8_t updates_bytes[NUM_BLOCKS_SIZE];
        updates_bytes[0] = num_updates & 0xFF;
        updates_bytes[1] = (num_updates >> MATCH_BYTE_BITS) & 0xFF;
        updates_bytes[2] = (num_updates >> (MATCH_BYTE_BITS * 2)) & 0xFF;
        fwrite(updates_bytes, 1, NUM_BLOCKS_SIZE, write_file);

        // Write updates section (unchanged, but uses matches safely)
        FILE *sender_file = fopen(pathname, "rb");
        if (sender_file == NULL) {
            perror("Failed to open sender file");
            if (matches) free(matches);
            exit(1);
        }

        // Read entire sender file into memory
        uint8_t *sender_data = malloc(file_size);

        fread(sender_data, 1, file_size, sender_file);
        fclose(sender_file);

        // Determine block indices needing updates
        for (size_t i = 0; i < matches_size; i++) {
            uint8_t byte = matches[i];
            int bits_to_check;

            if (i == matches_size - 1) {
                if (num_blocks % MATCH_BYTE_BITS) {
                    bits_to_check = num_blocks % MATCH_BYTE_BITS;
                } else {
                    bits_to_check = MATCH_BYTE_BITS;
                }
            } else {
                bits_to_check = MATCH_BYTE_BITS;
            }

            for (int bit_pos = 0; bit_pos < bits_to_check; bit_pos++) {
                int bit = MATCH_BYTE_BITS - 1 - bit_pos;
                if (!(byte & (1 << bit))) {
                    uint32_t block_idx = (i * MATCH_BYTE_BITS) + bit_pos;

                    // Calculate start and length of the block
                    size_t start_byte = block_idx * BLOCK_SIZE;
                    size_t update_length;
                    if (block_idx == num_blocks - 1) {
                        update_length = (file_size - start_byte);
                    } else {
                        update_length = BLOCK_SIZE;
                    }
                    if (update_length > BLOCK_SIZE) {
                        update_length = BLOCK_SIZE;
                    }

                    // Write block index (3 bytes, little-endian)
                    uint8_t idx_bytes[BLOCK_INDEX_SIZE];
                    idx_bytes[0] = block_idx & 0xFF;
                    idx_bytes[1] = (block_idx >> MATCH_BYTE_BITS) & 0xFF;
                    idx_bytes[2] = (block_idx >> (MATCH_BYTE_BITS * 2)) & 0xFF;

                    if (fwrite(idx_bytes, 1, BLOCK_INDEX_SIZE, write_file)
                        != BLOCK_INDEX_SIZE) {
                        perror("Failed to write block index");
                        free(sender_data);
                        if (matches) free(matches);
                        exit(1);
                    }

                    // Write update length (2 bytes, little-endian)
                    uint8_t update_len_bytes[UPDATE_LEN_SIZE];
                    update_len_bytes[0] = update_length & 0xFF;
                    update_len_bytes[1] =
                        (update_length >> MATCH_BYTE_BITS) & 0xFF;
                    fwrite(update_len_bytes, 1, UPDATE_LEN_SIZE, write_file);

                    // Write update data
                    fwrite(sender_data + start_byte, 1, update_length, write_file);
                }
            }
        }

        free(sender_data);
        if (matches) {
            free(matches);
        }
        free(pathname);
    }

    // Process each record in the TBBI file
    int extra_byte = fgetc(read_file);
    if (extra_byte != EOF) {
        perror("Extra data in TBBI File");
        exit(1);
    }

    fclose(read_file);
    fclose(write_file);
}


/// @brief Apply a TCBI file to the filesystem.
/// @param in_pathname A path to where the existing TCBI file is located.

void stage_4(char *in_pathname) {

    // Open and validate the TCBI input file
    FILE *read_file = fopen(in_pathname, "rb");
    if (read_file == NULL) {
        perror("Failed to open TCBI file");
        exit(1);
    }

    // Validate the magic number from the TCBI file
    uint8_t magic[MAGIC_SIZE];
    if (fread(magic, 1, MAGIC_SIZE, read_file) != MAGIC_SIZE ||
        magic[0] != TYPE_C_MAGIC[0] || magic[1] != TYPE_C_MAGIC[1] ||
        magic[2] != TYPE_C_MAGIC[2] || magic[3] != TYPE_C_MAGIC[3]) {
        perror("Bad magic");
        fclose(read_file);
        exit(1);
    }

    // Read the number of records from the TCBI file
    int c = fgetc(read_file);
    if (c == EOF) {
        perror("Failed to read number of records");
        fclose(read_file);
        exit(1);
    }
    uint8_t num_records = (uint8_t)c;
    if (num_records == 0) {
        perror("Invalid records");
        fclose(read_file);
        exit(1);
    }

    // Process each record in the TCBI file
    for (uint8_t j = 0; j < num_records; j++) {
        uint8_t len_bytes[PATHNAME_LEN_SIZE];
        fread(len_bytes, 1, PATHNAME_LEN_SIZE, read_file);

        uint16_t pathname_length = len_bytes[0] |
            (len_bytes[1] << MATCH_BYTE_BITS);
        char *pathname = malloc(pathname_length + 1);

        // Read and validate pathname
        if (fread(pathname, 1, pathname_length, read_file) != pathname_length) {
            perror("Failed to read pathname");
            free(pathname);
            fclose(read_file);
            exit(1);
        }
        pathname[pathname_length] = '\0';

        uint8_t mode[MODE_SIZE];
        fread(mode, 1, MODE_SIZE, read_file);

        // Read file size from 4-byte little-endian value
        uint8_t size_bytes[FILE_SIZE_SIZE];
        fread(size_bytes, 1, FILE_SIZE_SIZE, read_file);

        uint32_t file_size = size_bytes[0] | (size_bytes[1] << MATCH_BYTE_BITS) |
            (size_bytes[2] << (MATCH_BYTE_BITS * 2)) |
            (size_bytes[3] << (MATCH_BYTE_BITS * 3));

        uint8_t updates_bytes[NUM_BLOCKS_SIZE];
        fread(updates_bytes, 1, NUM_BLOCKS_SIZE, read_file);

        // Read number of updates from 3-byte little-endian value
        uint32_t num_updates = updates_bytes[0] |
            (updates_bytes[1] << MATCH_BYTE_BITS) |
            (updates_bytes[2] << (MATCH_BYTE_BITS * 2));

        // Parse permissions from mode field
        mode_t permissions = parse_mode(mode);
        struct stat existing_stat;
        int file_exists = (stat(pathname, &existing_stat) == 0);
        int needs_update = (num_updates > 0) || !file_exists ||
            existing_stat.st_size != file_size;

        FILE *out_file = NULL;
        if (needs_update) {
            int file_descriptor =
                open(pathname, O_CREAT | O_WRONLY, READ_WRITE_PERMISSIONS);
            if (file_descriptor < 0) {
                perror("Failed to create output file");
                free(pathname);
                fclose(read_file);
                exit(1);
            }

            ftruncate(file_descriptor, file_size);
            close(file_descriptor);

            out_file = fopen(pathname, "r + b");
            if (out_file == NULL) {
                perror("Failed to open output file for writing");
                free(pathname);
                fclose(read_file);
                exit(1);
            }
        }

        // Apply file permissions
        chmod(pathname, permissions);

        // Apply updates to the file
        for (uint32_t k = 0; k < num_updates; k++) {
            uint8_t idx_bytes[BLOCK_INDEX_SIZE];
            fread(idx_bytes, 1, BLOCK_INDEX_SIZE, read_file);

            uint32_t block_idx = idx_bytes[0] | (idx_bytes[1] << MATCH_BYTE_BITS) |
                (idx_bytes[2] << (MATCH_BYTE_BITS * 2));

            // Read 2-byte update length (little-endian)
            uint8_t update_len_bytes[UPDATE_LEN_SIZE];
            if (fread(update_len_bytes, 1, UPDATE_LEN_SIZE, read_file)
                != UPDATE_LEN_SIZE) {
                perror("Failed to read update length");
                if (out_file) fclose(out_file);
                free(pathname);
                fclose(read_file);
                exit(1);
            }
            uint16_t update_length = update_len_bytes[0]
                | (update_len_bytes[1] << MATCH_BYTE_BITS);

            uint8_t *update_data = malloc(update_length);

            // Apply updates
            fread(update_data, 1, update_length, read_file);
            fseek(out_file, block_idx * BLOCK_SIZE, SEEK_SET);
            fwrite(update_data, 1, update_length, out_file);
            free(update_data);
        }

        // Close the output file if opened
        if (out_file) {
            fclose(out_file);
        }
        free(pathname);
    }

    // Check for extra data by attempting to read one more byte
    int extra_byte = fgetc(read_file);
    if (extra_byte != EOF) {
        perror("Extra data in TCBI file");
        fclose(read_file);
        exit(1);
    }

    fclose(read_file);
}


// Helper function to parse a 10-byte ls-like mode string into a mode_t value
// Decided not to expand the ifs to keep function clean and compact
mode_t parse_mode(uint8_t *mode) {
    mode_t m = 0;

    if (mode[0] == 'd') m |= S_IFDIR;
    if (mode[1] == 'r') m |= S_IRUSR;
    if (mode[2] == 'w') m |= S_IWUSR;
    if (mode[3] == 'x') m |= S_IXUSR;
    if (mode[4] == 'r') m |= S_IRGRP;
    if (mode[5] == 'w') m |= S_IWGRP;
    if (mode[6] == 'x') m |= S_IXGRP;
    if (mode[7] == 'r') m |= S_IROTH;
    if (mode[8] == 'w') m |= S_IWOTH;
    if (mode[9] == 'x') m |= S_IXOTH;
    return m & ALL_PERMISSIONS;
}