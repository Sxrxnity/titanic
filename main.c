////////////////////////////////////////////////////////////////////////
// COMP1521 25T2 --- Assignment 2: `titanic', a simple file synchroniser
// <https://cgi.cse.unsw.edu.au/~cs1521/25T2/assignments/ass2/index.html>
//
// Written by Danny Sun (z5691331) on 21/07/2025.
// INSERT-DESCRIPTION-OF-PROGRAM-HERE
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


/// @brief Create a TABI file from an array of pathnames.
/// @param out_pathname A path to where the new TABI file should be created.
/// @param in_pathnames An array of strings containing, in order, the files
//                      that should be placed in the new TABI file.
/// @param num_in_pathnames The length of the `in_pathnames` array. In
///                         subset 5, when this is zero, you should include
///                         everything in the current directory.

    // Hint: you will need to:
    //   * Open `out_pathname` using fopen, which will be the output TABI file.
    //   * For each pathname in `in_pathnames`:
    //      * Write the length of the pathname as a 2 byte little endian integer
    //      * Write the pathname
    //      * Check the size of the input file, e.g. using stat
    //      * Compute the number of blocks using number_of_blocks_in_file
    //      * Write the number of blocks as a 3 byte little endian integer
    //      * Open the input file, and read in blocks of size BLOCK_SIZE, and
    //         * For each block call hash_black to compute the hash
    //         * Write out that hash as an 8 byte little endian integer
    // Each time you need to write out a little endian integer you should
    // compute each byte using bitwise operations like <<, &, or |

void stage_1(char *out_pathname, char *in_pathnames[], size_t num_in_pathnames) {

    FILE *file = fopen(out_pathname, "wb");

    fputc(0x54, file);
    fputc(0x41, file);
    fputc(0x42, file);
    fputc(0x49, file);
    fputc(num_in_pathnames, file);

    for (size_t i = 0; i < num_in_pathnames; i++) {
        struct stat info;
        if (stat(in_pathnames[i], &info) != 0) {
            perror("SOME ERROR MESSAGE");
            exit(1);
        }

        size_t len = strlen(in_pathnames[i]);
        fputc(len & 0xFF, file);
        fputc((len >> 8) & 0xFF, file);
        fwrite(in_pathnames[i], 1, len, file);

        size_t num_blocks = number_of_blocks_in_file(info.st_size);
        fputc(num_blocks & 0xFF, file);
        fputc((num_blocks) >> 8 & 0xFF, file);
        fputc((num_blocks) >> 16 & 0xFF, file);

        FILE *input_file = fopen(in_pathnames[i], "rb");
        if (input_file == NULL) {
            perror("AN ERROR MESSAGE");
            exit(1);
        }

        unsigned char buffer[BLOCK_SIZE];

        for (size_t j = 0; j < num_blocks; j++) {
            size_t bytes_read = fread(buffer, 1, BLOCK_SIZE, input_file);

            if (bytes_read == 0 && ferror(input_file)) {
                perror("SOMME OTHER ERROR MESSAGE");
                exit(1);
            }

            uint64_t hash = hash_block((char *)buffer, bytes_read);
            for (int k = 0; k < 8; k++) {
                fputc(hash >> (k * 8) & 0xFF, file);
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

}


/// @brief Create a TCBI file from a TBBI file.
/// @param out_pathname A path to where the new TCBI file should be created.
/// @param in_pathname A path to where the existing TBBI file is located.
void stage_3(char *out_pathname, char *in_pathname) {

}


/// @brief Apply a TCBI file to the filesystem.
/// @param in_pathname A path to where the existing TCBI file is located.
void stage_4(char *in_pathname) {

}
