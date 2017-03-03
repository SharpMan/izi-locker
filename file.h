#ifndef FILEE_H
#define FILEE_H
#ifndef uint8_t
#define uint8_t  unsigned char
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include "aes256.h"



    typedef struct{
      char *name;
      unsigned long fileLen;
      uint8_t * buffer;
      uint8_t encryption_key[32];
      aes256_context ctx;
    } File;

    int read_entry(File *file);
    void file_encrypt(File *File);
    int write_entry(File *file, char *name);
    void file_entry_decrypt(File *file);
    char *mkrndstr(size_t length);

    static const char *get_filename_ext(const char *filename) {
      const char *dot = strrchr(filename, '.');
      if(!dot || dot == filename) return "";
      return dot + 1;
  }


#ifdef __cplusplus
}
#endif
#endif
