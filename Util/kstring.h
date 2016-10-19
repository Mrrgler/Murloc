#ifndef _STRING_H
#define _STRING_H

#ifndef NULL
#define NULL 0
#endif

#ifndef _SIZE_T
#define _SIZE_T
typedef uint32_t size_t;
#endif

void   *memchr(const void *, int, size_t);
int     memcmp(const void *, const void *, size_t);
void   *memcpy(void *, const void *, size_t);
//#define memcpy __builtin_memcpy
void   *memmove(void *, const void *, size_t);
void   *memset(void *, uint8_t, size_t);
//#define memset __builtin_memset
char   *strcat(char *, const char *);
//#define strcat __builtin_strcat
char   *strchr(const char *, int);
int     strcmp(const char *, const char *);
int     strcoll(const char *, const char *);
char   *strcpy(char *, const char *);
//#define strcpy __builtin_strcpy
size_t  strcspn(const char *, const char *);
char   *strerror(int);
size_t  strlen(const char *);
//#define strlen __builtin_strlen
char   *strncat(char *, const char *, size_t);
int     strncmp(const char *, const char *, size_t);
char   *strncpy(char *, const char *, size_t);
char   *strpbrk(const char *, const char *);
char   *strrchr(const char *, int);
size_t  strspn(const char *, const char *);
char   *strstr(const char *, const char *);
char   *strtok(char *, const char *);
size_t  strxfrm(char *, const char *, size_t);

#endif /* _STRING_H */
