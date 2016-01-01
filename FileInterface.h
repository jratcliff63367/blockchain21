#ifndef FILE_INTERFACE_H

#define FILE_INTERFACE_H

#include <stdint.h>

typedef struct
{
  void *mInterface;
} FILE_INTERFACE;

FILE_INTERFACE *	fi_fopen(const char *fname,const char *spec,void *mem,uint64_t len,bool useMemoryMappedFile);
uint64_t			fi_fclose(FILE_INTERFACE *file);
uint64_t			fi_fread(void *buffer,uint64_t size,uint64_t count,FILE_INTERFACE *fph);
uint64_t			fi_fwrite(const void *buffer,uint64_t size,uint64_t count,FILE_INTERFACE *fph);
uint64_t			fi_fprintf(FILE_INTERFACE *fph,const char *fmt,...);
uint64_t			fi_fflush(FILE_INTERFACE *fph);
uint64_t			fi_fseek(FILE_INTERFACE *fph,uint64_t loc,int mode);
uint64_t			fi_ftell(FILE_INTERFACE *fph);
uint64_t			fi_fputc(char c,FILE_INTERFACE *fph);
uint64_t			fi_fputs(const char *str,FILE_INTERFACE *fph);
uint64_t			fi_feof(FILE_INTERFACE *fph);
uint64_t			fi_ferror(FILE_INTERFACE *fph);
void				fi_clearerr(FILE_INTERFACE *fph);
void *				fi_getMemBuffer(FILE_INTERFACE *fph,uint64_t *outputLength);  // return the buffer and length of the file.
bool				fi_usesMemoryMappedFile(FILE_INTERFACE *fph);
void *				fi_getCurrentMemoryLocation(FILE_INTERFACE *fph); // only valid for memory based files; but will return the address in memory of the current file location


#endif
