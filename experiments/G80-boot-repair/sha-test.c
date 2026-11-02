#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define STATIC static
#define CONST const
#define VOID void
typedef uint8_t UINT8;typedef uint32_t UINT32;typedef uint64_t UINT64;typedef size_t UINTN;
#define CopyMem memcpy
#define ZeroMem(p,n) memset(p,0,n)
#include "OpenSha256.h"
int main(int argc,char **argv){OPEN_SHA256 s;unsigned char b[65536],out[32];FILE*f=argc==2?fopen(argv[1],"rb"):stdin;if(!f)return 1;OpenShaInit(&s);size_t n;while((n=fread(b,1,sizeof(b),f))!=0)OpenShaUpdate(&s,b,n);OpenShaFinal(&s,out);for(size_t i=0;i<32;i++)printf("%02x",out[i]);printf("\n");OpenShaAll("abc",3,out);if(out[0]!=0xba)return 2;return ferror(f)?3:0;}
