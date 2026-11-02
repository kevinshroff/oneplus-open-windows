#ifndef OPEN_184_OS_IDENTITY_H
#define OPEN_184_OS_IDENTITY_H
#include <stdint.h>
/* mini: 1=key exists,0=key absent,-1=an observation failed. */
uint32_t Op184OsMode(uint32_t build,int mini,uint32_t type,const uint16_t*root,uint32_t bytes);
#endif
