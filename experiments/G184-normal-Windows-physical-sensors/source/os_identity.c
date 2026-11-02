#include "os_identity.h"
uint32_t Op184OsMode(uint32_t build,int mini,uint32_t type,const uint16_t*root,uint32_t bytes)
{
 static const uint16_t suffix[]={':','\\','w','i','n','d','o','w','s'};
 if(!root||type!=1||(bytes!=20&&bytes!=22)||mini<0||mini>1)return 0;
 if(bytes==22&&root[10])return 0;
 for(unsigned i=1;i<10;i++){
  uint16_t v=root[i];if(v>='A'&&v<='Z')v+='a'-'A';
  if(v!=suffix[i-1])return 0;
 }
 uint16_t drive=root[0];if(drive>='A'&&drive<='Z')drive+='a'-'A';
 if(mini==1&&build==26100&&drive=='x')return 1;
 if(mini==0&&build==26300&&drive=='c')return 2;
 return 0;
}
