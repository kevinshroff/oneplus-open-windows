/* Fixed raw/translated memory contract. Returns zero only for the whole set. */
#include "resources.h"
uint32_t Op182Validate(const OP182_RESOURCE*raw,const OP182_RESOURCE*translated,size_t count)
{
 if(!raw||!translated||count!=OP182_RESOURCE_COUNT)return 1;
 uint32_t seen=0;
 for(size_t i=0;i<count;i++){
  const OP182_RESOURCE*a=raw+i,*b=translated+i;unsigned j;
  if(a->Base!=b->Base||a->Bytes!=b->Bytes||a->Write!=b->Write||a->Share!=b->Share)return 2;
  for(j=0;j<OP182_RESOURCE_COUNT;j++)if(b->Base==OP182Expected[j].Base)break;
  if(j==OP182_RESOURCE_COUNT||seen&(1u<<j))return 3;
  const OP182_RESOURCE*e=OP182Expected+j;
  if(b->Bytes!=e->Bytes||b->Write!=e->Write)return 4;
  /* Windows shared RO views may be legitimate. A writable controller/SMEM
   * assignment must be exclusive to this OS driver,not an overlapping client. */
  if(b->Share<1||b->Share>3||(e->Write&&b->Share==3))return 5;
  seen|=1u<<j;
 }
 return seen==((1u<<OP182_RESOURCE_COUNT)-1)?0:6;
}
