/* SPDX-License-Identifier: MIT
 * Copy-only observer. No resource is mapped, enabled or interpreted here.
 * The caller holds its own device lock and owns every source descriptor.
 */
#include "g63_capture.h"
void G63CaptureBegin(G63_REPORT*r,uint32_t raw,uint32_t translated,uint32_t bytes)
{
 uint32_t i,j;r->PrepareCalls++;r->CaptureComplete=0;r->RawCount=raw;r->TranslatedCount=translated;r->DescriptorBytes=bytes;r->Capacity=G63_CAPACITY;r->StoredRaw=r->StoredTranslated=r->CaptureFlags=0;
 for(i=0;i<G63_CAPACITY;i++)for(j=0;j<G63_RECORD_BYTES;j++)r->Raw[i][j]=r->Translated[i][j]=0;
 if(raw>G63_CAPACITY)r->CaptureFlags|=G63_RAW_CAP;
 if(translated>G63_CAPACITY)r->CaptureFlags|=G63_TRANSLATED_CAP;
 if(!bytes||bytes>G63_RECORD_BYTES)r->CaptureFlags|=G63_DESCRIPTOR_SIZE;
 if(raw!=translated)r->CaptureFlags|=G63_COUNT_MISMATCH;
}
void G63CaptureRow(G63_REPORT*r,int translated,uint32_t index,const void*descriptor)
{
 uint32_t i;uint8_t*dst;const uint8_t*src=descriptor;uint32_t*stored=translated?&r->StoredTranslated:&r->StoredRaw;uint32_t count=translated?r->TranslatedCount:r->RawCount;
 if(index>=G63_CAPACITY||index>=count||!r->DescriptorBytes||r->DescriptorBytes>G63_RECORD_BYTES)return;
 if(!src||index!=*stored){r->CaptureFlags|=translated?G63_TRANSLATED_MISSING:G63_RAW_MISSING;return;}
 dst=translated?r->Translated[index]:r->Raw[index];for(i=0;i<r->DescriptorBytes;i++)dst[i]=src[i];(*stored)++;
}
void G63CaptureEnd(G63_REPORT*r)
{
 if(r->StoredRaw!=r->RawCount)r->CaptureFlags|=G63_RAW_MISSING;
 if(r->StoredTranslated!=r->TranslatedCount)r->CaptureFlags|=G63_TRANSLATED_MISSING;
 r->CaptureComplete=r->CaptureFlags==0;
}
