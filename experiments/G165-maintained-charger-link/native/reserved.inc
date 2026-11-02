static int ReservedRam(void)
{
 const ULONGLONG bases[]={0x400000ULL,0x81a00000ULL,0x81d00000ULL};
 const ULONGLONG lengths[]={0x100000ULL,0x300000ULL,0x200000ULL};
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;
 if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){
  ULONGLONG start=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}if(n>MAXULONGLONG-start)break;
  for(ULONG j=0;j<3;j++)if(start<bases[j]+lengths[j]&&bases[j]<start+n)goto done;
 }
 done:ExFreePool(ranges);return valid;
}
