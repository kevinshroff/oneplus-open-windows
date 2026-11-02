#ifndef OPEN_G80_SHA256_H
#define OPEN_G80_SHA256_H
// SHA-256 streaming core. Validated against FIPS vectors and independent hashlib.
typedef struct { UINT32 H[8]; UINT64 Bytes; UINTN Used; UINT8 Block[64]; } OPEN_SHA256;
STATIC UINT32 OpenRor32 (UINT32 X, UINTN N) { return (X >> N) | (X << (32 - N)); }
STATIC VOID OpenShaBlock (OPEN_SHA256 *S, CONST UINT8 *B) {
 STATIC CONST UINT32 K[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
 UINT32 W[64],A,C,D,E,F,G,H,T1,T2,Bb; UINTN I;
 for (I=0;I<16;I++) { W[I]=((UINT32)B[I*4]<<24)|((UINT32)B[I*4+1]<<16)|((UINT32)B[I*4+2]<<8)|B[I*4+3]; }
 for (I=16;I<64;I++) { UINT32 X=W[I-15],Y=W[I-2]; W[I]=W[I-16]+(OpenRor32(X,7)^OpenRor32(X,18)^(X>>3))+W[I-7]+(OpenRor32(Y,17)^OpenRor32(Y,19)^(Y>>10)); }
 A=S->H[0];Bb=S->H[1];C=S->H[2];D=S->H[3];E=S->H[4];F=S->H[5];G=S->H[6];H=S->H[7];
 for(I=0;I<64;I++){T1=H+(OpenRor32(E,6)^OpenRor32(E,11)^OpenRor32(E,25))+((E&F)^((~E)&G))+K[I]+W[I];T2=(OpenRor32(A,2)^OpenRor32(A,13)^OpenRor32(A,22))+((A&Bb)^(A&C)^(Bb&C));H=G;G=F;F=E;E=D+T1;D=C;C=Bb;Bb=A;A=T1+T2;}
 S->H[0]+=A;S->H[1]+=Bb;S->H[2]+=C;S->H[3]+=D;S->H[4]+=E;S->H[5]+=F;S->H[6]+=G;S->H[7]+=H;
}
STATIC VOID OpenShaInit (OPEN_SHA256 *S) {
 STATIC CONST UINT32 Initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 CopyMem(S->H,Initial,sizeof(Initial));S->Bytes=0;S->Used=0;
}
STATIC VOID OpenShaUpdate (OPEN_SHA256 *S, CONST VOID *Data, UINTN N) {
 CONST UINT8 *B=Data;UINTN Take;S->Bytes+=N;
 while(N){Take=64-S->Used;if(Take>N){Take=N;}CopyMem(S->Block+S->Used,B,Take);S->Used+=Take;B+=Take;N-=Take;if(S->Used==64){OpenShaBlock(S,S->Block);S->Used=0;}}
}
STATIC VOID OpenShaFinal (OPEN_SHA256 *S, UINT8 Out[32]) {
 UINT64 Bits=S->Bytes*8;UINTN I;S->Block[S->Used++]=0x80;
 if(S->Used>56){ZeroMem(S->Block+S->Used,64-S->Used);OpenShaBlock(S,S->Block);S->Used=0;}
 ZeroMem(S->Block+S->Used,56-S->Used);for(I=0;I<8;I++){S->Block[63-I]=(UINT8)(Bits>>(I*8));}OpenShaBlock(S,S->Block);
 for(I=0;I<8;I++){Out[I*4]=(UINT8)(S->H[I]>>24);Out[I*4+1]=(UINT8)(S->H[I]>>16);Out[I*4+2]=(UINT8)(S->H[I]>>8);Out[I*4+3]=(UINT8)S->H[I];}
}
STATIC inline VOID OpenShaAll (CONST VOID *B, UINTN N, UINT8 H[32]) { OPEN_SHA256 S;OpenShaInit(&S);OpenShaUpdate(&S,B,N);OpenShaFinal(&S,H); }
#endif
