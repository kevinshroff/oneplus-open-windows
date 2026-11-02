/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Original fixed Open input adapter. Reference format facts are recorded in
 * evidence/input-identities.json; no GPL implementation is compiled here. */
#include "g196_preflight.h"

static void Copy(void *out,const void *in,size_t n)
{ uint8_t *d=out;const uint8_t *s=in;while(n--)*d++=*s++; }
static void Zero(void *out,size_t n)
{ uint8_t *d=out;while(n--)*d++=0; }
static int Equal(const void *a,const void *b,size_t n)
{ const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1; }
static int Extent(const void *p,size_t n)
{ return p&&n&&n<=UINTPTR_MAX-(uintptr_t)p; }
static int Overlap(const void *a,size_t n,const void *b,size_t m)
{ return (uintptr_t)a<(uintptr_t)b+m&&(uintptr_t)b<(uintptr_t)a+n; }
static uint32_t U32(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint32_t U16(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8; }
static uint32_t BE32(const uint8_t *p)
{ return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3]; }

/* Existing project SHA256 core, unchanged; no Windows/native hash callback. */
#define UINT8 uint8_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define UINTN size_t
#define VOID void
#define CONST const
#define STATIC static
#define CopyMem Copy
#define ZeroMem Zero
#include "OpenSha256.h"
#undef UINT8
#undef UINT32
#undef UINT64
#undef UINTN
#undef VOID
#undef CONST
#undef STATIC
#undef CopyMem
#undef ZeroMem
#include "g196_pins.h"
static int Pin(const uint8_t *p,size_t n,const uint8_t expected[32])
{ uint8_t actual[32];OpenShaAll(p,n,actual);return Equal(actual,expected,32); }

g196_status g196_check_command_db(g196_bytes input,g196_db_fact *out)
{
    /* The exact current profile needs all declared tables/aux through5464.
     * Uncaptured reservation bytes are never read, invented or authenticated. */
    if(!out||!Extent(out,sizeof(*out))||!Extent(input.data,input.bytes)||
       input.bytes<5464||input.bytes>0x20000||
       Overlap(out,sizeof(*out),input.data,input.bytes))return G196_ARGUMENT;
    const uint8_t *p=input.data;
    if(U32(p)!=1||U32(p+4)!=0x0c0330db)return G196_DB_LAYOUT;
    uint32_t table_start[8]={0},table_end[8]={0};
    uint8_t ids[175][8];uint32_t count=0,tables=0,max_used=144;
    for(unsigned s=0;s<8;s++){
        const uint8_t *h=p+8+16*s;uint32_t sid=U16(h),n=U16(h+6);
        if(U16(h+10)||U16(h+12)||U16(h+14))return G196_DB_LAYOUT;
        if(!sid){if(n)return G196_DB_LAYOUT;continue;}
        uint32_t a=144+U16(h+2),z=a+n*24u;
        if(!n||n>175-count||a<144||z>5464)return G196_DB_LAYOUT;
        for(unsigned j=0;j<s;j++)if(table_end[j]&&a<table_end[j]&&table_start[j]<z)return G196_DB_LAYOUT;
        table_start[s]=a;table_end[s]=z;tables++;
        if(z>max_used)max_used=z;
        for(unsigned i=0;i<n;i++){
            const uint8_t *e=p+a+i*24u;unsigned ended=0;
            for(unsigned k=0;k<8;k++){
                if(!e[k])ended=1;
                else if(ended||e[k]<0x21||e[k]>0x7e)return G196_DB_LAYOUT;
            }
            if(!e[0]||(U32(e+16)&3))return G196_DB_LAYOUT;
            for(unsigned j=0;j<count;j++)if(Equal(ids[j],e,8))return G196_DB_LAYOUT;
            Copy(ids[count++],e,8);
            uint32_t aux=144+U16(h+4)+U16(e+22),bytes=U16(e+20);
            if(aux<144||aux>5464||bytes>5464-aux)return G196_DB_LAYOUT;
            if(aux+bytes>max_used)max_used=aux+bytes;
        }
    }
    if(count!=175||tables!=4||max_used!=5464)return G196_DB_LAYOUT;
    /* Every auxiliary extent must avoid every entry table, including tables
     * encountered later than its own slave header. Empty extents do not read. */
    for(unsigned s=0;s<8;s++)if(table_end[s]){
        const uint8_t *h=p+8+16*s;
        for(unsigned at=table_start[s];at<table_end[s];at+=24){
            uint32_t a=144+U16(h+4)+U16(p+at+22),n=U16(p+at+20);
            for(unsigned j=0;j<8;j++)if(n&&table_end[j]&&a<table_end[j]&&table_start[j]<a+n)return G196_DB_LAYOUT;
        }
    }
    /* Full declared-byte identity binds gfx/cx/mx rail auxiliary tables and
     * SH0/MC0/ACV/CN0 metadata/addresses to the reviewed numeric policy. */
    if(!Pin(p,5464,G196CmdDeclaredSha))return G196_DB_IDENTITY;
    const g196_db_fact fact={175,5464,4,7};Copy(out,&fact,sizeof(fact));
    return G196_INPUTS_MATCH;
}

typedef struct { const uint8_t *item;uint32_t offset,count; } Soc;
static int Smem(g196_bytes in,Soc *out)
{
    if(in.bytes!=0xb0000||!Extent(in.data,in.bytes))return 0;
    const uint8_t *p=in.data;uint32_t n=(uint32_t)in.bytes;
    if(U32(p)!=0x54525024||U16(p+4)!=0xfffe||U16(p+6)!=0xfffe||U32(p+8)!=n)return 0;
    uint32_t free_u=U32(p+12),free_c=U32(p+16),count=0;
    uint16_t ids[64];Soc result={0};
    if(free_u<32||free_u>free_c||free_c>n)return 0;
    for(unsigned cached=0;cached<2;cached++){
        uint32_t at=cached?n-32:32;
        while(cached?at>free_c:at<free_u){
            if(at<32||at>n-16||count>=64)return 0;
            const uint8_t *h=p+at;uint32_t id=U16(h+2),bytes=U32(h+4),padding=U16(h+8),hpad=U16(h+10);
            if(U16(h)!=0xa5a5||!bytes||bytes>=n||padding>=bytes||U32(h+12))return 0;
            for(unsigned i=0;i<count;i++)if(ids[i]==id)return 0;
            ids[count++]=(uint16_t)id;
            uint32_t start,next;
            if(cached){
                if(bytes>at-32)return 0;
                start=at-bytes;next=start-32;
                if(next>=at||free_c<32||next<free_c-32)return 0;
            }else{
                if(hpad>n-at-16)return 0;
                start=at+16+hpad;
                if(bytes>n-start)return 0;
                next=start+bytes;if(next<=at||next>free_u)return 0;
            }
            if(start<32||bytes>n-start)return 0;
            if(id==137){if(bytes-padding!=408)return 0;result.item=p+start;result.offset=start;}
            at=next;
        }
        if(!cached&&at!=free_u)return 0;
    }
    if(!result.item)return 0;
    result.count=count;*out=result;return 1;
}

g196_status g196_prepare(const g196_inputs *in,g196_preflight *out)
{
    if(!Extent(in,sizeof(*in))||!Extent(out,sizeof(*out))||
       Overlap(in,sizeof(*in),out,sizeof(*out)))return G196_ARGUMENT;
    const g196_bytes inputs[]={in->firmware_fdt,in->global_smem_first,in->global_smem_second,in->command_db,in->gmu_image};
    for(unsigned i=0;i<5;i++){
        if(!Extent(inputs[i].data,inputs[i].bytes)||Overlap(out,sizeof(*out),inputs[i].data,inputs[i].bytes)||
           Overlap(in,sizeof(*in),inputs[i].data,inputs[i].bytes))return G196_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(Overlap(inputs[i].data,inputs[i].bytes,inputs[j].data,inputs[j].bytes))return G196_ARGUMENT;
    }
    const uint8_t *f=in->firmware_fdt.data;size_t fn=in->firmware_fdt.bytes;
    if(fn<60399||fn>65536||BE32(f)!=0xd00dfeed||BE32(f+4)!=60399||
       !Pin(f,60399,G196FdtSha))return G196_FDT;
    Soc a,b;
    if(!Smem(in->global_smem_first,&a)||!Smem(in->global_smem_second,&b)||
       a.offset!=b.offset||a.count!=b.count||!Equal(a.item,b.item,408))return G196_SMEM;
    if(!Pin(a.item,408,G196SocSha)||U32(a.item)!=18||U32(a.item+4)!=519||
       U32(a.item+8)!=0x20000||U32(a.item+108)!=127||U32(a.item+176)!=2||U32(a.item+180)!=1)return G196_SOC;
    g196_preflight result;Zero(&result,sizeof(result));
    g196_status status=g196_check_command_db(in->command_db,&result.command_db);
    if(status!=G196_INPUTS_MATCH)return status;
    if(in->gmu_image.bytes!=66844||!Pin(in->gmu_image.data,66844,G196GmuSha))return G196_GMU;
    result.image.bytes=in->gmu_image.data;result.image.size=66844;result.image.expected_blocks=15;
    Copy(result.image.sha256,G196GmuSha,32);
    if(g190_plan_image(&result.image,result.blocks,32,&result.block_count)!=G190_OK||result.block_count!=15)return G196_BACKEND;
    Copy(&result.policy,&G196Policy,sizeof(result.policy));
    if(AdrenoHfiStartupValidate(&result.policy)!=AdrenoHfiStartupSuccess)return G196_BACKEND;
    result.soc_id=519;result.revision=0x20000;result.feature_code=result.source_sku=2;
    result.soc_item_offset=a.offset;result.smem_items=a.count;
    result.remaining_native=G196_REQUIRED_NATIVE; /* NativeReady stays0. */
    Copy(out,&result,sizeof(result));return G196_INPUTS_MATCH;
}
