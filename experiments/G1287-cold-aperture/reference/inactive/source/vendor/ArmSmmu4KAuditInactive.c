/* SPDX-License-Identifier: MIT */
#include "ArmSmmu4KAudit.h"
#define PAGE UINT64_C(4096)
#define ADDRESS UINT64_C(0x0000fffffffff000)
typedef struct {
    const ArmSmmu4KTableIo *io;
    const ArmSmmu4KConfig *c;
    const ArmSmmu4KResult *built;
    const ArmSmmu4KAuditRegion *a;
    ArmSmmu4KTableAuditResult *r;
    size_t range;
    uint64_t offset;
} Walk;
static int intersects(uint64_t a,uint64_t an,uint64_t b,uint64_t bn)
{return a<b+bn && b<a+an;}
static int incompatible(const ArmSmmu4KRange *a,const ArmSmmu4KRange *b)
{return a->writeback!=b->writeback || a->shareability!=b->shareability || ((a->permissions^b->permissions)&ArmSmmu4KPrivileged);}
static ArmSmmu4KStatus validate(const ArmSmmu4KConfig *c,const ArmSmmu4KResult *b,
    const ArmSmmu4KAuditRegion *a,uint64_t root)
{
    if(!c || !b || !a || !a->ranges || !a->range_count || !a->visited ||
        !a->capacity_pages || a->capacity_pages>SIZE_MAX/4096 ||
        a->visited_bytes<a->capacity_pages || !a->read_budget ||
        c->input_bits<32 || c->input_bits>48 ||
        !(c->output_bits==32 || c->output_bits==36 || c->output_bits==40 ||
          c->output_bits==42 || c->output_bits==44 || c->output_bits==48) ||
        !c->leaf_budget || c->leaf_budget>(SIZE_MAX-1)/3 ||
        a->range_count>SIZE_MAX/sizeof(*a->ranges))return ArmSmmu4KArgument;
    if(a->range_count>c->leaf_budget)return ArmSmmu4KBudget;
    uint64_t limit=UINT64_C(1)<<c->output_bits,span=UINT64_C(1)<<c->input_bits;
    uint64_t pool_bytes=(uint64_t)a->capacity_pages*PAGE;
    if((c->table_physical&4095) || c->table_physical>=limit || pool_bytes>limit-c->table_physical)
        return ArmSmmu4KBadRange;
    if(root!=c->table_physical || b->root_physical!=root || b->mair!=0xff44 ||
        !b->table_pages || b->table_pages>a->capacity_pages || !b->leaf_pages ||
        b->start_level!=4-(c->input_bits-12+8)/9 || b->upper_region>1)
        return ArmSmmu4KStateMismatch;
    if(b->table_pages>a->read_budget/512)return ArmSmmu4KBudget;
    size_t leaves=0;uint64_t end=0;
    for(size_t i=0;i<a->range_count;++i) {
        const ArmSmmu4KRange *r=&a->ranges[i];
        if(!r->bytes || ((r->iova|r->physical|r->bytes)&4095) ||
            !(r->permissions&ArmSmmu4KRead) || (r->permissions&~15u) ||
            r->writeback>1 || (r->shareability!=2 && r->shareability!=3) ||
            r->physical>=limit || r->bytes>limit-r->physical ||
            (b->upper_region?(r->iova<UINT64_MAX-span+1 || r->bytes-1>UINT64_MAX-r->iova):
             (r->iova>=span || r->bytes>span-r->iova)))return ArmSmmu4KBadRange;
        if(i && r->iova<=end)return ArmSmmu4KOverlap;
        end=r->iova+r->bytes-1;
        if(intersects(r->physical,r->bytes,c->table_physical,pool_bytes))return ArmSmmu4KOverlap;
        for(size_t j=0;j<i;++j)if(incompatible(r,&a->ranges[j]) &&
            intersects(r->physical,r->bytes,a->ranges[j].physical,a->ranges[j].bytes))return ArmSmmu4KOverlap;
        uint64_t pages=r->bytes/PAGE;
        if(pages>c->leaf_budget-leaves)return ArmSmmu4KBudget;
        leaves+=(size_t)pages;
    }
    return leaves==b->leaf_pages?ArmSmmu4KSuccess:ArmSmmu4KStateMismatch;
}
static ArmSmmu4KStatus walk(Walk *w,uint64_t table,unsigned level,uint64_t base)
{
    if((table&4095) || table<w->c->table_physical ||
        (table-w->c->table_physical)/PAGE>=w->a->capacity_pages)return ArmSmmu4KBadRange;
    size_t page=(size_t)((table-w->c->table_physical)/PAGE);
    if(w->a->visited[page])return ArmSmmu4KOverlap;
    if(w->r->table_pages>=w->built->table_pages)return ArmSmmu4KStateMismatch;
    w->a->visited[page]=1;++w->r->table_pages;
    size_t initial_leaves=w->r->leaf_pages;
    unsigned shift=39-9*level;
    unsigned width=level==w->built->start_level?w->c->input_bits-shift:9;
    for(unsigned i=0;i<512;++i) {
        w->r->descriptor_physical=table+8*i;w->r->descriptor=0;
        w->r->level=level;w->r->iova=base|((uint64_t)i<<shift);w->r->expected_descriptor=0;
        if(w->r->descriptor_reads==w->a->read_budget)return ArmSmmu4KBudget;
        ++w->r->descriptor_reads;
        uint64_t d;
        if(w->io->read_descriptor(w->io->cookie,table+8*i,&d))return ArmSmmu4KIoError;
        w->r->descriptor=d;
        if(!d)continue;
        if(i>=(1u<<width) || (d&3)!=3)return ArmSmmu4KStateMismatch;
        if(level<3) {
            if(d!=((d&ADDRESS)|3))return ArmSmmu4KStateMismatch;
            ArmSmmu4KStatus status=walk(w,d&ADDRESS,level+1,base|((uint64_t)i<<shift));
            if(status)return status;
        } else {
            if(w->range==w->a->range_count)return ArmSmmu4KStateMismatch;
            const ArmSmmu4KRange *r=&w->a->ranges[w->range];
            uint64_t expected=(r->physical+w->offset)|3|(1u<<11)|(1u<<10)|((uint64_t)r->shareability<<8);
            if(!(r->permissions&ArmSmmu4KExecute))expected|=UINT64_C(3)<<53;
            if(!(r->permissions&ArmSmmu4KPrivileged))expected|=1u<<6;
            if(!(r->permissions&ArmSmmu4KWrite))expected|=1u<<7;
            if(r->writeback)expected|=1u<<2;
            w->r->expected_descriptor=expected;
            if(w->r->iova!=r->iova+w->offset || d!=expected)return ArmSmmu4KStateMismatch;
            ++w->r->leaf_pages;w->offset+=PAGE;
            if(w->offset==r->bytes){++w->range;w->offset=0;}
        }
    }
    /* Empty intermediate tables are not part of the declared resource graph. */
    return w->r->leaf_pages>initial_leaves?ArmSmmu4KSuccess:ArmSmmu4KStateMismatch;
}
ArmSmmu4KStatus ArmSmmu4KAuditTables(const ArmSmmu4KTableIo *io,
    const ArmSmmu4KConfig *c,const ArmSmmu4KResult *b,const ArmSmmu4KAuditRegion *a,
    uint64_t root,ArmSmmu4KTableAuditResult *r)
{
    if(!r)return ArmSmmu4KArgument;*r=(ArmSmmu4KTableAuditResult){0};
    if(!io || !io->read_descriptor)return ArmSmmu4KArgument;
    ArmSmmu4KStatus status=validate(c,b,a,root);if(status)return status;
    for(size_t i=0;i<a->capacity_pages;++i)a->visited[i]=0;
    Walk w={io,c,b,a,r,0,0};
    uint64_t base=b->upper_region?UINT64_MAX-(UINT64_C(1)<<c->input_bits)+1:0;
    status=walk(&w,root,b->start_level,base);if(status)return status;
    if(r->table_pages!=b->table_pages || r->leaf_pages!=b->leaf_pages || w.range!=a->range_count)
        return ArmSmmu4KStateMismatch;
    r->complete=1;return ArmSmmu4KSuccess;
}
