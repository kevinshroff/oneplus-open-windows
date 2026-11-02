#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define BIT(n) (1U<<(n))
enum { OBS=0x0c4456e0,WR=0x0c7b7000 };
struct access {uintptr_t address;uint32_t value;unsigned write;};
static struct access accesses[2048];
static unsigned count,locked,warnings,delays,status_reads,pending;
static uint32_t terminal;
static uint32_t model_read(uintptr_t a) {
    uint32_t v;
    assert(locked);
    assert(a!=WR&&a!=WR+0x10&&a!=WR+0x14);
    if(a==WR+8||a==OBS+8){v=status_reads++<pending?0:terminal;}
    else if(a==OBS+0x18)v=0x01010400;
    else {assert(a==OBS+0x1c);v=0x0000ab04;}
    assert(count<2048);accesses[count++]=(struct access){a,v,0};return v;
}
static void model_write(uintptr_t a,uint32_t v) {
    assert(locked);assert(a==WR||a==WR+0x10||a==WR+0x14||a==OBS);
    assert(count<2048);accesses[count++]=(struct access){a,v,1};
}
#include "stock-spmi.inc"
static int lookup(struct spmi_pmic_arb *a,u16 ppid){(void)a;return ppid==0x1c4?695:-ENODEV;}
static struct pmic_arb_ver_ops ops={lookup,pmic_arb_offset_v7,pmic_arb_fmt_cmd_v2};
static struct spmi_pmic_arb arb;
static struct spmi_controller ctrl;
static void setup(uint32_t status,unsigned polls) {
    memset(&arb,0,sizeof(arb));arb.ver_ops=&ops;
    arb.rd_base=(uint8_t *)(uintptr_t)0xc440000;
    arb.wr_base=(uint8_t *)(uintptr_t)0xc500000;ctrl.arb=&arb;
    count=locked=warnings=delays=status_reads=0;pending=polls;terminal=status;
    assert(pmic_arb_offset_v7(&arb,1,0xc446,PMIC_ARB_CHANNEL_RW)==0x2b7000);
    assert(pmic_arb_offset_v7(&arb,1,0xc446,PMIC_ARB_CHANNEL_OBS)==0x56e0);
}
static void check_accesses(void) {
    assert(!locked);
    for(unsigned i=0;i<count;i++)if(!accesses[i].write)
        assert(accesses[i].address==WR+8||accesses[i].address==OBS+8||
               accesses[i].address==OBS+0x18||accesses[i].address==OBS+0x1c);
}
int main(void) {
    unsigned cases=0;uint8_t data[9]={0x80,2,3,4,5,6,7,8,9};
    for(unsigned enabled=0;enabled<2;enabled++) {
        setup(1,0);data[0]=enabled?0x80:0;
        assert(!pmic_arb_write_cmd(&ctrl,0x30,1,0xc446,data,1));
        assert(count==3&&accesses[0].address==WR+0x10&&accesses[0].value==data[0]);
        assert(accesses[1].address==WR&&accesses[1].value==0x460);
        assert(accesses[2].address==WR+8&&!accesses[2].write);check_accesses();cases++;
    }
    const uint32_t status[4]={5,3,9,0};
    const int expect[4]={-EPERM,-EIO,-EIO,-ETIMEDOUT};
    for(unsigned i=0;i<4;i++) {
        setup(status[i],0);assert(pmic_arb_write_cmd(&ctrl,0x30,1,0xc446,data,1)==expect[i]);
        assert(count==(i==3?1002:3));assert(delays==(i==3?1000:0));check_accesses();cases++;
    }
    setup(1,3);assert(!pmic_arb_write_cmd(&ctrl,0x30,1,0xc446,data,1));
    assert(count==6&&delays==3);check_accesses();cases++;
    setup(1,0);arb.apid_data[695].write_ee=4;
    assert(pmic_arb_write_cmd(&ctrl,0x30,1,0xc446,data,1)==-EPERM&&count==0);cases++;
    setup(1,0);assert(pmic_arb_write_cmd(&ctrl,0x30,1,0xc346,data,1)==-ENODEV&&count==0);cases++;
    for(unsigned len=0;len<=9;len+=9) {
        setup(1,0);assert(pmic_arb_write_cmd(&ctrl,0x30,1,0xc446,data,len)==-EINVAL&&count==0);cases++;
    }
    setup(1,0);assert(pmic_arb_write_cmd(&ctrl,0x20,1,0xc446,data,1)==-EINVAL&&count==0);cases++;
    setup(1,0);data[0]=1;assert(!pmic_arb_write_cmd(&ctrl,0x30,1,0xc446,data,8));
    assert(count==4&&accesses[0].value==0x04030201&&accesses[1].value==0x08070605);
    assert(accesses[2].address==WR&&accesses[2].value==0x467);check_accesses();cases++;
    setup(1,0);uint8_t received[8]={0};assert(!pmic_arb_read_cmd(&ctrl,0x38,1,0xc400,received,8));
    const uint8_t identity[8]={0,4,1,1,4,0xab,0,0};assert(!memcmp(received,identity,8));
    assert(count==4&&accesses[0].address==OBS&&accesses[0].value==0x08000007);check_accesses();cases++;
    setup(1,0);arb.ee=2;
    assert(pmic_arb_offset_v7(&arb,1,0xc446,PMIC_ARB_CHANNEL_OBS)==0x156e0);cases++;
    assert(cases==15);
    puts("{\"cases\":15,\"unchanged_source_functions\":9,\"RW_reads_only_STATUS\":true,\"native_hardware\":false}");
    return 0;
}
