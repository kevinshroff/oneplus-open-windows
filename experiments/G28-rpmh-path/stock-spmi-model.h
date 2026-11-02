typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define __iomem
struct spmi_pmic_arb;
struct pmic_arb_ver_ops {
    int (*ppid_to_apid)(struct spmi_pmic_arb *,u16);
    int (*offset)(struct spmi_pmic_arb *,u8,u16,enum pmic_arb_channel);
    u32 (*fmt_cmd)(u8,u8,u16,u8);
};
struct apid_data { u16 ppid;u8 write_ee,irq_ee; };
struct spmi_pmic_arb {
    uint8_t *rd_base,*wr_base;
    struct pmic_arb_ver_ops *ver_ops;
    struct apid_data apid_data[1024];
    unsigned ee;
    int lock;
};
struct spmi_controller { int dev;struct spmi_pmic_arb *arb; };
#define spmi_controller_get_drvdata(c) ((c)->arb)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define dev_err(...) ((void)0)
#define dev_dbg(...) ((void)0)
#define WARN_ON(x) do {if(x)warnings++;}while(0)
#define raw_spin_lock_irqsave(p,f) do{(void)(p);assert(!locked);locked=1;(f)=0;}while(0)
#define raw_spin_unlock_irqrestore(p,f) do{(void)(p);(void)(f);assert(locked);locked=0;}while(0)
#define readl_relaxed(p) model_read((uintptr_t)(p))
#define __raw_readl(p) model_read((uintptr_t)(p))
#define writel_relaxed(v,p) model_write((uintptr_t)(p),(v))
#define __raw_writel(v,p) model_write((uintptr_t)(p),(v))
#define udelay(n) do{assert((n)==1);delays++;}while(0)
