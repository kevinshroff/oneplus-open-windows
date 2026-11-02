/* Generated fixed identity/policy facts; no vendor payload or admission flag. */
#ifndef G196_PINS_H
#define G196_PINS_H
static const uint8_t G196FdtSha[32]={0xf0,0x85,0x4f,0x17,0x17,0x13,0x51,0xb6,0x02,0x54,0x53,0x89,0x41,0x04,0x4e,0x68,0xca,0xe2,0x83,0xf1,0xf6,0xc9,0x24,0x3f,0xaa,0x14,0xb7,0x1b,0xad,0xbc,0x2e,0x29};
static const uint8_t G196SocSha[32]={0x1e,0xc6,0x17,0xf1,0x24,0x03,0x4c,0x90,0x07,0x1a,0x56,0xc8,0x07,0x5b,0x6d,0xc5,0x04,0xf2,0xdd,0xe4,0x3b,0x84,0x67,0x8d,0x19,0x10,0x2d,0xec,0xf6,0x0c,0xb0,0xd8};
static const uint8_t G196CmdDeclaredSha[32]={0x63,0x60,0xb1,0xef,0x8d,0xdf,0x5c,0xeb,0xb0,0x7c,0x6e,0xae,0xb4,0x4d,0x99,0xfa,0xe8,0x2d,0x1a,0x17,0x39,0xd2,0x02,0x41,0xba,0x7a,0x29,0x45,0x55,0x69,0x7c,0x69};
static const uint8_t G196GmuSha[32]={0x1a,0x2a,0x41,0x9c,0x39,0x04,0x6d,0x31,0x41,0xfc,0x5f,0xed,0x5a,0xa7,0xf9,0x71,0xde,0x2d,0xb4,0x0c,0xc7,0xa1,0xd8,0x96,0x93,0xc3,0xe2,0x6f,0xad,0x64,0xdd,0x98};
static const AdrenoHfiStartupConfig G196Policy={
.gpu_count=10u,
.gmu_count=3u,
.gpu={{UINT64_C(0),UINT32_C(0)},{UINT64_C(124800000),UINT32_C(3408385)},{UINT64_C(220000000),UINT32_C(3408385)},{UINT64_C(295000000),UINT32_C(3670530)},{UINT64_C(348000000),UINT32_C(3932675)},{UINT64_C(401000000),UINT32_C(4194820)},{UINT64_C(475000000),UINT32_C(5243653)},{UINT64_C(550000000),UINT32_C(8389382)},{UINT64_C(615000000),UINT32_C(9438215)},{UINT64_C(680000000),UINT32_C(12583944)}},
.gmu={{UINT64_C(0),UINT32_C(0)},{UINT64_C(220000000),UINT32_C(4194818)},{UINT64_C(550000000),UINT32_C(8389379)}},
.bandwidth_count=10u,
.cnoc_count=1u,
.ddr_count=3u,
.cnoc_wait_mask=1u,
.ddr_wait_mask=7u,
.cnoc_addresses={327736u,0u,0u,0u,0u,0u},
.cnoc_data={{1073741824u,0u,0u,0u,0u,0u},{1610612737u,0u,0u,0u,0u,0u}},
.ddr_addresses={327684u,327680u,327784u,0u,0u,0u,0u,0u},
.ddr_data={{1073741824u,1073741824u,1073741824u,0u,0u,0u,0u,0u},{1610614770u,1610614770u,1610612744u,0u,0u,0u,0u,0u},{1610615593u,1610615593u,1610612744u,0u,0u,0u,0u,0u},{1610618520u,1610618520u,1610612744u,0u,0u,0u,0u,0u},{1610619090u,1610619090u,1610612744u,0u,0u,0u,0u,0u},{1610620518u,1610620518u,1610612744u,0u,0u,0u,0u,0u},{1610622914u,1610622914u,1610612744u,0u,0u,0u,0u,0u},{1610624592u,1610624592u,1610612744u,0u,0u,0u,0u,0u},{1610626448u,1610626448u,1610612744u,0u,0u,0u,0u,0u},{1610628450u,1610628450u,1610612744u,0u,0u,0u,0u,0u},{0u,0u,0u,0u,0u,0u,0u,0u},{0u,0u,0u,0u,0u,0u,0u,0u},{0u,0u,0u,0u,0u,0u,0u,0u},{0u,0u,0u,0u,0u,0u,0u,0u},{0u,0u,0u,0u,0u,0u,0u,0u},{0u,0u,0u,0u,0u,0u,0u,0u}},
.acd_version=0u,
.acd_enable_mask=0u,
.acd_stride=0u,
.acd_count=0u,
.acd_data={0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u},
.enable_ifpc=0u,
};
#endif
