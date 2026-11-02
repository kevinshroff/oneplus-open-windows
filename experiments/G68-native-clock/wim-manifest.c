// SPDX-License-Identifier: MIT
// Read the documented libwim directory API, including actual relative Windows
// security descriptor bytes. Hex strings make every path/stream unambiguous.
#include <wimlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void hex(const void *ptr, size_t n) {
    const unsigned char *p = ptr;
    for (size_t i=0; i<n; ++i) printf("%02x", p[i]);
}
static void str(const char *s) { if(s) hex(s, strlen(s)); }
static int row(const struct wimlib_dir_entry *d, void *ctx) {
    (void)ctx;
    str(d->full_path); putchar('\t'); str(d->dos_name);
    printf("\t%08x\t%08x\t%u\t%llu\t",d->attributes,d->reparse_tag,
           d->num_links,(unsigned long long)d->hard_link_group_id);
    hex(d->security_descriptor,d->security_descriptor_size);
    printf("\t%lld:%ld\t%lld:%ld\t%lld:%ld\t%u:%u:%u:%u\t",
        (long long)d->creation_time.tv_sec,(long)d->creation_time.tv_nsec,
        (long long)d->last_write_time.tv_sec,(long)d->last_write_time.tv_nsec,
        (long long)d->last_access_time.tv_sec,(long)d->last_access_time.tv_nsec,
        d->unix_uid,d->unix_gid,d->unix_mode,d->unix_rdev);
    hex(&d->object_id,sizeof(d->object_id));
    for(uint32_t i=0;i<=d->num_named_streams;++i) {
        putchar('\t'); str(d->streams[i].stream_name); putchar(':');
        hex(d->streams[i].resource.sha1_hash,20);
        printf(":%llu",(unsigned long long)d->streams[i].resource.uncompressed_size);
    }
    putchar('\n');
    return ferror(stdout)?1:0;
}
int main(int argc,char **argv) {
    WIMStruct *wim=NULL;
    if(argc!=2)return 2;
    int r=wimlib_open_wim(argv[1],0,&wim);
    if(r)return r;
    r=wimlib_iterate_dir_tree(wim,1,"/",WIMLIB_ITERATE_DIR_TREE_FLAG_RECURSIVE|
             WIMLIB_ITERATE_DIR_TREE_FLAG_RESOURCES_NEEDED,row,NULL);
    wimlib_free(wim);
    return r;
}
