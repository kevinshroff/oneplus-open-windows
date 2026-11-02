/* Build only against the retained wimlib 1.14.4 source/static library.
 * Restore the two fixed GPIO aliases' original ACL/attributes/timestamps.
 * Do not reconstruct private layouts against a different binary library.
 * The caller must hash-bind both WIMs before invoking this offline tool.
 */
#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "wimlib.h"
#include "wimlib/wim.h"
#include "wimlib/dentry.h"
#include "wimlib/inode.h"
#include "wimlib/metadata.h"
#include "wimlib/security.h"

static const char *paths[] = {
    "/Windows/System32/DriverStore/FileRepository/qcgpio_i.inf_arm64_41e106a2e4fca1b9/qcgpio_i.sys",
    "/Windows/WinSxS/arm64_dual_qcgpio_i.inf_31bf3856ad364e35_10.0.26100.8115_none_ec59ac755c635f0a/qcgpio_i.sys",
};

static int check(int result, const char *operation)
{
    if (result)
        fprintf(stderr, "%s: %d (%s)\n", operation, result, wimlib_get_error_string(result));
    return result;
}

int main(int argc, char **argv)
{
    WIMStruct *source = NULL, *target = NULL;
    struct wim_dentry *old[2], *now[2];
    struct wimlib_wim_info info;
    struct wim_sd_set set;
    int result;
    if (argc != 3 || strcmp(argv[1], argv[2]) == 0) {
        fprintf(stderr, "usage: restore-wim-driver-metadata ORIGINAL_WIM DEVELOPMENT_WIM\n");
        return 2;
    }
    if ((result = check(wimlib_open_wim(argv[1], 0, &source), "open source")) ||
        (result = check(wimlib_open_wim(argv[2], WIMLIB_OPEN_FLAG_WRITE_ACCESS, &target), "open target")))
        return result;
    if ((result = check(wimlib_get_wim_info(source, &info), "source info"))) return result;
    if (info.image_count != 1 || info.boot_index != 1) return 3;
    if ((result = check(wimlib_get_wim_info(target, &info), "target info"))) return result;
    if (info.image_count != 1 || info.boot_index != 1) return 3;
    if ((result = check(select_wim_image(source, 1), "source image")) ||
        (result = check(select_wim_image(target, 1), "target image"))) return result;
    for (unsigned i = 0; i < 2; i++) {
        old[i] = get_dentry(source, paths[i], WIMLIB_CASE_SENSITIVE);
        now[i] = get_dentry(target, paths[i], WIMLIB_CASE_SENSITIVE);
        if (!old[i] || !now[i]) return 4;
        if (old[i]->d_inode->i_attributes != 0x20 ||
            now[i]->d_inode->i_attributes != 0x80 ||
            old[i]->d_inode->i_nlink != 2 || now[i]->d_inode->i_nlink != 2 ||
            old[i]->d_inode->i_security_id < 0 || now[i]->d_inode->i_security_id != -1)
            return 5;
    }
    if (old[0]->d_inode != old[1]->d_inode || now[0]->d_inode != now[1]->d_inode) return 6;
    struct wim_security_data *from = wim_get_current_security_data(source);
    struct wim_security_data *to = wim_get_current_security_data(target);
    int sid = old[0]->d_inode->i_security_id;
    if ((unsigned)sid >= from->num_entries || from->sizes[sid] != 80) return 7;
    /* Exact expected Windows descriptor from the independent G21 manifest. */
    static const unsigned char expected[] = {
        0x01,0x00,0x04,0x80,0x14,0x00,0x00,0x00,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x34,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,
        0x20,0x02,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,
        0x20,0x02,0x00,0x00,0x02,0x00,0x1c,0x00,0x01,0x00,0x00,0x00,0x00,0x03,0x14,0x00,
        0xff,0x01,0x1f,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00
    };
    if (from->sizes[sid] != sizeof(expected) ||
        memcmp(from->descriptors[sid], expected, sizeof(expected)) != 0) return 8;
    if ((result = check(init_sd_set(&set, to), "security set"))) return result;
    int assigned = sd_set_add_sd(&set, (const char *)from->descriptors[sid], from->sizes[sid]);
    if (assigned < 0) return 9;
    struct wim_inode *a = old[0]->d_inode, *b = now[0]->d_inode;
    b->i_security_id = assigned;
    b->i_attributes = a->i_attributes;
    b->i_creation_time = a->i_creation_time;
    b->i_last_access_time = a->i_last_access_time;
    b->i_last_write_time = a->i_last_write_time;
    mark_image_dirty(wim_get_current_image_metadata(target));
    destroy_sd_set(&set);
    result = check(wimlib_overwrite(target, WIMLIB_WRITE_FLAG_CHECK_INTEGRITY, 1), "append repaired metadata");
    if (!result) printf("Restored original Windows descriptor, attributes and times for two fixed hard-link aliases.\n");
    wimlib_free(target);
    wimlib_free(source);
    return result;
}
