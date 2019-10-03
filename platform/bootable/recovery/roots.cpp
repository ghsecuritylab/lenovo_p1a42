/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

//lenovo-sw zhucc2 add for third
#include <linux/fs.h>
#include <fs_mgr.h>
#include "mtdutils/mtdutils.h"
#include "mtdutils/mounts.h"
#include "roots.h"
#include "common.h"
#include "make_ext4fs.h"
extern "C" {
#include "wipe.h"
#include "cryptfs.h"
}

static struct fstab *fstab = NULL;

extern struct selabel_handle *sehandle;
/**lenovo-sw zhucc2 add for third   --------begin**/
static int getDeviceSize(char *devicePath, uint64_t *outSize)
{
    int err = 0;
    int fd = open(devicePath, O_RDONLY);
    if (fd == -1)
      err = errno ? errno : EIO;
    else {
      uint64_t size;
      if (ioctl(fd, BLKGETSIZE64, &size) == -1)
        err = errno ? errno : EIO;
      else
        *outSize = size;
      close(fd);
    }
 return err;
}
static int checkSize(char *wholeDevicePath)
{
    int res;
    uint64_t size = 0;
    int err = getDeviceSize(wholeDevicePath, &size);
    if (!err) {
      if (size < 34359738368ULL || size > 2199023255552ULL)
      {
        res = 0;
        printf("wangxf14 debug checkSize fat!\n");
      }
      else
      {
        res = 1;
        printf("wangxf14 debug checkSize exfat!\n");
      }
    }
    else {
      res = -1;
      errno = err;
      printf("wangxf14 debug getDeviceSize errno = %d\n", err);
    }
    return res;
}
bool exfatdetect(const char *fsPath) {
    bool retval = false;
    int fd = open(fsPath, O_RDONLY);
    if (fd != -1) {
        loff_t seek_res = lseek64(fd, 0, SEEK_SET);
        if (seek_res == 0) {
            char boot_sector[512];
            ssize_t read_res = read(fd, boot_sector, 512);
            if (read_res == 512) {
                if (!memcmp(&boot_sector[3], "EXFAT   ", 8)) {
                    printf("exFAT filesystem detected.");
                    retval = true;
                }
                else if (!memcmp(&boot_sector[0], "RRaAXFAT   ", 11)) {
                    printf("Corrupted exFAT filesystem detected. Fixing.");
                    retval = true;
                }
                else {
                    printf("Filesystem detection failed (not an exFAT "
                          "filesystem).");
                    retval = false;
                }
            }
            else if (read_res != -1)
                errno = EIO;
        }
        else if (seek_res != -1)
            errno = EIO;
        close(fd);
    }
    return retval;
}
bool ntfsdetect(const char *fsPath) {
    bool retval = false;
    int fd = open(fsPath, O_RDONLY);
    if(fd != -1) {
        loff_t seek_res = lseek64(fd, 3, SEEK_SET);
        if(seek_res == 3) {
            char signature[8];
            ssize_t read_res = read(fd, signature, 8);
            if(read_res == 8) {
                if(!memcmp(signature, "NTFS    ", 8)) {
                    printf("Detected NTFS filesystem.");
                    retval = true;
                }
                else {
                    printf("Filesystem detection failed (not an NTFS "
                          "filesystem).");
                    retval = false;
                }
            }
            else if(read_res != -1)
                errno = EIO;
        }
        else if(seek_res != -1)
            errno = EIO;
        close(fd);
    }
    return retval;
}
/**lenovo-sw zhucc2 add for third   --------end**/

void load_volume_table()
{
    int i;
    int ret;

    fstab = fs_mgr_read_fstab("/etc/recovery.fstab");
    if (!fstab) {
        LOGE("failed to read /etc/recovery.fstab\n");
        return;
    }

    ret = fs_mgr_add_entry(fstab, "/tmp", "ramdisk", "ramdisk");
    if (ret < 0 ) {
        LOGE("failed to add /tmp entry to fstab\n");
        fs_mgr_free_fstab(fstab);
        fstab = NULL;
        return;
    }

    printf("recovery filesystem table\n");
    printf("=========================\n");
    for (i = 0; i < fstab->num_entries; ++i) {
        Volume* v = &fstab->recs[i];
        printf("  %d %s %s %s %lld\n", i, v->mount_point, v->fs_type,
               v->blk_device, v->length);
        /*begin lenovo-sw zhucc2 add for exfat*/
        if(!strcmp(v->mount_point, "/sdcard") && !strcmp(v->blk_device, "/dev/block/mmcblk1p1"))
        {
          int checkSizeP1Result = checkSize("/dev/block/mmcblk1p1");
          int checkSizeResult = checkSize("/dev/block/mmcblk1");
          if( exfatdetect(v->blk_device) || exfatdetect("/dev/block/mmcblk1"))
          {
            printf("devices detect as exfat\n");
            fstab->recs[i].fs_type = strdup("exfat");
		printf("fs_type is open exfat ......\n");
          }
          else if ( ntfsdetect(v->blk_device) || ntfsdetect("/dev/block/mmcblk1")) {
            printf("devices detect as ntfs\n");
	    fstab->recs[i].fs_type = strdup("ntfs");
          }
          else{
	      printf("all devices checksize failure, set default\n");
	      fstab->recs[i].fs_type = strdup("vfat");
          }
       }
    }
    for (i = 0; i < fstab->num_entries; ++i) {
        Volume* v = &fstab->recs[i];
        printf("  %d %s %s %s %lld\n", i, v->mount_point, v->fs_type,
               v->blk_device, v->length);
    }
        /*end lenovo-sw zhucc2 add for exfat*/
    printf("\n");
}

Volume* volume_for_path(const char* path) {
    return fs_mgr_get_entry_for_mount_point(fstab, path);
}

int ensure_path_mounted(const char* path) {
    Volume* v = volume_for_path(path);
    if (v == NULL) {
        LOGE("unknown volume for path [%s]\n", path);
        return -1;
    }
    if (strcmp(v->fs_type, "ramdisk") == 0) {
        // the ramdisk is always mounted.
        return 0;
    }

    int result;
    result = scan_mounted_volumes();
    if (result < 0) {
        LOGE("failed to scan mounted volumes\n");
        return -1;
    }

    const MountedVolume* mv =
        find_mounted_volume_by_mount_point(v->mount_point);
    if (mv) {
        // volume is already mounted
        return 0;
    }

    mkdir(v->mount_point, 0755);  // in case it doesn't already exist

    if (strcmp(v->fs_type, "yaffs2") == 0) {
        // mount an MTD partition as a YAFFS2 filesystem.
        mtd_scan_partitions();
        const MtdPartition* partition;
        partition = mtd_find_partition_by_name(v->blk_device);
        if (partition == NULL) {
            LOGE("failed to find \"%s\" partition to mount at \"%s\"\n",
                 v->blk_device, v->mount_point);
            return -1;
        }
        return mtd_mount_partition(partition, v->mount_point, v->fs_type, 0);
    } else if (strcmp(v->fs_type, "ext4") == 0 ||
               strcmp(v->fs_type, "squashfs") == 0 ||
		strcmp(v->fs_type, "exfat") == 0 ||
               strcmp(v->fs_type, "vfat") == 0||
               strcmp(v->fs_type, "thirdexfat") == 0) {
        result = mount(v->blk_device, v->mount_point, v->fs_type,
                       v->flags, v->fs_options);
        if (result == 0) {
		return 0;
		}else {
        /*Lenovo-sw zhucc2 add for slowly SD -------start*/
        #if 1 //wschen 2013-05-03 workaround for slowly SD
       if (strstr(v->mount_point, "/sdcard") && (strstr(v->blk_device, "/dev/block/mmcblk1") || strstr(v->blk_device, "/dev/block/mmcblk0")))
       {
          int retry = 0;
          for (; retry <= 3; retry++)
          {
             result = mount(v->blk_device, v->mount_point, v->fs_type,v->flags, v->fs_options);
             if (result == 0)
             {
                 return 0;
             } else {
                 sleep(1);
             }
           }
		   //tonykuo 2014-04-11 Try mount mmcblk0 in case mmcblk0p1 failed
           if (strstr(v->blk_device, "/dev/block/mmcblk1"))
           {
              int retry_tmp = 0;
              for (; retry_tmp <= 3; retry_tmp++)//lenovo-sw wuwl9 add for fixed PASSION-2452
              {
                 result = mount("/dev/block/mmcblk1", v->mount_point, v->fs_type, v->flags, v->fs_options);
                 printf("Slowly SD /dev/block/mmcblk1 %d \n", result);
                 if (result == 0)
                 {
                    return 0;
                  }
                  else{
                    sleep(1);
                  }
               }
            }
            printf("Slowly SD retry failed (%s)\n", v->blk_device);
       }
       #endif
    }
        LOGE("failed to mount %s (%s)\n", v->mount_point, strerror(errno));
        return -1;
    }

    LOGE("unknown fs_type \"%s\" for %s\n", v->fs_type, v->mount_point);
    return -1;
}

int ensure_path_unmounted(const char* path) {
    Volume* v = volume_for_path(path);
    if (v == NULL) {
        LOGE("unknown volume for path [%s]\n", path);
        return -1;
    }
    if (strcmp(v->fs_type, "ramdisk") == 0) {
        // the ramdisk is always mounted; you can't unmount it.
        return -1;
    }

    int result;
    result = scan_mounted_volumes();
    if (result < 0) {
        LOGE("failed to scan mounted volumes\n");
        return -1;
    }

    const MountedVolume* mv =
        find_mounted_volume_by_mount_point(v->mount_point);
    if (mv == NULL) {
        // volume is already unmounted
        return 0;
    }

    return unmount_mounted_volume(mv);
}

static int exec_cmd(const char* path, char* const argv[]) {
    int status;
    pid_t child;
    if ((child = vfork()) == 0) {
        execv(path, argv);
        _exit(-1);
    }
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LOGE("%s failed with status %d\n", path, WEXITSTATUS(status));
    }
    return WEXITSTATUS(status);
}

int format_volume(const char* volume) {
    Volume* v = volume_for_path(volume);
    if (v == NULL) {
        LOGE("unknown volume \"%s\"\n", volume);
        return -1;
    }
    if (strcmp(v->fs_type, "ramdisk") == 0) {
        // you can't format the ramdisk.
        LOGE("can't format_volume \"%s\"", volume);
        return -1;
    }
    if (strcmp(v->mount_point, volume) != 0) {
        LOGE("can't give path \"%s\" to format_volume\n", volume);
        return -1;
    }

    if (ensure_path_unmounted(volume) != 0) {
        LOGE("format_volume failed to unmount \"%s\"\n", v->mount_point);
        return -1;
    }

    if (strcmp(v->fs_type, "yaffs2") == 0 || strcmp(v->fs_type, "mtd") == 0) {
        mtd_scan_partitions();
        const MtdPartition* partition = mtd_find_partition_by_name(v->blk_device);
        if (partition == NULL) {
            LOGE("format_volume: no MTD partition \"%s\"\n", v->blk_device);
            return -1;
        }

        MtdWriteContext *write = mtd_write_partition(partition);
        if (write == NULL) {
            LOGW("format_volume: can't open MTD \"%s\"\n", v->blk_device);
            return -1;
        } else if (mtd_erase_blocks(write, -1) == (off_t) -1) {
            LOGW("format_volume: can't erase MTD \"%s\"\n", v->blk_device);
            mtd_write_close(write);
            return -1;
        } else if (mtd_write_close(write)) {
            LOGW("format_volume: can't close MTD \"%s\"\n", v->blk_device);
            return -1;
        }
        return 0;
    }

    if (strcmp(v->fs_type, "ext4") == 0 || strcmp(v->fs_type, "f2fs") == 0) {
        // if there's a key_loc that looks like a path, it should be a
        // block device for storing encryption metadata.  wipe it too.
        if (v->key_loc != NULL && v->key_loc[0] == '/') {
            LOGI("wiping %s\n", v->key_loc);
            int fd = open(v->key_loc, O_WRONLY | O_CREAT, 0644);
            if (fd < 0) {
                LOGE("format_volume: failed to open %s\n", v->key_loc);
                return -1;
            }
            wipe_block_device(fd, get_file_size(fd));
            close(fd);
        }

        ssize_t length = 0;
        if (v->length != 0) {
            length = v->length;
        } else if (v->key_loc != NULL && strcmp(v->key_loc, "footer") == 0) {
            length = -CRYPT_FOOTER_OFFSET;
        }
        int result;
        if (strcmp(v->fs_type, "ext4") == 0) {
            result = make_ext4fs(v->blk_device, length, volume, sehandle);
        } else {   /* Has to be f2fs because we checked earlier. */
            if (v->key_loc != NULL && strcmp(v->key_loc, "footer") == 0 && length < 0) {
                LOGE("format_volume: crypt footer + negative length (%zd) not supported on %s\n", length, v->fs_type);
                return -1;
            }
            if (length < 0) {
                LOGE("format_volume: negative length (%zd) not supported on %s\n", length, v->fs_type);
                return -1;
            }
            char *num_sectors;
            if (asprintf(&num_sectors, "%zd", length / 512) <= 0) {
                LOGE("format_volume: failed to create %s command for %s\n", v->fs_type, v->blk_device);
                return -1;
            }
            const char *f2fs_path = "/sbin/mkfs.f2fs";
            const char* const f2fs_argv[] = {"mkfs.f2fs", "-t", "-d1", v->blk_device, num_sectors, NULL};

            result = exec_cmd(f2fs_path, (char* const*)f2fs_argv);
            free(num_sectors);
        }
        if (result != 0) {
            LOGE("format_volume: make %s failed on %s with %d(%s)\n", v->fs_type, v->blk_device, result, strerror(errno));
            return -1;
        }
        return 0;
    }

    LOGE("format_volume: fs_type \"%s\" unsupported\n", v->fs_type);
    return -1;
}

int setup_install_mounts() {
    if (fstab == NULL) {
        LOGE("can't set up install mounts: no fstab loaded\n");
        return -1;
    }
    for (int i = 0; i < fstab->num_entries; ++i) {
        Volume* v = fstab->recs + i;

        if (strcmp(v->mount_point, "/tmp") == 0 ||
            strcmp(v->mount_point, "/cache") == 0) {
            if (ensure_path_mounted(v->mount_point) != 0) {
                LOGE("failed to mount %s\n", v->mount_point);
                return -1;
            }

        } else {
            if (ensure_path_unmounted(v->mount_point) != 0) {
                LOGE("failed to unmount %s\n", v->mount_point);
                return -1;
            }
        }
    }
    return 0;
}
