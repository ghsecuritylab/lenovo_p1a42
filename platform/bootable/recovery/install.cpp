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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mount.h>

#ifndef LENOVO_RECOVERY_SUPPORT   //wuwl9 modify for lenovo recovery
#include "common.h"
#include "install.h"
#include "mincrypt/rsa.h"
#include "minui/minui.h"
#include "minzip/SysUtil.h"
#include "minzip/Zip.h"
#include "mtdutils/mounts.h"
#include "mtdutils/mtdutils.h"
#include "roots.h"
#include "verifier.h"
#include "ui.h"

extern RecoveryUI* ui;

#else
#include "common.h"
#include "recovery_ui.h"
#include "install.h"
#include "mincrypt/rsa.h"
#include "minui/minui.h"
#include "minzip/SysUtil.h"
#include "minzip/Zip.h"
#include "mtdutils/mounts.h"
#include "mtdutils/mtdutils.h"
#include "roots.h"
#include "verifier.h"
#include "ui.h"
extern "C" {
#include "miui/src/miui.h"
}
#endif
#if 1 //wschen 2012-07-10  wuwl9 modify for recovery
static void reset_mark_block(void)
{
#if 0    // wuwl9 modify
    struct bootloader_message boot;
    memset(&boot, 0, sizeof(boot));
    set_bootloader_message(&boot);
    sync();
#endif
}
#endif
#define ASSUMED_UPDATE_BINARY_NAME  "META-INF/com/google/android/update-binary"
#define PUBLIC_KEYS_FILE "/res/keys"

// Default allocation of progress bar segments to operations
#ifndef LENOVO_RECOVERY_SUPPORT   //wuwl9 modify for lenovo recovery
static const int VERIFICATION_PROGRESS_TIME = 60;
static const float VERIFICATION_PROGRESS_FRACTION = 0.25;
static const float DEFAULT_FILES_PROGRESS_FRACTION = 0.4;
static const float DEFAULT_IMAGE_PROGRESS_FRACTION = 0.1;
#endif

// If the package contains an update binary, extract it and run it.
#ifndef LENOVO_RECOVERY_SUPPORT   //wuwl9 modify for lenovo recovery
static int
try_update_binary(const char* path, ZipArchive* zip, bool* wipe_cache) {
    const ZipEntry* binary_entry =
            mzFindZipEntry(zip, ASSUMED_UPDATE_BINARY_NAME);
    if (binary_entry == NULL) {
        mzCloseZipArchive(zip);
        return INSTALL_CORRUPT;
    }

    const char* binary = "/tmp/update_binary";
    unlink(binary);
    int fd = creat(binary, 0755);
    if (fd < 0) {
        mzCloseZipArchive(zip);
        LOGE("Can't make %s\n", binary);
        return INSTALL_ERROR;
    }
    bool ok = mzExtractZipEntryToFile(zip, binary_entry, fd);
    close(fd);
    mzCloseZipArchive(zip);

    if (!ok) {
        LOGE("Can't copy %s\n", ASSUMED_UPDATE_BINARY_NAME);
        return INSTALL_ERROR;
    }

    int pipefd[2];
    pipe(pipefd);

    // When executing the update binary contained in the package, the
    // arguments passed are:
    //
    //   - the version number for this interface
    //
    //   - an fd to which the program can write in order to update the
    //     progress bar.  The program can write single-line commands:
    //
    //        progress <frac> <secs>
    //            fill up the next <frac> part of of the progress bar
    //            over <secs> seconds.  If <secs> is zero, use
    //            set_progress commands to manually control the
    //            progress of this segment of the bar.
    //
    //        set_progress <frac>
    //            <frac> should be between 0.0 and 1.0; sets the
    //            progress bar within the segment defined by the most
    //            recent progress command.
    //
    //        firmware <"hboot"|"radio"> <filename>
    //            arrange to install the contents of <filename> in the
    //            given partition on reboot.
    //
    //            (API v2: <filename> may start with "PACKAGE:" to
    //            indicate taking a file from the OTA package.)
    //
    //            (API v3: this command no longer exists.)
    //
    //        ui_print <string>
    //            display <string> on the screen.
    //
    //        wipe_cache
    //            a wipe of cache will be performed following a successful
    //            installation.
    //
    //        clear_display
    //            turn off the text display.
    //
    //        enable_reboot
    //            packages can explicitly request that they want the user
    //            to be able to reboot during installation (useful for
    //            debugging packages that don't exit).
    //
    //   - the name of the package zip file.
    //

    const char** args = (const char**)malloc(sizeof(char*) * 5);
    args[0] = binary;
    args[1] = EXPAND(RECOVERY_API_VERSION);   // defined in Android.mk
    char* temp = (char*)malloc(10);
    sprintf(temp, "%d", pipefd[1]);
    args[2] = temp;
    args[3] = (char*)path;
    args[4] = NULL;

    pid_t pid = fork();
    if (pid == 0) {
        umask(022);
        close(pipefd[0]);
        execv(binary, (char* const*)args);
        fprintf(stdout, "E:Can't run %s (%s)\n", binary, strerror(errno));
        _exit(-1);
    }
    close(pipefd[1]);

    *wipe_cache = false;

    char buffer[1024];
    FILE* from_child = fdopen(pipefd[0], "r");
    while (fgets(buffer, sizeof(buffer), from_child) != NULL) {
        char* command = strtok(buffer, " \n");
        if (command == NULL) {
            continue;
        } else if (strcmp(command, "progress") == 0) {
            char* fraction_s = strtok(NULL, " \n");
            char* seconds_s = strtok(NULL, " \n");

            float fraction = strtof(fraction_s, NULL);
            int seconds = strtol(seconds_s, NULL, 10);

            ui->ShowProgress(fraction * (1-VERIFICATION_PROGRESS_FRACTION), seconds);
        } else if (strcmp(command, "set_progress") == 0) {
            char* fraction_s = strtok(NULL, " \n");
            float fraction = strtof(fraction_s, NULL);
            ui->SetProgress(fraction);
        } else if (strcmp(command, "ui_print") == 0) {
            char* str = strtok(NULL, "\n");
            if (str) {
                ui->Print("%s", str);
            } else {
                ui->Print("\n");
            }
            fflush(stdout);
        } else if (strcmp(command, "wipe_cache") == 0) {
            *wipe_cache = true;
        } else if (strcmp(command, "clear_display") == 0) {
            ui->SetBackground(RecoveryUI::NONE);
        } else if (strcmp(command, "enable_reboot") == 0) {
            // packages can explicitly request that they want the user
            // to be able to reboot during installation (useful for
            // debugging packages that don't exit).
            ui->SetEnableReboot(true);
        } else {
            LOGE("unknown command [%s]\n", command);
        }
    }
    fclose(from_child);

    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LOGE("Error in %s\n(Status %d)\n", path, WEXITSTATUS(status));
        return INSTALL_ERROR;
    }

    return INSTALL_SUCCESS;
}
#else
static int try_update_binary(const char* path, ZipArchive* zip, int* wipe_cache) {
    const ZipEntry* binary_entry =
            mzFindZipEntry(zip, ASSUMED_UPDATE_BINARY_NAME);
    if (binary_entry == NULL) {
        mzCloseZipArchive(zip);
        return INSTALL_CORRUPT;
    }
    const char* binary = "/tmp/update_binary";
    unlink(binary);
    int fd = creat(binary, 0755);
    if (fd < 0) {
        mzCloseZipArchive(zip);
        LOGE("Can't make %s\n", binary);
        return INSTALL_ERROR;
    }
    bool ok = mzExtractZipEntryToFile(zip, binary_entry, fd);
    close(fd);
    mzCloseZipArchive(zip);
    if (!ok) {
        LOGE("Can't copy %s\n", ASSUMED_UPDATE_BINARY_NAME);
        return INSTALL_ERROR;
    }
    int pipefd[2];
    pipe(pipefd);
    const char** args = (const char**)malloc(sizeof(char*) * 5);
    args[0] = binary;
    args[1] = EXPAND(RECOVERY_API_VERSION);   // defined in Android.mk
    char* temp = (char*)malloc(10);
    sprintf(temp, "%d", pipefd[1]);
    args[2] = temp;
    args[3] = (char*)path;
    args[4] = NULL;
    pid_t pid = fork();
    if (pid == 0) {
        umask(022);
        close(pipefd[0]);
        execv(binary, (char* const*)args);
        fprintf(stdout, "E:Can't run %s (%s)\n", binary, strerror(errno));
        _exit(-1);
    }
    close(pipefd[1]);
    *wipe_cache = false;
    char buffer[1024];
    FILE* from_child = fdopen(pipefd[0], "r");
    while (fgets(buffer, sizeof(buffer), from_child) != NULL) {
        char* command = strtok(buffer, " \n");
        if (command == NULL) {
            continue;
        } else if (strcmp(command, "progress") == 0) {
            char* fraction_s = strtok(NULL, " \n");
            char* seconds_s = strtok(NULL, " \n");
            float fraction = strtof(fraction_s, NULL);
            int seconds = strtol(seconds_s, NULL, 10);
            ui_show_progress(fraction * (1-VERIFICATION_PROGRESS_FRACTION), seconds);
        } else if (strcmp(command, "set_progress") == 0) {
            char* fraction_s = strtok(NULL, " \n");
            float fraction = strtof(fraction_s, NULL);
            ui_set_progress(fraction);
        } else if (strcmp(command, "ui_print") == 0) {
            char* str = strtok(NULL, "\n");
            if (str) {
               ui_print("%s", str);
            } else {
                ui_print("\n");
            }
            fflush(stdout);
        } else if (strcmp(command, "wipe_cache") == 0) {
            *wipe_cache = 1;
	} else if (strcmp(command, "minzip:") == 0) {
            char* str = strtok(NULL, "\n");
#if 0
            miuiInstall_set_info(str);
#else
            ui_print("%s", str);
#endif
#if 1 //wschen 2012-07-25
        } else if (strcmp(command, "special_factory_reset") == 0) {
            *wipe_cache = 2;
#endif
        } else if (strcmp(command, "clear_display") == 0) {
            ui_set_background(BACKGROUND_ICON_NONE);
        } else if (strcmp(command, "enable_reboot") == 0) {
	 ui_print("lenovo do not need to do anything!\n");
        } else {
        char * str = strtok(NULL, "\n");
            if (str)
                LOGD("[%s]:%s\n",command, str);
        }
    }
    fclose(from_child);
    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LOGE("Error in %s\n(Status %d)\n", path, WEXITSTATUS(status));
        return INSTALL_ERROR;
    }
#ifdef SUPPORT_DATA_BACKUP_RESTORE //wschen 2011-03-09
    if (!usrdata_changed && update_from_data) {
        ui_print("/data offset remains the same no need to restore usrdata\n");
    } else {
        if (part_size_changed) {
            if (ensure_path_mounted("/sdcard") != 0) {
                LOGE("Can't mount %s\n", path);
                return INSTALL_NO_SDCARD;
            }
            if (userdata_restore(backup_path, 1)) {
                return INSTALL_FILE_SYSTEM_ERROR;
            }
        }
    }
#endif //SUPPORT_DATA_BACKUP_RESTORE
#ifdef SUPPORT_SBOOT_UPDATE
    sec_seccfg_update();
#endif
    return INSTALL_SUCCESS;
}
#endif

#ifdef USE_MDTP
static int
mdtp_update()
{
    const char** args = (const char**)malloc(sizeof(char*) * 2);

    if (args == NULL) {
        LOGE("Failed to allocate memory for MDTP FOTA app arguments\n");
        return 0;
    }

    args[0] = "/sbin/mdtp_fota";
    args[1] = NULL;
    int status = 0;

    ui->Print("Running MDTP integrity verification and update...\n");

    /* Make sure system partition is mounted, so MDTP can process its content. */
    mkdir("/system", 0755);
    status = mount("/dev/block/bootdevice/by-name/system", "/system", "ext4",
                 MS_NOATIME | MS_NODEV | MS_NODIRATIME |
                 MS_RDONLY, "");

    if (status) {
        LOGE("Failed to mount the system partition, error=%s.\n", strerror(errno));
        free(args);
        return 0;
    }

    status = 0;

    pid_t pid = fork();
    if (pid == 0) {
        execv(args[0], (char* const*)args);
        LOGE("Can't run %s (%s)\n", args[0], strerror(errno));
        _exit(-1);
    }
    if (pid > 0) {
        LOGE("Waiting for MDTP FOTA to complete...\n");
        pid = waitpid(pid, &status, 0);
        LOGE("MDTP FOTA completed, status: %d\n", status);
    }

    /* Leave the system partition unmounted before we finish. */
    umount("/system");

    free(args);

    return (status > 0) ? 1 : 0;
}
#endif /* USE_MDTP */
#ifndef LENOVO_RECOVERY_SUPPORT   //wuwl9 modify for lenovo recovery
static int
really_install_package(const char *path, bool* wipe_cache, bool needs_mount)
{
    ui->SetBackground(RecoveryUI::INSTALLING_UPDATE);
    ui->Print("Finding update package...\n");
    // Give verification half the progress bar...
    ui->SetProgressType(RecoveryUI::DETERMINATE);
    ui->ShowProgress(VERIFICATION_PROGRESS_FRACTION, VERIFICATION_PROGRESS_TIME);
    LOGI("Update location: %s\n", path);

    // Map the update package into memory.
    ui->Print("Opening update package...\n");

    if (path && needs_mount) {
        if (path[0] == '@') {
            ensure_path_mounted(path+1);
        } else {
            ensure_path_mounted(path);
        }
    }

    MemMapping map;
    if (sysMapFile(path, &map) != 0) {
        LOGE("failed to map file\n");
        return INSTALL_CORRUPT;
    }

    int numKeys;
    Certificate* loadedKeys = load_keys(PUBLIC_KEYS_FILE, &numKeys);
    if (loadedKeys == NULL) {
        LOGE("Failed to load keys\n");
        return INSTALL_CORRUPT;
    }
    LOGI("%d key(s) loaded from %s\n", numKeys, PUBLIC_KEYS_FILE);

    ui->Print("Verifying update package...\n");

    int err;
    err = verify_file(map.addr, map.length, loadedKeys, numKeys);
    free(loadedKeys);
    LOGI("verify_file returned %d\n", err);
    if (err != VERIFY_SUCCESS) {
        LOGE("signature verification failed\n");
        sysReleaseMap(&map);
        return INSTALL_CORRUPT;
    }

    /* Try to open the package.
     */
    ZipArchive zip;
    err = mzOpenZipArchive(map.addr, map.length, &zip);
    if (err != 0) {
        LOGE("Can't open %s\n(%s)\n", path, err != -1 ? strerror(err) : "bad");
        sysReleaseMap(&map);
        return INSTALL_CORRUPT;
    }

    /* Verify and install the contents of the package.
     */
    ui->Print("Installing update...\n");
    ui->SetEnableReboot(false);
    int result = try_update_binary(path, &zip, wipe_cache);
    ui->SetEnableReboot(true);
    ui->Print("\n");

    sysReleaseMap(&map);

#ifdef USE_MDTP
    /* If MDTP update failed, return an error such that recovery will not finish. */
    if (result == INSTALL_SUCCESS) {
        if (!mdtp_update()) {
            ui->Print("Unable to verify integrity of /system for MDTP, update aborted.\n");
            return INSTALL_ERROR;
        }
        ui->Print("Successfully verified integrity of /system for MDTP.\n");
    }
#endif /* USE_MDTP */

    return result;
}
#else
static int really_install_package(const char *path, int* wipe_cache, int needs_mount)
{
    ui_set_background(BACKGROUND_ICON_INSTALLING);
    ui_print("Finding update package...\n");

    LOGI("Update location: %s\n", path);
    ui_print("Opening update package...\n");
    if (path && needs_mount) {
        if (path[0] == '@') {
            if (ensure_path_mounted(path+1) != 0) {
                LOGE("Can't mount %s\n", path);
                return INSTALL_CORRUPT;
            }
        } else {
             if (ensure_path_mounted(path) != 0) {
                LOGE("Can't mount %s\n", path);
                return INSTALL_CORRUPT;
        }
        }
    }
    MemMapping map;
    if (sysMapFile(path, &map) != 0) {
        LOGE("failed to map file\n");
	reset_mark_block();
        return INSTALL_CORRUPT;
    }
    int numKeys;
    Certificate* loadedKeys = load_keys(PUBLIC_KEYS_FILE, &numKeys);
    if (loadedKeys == NULL) {
        LOGE("Failed to load keys\n");
#if 0 //wschen 2012-07-10
        return INSTALL_CORRUPT;
#else
        reset_mark_block();
        return INSTALL_NO_KEY;
#endif
    }
    LOGI("%d key(s) loaded from %s\n", numKeys, PUBLIC_KEYS_FILE);
#if 0 //wschen 2012-07-10
    ui->Print("Verifying update package...\n");
#else
    LOGI("Verifying update package...\n");
#endif
    int err;
    err = verify_file(map.addr, map.length, loadedKeys, numKeys);
    free(loadedKeys);
    LOGI("verify_file returned %d\n", err);
    if (err != VERIFY_SUCCESS) {
        LOGE("signature verification failed\n");
#if 0 //wschen 2012-07-10
        return INSTALL_CORRUPT;
#else
        reset_mark_block();
        sysReleaseMap(&map);
        return INSTALL_SIGNATURE_ERROR;
#endif
    }
    ZipArchive zip;
    err = mzOpenZipArchive(map.addr, map.length, &zip);
    if (err != 0) {
        LOGE("Can't open %s\n(%s)\n", path, err != -1 ? strerror(err) : "bad");
#if 1 //wschen 2012-07-10
        reset_mark_block();
#endif
        sysReleaseMap(&map);
        return INSTALL_CORRUPT;
    }
#ifdef SUPPORT_DATA_BACKUP_RESTORE //wschen 2011-03-09
    update_from_data = 0;
    Volume* v = volume_for_path(path);
    if (strcmp(v->mount_point, "/data") == 0) {
	update_from_data = 1;
    }
    if (check_part_size(&zip, update_from_data) != 0) {
        reset_mark_block();
        sysReleaseMap(&map);
        return INSTALL_ERROR;
    }
#endif //SUPPORT_DATA_BACKUP_RESTORE
#ifdef SUPPORT_SBOOT_UPDATE
    if (0 != (err = sec_verify_img_info(&zip, false))) {
        sysReleaseMap(&map);
        return INSTALL_SECURE_CHECK_FAIL;
    }
    sec_mark_status(false);
#endif
    ui_print("Installing update...\n");
    int result = try_update_binary(path, &zip, wipe_cache);
    ui_print("\n");
    sysReleaseMap(&map);
#ifdef EXTERNAL_MODEM_UPDATE
    ui_print("Installing update Modem...\n");
    result = try_update_modem(path);
    if (result != INSTALL_SUCCESS) {
        LOGE("try_update_modem fail \n");
        return result;
    }
#endif
#ifdef USE_MDTP
    if (result == INSTALL_SUCCESS) {
        if (!mdtp_update()) {
            ui->Print("Unable to verify integrity of /system for MDTP, update aborted.\n");
            return INSTALL_ERROR;
        }
        ui->Print("Successfully verified integrity of /system for MDTP.\n");
    }
#endif /* USE_MDTP */
    return result;
}
#endif
#ifndef LENOVO_RECOVERY_SUPPORT   //wuwl9 modify for lenovo recovery
int
install_package(const char* path, bool* wipe_cache, const char* install_file,
                bool needs_mount)
{
    modified_flash = true;

    FILE* install_log = fopen_path(install_file, "w");
    if (install_log) {
        fputs(path, install_log);
        fputc('\n', install_log);
    } else {
        LOGE("failed to open last_install: %s\n", strerror(errno));
    }
    int result;
    if (setup_install_mounts() != 0) {
        LOGE("failed to set up expected mounts for install; aborting\n");
        result = INSTALL_ERROR;
    } else {
        result = really_install_package(path, wipe_cache, needs_mount);
    }
    if (install_log) {
        fputc(result == INSTALL_SUCCESS ? '1' : '0', install_log);
        fputc('\n', install_log);
        fclose(install_log);
    }
    return result;
}
#else  //wuwl9 modify for lenovo recovery
int install_package(const char* path, int* wipe_cache, const char* install_file,
                int needs_mount) 
{
    FILE* install_log = fopen_path(install_file, "w");
    if (install_log) {
        fputs(path, install_log);
        fputc('\n', install_log);
    } else {
        LOGE("failed to open last_install: %s\n", strerror(errno));
    }
    int result;
    ensure_path_mounted("/cache");
    result = really_install_package(path, wipe_cache, needs_mount);
    if (install_log) {
        fputc(result == INSTALL_SUCCESS ? '1' : '0', install_log);
        fputc('\n', install_log);
        fclose(install_log);
    }
    return result;
}
#endif
