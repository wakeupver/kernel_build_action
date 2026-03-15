// ============================================================
// classic.cocci — KernelSU-Next manual hooks for non-GKI kernels
// Reference: https://kernelsu-next.github.io/webpage/pages/how-to-integrate-for-non-gki.html
// ============================================================


// ============================================================
// File: fs/exec.c
// Hook: do_execve — add ksu_handle_execveat call
// ============================================================

@exec_do_execve depends on file in "fs/exec.c"@
attribute name __user;
identifier filename, argv, envp;
@@

+#ifdef CONFIG_KSU
+__attribute__((hot))
+extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
+				void *argv, void *envp, int *flags);
+#endif
do_execve(struct filename *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp) {
...
+#ifdef CONFIG_KSU
+ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
+#endif
  return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}

// ============================================================
// File: fs/exec.c
// Hook: compat_do_execve — 32-bit ksud and 32-on-64 support
// ============================================================

@exec_compat_do_execve depends on file in "fs/exec.c"@
identifier filename, argv, envp;
@@

compat_do_execve(struct filename *filename, ...) {
...
+#ifdef CONFIG_KSU // 32-bit ksud and 32-on-64 support
+ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
+#endif
  return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}

// ============================================================
// File: fs/open.c
// Hook: do_faccessat (newer kernels)
// ============================================================

@do_faccessat depends on file in "fs/open.c"@
attribute name __user;
identifier dfd, filename, mode;
statement S1, S2;
@@

+#ifdef CONFIG_KSU
+__attribute__((hot))
+extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
+				int *mode, int *flags);
+#endif
do_faccessat(int dfd, const char __user *filename, int mode) {
... when != S1
+#ifdef CONFIG_KSU
+ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
+#endif
S2
...
}

// ============================================================
// File: fs/open.c
// Hook: SYSCALL_DEFINE3(faccessat, ...) — older kernels without do_faccessat
// ============================================================

@syscall_faccessat depends on file in "fs/open.c" && never do_faccessat@
attribute name __user;
identifier dfd, filename, mode;
statement S1, S2;
@@

+#ifdef CONFIG_KSU
+__attribute__((hot))
+extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
+				int *mode, int *flags);
+#endif
// SYSCALL_DEFINE3(faccessat, ...) {}
faccessat(int dfd, const char __user *filename, int mode) {
... when != S1
+#ifdef CONFIG_KSU
+ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
+#endif
S2
...
}

// ============================================================
// File: fs/read_write.c
// Hook: SYSCALL_DEFINE3(read, ...) — intercept sys_read
// ============================================================

@sys_read depends on file in "fs/read_write.c"@
attribute name __read_mostly, __user;
identifier fd, buf, count;
statement S1, S2;
@@

+#ifdef CONFIG_KSU
+extern bool ksu_vfs_read_hook __read_mostly;
+extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,
+				char __user **buf_ptr, size_t *count_ptr);
+#endif
read(unsigned int fd, char __user *buf, size_t count) {
... when != S1
+#ifdef CONFIG_KSU
+if (unlikely(ksu_vfs_read_hook))
+  ksu_handle_sys_read(fd, &buf, &count);
+#endif
S2
...
}

// ============================================================
// File: fs/stat.c
// Hook: SYSCALL_DEFINE4(newfstatat, ...) — vfs_statx variant (newer kernels)
// ============================================================

@stat_vfs_statx depends on file in "fs/stat.c"@
attribute name __user;
identifier dfd, filename, flags;
statement S1, S2;
@@

+#ifdef CONFIG_KSU
+__attribute__((hot))
+extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
+				int *flags);
+#endif
vfs_statx(int dfd, const char __user *filename, int flags, ...) {
... when != S1
+#ifdef CONFIG_KSU
+ksu_handle_stat(&dfd, &filename, &flags);
+#endif
S2
...
}

// ============================================================
// File: fs/stat.c
// Hook: SYSCALL_DEFINE4(newfstatat, ...) — vfs_fstatat fallback (older kernels)
// ============================================================

@stat_newfstatat depends on file in "fs/stat.c" && never stat_vfs_statx@
attribute name __user;
identifier dfd, filename, statbuf, flag;
statement S1, S2;
@@

+#ifdef CONFIG_KSU
+__attribute__((hot))
+extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
+				int *flags);
+#endif
newfstatat(int dfd, const char __user *filename,
		struct stat __user *statbuf, int flag) {
... when != S1
+#ifdef CONFIG_KSU
+ksu_handle_stat(&dfd, &filename, &flag);
+#endif
S2
...
}

// ============================================================
// File: kernel/reboot.c
// Hook: SYSCALL_DEFINE4(reboot, ...) — intercept sys_reboot
// ============================================================

@sys_reboot depends on file in "kernel/reboot.c"@
attribute name __user;
identifier magic1, magic2, cmd, arg;
statement S1, S2;
@@

+#ifdef CONFIG_KSU
+extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
+				void __user **arg);
+#endif
reboot(int magic1, int magic2, unsigned int cmd, void __user *arg) {
... when != S1
+#ifdef CONFIG_KSU
+ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
+#endif
S2
...
}

// ============================================================
// File: fs/namespace.c
// Add can_umount + path_umount if missing (needed for KSU mount support)
// ============================================================

@has_can_umount depends on file in "fs/namespace.c"@
identifier path, flags;
@@
can_umount(const struct path *path, int flags) { ... }

@path_umount depends on file in "fs/namespace.c" && never has_can_umount@
@@
+static int can_umount(const struct path *path, int flags)
+{
+struct mount *mnt = real_mount(path->mnt);
+
+if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
+  return -EINVAL;
+if (!may_mount())
+  return -EPERM;
+if (path->dentry != path->mnt->mnt_root)
+  return -EINVAL;
+if (!check_mnt(mnt))
+  return -EINVAL;
+if (mnt->mnt.mnt_flags & MNT_LOCKED) /* Check optimistically */
+  return -EINVAL;
+if (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))
+  return -EPERM;
+return 0;
+}
+
+int path_umount(struct path *path, int flags)
+{
+struct mount *mnt = real_mount(path->mnt);
+int ret;
+
+ret = can_umount(path, flags);
+if (!ret)
+  ret = do_umount(mnt, flags);
+
+/* we mustn't call path_put() as that would clear mnt_expiry_mark */
+dput(path->dentry);
+mntput_no_expire(mnt);
+return ret;
+}
mnt_alloc_id(...) { ... }
