// Patches author: backslashxx @ Github
// Coccinelle conversion: syscall_hook_patches.sh
// Tested kernel versions: 5.4, 4.19, 4.14, 4.9, 4.4, 3.18
// 20250309
// PATCH_LEVEL: 1.9

// ========================================
// fs/exec.c patches
// ========================================

@ksu_execve_sucompat_exists@
@@
#ifdef CONFIG_KSU
__attribute__((hot))
extern int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
				       void *__never_use_argv, void *__never_use_envp,
				       int *__never_use_flags);
#endif

@ksu_execve_sucompat_insert_1 depends on ksu_execve_sucompat_exists@
@@
-return do_execve(getname(filename), argv, envp);
+#ifdef CONFIG_KSU
+	ksu_handle_execve_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL);
+#endif
+return do_execve(getname(filename), argv, envp);

@ksu_execve_sucompat_insert_2 depends on ksu_execve_sucompat_exists@
@@
-return compat_do_execve(getname(filename), argv, envp);
+#ifdef CONFIG_KSU
+	ksu_handle_execve_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL);
+#endif
+return compat_do_execve(getname(filename), argv, envp);

@ksu_execveat_hook_header@
@@
 static int do_execveat_common(int fd, struct filename *filename,
+#ifdef CONFIG_KSU
+extern bool ksu_execveat_hook __read_mostly;
+extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
+			void *envp, int *flags);
+extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
+				 void *envp, int *flags);
+#endif

@ksu_execveat_insert depends on ksu_execveat_hook_header@
@@
 if (IS_ERR(filename))
+#ifdef CONFIG_KSU
+	if (unlikely(ksu_execveat_hook))
+		ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
+	else
+		ksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);
+#endif

// ========================================
// fs/open.c patches
// ========================================

@ksu_faccessat_header@
@@
+#ifdef CONFIG_KSU
+__attribute__((hot))
+extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
+				int *mode, int *flags);
+#endif
 SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)

@ksu_faccessat_old_kernel depends on ksu_faccessat_header@
@@
 if (mode & ~S_IRWXO)
+#ifdef CONFIG_KSU
+	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
+#endif

@ksu_faccessat_new_kernel depends on ksu_faccessat_header@
@@
-return do_faccessat(dfd, filename, mode);
+#ifdef CONFIG_KSU
+	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
+#endif
+return do_faccessat(dfd, filename, mode);

// ========================================
// fs/read_write.c patches
// ========================================

@ksu_read_hook_header@
@@
+#ifdef CONFIG_KSU
+extern bool ksu_vfs_read_hook __read_mostly;
+extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,
+			char __user **buf_ptr, size_t *count_ptr);
+#endif
 SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)

@ksu_read_old_kernel depends on ksu_read_hook_header@
@@
 if (f.file) {
+#ifdef CONFIG_KSU
+	if (unlikely(ksu_vfs_read_hook))
+		ksu_handle_sys_read(fd, &buf, &count);
+#endif

@ksu_read_new_kernel depends on ksu_read_hook_header@
@@
-return ksys_read(fd, buf, count);
+#ifdef CONFIG_KSU
+	if (unlikely(ksu_vfs_read_hook))
+		ksu_handle_sys_read(fd, &buf, &count);
+#endif
+return ksys_read(fd, buf, count);

// ========================================
// fs/stat.c patches
// ========================================

@ksu_stat_header@
@@
+#ifdef CONFIG_KSU
+__attribute__((hot))
+extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
+				int *flags);
+#endif
 #if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)

@ksu_stat_call depends on ksu_stat_header@
@@
-error = vfs_fstatat(dfd, filename, &stat, flag);
+#ifdef CONFIG_KSU
+	ksu_handle_stat(&dfd, &filename, &flag);
+#endif
+error = vfs_fstatat(dfd, filename, &stat, flag);

@ksu_newfstat_header@
@@
+#ifdef CONFIG_KSU
+extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
+#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
+extern void ksu_handle_fstat64_ret(unsigned int *fd, struct stat64 __user **statbuf_ptr);
+#endif
+#endif
 SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)

@ksu_newfstat_call depends on ksu_newfstat_header@
@@
 error = cp_new_stat(&stat, statbuf);
+#ifdef CONFIG_KSU
+	ksu_handle_newfstat_ret(&fd, &statbuf);
+#endif

@ksu_fstat64_call depends on ksu_newfstat_header@
@@
 error = cp_new_stat64(&stat, statbuf);
+#ifdef CONFIG_KSU
+	ksu_handle_fstat64_ret(&fd, &statbuf);
+#endif

// ========================================
// fs/namei.c patches
// ========================================

@ksu_namei_header@
@@
+#ifdef CONFIG_KSU
+extern int ksu_handle_chdir(struct filename *filename);
+#endif
 SYSCALL_DEFINE1(chdir, const char __user *, filename)

@ksu_namei_call depends on ksu_namei_header@
@@
 error = -ENOENT;
+#ifdef CONFIG_KSU
+	ksu_handle_chdir(filename);
+#endif

// ========================================
// drivers/input/input.c patches
// ========================================

@ksu_input_header@
@@
+#ifdef CONFIG_KSU
+extern int ksu_handle_input_handle_event(unsigned int type, unsigned int code, int value);
+#endif
 static void input_handle_event(struct input_dev *dev,
 				unsigned int type, unsigned int code, int value)

@ksu_input_call depends on ksu_input_header@
@@
 if (disposition != INPUT_IGNORE_EVENT && type != EV_NONE)
+#ifdef CONFIG_KSU
+	ksu_handle_input_handle_event(type, code, value);
+#endif

// ========================================
// drivers/tty/pty.c patches
// ========================================

@ksu_devpts_header@
@@
+#ifdef CONFIG_KSU
+extern int ksu_handle_devpts_ioctl(unsigned int cmd);
+#endif
 static int pty_bsd_ioctl(struct tty_struct *tty, struct file *file,
 			unsigned int cmd, unsigned long arg)

@ksu_devpts_call depends on ksu_devpts_header@
@@
 switch (cmd) {
+#ifdef CONFIG_KSU
+	ksu_handle_devpts_ioctl(cmd);
+#endif

// ========================================
// security/security.c patches
// ========================================

@ksu_security_header_old@
@@
+#ifdef CONFIG_KSU
+extern int ksu_bprm_check(struct linux_binprm *bprm);
+extern int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry);
+extern int ksu_handle_setuid(struct cred *new, const struct cred *old);
+#endif
 int security_binder_set_context_mgr(struct task_struct

@ksu_security_header_new depends on !ksu_security_header_old@
@@
+#ifdef CONFIG_KSU
+extern int ksu_bprm_check(struct linux_binprm *bprm);
+extern int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry);
+extern int ksu_handle_setuid(struct cred *new, const struct cred *old);
+extern int ksu_file_permission(struct file *file, int mask);
+#endif
 int security_binder_set_context_mgr(struct task_struct

@ksu_bprm_call@
@@
-ret = security_ops->bprm_check_security(bprm);
+#ifdef CONFIG_KSU
+	ksu_bprm_check(bprm);
+#endif
+ret = security_ops->bprm_check_security(bprm);

@ksu_rename_call@
@@
-if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
+#ifdef CONFIG_KSU
+	ksu_handle_rename(old_dentry, new_dentry);
+#endif
+if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||

@ksu_file_perm_call@
@@
-ret = security_ops->file_permission(file, mask);
+#ifdef CONFIG_KSU
+	ksu_file_permission(file, mask);
+#endif
+ret = security_ops->file_permission(file, mask);

@ksu_setuid_call@
@@
-return security_ops->task_fix_setuid(new, old, flags);
+#ifdef CONFIG_KSU
+	ksu_handle_setuid(new, old);
+#endif
+return security_ops->task_fix_setuid(new, old, flags);

// ========================================
// security/selinux/hooks.c patches
// ========================================

@ksu_selinux_ksu_sid@
@@
 int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);
+#ifdef CONFIG_KSU
+	static u32 ksu_sid;
+	char *secdata;
+#endif

@ksu_selinux_error@
@@
 if (!nnp && !nosuid)
+#ifdef CONFIG_KSU
+	int error;
+	u32 seclen;
+#endif

@ksu_selinux_secctx@
@@
 return 0; /* No change in credentials */
+#ifdef CONFIG_KSU
+	if (!ksu_sid)
+		security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &ksu_sid);
+
+	error = security_secid_to_secctx(old_tsec->sid, &secdata, &seclen);
+	if (!error) {
+		rc = strcmp("u:r:init:s0", secdata);
+		security_release_secctx(secdata, seclen);
+		if (rc == 0 && new_tsec->sid == ksu_sid)
+			return 0;
+	}
+#endif

// ========================================
// kernel/reboot.c patches
// ========================================

@ksu_reboot_header@
@@
+#ifdef CONFIG_KSU
+extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
+#endif
 SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,

@ksu_reboot_call depends on ksu_reboot_header@
@@
 int ret = 0;
+#ifdef CONFIG_KSU
+	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
+#endif

// ========================================
// kernel/sys.c patches
// ========================================

@ksu_setresuid_header@
@@
+#ifdef CONFIG_KSU
+extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);
+#endif
 SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)

@ksu_setresuid_old depends on ksu_setresuid_header@
@@
-return __sys_setresuid(ruid, euid, suid);
+#ifdef CONFIG_KSU_SUSFS
+	if (ksu_handle_setresuid(ruid, euid, suid)) {
+		pr_info("Something wrong with ksu_handle_setresuid()\n");
+	}
+#endif
+return __sys_setresuid(ruid, euid, suid);

@ksu_setresuid_new depends on ksu_setresuid_header@
@@
 if ((ruid != (uid_t) -1) && !uid_valid(kruid))
+#ifdef CONFIG_KSU_SUSFS
+	if (ksu_handle_setresuid(ruid, euid, suid)) {
+		pr_info("Something wrong with ksu_handle_setresuid()\n");
+	}
+#endif
