/*
 * System call argument lists.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.14 1995/10/14 20:25:06 christos Exp 
 */

#define	syscallarg(x)	union { x datum; register_t pad; }

struct svr4_sys_open_args {
	syscallarg(char *) path;
	syscallarg(int) flags;
	syscallarg(int) mode;
};

struct svr4_sys_wait_args {
	syscallarg(int *) status;
};

struct svr4_sys_creat_args {
	syscallarg(char *) path;
	syscallarg(int) mode;
};

struct svr4_sys_execv_args {
	syscallarg(char *) path;
	syscallarg(char **) argp;
};

struct svr4_sys_time_args {
	syscallarg(svr4_time_t *) t;
};

struct svr4_sys_mknod_args {
	syscallarg(char *) path;
	syscallarg(int) mode;
	syscallarg(int) dev;
};

struct svr4_sys_break_args {
	syscallarg(caddr_t) nsize;
};

struct svr4_sys_stat_args {
	syscallarg(char *) path;
	syscallarg(struct svr4_stat *) ub;
};

struct svr4_sys_alarm_args {
	syscallarg(unsigned) sec;
};

struct svr4_sys_fstat_args {
	syscallarg(int) fd;
	syscallarg(struct svr4_stat *) sb;
};

struct svr4_sys_access_args {
	syscallarg(char *) path;
	syscallarg(int) flags;
};

struct svr4_sys_kill_args {
	syscallarg(int) pid;
	syscallarg(int) signum;
};

struct svr4_sys_pgrpsys_args {
	syscallarg(int) cmd;
	syscallarg(int) pid;
	syscallarg(int) pgid;
};

struct svr4_sys_times_args {
	syscallarg(struct tms *) tp;
};

struct svr4_sys_signal_args {
	syscallarg(int) signum;
	syscallarg(svr4_sig_t) handler;
};

struct svr4_sys_msgsys_args {
	syscallarg(int) what;
	syscallarg(int) a2;
	syscallarg(int) a3;
	syscallarg(int) a4;
	syscallarg(int) a5;
};

struct svr4_sys_sysarch_args {
	syscallarg(int) op;
	syscallarg(void *) a1;
};

struct svr4_sys_shmsys_args {
	syscallarg(int) what;
	syscallarg(int) a2;
	syscallarg(int) a3;
	syscallarg(int) a4;
};

struct svr4_sys_semsys_args {
	syscallarg(int) what;
	syscallarg(int) a2;
	syscallarg(int) a3;
	syscallarg(int) a4;
	syscallarg(int) a5;
};

struct svr4_sys_ioctl_args {
	syscallarg(int) fd;
	syscallarg(u_long) com;
	syscallarg(caddr_t) data;
};

struct svr4_sys_utssys_args {
	syscallarg(void *) a1;
	syscallarg(void *) a2;
	syscallarg(int) sel;
	syscallarg(void *) a3;
};

struct svr4_sys_execve_args {
	syscallarg(char *) path;
	syscallarg(char **) argp;
	syscallarg(char **) envp;
};

struct svr4_sys_fcntl_args {
	syscallarg(int) fd;
	syscallarg(int) cmd;
	syscallarg(char *) arg;
};

struct svr4_sys_ulimit_args {
	syscallarg(int) cmd;
	syscallarg(long) newlimit;
};

struct svr4_sys_getdents_args {
	syscallarg(int) fd;
	syscallarg(char *) buf;
	syscallarg(int) nbytes;
};

struct svr4_sys_getmsg_args {
	syscallarg(int) fd;
	syscallarg(struct svr4_strbuf *) ctl;
	syscallarg(struct svr4_strbuf *) dat;
	syscallarg(int *) flags;
};

struct svr4_sys_putmsg_args {
	syscallarg(int) fd;
	syscallarg(struct svr4_strbuf *) ctl;
	syscallarg(struct svr4_strbuf *) dat;
	syscallarg(int) flags;
};

struct svr4_sys_poll_args {
	syscallarg(struct svr4_pollfd *) fds;
	syscallarg(long) nfds;
	syscallarg(int) timeout;
};

struct svr4_sys_lstat_args {
	syscallarg(char *) path;
	syscallarg(struct svr4_stat *) ub;
};

struct svr4_sys_sigprocmask_args {
	syscallarg(int) how;
	syscallarg(svr4_sigset_t *) set;
	syscallarg(svr4_sigset_t *) oset;
};

struct svr4_sys_sigsuspend_args {
	syscallarg(svr4_sigset_t *) ss;
};

struct svr4_sys_sigaltstack_args {
	syscallarg(struct svr4_sigaltstack *) nss;
	syscallarg(struct svr4_sigaltstack *) oss;
};

struct svr4_sys_sigaction_args {
	syscallarg(int) signum;
	syscallarg(struct svr4_sigaction *) nsa;
	syscallarg(struct svr4_sigaction *) osa;
};

struct svr4_sys_sigpending_args {
	syscallarg(int) what;
	syscallarg(svr4_sigset_t *) mask;
};

struct svr4_sys_context_args {
	syscallarg(int) func;
	syscallarg(struct svr4_ucontext *) uc;
};

struct svr4_sys_statvfs_args {
	syscallarg(char *) path;
	syscallarg(struct svr4_statvfs *) fs;
};

struct svr4_sys_fstatvfs_args {
	syscallarg(int) fd;
	syscallarg(struct svr4_statvfs *) fs;
};

struct svr4_sys_waitsys_args {
	syscallarg(int) grp;
	syscallarg(int) id;
	syscallarg(union svr4_siginfo *) info;
	syscallarg(int) options;
};

struct svr4_sys_hrtsys_args {
	syscallarg(int) cmd;
	syscallarg(int) fun;
	syscallarg(int) sub;
	syscallarg(void *) rv1;
	syscallarg(void *) rv2;
};

struct svr4_sys_mmap_args {
	syscallarg(svr4_caddr_t) addr;
	syscallarg(svr4_size_t) len;
	syscallarg(int) prot;
	syscallarg(int) flags;
	syscallarg(int) fd;
	syscallarg(svr4_off_t) pos;
};

struct svr4_sys_xstat_args {
	syscallarg(int) two;
	syscallarg(char *) path;
	syscallarg(struct svr4_xstat *) ub;
};

struct svr4_sys_lxstat_args {
	syscallarg(int) two;
	syscallarg(char *) path;
	syscallarg(struct svr4_xstat *) ub;
};

struct svr4_sys_fxstat_args {
	syscallarg(int) two;
	syscallarg(int) fd;
	syscallarg(struct svr4_xstat *) sb;
};

struct svr4_sys_setrlimit_args {
	syscallarg(int) which;
	syscallarg(struct ogetrlimit *) rlp;
};

struct svr4_sys_getrlimit_args {
	syscallarg(int) which;
	syscallarg(struct ogetrlimit *) rlp;
};

struct svr4_sys_uname_args {
	syscallarg(struct svr4_utsname *) name;
	syscallarg(int) dummy;
};

struct svr4_sys_sysconfig_args {
	syscallarg(int) name;
};

struct svr4_sys_systeminfo_args {
	syscallarg(int) what;
	syscallarg(char *) buf;
	syscallarg(long) len;
};

struct svr4_sys_fchroot_args {
	syscallarg(int) fd;
};

struct svr4_sys_gettimeofday_args {
	syscallarg(struct timeval *) tp;
};

/*
 * System call prototypes.
 */

int	sys_nosys	__P((struct proc *, void *, register_t *));
int	sys_exit	__P((struct proc *, void *, register_t *));
int	sys_fork	__P((struct proc *, void *, register_t *));
int	sys_read	__P((struct proc *, void *, register_t *));
int	sys_write	__P((struct proc *, void *, register_t *));
int	svr4_sys_open	__P((struct proc *, void *, register_t *));
int	sys_close	__P((struct proc *, void *, register_t *));
int	svr4_sys_wait	__P((struct proc *, void *, register_t *));
int	svr4_sys_creat	__P((struct proc *, void *, register_t *));
int	sys_link	__P((struct proc *, void *, register_t *));
int	sys_unlink	__P((struct proc *, void *, register_t *));
int	svr4_sys_execv	__P((struct proc *, void *, register_t *));
int	sys_chdir	__P((struct proc *, void *, register_t *));
int	svr4_sys_time	__P((struct proc *, void *, register_t *));
int	svr4_sys_mknod	__P((struct proc *, void *, register_t *));
int	sys_chmod	__P((struct proc *, void *, register_t *));
int	sys_chown	__P((struct proc *, void *, register_t *));
int	svr4_sys_break	__P((struct proc *, void *, register_t *));
int	svr4_sys_stat	__P((struct proc *, void *, register_t *));
int	compat_43_sys_lseek	__P((struct proc *, void *, register_t *));
int	sys_getpid	__P((struct proc *, void *, register_t *));
int	sys_setuid	__P((struct proc *, void *, register_t *));
int	sys_getuid	__P((struct proc *, void *, register_t *));
int	svr4_sys_alarm	__P((struct proc *, void *, register_t *));
int	svr4_sys_fstat	__P((struct proc *, void *, register_t *));
int	svr4_sys_access	__P((struct proc *, void *, register_t *));
int	sys_sync	__P((struct proc *, void *, register_t *));
int	svr4_sys_kill	__P((struct proc *, void *, register_t *));
int	svr4_sys_pgrpsys	__P((struct proc *, void *, register_t *));
int	sys_dup	__P((struct proc *, void *, register_t *));
int	sys_pipe	__P((struct proc *, void *, register_t *));
int	svr4_sys_times	__P((struct proc *, void *, register_t *));
int	sys_setgid	__P((struct proc *, void *, register_t *));
int	sys_getgid	__P((struct proc *, void *, register_t *));
int	svr4_sys_signal	__P((struct proc *, void *, register_t *));
#ifdef SYSVMSG
int	svr4_sys_msgsys	__P((struct proc *, void *, register_t *));
#else
#endif
int	svr4_sys_sysarch	__P((struct proc *, void *, register_t *));
#ifdef SYSVSHM
int	svr4_sys_shmsys	__P((struct proc *, void *, register_t *));
#else
#endif
#ifdef SYSVSEM
int	svr4_sys_semsys	__P((struct proc *, void *, register_t *));
#else
#endif
int	svr4_sys_ioctl	__P((struct proc *, void *, register_t *));
int	svr4_sys_utssys	__P((struct proc *, void *, register_t *));
int	sys_fsync	__P((struct proc *, void *, register_t *));
int	svr4_sys_execve	__P((struct proc *, void *, register_t *));
int	sys_umask	__P((struct proc *, void *, register_t *));
int	sys_chroot	__P((struct proc *, void *, register_t *));
int	svr4_sys_fcntl	__P((struct proc *, void *, register_t *));
int	svr4_sys_ulimit	__P((struct proc *, void *, register_t *));
int	sys_rmdir	__P((struct proc *, void *, register_t *));
int	sys_mkdir	__P((struct proc *, void *, register_t *));
int	svr4_sys_getdents	__P((struct proc *, void *, register_t *));
int	svr4_sys_getmsg	__P((struct proc *, void *, register_t *));
int	svr4_sys_putmsg	__P((struct proc *, void *, register_t *));
int	svr4_sys_poll	__P((struct proc *, void *, register_t *));
int	svr4_sys_lstat	__P((struct proc *, void *, register_t *));
int	sys_symlink	__P((struct proc *, void *, register_t *));
int	sys_readlink	__P((struct proc *, void *, register_t *));
int	sys_getgroups	__P((struct proc *, void *, register_t *));
int	sys_setgroups	__P((struct proc *, void *, register_t *));
int	sys_fchmod	__P((struct proc *, void *, register_t *));
int	sys_fchown	__P((struct proc *, void *, register_t *));
int	svr4_sys_sigprocmask	__P((struct proc *, void *, register_t *));
int	svr4_sys_sigsuspend	__P((struct proc *, void *, register_t *));
int	svr4_sys_sigaltstack	__P((struct proc *, void *, register_t *));
int	svr4_sys_sigaction	__P((struct proc *, void *, register_t *));
int	svr4_sys_sigpending	__P((struct proc *, void *, register_t *));
int	svr4_sys_context	__P((struct proc *, void *, register_t *));
int	svr4_sys_statvfs	__P((struct proc *, void *, register_t *));
int	svr4_sys_fstatvfs	__P((struct proc *, void *, register_t *));
int	svr4_sys_waitsys	__P((struct proc *, void *, register_t *));
int	svr4_sys_hrtsys	__P((struct proc *, void *, register_t *));
int	svr4_sys_mmap	__P((struct proc *, void *, register_t *));
int	sys_mprotect	__P((struct proc *, void *, register_t *));
int	sys_munmap	__P((struct proc *, void *, register_t *));
int	sys_fpathconf	__P((struct proc *, void *, register_t *));
int	sys_vfork	__P((struct proc *, void *, register_t *));
int	sys_fchdir	__P((struct proc *, void *, register_t *));
int	sys_readv	__P((struct proc *, void *, register_t *));
int	sys_writev	__P((struct proc *, void *, register_t *));
int	svr4_sys_xstat	__P((struct proc *, void *, register_t *));
int	svr4_sys_lxstat	__P((struct proc *, void *, register_t *));
int	svr4_sys_fxstat	__P((struct proc *, void *, register_t *));
int	svr4_sys_setrlimit	__P((struct proc *, void *, register_t *));
int	svr4_sys_getrlimit	__P((struct proc *, void *, register_t *));
int	sys_rename	__P((struct proc *, void *, register_t *));
int	svr4_sys_uname	__P((struct proc *, void *, register_t *));
int	sys_setegid	__P((struct proc *, void *, register_t *));
int	svr4_sys_sysconfig	__P((struct proc *, void *, register_t *));
int	sys_adjtime	__P((struct proc *, void *, register_t *));
int	svr4_sys_systeminfo	__P((struct proc *, void *, register_t *));
int	sys_seteuid	__P((struct proc *, void *, register_t *));
int	svr4_sys_fchroot	__P((struct proc *, void *, register_t *));
int	svr4_sys_vhangup	__P((struct proc *, void *, register_t *));
int	svr4_sys_gettimeofday	__P((struct proc *, void *, register_t *));
int	sys_getitimer	__P((struct proc *, void *, register_t *));
int	sys_setitimer	__P((struct proc *, void *, register_t *));
