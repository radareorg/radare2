/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <signal.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <kvm.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <kvm.h>
#include <limits.h>
#include "bsd_debug.h"
#if __KFBSD__ || __DragonFly__
#include <sys/user.h>
#include <libutil.h>
#elif __OpenBSD__ || __NetBSD__
#include <sys/proc.h>
#endif

#if __KFBSD__
static void addr_to_string (struct sockaddr_storage *ss, char *buffer, int buflen) {
	char buffer2[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;

	if (buflen > 0)
	switch (ss->ss_family) {
	case AF_LOCAL:
		sun = (struct sockaddr_un *)ss;
		strncpy (buffer, (sun && *sun->sun_path)?
			sun->sun_path: "-", buflen - 1);
		break;
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		snprintf (buffer, buflen, "%s:%d", inet_ntoa (sin->sin_addr),
				ntohs (sin->sin_port));
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		if (inet_ntop (AF_INET6, &sin6->sin6_addr, buffer2,
				sizeof (buffer2)) != NULL) {
			snprintf (buffer, buflen, "%s.%d", buffer2,
				ntohs (sin6->sin6_port));
		} else {
			strcpy (buffer, "-");
		}
		break;
	default:
		*buffer = 0;
		break;
	}
}
#endif

int bsd_handle_signals(RDebug *dbg) {
#if __KFBSD__
	// Trying to figure out a bit by the signal
	struct ptrace_lwpinfo linfo = {0};
	siginfo_t siginfo;
	int ret = ptrace (PT_LWPINFO, dbg->pid, (char *)&linfo, sizeof (linfo));
	if (ret == -1) {
		if (errno == ESRCH) {
			dbg->reason.type = R_DEBUG_REASON_DEAD;
			return 0;
		}
		r_sys_perror ("ptrace PTRACE_LWPINFO");
		return -1;
	}

	// Not stopped by the signal
	if (linfo.pl_event == PL_EVENT_NONE) {
		dbg->reason.type = R_DEBUG_REASON_BREAKPOINT;
		return 0;
	}

	siginfo = linfo.pl_siginfo;
	dbg->reason.type = R_DEBUG_REASON_SIGNAL;
	dbg->reason.signum = siginfo.si_signo;

	switch (dbg->reason.signum) {
		case SIGABRT:
			dbg->reason.type = R_DEBUG_REASON_ABORT;
			break;
		case SIGSEGV:
			dbg->reason.type = R_DEBUG_REASON_SEGFAULT;
			break;
	}

	return 0;
#else
	return -1;
#endif
}

int bsd_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	int r = -1;
	switch (type) {
		case R_REG_TYPE_GPR:
			r = ptrace (PT_SETREGS, dbg->pid,
				(caddr_t)buf, sizeof (struct reg));
			break;
		case R_REG_TYPE_DRX:
#if __KFBSD__ || __NetBSD__
			r = ptrace (PT_SETDBREGS, dbg->pid, (caddr_t)buf, sizeof (struct dbreg));
#endif
			break;
		case R_REG_TYPE_FPU:
			r = ptrace (PT_SETFPREGS, dbg->pid, (caddr_t)buf, sizeof (struct fpreg));
			break;
	}

	return (r == 0 ? true : false);
}

RDebugInfo *bsd_info(RDebug *dbg, const char *arg) {
#if __KFBSD__
	struct kinfo_proc *kp;
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) {
		return NULL;
	}

	if (!(kp = kinfo_getproc (dbg->pid))) {
		free (rdi);
		return NULL;
	}

	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = kp->ki_uid;
	rdi->gid = kp->ki_pgid;
	rdi->exe = strdup (kp->ki_comm);

	switch (kp->ki_stat) {
		case SSLEEP:
			rdi->status = R_DBG_PROC_SLEEP;
			break;
		case SSTOP:
			rdi->status = R_DBG_PROC_STOP;
			break;
		case SZOMB:
			rdi->status = R_DBG_PROC_ZOMBIE;
			break;
		case SRUN:
		case SIDL:
		case SLOCK:
		case SWAIT:
			rdi->status = R_DBG_PROC_RUN;
			break;
		default:
			rdi->status = R_DBG_PROC_DEAD;
	}

	free (kp);

	return rdi;
#elif __OpenBSD__
	struct kinfo_proc *kp;
	char err[_POSIX2_LINE_MAX];
	int rc;
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) {
		return NULL;
	}

	kvm_t *kd = kvm_openfiles (NULL, NULL, NULL, KVM_NO_FILES, err);
	if (!kd) {
		free (rdi);
		return NULL;
	}

	kp = kvm_getprocs (kd, KERN_PROC_PID, dbg->pid, sizeof (*kp), &rc);
	if (kp) {
		rdi->pid = dbg->pid;
		rdi->tid = dbg->tid;
		rdi->uid = kp->p_uid;
		rdi->gid = kp->p__pgid;
		rdi->exe = strdup (kp->p_comm);

		rdi->status = R_DBG_PROC_STOP;

		if (kp->p_psflags & PS_ZOMBIE) {
				rdi->status = R_DBG_PROC_ZOMBIE;
		} else if (kp->p_psflags & PS_STOPPED){
				rdi->status = R_DBG_PROC_STOP;
		} else if (kp->p_psflags & PS_PPWAIT) {
				rdi->status = R_DBG_PROC_SLEEP;
		} else if ((kp->p_psflags & PS_EXEC) || (kp->p_psflags & PS_INEXEC)) {
				rdi->status = R_DBG_PROC_RUN;
		}

	}

	kvm_close (kd);

	return rdi;
#elif __NetBSD__
	struct kinfo_proc2 *kp;
	char err[_POSIX2_LINE_MAX];
	int np;
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) {
		return NULL;
	}

	kvm_t *kd = kvm_openfiles (NULL, NULL, NULL, KVM_NO_FILES, err);
	if (!kd) {
		free (rdi);
		return NULL;
	}

	kp = kvm_getproc2 (kd, KERN_PROC_PID, dbg->pid, sizeof(*kp), &np);
	if (kp) {
		rdi->pid = dbg->pid;
		rdi->tid = dbg->tid;
		rdi->uid = kp->p_uid;
		rdi->gid = kp->p__pgid;
		rdi->exe = strdup (kp->p_comm);

		rdi->status = R_DBG_PROC_STOP;

		switch (kp->p_stat) {
			case SDEAD:
				rdi->status = R_DBG_PROC_DEAD;
				break;
			case SSTOP:
				rdi->status = R_DBG_PROC_STOP;
				break;
			case SZOMB:
				rdi->status = R_DBG_PROC_ZOMBIE;
				break;
			case SACTIVE:
			case SIDL:
			case SDYING:
				rdi->status = R_DBG_PROC_RUN;
				break;
			default:
				rdi->status = R_DBG_PROC_SLEEP;
		}
	}

	kvm_close (kd);

	return rdi;
#endif
}

RList *bsd_pid_list(RDebug *dbg, int pid, RList *list) {
#if __KFBSD__
#ifdef __NetBSD__
# define KVM_OPEN_FLAG KVM_NO_FILES
# define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getproc2 (kd, opt, arg, sizeof(struct kinfo_proc2), cntptr)
# define KP_COMM(x) (x)->p_comm
# define KP_PID(x) (x)->p_pid
# define KP_PPID(x) (x)->p_ppid
# define KP_UID(x) (x)->p_uid
# define KINFO_PROC kinfo_proc2
#elif defined(__OpenBSD__)
# define KVM_OPEN_FLAG KVM_NO_FILES
# define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getprocs (kd, opt, arg, sizeof(struct kinfo_proc), cntptr)
# define KP_COMM(x) (x)->p_comm
# define KP_PID(x) (x)->p_pid
# define KP_PPID(x) (x)->p_ppid
# define KP_UID(x) (x)->p_uid
# define KINFO_PROC kinfo_proc
#elif __DragonFly__
# define KVM_OPEN_FLAG O_RDONLY
# define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getprocs (kd, opt, arg, cntptr)
# define KP_COMM(x) (x)->kp_comm
# define KP_PID(x) (x)->kp_pid
# define KP_PPID(x) (x)->kp_ppid
# define KP_UID(x) (x)->kp_uid
# define KINFO_PROC kinfo_proc
#else
# define KVM_OPEN_FLAG O_RDONLY
# define KVM_GETPROCS(kd, opt, arg, cntptr) \
	kvm_getprocs (kd, opt, arg, cntptr)
# define KP_COMM(x) (x)->ki_comm
# define KP_PID(x) (x)->ki_pid
# define KP_PPID(x) (x)->ki_ppid
# define KP_UID(x) (x)->ki_uid
# define KINFO_PROC kinfo_proc
#endif
	char errbuf[_POSIX2_LINE_MAX];
	struct KINFO_PROC *kp, *entry;
	int cnt = 0;
	int i;

#if __FreeBSD__
	kvm_t *kd = kvm_openfiles (NULL, "/dev/null", NULL, KVM_OPEN_FLAG, errbuf);
#else
	kvm_t *kd = kvm_openfiles (NULL, NULL, NULL, KVM_OPEN_FLAG, errbuf);
#endif
	if (!kd) {
		eprintf ("kvm_openfiles failed: %s\n", errbuf);
		return NULL;
	}

	kp = KVM_GETPROCS (kd, KERN_PROC_PROC, 0, &cnt);
	for (i = 0; i < cnt; i++) {
		entry = kp + i;
		// Unless pid 0 is requested, only add the requested pid and it's child processes
		if (0 == pid || KP_PID (entry) == pid || KP_PPID (entry) == pid) {
			RDebugPid *p = r_debug_pid_new (KP_COMM (entry), KP_PID (entry), KP_UID (entry), 's', 0);
			if (p) {
				p->ppid = KP_PPID (entry);
				r_list_append (list, p);
			}
		}
	}

	kvm_close (kd);
#endif
	return list;
}

RList *bsd_native_sysctl_map(RDebug *dbg) {
#if __KFBSD__
	int mib[4];
	size_t len;
	char *buf, *bp, *eb;
	struct kinfo_vmentry *kve;
	RList *list = NULL;
	RDebugMap *map;

	len = 0;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_VMMAP;
	mib[3] = dbg->pid;

	if (sysctl (mib, 4, NULL, &len, NULL, 0) != 0) return NULL;
	len = len * 4 / 3;
	buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	if (sysctl (mib, 4, buf, &len, NULL, 0) != 0) {
		free (buf);
		return NULL;
	}
	bp = buf;
	eb = buf + len;
	list = r_debug_map_list_new();
	if (!list) {
		free (buf);
		return NULL;
	}
	while (bp < eb) {
		kve = (struct kinfo_vmentry *)(uintptr_t)bp;
		map = r_debug_map_new (kve->kve_path, kve->kve_start,
					kve->kve_end, kve->kve_protection, 0);
		if (!map) break;
		r_list_append (list, map);
		bp += kve->kve_structsize;
	}
	free (buf);
	return list;
#elif __OpenBSD__
	int mib[3];
	size_t len;
	struct kinfo_vmentry entry;
	u_long old_end = 0;
	RList *list = NULL;
	RDebugMap *map;

	len = sizeof(entry);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_VMMAP;
	mib[2] = dbg->pid;
	entry.kve_start = 0;

	if (sysctl (mib, 3, &entry, &len, NULL, 0) == -1) {
		eprintf ("Could not get memory map: %s\n", strerror(errno));
		return NULL;
	}

	list = r_debug_map_list_new();
	if (!list) return NULL;

	while (sysctl (mib, 3, &entry, &len, NULL, 0) != -1) {
		if (old_end == entry.kve_end) {
			/* No more entries */
			break;
		}
		/* path to vm obj is not included in kinfo_vmentry.
		 * see usr.sbin/procmap for namei-cache lookup.
		 */
		map = r_debug_map_new ("", entry.kve_start, entry.kve_end,
				entry.kve_protection, 0);
		if (!map) break;
		r_list_append (list, map);

		entry.kve_start = entry.kve_start + 1;
		old_end = entry.kve_end;
	}

	return list;
#else
	return NULL;
#endif
}

RList *bsd_desc_list(int pid) {
#if __KFBSD__
	RList *ret = NULL;
	int perm, type, mib[4];
	size_t len;
	char *buf, *bp, *eb, *str, path[1024];
	RDebugDesc *desc;
	struct kinfo_file *kve;

	len = 0;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_FILEDESC;
	mib[3] = pid;

	if (sysctl (mib, 4, NULL, &len, NULL, 0) != 0) return NULL;
	len = len * 4 / 3;
	buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	if (sysctl (mib, 4, buf, &len, NULL, 0) != 0) {
		free (buf);
		return NULL;
	}
	bp = buf;
	eb = buf + len;
	ret = r_list_new ();
	if (!ret) {
		free (buf);
		return NULL;
	}
	ret->free = (RListFree) r_debug_desc_free;
	while (bp < eb) {
		kve = (struct kinfo_file *)(uintptr_t)bp;
		bp += kve->kf_structsize;
		if (kve->kf_fd < 0) continue; // Skip root and cwd. We need it ??
		str = kve->kf_path;
		switch (kve->kf_type) {
		case KF_TYPE_VNODE: type = 'v'; break;
		case KF_TYPE_SOCKET:
			type = 's';
#if __FreeBSD_version < 1200031
			if (kve->kf_sock_domain == AF_LOCAL) {
				struct sockaddr_un *sun =
					(struct sockaddr_un *)&kve->kf_sa_local;
				if (sun->sun_path[0] != 0)
					addr_to_string (&kve->kf_sa_local, path, sizeof(path));
				else
					addr_to_string (&kve->kf_sa_peer, path, sizeof(path));
			} else {
				addr_to_string (&kve->kf_sa_local, path, sizeof(path));
				strcat (path, " ");
				addr_to_string (&kve->kf_sa_peer, path + strlen (path),
						sizeof (path));
			}
#else
			if (kve->kf_sock_domain == AF_LOCAL) {
				struct sockaddr_un *sun =
					(struct sockaddr_un *)&kve->kf_un.kf_sock.kf_sa_local;;
				if (sun->sun_path[0] != 0)
					addr_to_string (&kve->kf_un.kf_sock.kf_sa_local, path, sizeof(path));
				else
					addr_to_string (&kve->kf_un.kf_sock.kf_sa_peer, path, sizeof(path));
			} else {
				addr_to_string (&kve->kf_un.kf_sock.kf_sa_local, path, sizeof(path));
				strcat (path, " ");
				addr_to_string (&kve->kf_un.kf_sock.kf_sa_peer, path + strlen (path),
						sizeof (path));
			}
#endif
			str = path;
			break;
		case KF_TYPE_PIPE: type = 'p'; break;
		case KF_TYPE_FIFO: type = 'f'; break;
		case KF_TYPE_KQUEUE: type = 'k'; break;
		case KF_TYPE_CRYPTO: type = 'c'; break;
		case KF_TYPE_MQUEUE: type = 'm'; break;
		case KF_TYPE_SHM: type = 'h'; break;
		case KF_TYPE_PTS: type = 't'; break;
		case KF_TYPE_SEM: type = 'e'; break;
		case KF_TYPE_NONE:
		case KF_TYPE_UNKNOWN:
		default: type = '-'; break;
		}
		perm = (kve->kf_flags & KF_FLAG_READ)? R_PERM_R: 0;
		perm |= (kve->kf_flags & KF_FLAG_WRITE)? R_PERM_W: 0;
		desc = r_debug_desc_new (kve->kf_fd, str, perm, type, kve->kf_offset);
		if (!desc) {
			break;
		}
		r_list_append (ret, desc);
	}

	free (buf);
	return ret;
#else
	return false;
#endif
}

#if __KFBSD__
static int get_r2_status(int stat) {
	switch (stat) {
	case SRUN:
	case SIDL:
	case SLOCK:
	case SWAIT:
		return R_DBG_PROC_RUN;
	case SSTOP:
		return R_DBG_PROC_STOP;
	case SZOMB:
		return R_DBG_PROC_ZOMBIE;
	case SSLEEP:
		return R_DBG_PROC_SLEEP;
	default:
		return R_DBG_PROC_DEAD;
	}
}
#endif

RList *bsd_thread_list(RDebug *dbg, int pid, RList *list) {
#if __KFBSD__
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID | KERN_PROC_INC_THREAD, pid };
	struct kinfo_proc *kp;
	size_t len = 0;
	size_t max;
	int i = 0;

	if (sysctl (mib, 4, NULL, &len, NULL, 0) == -1) {
		r_list_free (list);
		return NULL;
	}

	len += sizeof(*kp) + len / 10;
	kp = malloc(len);
	if (sysctl (mib, 4, kp, &len, NULL, 0) == -1) {
		free (kp);
		r_list_free (list);
		return NULL;
	}

	max = len / sizeof(*kp);
	for (i = 0; i < max; i ++) {
		RDebugPid *pid_info;
		int pid_stat;

		pid_stat = get_r2_status (kp[i].ki_stat);
		pid_info = r_debug_pid_new (kp[i].ki_comm, kp[i].ki_tid,
			kp[i].ki_uid, pid_stat, (ut64)kp[i].ki_wchan);
		r_list_append (list, pid_info);
	}

	free (kp);
	return list;
#else
	eprintf ("bsd_thread_list unsupported on this platform\n");
	r_list_free (list);
	return NULL;
#endif
}
