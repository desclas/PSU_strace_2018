/*
** EPITECH PROJECT, 2019
** PSU_strace_2018
** File description:
** strace
*/

/*
** read:size_t:char ptr:size_t:3
** write:size_t:char ptr:size_t:3
** open:char ptr:int:int:3
** close:size_t:1
** stat:char ptr:struct stat ptr:2
** fstat:size_t:struct stat ptr:2
** lstat:char ptr:struct stat ptr:2
** poll:struct pollfd ptr:size_t:int:3
** lseek:size_t:long int:size_t:3
** mmap:void ptr:size_t:int:int:int:long int:6
** mprotect:void ptr:size_t:int:3
** munmap:void ptr:size_t:2
** brk:void ptr:1
** rt_sigaction:int:struct sigaction ptr:struct sigaction ptr:size_t:4
** rt_sigprocmask:int:sigset_t:sigset_t:size_t:4
** rt_sigreturn:struct pt_regs ptr:1
** ioctl:size_t:size_t:unsigned long:3
** pread64:size_t:char ptr:size_t:loff_t:4
** vpwrite64:void ptr:void ptr:void ptr:void ptr:4
** readv:unsigned long:struct iovec ptr:unsigned long:3
** writev:unsigned long:struct iovec ptr:unsigned long:3
** access:char ptr:int:2
** pipe:int ptr:1
** select:int:fd_set ptr:fd_set ptr:fd_set ptr:struct timeval ptr:5
** sched_yield:0
** mremap:unsigned long:unsigned long:unsegned long:unsigned long:unsigned long:5
** msync:unsigned long:size_t:int:3
** mincore:unsigned long:size_t:unsigned char ptr:3
** madvise:unsigned long:size_t:int:3
** shmget:key_t:size_t:int:3
** shmat:int:void ptr:int:3
** shmctl:int:int:struct shmid_ds ptr:3
** dup:size_t:1
** dup2:size_t:size_t:2
** pause:0
** nanosleep:struct timespec ptr:struct timespec ptr:2
** getitimer:int:struct itimerval ptr:2
** alarm:size_t:1
** settimer:void ptr:void ptr:void ptr:3
** getpid:0
** sendfile:int:int:off_t:size_t:4
** socket:int:int:int:3
** connect:int:struct sockaddr ptr:socklen_t:3
** accept:int:struct sockaddr ptr:socklen_t ptr:3
** sendto:int:void ptr:size_t:int:struct sockaddr ptr:socklen_t:6
** recvfrom:int:void ptr:size_t:int:struct sockaddr ptr:soclen_t ptr:6
** sendmsg:int:struct msghdr ptr:int:3
** recvmsg:int:struct msghdr ptr:int:3
** shutdown:int:int:2
** bind:int:struct sockaddr ptr:socklen_t:3
** listen:int:int:2
** getsockname:int:struct sockaddr ptr:socklen_t ptr:3
** getpeername:int:struct sockaddr ptr:socklen_t ptr:3
** socketpair:int:int:int:int ptr:4
** setsockopt:int:int:int:void ptr:socklen_t:5
** getsockopt:int:int:int:void ptr:socklen_t ptr:5
** clone:unsigned long:unsigned long:unsigned long:unsigned long:4
** fork:0
** vfork:0
** execve:char ptr:char ptr ptr:char ptr ptr:3
** exit:int:1
** wait4:pid_t:int ptr:int:struct rusage ptr:4
** kill:int:int:2
** uname:struct utsname ptr:1
** semget:key_t:int:int:3
** semop:int:struct sembuf ptr:size_t:3
** semctl:int:int:int:void ptr:4
** shmdt:void ptr:1
** msgget:key_t:int:2
** msgsnd:int:void ptr:size_t:int:4
** msgrcv:int:void ptr:size_t:long:int:5
** msgctl:int:int:struct msqid_ds ptr:3
** fcntl:int:int:void ptr:3
** flock:int:int:2
** fsync:int:1
** fdatasync:int:1
** truncate:char ptr:off_t:2
** ftruncate:int:off_t:2
** getdents:size_t:struct linux_dirent ptr:size_t:3
** getcwd:char ptr:size_t:2
** chdir:char ptr:1
** fchdir:int:1
** rename:char ptr:char ptr:2
** mkdir:char ptr:mode_t:2
** rmdir:char ptr:1
** creat:char ptr:int:2
** link:char ptr:char ptr:2
** unlink:char ptr:1
** symlink:char ptr:char ptr:2
** readlink:char ptr:char ptr:size_t:3
** chmod:char ptr:mode_t:2
** fchmod:int:mode_t:2
** chown:char ptr:uid_t:gid_t:3
** fchown:int:uid_t:gid_t:3
** lchown:char ptr:uid_t:gid_t:3
** umask:mod_t:1
** gettimeofday:struct timeval ptr:struct timezone ptr:2
** getrlimit:int:struct rlimit ptr:2
** getrusage:int:struct rusage ptr:2
** sysinfo:struct sysinfo ptr:1
** times:struct tms ptr:1
** ptrace:long:long:long:long:4
** getuid:0
** syslog:int:char ptr:int:3
** getpid:0
** setuid:uid_t:1
** setgid:gid_t:1
** geteuid:0
** getegid:0
** setpgid:pid_t:pid_t:2
** getppid:0
** getpgrp:0
** setsid:0
** setreuid:uid_t:uid_t:2
** setregid:gid_t:gid_t:2
** getgroups:int:gid_t ptr:2
** setgroups:size_t:gid_t ptr:2
** setresuid:uid_t:uid_t:uid_t:3
** getresuid:uid_t ptr:uid_t ptr:uid_t ptr:3
** setresgid:gid_t:gid_t:gid_t:3
** getresgid:gid_t ptr:gid_t ptr:gid_t ptr:3
** getpgid:pid_t:1
** setfsuid:uid_t:1
** setfsgid:uid_t:1
** getsid:pid_t:1
** capget:cap_user_header_t:cap_user_data_t:2
** capset:cap_user_header_t:cap_user_dat_t:2
** rt_sigpending:sigset_t ptr:size_t:2
** rt_sigtimedwait:sigset_t ptr:siginfo_t ptr:struct timespec ptr:size_t:4
** rt_sigqueueinfo:int:int:sigset_t ptr:3
** rt_sigsuspend:sigset_t ptr:size_t:2
** sigaltstrack:void ptr:void ptr:2
** utime:char ptr:struct utime ptr:2
** mknod:char ptr:mode_t:dev_t:3
** uselib:char ptr:1
** personality:unsigned long:1
** ustat:dev_t:struct ustat ptr:2
** statfs:char ptr:struct statfs ptr:2
** fstatfs:int:struct statfs ptr:2
** sysfs:int:size_t:char ptr:3
** getpriority:int:id_t:2
** setpriority:int:id_t:int:3
** sched_setparam:pid_t:struct sched_param ptr:2
** sched_getparam:pid_t:struct sched_param ptr:2
** sched_setscheduler:pid_t:int:struct sched_param ptr:3
** sched_getscheduler:pid_t:1
** sched_get_priority_max:int:1
** sched_get_priority_min:int:1
** sched_rr_get_interval:pid_t:struct timespec ptr:2
** mlock:void ptr:size_t:2
** munlock:void ptr:size_t:2
** mlockall:int:1
** munlockall:0
** vhangup:0
** modify_ldt:int:void ptr:unsigned long:3
** pivot_root:char ptr:char ptr:2
** _sysctl:struct __sysctl_args ptr:1
** prctl:int:unsigned long:unsigned long:unsigned long:unsigned long:5
** arch_prctl:int:unsigned long:2
** adjtimex:struct timex ptr:1
** setrlimit:int:struct rlimit ptr:2
** chroot:char ptr:1
** sync:0
** acct:char ptr:1
** settimeofday:struct timeval ptr:struct timezone ptr:2
** mount:char ptr:char ptr:char ptr:unsigned long:void ptr5
** umount2:char ptr:int:2
** swapon:char ptr:int:2
** swapoff:char ptr:1
** reboot:int:int:int:void ptr:4
** sethostname:char ptr:size_t:2
** setdomainname:char ptr:size_t:2
** iopl:size_t:struct pt_regs ptr:2
** ioperm:unsigned long:unsigned long:int:3
** create_module:char ptr:size_t:2
** init_module:void ptr:unsigned long:char ptr:3
** delete_module:char ptr:int:2
** get_kernel_syms:struct kernel_sym ptr:1
** query_module:char ptr:int:void ptr:size_t:size_t ptr:5
** quotactl:int:char ptr:int:caddr_t:4
** nfsservctl:int:struct nfsctl_arg ptr:union nfsctl_res ptr:3
** getpmsg:0
** putpmsg:0
** afs_syscall:0
** tuxcall:0
** security:0
** gettid:0
** readahead:int:off64_t:size_t:3
** setxattr:char ptr:char ptr:void ptr:size_t:int:5
** lsetxattr:char ptr:char ptr:void ptr:size_t:int:5
** fsetxattr:int:char ptr:void ptr:size_t:int:5
** getxattr:char ptr:char ptr:void ptr:size_t:4
** lgetxattr:char ptr:char ptr:void ptr:size_t:4
** fgetxattr:int:char ptr:void ptr:size_t:4
** listxattr:char ptr:char ptr:size_t:3
** llistxattr:char ptr:char ptr:size_t:3
** flistxattr:int:char ptr:size_t:3
** removexattr:char ptr:char ptr:2
** lremovexattr:char ptr:char ptr:2
** fremovexattr:int:char ptr:2
** tkill:int:int:2
** time:time_t ptr:1
** futex:int:intint:struct timespec ptr:int ptr:int:6
** sched_setaffinity:pid_t:size_t:cpu_set_t:3
** sched_getaffinity:pid_t:size_t:cpu_set_t ptr:3
** set_thread_area:struct user_desc ptr:1
** io_setup:size_t:aio_context_t ptr:2
** io_destroy:aio_context_t:1
** io_getevents:aio_context_t:long:long:struct io_event ptr:struct timespec ptr:5
** io_submid:aio_context:long:struct iocb ptr ptr:3
** io_cancel:aio_context_t:struct iocb ptr:struct io_event ptr:3
** get_thread_area:struct user_desc ptr:1
** lookup_dcookie:u64:char ptr:size_t:3
** epoll_create:int:1
** epoll_ctl:int:int:int:struct epoll_event ptr:4
** epoll_wait:int:struct epoll_event ptr:int:int:4
** remap_file_pages:unsigned long:unsigned long:unsigned long:unsigned long:unsigned long:5
** getgents64:void ptr:void ptr:void ptr:3
** set_tid_address:int ptr:1
** restart_syscall:0
** semtimedop:int:struct sembuf ptr:size_t:struct timespec ptr:4
** fadvise64:int:off_t:off_t:int:4
** timer_create:clockid_t:struct sigevent ptr:timer_t ptr:3
** timer_settime:timer_t:int:struct itimerspec ptr:struct itimerspec ptr:4
** timer_gettime:timer_t:struct itimerspec ptr:2
** timer_getoverrun:timer_t:1
** timer_delete:timer_t:1
** clock_settime:clockid_t:struct timespec ptr:2
** clock_gettime:clockid_t:struct timespec ptr:2
** clock_getres:clockid_t:struct timespec ptr:2
** clock_nanosleep:clockid_t:int:4
** exit_group:int:1
** epoll_wait:int:int:int:sturct epoll_event ptr:4
** epoll_ctl:int:struct epoll_event ptr:int:int:4
** tgkill:int:int:int:3
** utimes:char ptr:struct timeval ptr:2
** vserver:0
** mbind:void ptr:unsigned long:int:unsigned long:unsigned long:unsigned long:6
** set_mempolicy:int:unsigned long:unsigned long:3
** get_mempolicy:int ptr:unsigned long ptr:unsigned long:void ptr:unsigned long:5
** mq_open:char ptr:int:mod_t:struct mq_attr ptr:4
** mq_unlink:char ptr:1
** mq_timedsend:mqd_t:char ptr:size_t:size_t:struct timespec ptr:5
** mq_timedreceive:mqd_t:char ptr:size_t:size_t:struct timespec ptr:5
** mq_notify:mqd_t:struct sigevent ptr:2
** mq_getsetattr:mqd_t:struct mq_attr ptr:struct mq_attr ptr:3
** kexec_load:unsigned long:unsigned long:struct kexec_segment ptr:unsigned long:4
** waitid:int:pid_t:struct siginfo ptr:int:struct rusage ptr:5
** add_key:char ptr:char ptr:void ptr:size_t:key_serial_t:4
** request_key:char ptr:char ptr:char ptr:key_serial_t:4
** keyctl:int:unsigned long:unsigned long:unsigned long:unsigned long:5
** ioprio_set:int:int:int:3
** ioprio_get:int:int:2
** inotify_int:0
** inotify_add_watch:int:char ptr:u32:3
** inotify_rm_watch:int:__s32:2
** migrate_pages:pid_t:unsigned long:unsigned long ptr:unsigned long ptr:4
** openat:int:char ptr:int:int:4
** mkdirat:int:char ptr:int:3
** mknodat:int:char ptr:int:size_t:4
** fchownat:int:char ptr:uid_t:gid_t:int:5
** futimesat:int:char ptr:struct timeval ptr:3
** fstatat64:int:char ptr:struct stat64 ptr:int:4
** unlinkat:int:char ptr:int:3
** renameat:int:char ptr:int:char ptr:4
** linkat:int:char ptr:int:char ptr:int:5
** symlinlat:char ptr:int:char ptr:3
** readlinkat:int:char ptr:char ptr:int:4
** fchmodat:int:char ptr:mode_t:3
** faccessat:int:char ptr:int:3
** pselectl6:int:fd_set ptr:fd_set ptr:fd_set ptr:stuct timespec ptr:sigset_t ptr:6
** ppoll:struct pollfd ptr:size_t:struct timespec ptr:sigset_t ptr:size_t:5
** unshare:unsigned long:1
** set_robust_list:struct robust_list_head ptr:size_t:2
** get_robust_listint: struct robust_list_head ptr:size_t:3
** splice:int:loff_t ptr:int:loff_t ptr:size_t:size_t:6
** tee:int:int:size_t:size_t:4
** sync_file_range:int:loff_t:loff_t:size_t:4
** vmsplice:int:struct iovec ptr:unsigned long:size_t:4
** move_pages:int:unsigned long:void ptr ptr:int ptr:int ptr:int:6
** utimensat:int:char ptr:struct timespec ptr:int:4
** epoll_pwait:int:struct epoll_event ptr:int:int:sigset_t ptr:6
** signalfd:int:sigset_t ptr:int:3
** timerfd_create:int:int:2
** eventfd:size_t:1
** fallocate:int:int:loff_t:loff_t:4
** timerfd_settime:int:int:struct itimespec ptr:struct itimespec ptr:4
** timerfd_gettime:int:struct itimespec ptr:2
** accept4:int:struct sockaddr ptr:socklen_t ptr:int:4
** signalfd4:int:sigset_t ptr:size_t:int:4
** eventfd2:size_t:int:2
** epoll_create1:int:1
** dup3:size_t:size_t:int:3
** pipe2:int ptr:int:2
** inotify_init1:int:1
** preadv:unsigned long:struct iovec ptr:unsigned long:unsigned long:unsigned long:5
** pwritev:unsignedl long:struct iovec ptr:unsigned long:unsigned long:unsigned long:5
** rt_tgsigqueueinfo:pid_t:pid_t:int:siginfo_t ptr:4
** perf_event_open:struct perf_event_attr ptr:pid_t:int:int:unsigned long:5
** recvmmsg:int:struct mmsghdr ptr:size_t:size_t:struct timespec ptr:5
** fanotify_init:size_t:size_t:2
** fanotify_mark:int:size_t:uint64_t:int:char ptr:5
** prlimit64:pid_t:int:struct rlimit ptr:struct rlimit ptr:4
** name_to_handle_at:int:char ptr:struct file_handle ptr:int ptr:int:5
** open_by_handle_at:int:struct file_handle ptr:int:3
** clock_adjtime:void ptr:void ptr:2
** syncfs:int:1
** sendmmsg:int:struct msghdr ptr:int:3
** setns:int:int:2
** getcpu:size_t:size_t ptr:struct getcpu_cache ptr:3
** process_vm_readv:pid_t:struct iovec ptr:unsigned long:struct iovec ptr:unsigned long:unsigned long:6
** process_vm_writev:pid_t:struct iovec ptr:unsigned long:struct iovec ptr:unsigned long:unsigned long:6
** kcmp:pid_t:pid_t:int:unsigned long_unsigned long:5
** finit_module:int:char ptr:int:3
** sched_setattr:pid_t:struct sched_attr ptr:size_t:4
** sched_getattr:pid_t:struct sched_attr ptr:size_t:size_t:4
** renameat2:int:char ptr:int:char ptr:size_t:5
** seccomp:size_t:size_t:void ptr:3
** getrandom:void ptr:size_t:size_t:3
** memfd_create:char ptr:size_t:2
** kexec_file_load:int:int:unsigned long:char ptr:unsigned long:5
** bpf:int:union bpf_attr ptr:size_t:3
** execveat:int:char ptr:char ptr ptr:char ptr ptr:int:5
** userfaultfd:int:1
** membarier:void ptr:void ptr:2
** mlock2:void ptr:size_t:int:3
** copy_file_range:int:loff_t ptr:int:loff_t ptr:size_t:size_t:6
** preadv2:int:struct iovec ptr:int:off_t:int:6
** pwritev2:int:struct iovec ù:int:off_t:int:6
*/

#ifndef STRACE_H_
# define STRACE_H_

# include <stdio.h>
# include <stdlib.h>
# include <sys/types.h>
# include <sys/time.h>
# include <sys/resource.h>
# include <sys/wait.h>
# include <sys/ptrace.h>
# include <unistd.h>
# include <sys/user.h>
# include <sys/reg.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <string.h>

char **append_chartab(char **tab, char *str);
char ptrappend_char(char *str, char c);
char **getsyscalls_loop(char **res, char *str, int fd);
char **getsyscalls(void);
long int takeinfo(int nb, pid_t pid);
int child_func(char **ac, char **env, int flags);
void next_step(pid_t pid, int *st);
void tracer(char **name, pid_t pid, int *st, int flags);
size_t strlen_delim(char *str, char delim, size_t nb);
void strace_print(char *name, pid_t pid, int flag, int *st);
void print_void_ptr(long int i, pid_t pid);
void print_char_ptr(long int i, pid_t pid);
void print_int(long int i, pid_t pid);

#endif /* !STRACE_H_ */
