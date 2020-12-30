#ifndef _LINUX_IPC_H
#define _LINUX_IPC_H

#include <linux/types.h>

#define IPC_PRIVATE ((__kernel_key_t) 0)  

/**
 * @brief 结构体 - IPC权限
 * 原作者注：Obsolete, used only for backwards compatibility and libc5 compiles
 * 翻译：作废，仅用于向后兼容和libc5编译
 */
struct ipc_perm
{
	__kernel_key_t	key;
	__kernel_uid_t	uid;
	__kernel_gid_t	gid;
	__kernel_uid_t	cuid;
	__kernel_gid_t	cgid;
	__kernel_mode_t	mode; 
	unsigned short	seq;
};

/* Include the definition of ipc64_perm */
#include <asm/ipcbuf.h>

/* 资源获取请求标识符 */
#define IPC_CREAT  00001000   /* 若指定消息队列不存在，创建新的消息队列 */
#define IPC_EXCL   00002000   /* 若指定消息队列已经存在，返回错误，与IPC_CREAT一同使用 */
#define IPC_NOWAIT 00004000   /* 若系统等待，返回错误 */

/* these fields are used by the DIPC package so the kernel as standard
   should avoid using them if possible */
   
#define IPC_DIPC 00010000  /* make it distributed */
#define IPC_OWN  00020000  /* this machine is the DIPC owner */

/* 
 * Control commands used with semctl, msgctl and shmctl 
 * see also specific commands in sem.h, msg.h and shm.h
 */
#define IPC_RMID 0     /* 删除资源 */
#define IPC_SET  1     /* 置IPC权限选项 */
#define IPC_STAT 2     /* 获取IPC权限选项 */
#define IPC_INFO 3     /* 查看IPC信息 */

/*
 * Version flags for semctl, msgctl, and shmctl commands
 * These are passed as bitflags or-ed with the actual command
 */
#define IPC_OLD 0	/* Old version (no 32-bit UID support on many
			   architectures) */
#define IPC_64  0x0100  /* New version (support 32-bit UIDs, bigger
			   message sizes, etc. */

//#ifdef __KERNEL__

#define IPCMNI 32768  /* <= MAX_INT limit for ipc arrays (including sysctl changes) */

struct kern_ipc_perm
{
	key_t		key;		/* 键值/唯一标识符 */
	uid_t		uid;		/* 所有者用户id */
	gid_t		gid;		/* 所有者用户组ID */
	uid_t		cuid;		/* 创建者用户id */
	gid_t		cgid;		/* 创建者用户id */
	mode_t		mode;		/* 模式 */
	unsigned long	seq;	/* 实体ID */
};

#endif /* __KERNEL__ */

#endif /* _LINUX_IPC_H */


