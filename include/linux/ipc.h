#ifndef _LINUX_IPC_H
#define _LINUX_IPC_H

#include <linux/types.h>

#define IPC_PRIVATE ((__kernel_key_t) 0)  

/**
 * @brief �ṹ�� - IPCȨ��
 * ԭ����ע��Obsolete, used only for backwards compatibility and libc5 compiles
 * ���룺���ϣ������������ݺ�libc5����
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

/* ��Դ��ȡ�����ʶ�� */
#define IPC_CREAT  00001000   /* ��ָ����Ϣ���в����ڣ������µ���Ϣ���� */
#define IPC_EXCL   00002000   /* ��ָ����Ϣ�����Ѿ����ڣ����ش�����IPC_CREATһͬʹ�� */
#define IPC_NOWAIT 00004000   /* ��ϵͳ�ȴ������ش��� */

/* these fields are used by the DIPC package so the kernel as standard
   should avoid using them if possible */
   
#define IPC_DIPC 00010000  /* make it distributed */
#define IPC_OWN  00020000  /* this machine is the DIPC owner */

/* 
 * Control commands used with semctl, msgctl and shmctl 
 * see also specific commands in sem.h, msg.h and shm.h
 */
#define IPC_RMID 0     /* ɾ����Դ */
#define IPC_SET  1     /* ��IPCȨ��ѡ�� */
#define IPC_STAT 2     /* ��ȡIPCȨ��ѡ�� */
#define IPC_INFO 3     /* �鿴IPC��Ϣ */

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

/* used by in-kernel data structures */
struct kern_ipc_perm
{
	key_t		key;	/* ��ֵ/Ψһ��ʶ�� */
	uid_t		uid;	
	gid_t		gid;
	uid_t		cuid;
	gid_t		cgid;
	mode_t		mode; 
	unsigned long	seq;
};

#endif /* __KERNEL__ */

#endif /* _LINUX_IPC_H */


