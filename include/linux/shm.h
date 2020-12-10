#ifndef _LINUX_SHM_H_
#define _LINUX_SHM_H_

#include <linux/ipc.h>
#include <asm/page.h>

/*
 * SHMMAX, SHMMNI and SHMALL are upper limits are defaults which can
 * be increased by sysctl
 */

#define SHMMAX 0x2000000		 /* max shared seg size (bytes) */
#define SHMMIN 1			 /* min shared seg size (bytes) */
#define SHMMNI 4096			 /* max num of segs system wide */
#define SHMALL (SHMMAX/PAGE_SIZE*(SHMMNI/16)) /* max shm system wide (pages) */
#define SHMSEG SHMMNI			 /* max shared segs per process */

#include <asm/shmparam.h>

/**
 * @brief �ṹ�� - �������ڴ棬�����ڴ�ȫ�ֽṹ��
 * ԭ����ע��Obsolete, used only for backwards compatibility and libc5 compiles
 * ���룺���ϣ������������ݺ�libc5����
 */
struct shmid_ds {
	struct ipc_perm		shm_perm;	/* IPC���Ȩ�� */
	int			shm_segsz;			/* �δ�С */
	__kernel_time_t		shm_atime;	/* ���ҽ�ʱ�� */
	__kernel_time_t		shm_dtime;	/* ������ҽ�ʱ�� */
	__kernel_time_t		shm_ctime;	/* ���仯ʱ�� */
	__kernel_ipc_pid_t	shm_cpid;	/* �������̵�PID */
	__kernel_ipc_pid_t	shm_lpid;	/* ���ʹ�ý��̵�PID */
	unsigned short		shm_nattch;	/* �ҽӵ����ι����ڴ�Ľ����� */
	unsigned short 		shm_unused;	/* compatibility */
	void 			*shm_unused2;	/* ditto - used by DIPC */
	void			*shm_unused3;	/* unused */
};

/* Include the definition of shmid64_ds and shminfo64 */
#include <asm/shmbuf.h>

/* permission flag for shmget */
#define SHM_R		0400	/* or S_IRUGO from <linux/stat.h> */
#define SHM_W		0200	/* or S_IWUGO from <linux/stat.h> */

/* mode for attach */
#define	SHM_RDONLY	010000	/* read-only access */
#define	SHM_RND		020000	/* round attach address to SHMLBA boundary */
#define	SHM_REMAP	040000	/* take-over region on attach */

/* super user shmctl commands */
#define SHM_LOCK 	11
#define SHM_UNLOCK 	12

/* ipcs ctl commands */
#define SHM_STAT 	13
#define SHM_INFO 	14

/**
 * @brief �ṹ�� - �����ڴ���Ϣ
 * ԭ����ע��Obsolete, used only for backwards compatibility
 * ���룺���ϣ�������������
 */
struct	shminfo {
	int shmmax;
	int shmmin;
	int shmmni;
	int shmseg;
	int shmall;
};

/**
 * @brief �ṹ�� - �����ڴ���Ϣ
 */
struct shm_info {
	int used_ids;
	unsigned long shm_tot;			/* ���ѷ��乲���ڴ� */
	unsigned long shm_rss;			/* �ܳ�פ�����ڴ� */
	unsigned long shm_swp;			/* �ܽ��������ڴ� */
	unsigned long swap_attempts;	/* �������� */
	unsigned long swap_successes;	/* �����ɹ� */
};

#ifdef __KERNEL__

/* shm_mode upper byte flags */
#define	SHM_DEST	01000	/* segment will be destroyed on last detach */
#define SHM_LOCKED      02000   /* segment will not be swapped */

asmlinkage long sys_shmget (key_t key, size_t size, int flag);
asmlinkage long sys_shmat (int shmid, char *shmaddr, int shmflg, unsigned long *addr);
asmlinkage long sys_shmdt (char *shmaddr);
asmlinkage long sys_shmctl (int shmid, int cmd, struct shmid_ds *buf);
extern void shm_unuse(swp_entry_t entry, struct page *page);

#endif /* __KERNEL__ */

#endif /* _LINUX_SHM_H_ */
