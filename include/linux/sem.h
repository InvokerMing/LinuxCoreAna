#ifndef _LINUX_SEM_H
#define _LINUX_SEM_H

#include <linux/ipc.h>

/* semop ������ */
#define SEM_UNDO        0x1000  /* �˳�ʱ�������� */

/* semctl ����� */
#define GETPID  11       /* ��ȡ�ź���PID */
#define GETVAL  12       /* ��ȡ�ź���ֵ's */
#define GETALL  13       /* ��ȡ�����ź��� */
#define GETNCNT 14       /* ��ȡ�ź���N�� */
#define GETZCNT 15       /* ��ȡ�ź���Z�� */
#define SETVAL  16       /* ���ź���ֵ */
#define SETALL  17       /* �������ź���'s */

/* ipcs �������� */
#define SEM_STAT 18
#define SEM_INFO 19

/**
 * @brief �ṹ�� - �����ź������ź���ȫ�ֽṹ��
 * ԭ����ע��Obsolete, used only for backwards compatibility and libc5 compiles
 * ���룺���ϣ������������ݺ�libc5����
 */
struct semid_ds {
	struct ipc_perm	sem_perm;				/* �ź���IPCȨ�� */
	__kernel_time_t	sem_otime;				/* ���һ��semopʱ�� */
	__kernel_time_t	sem_ctime;				/* ���һ�θĶ�time */
	struct sem	*sem_base;					/* ָ�������е�һ���ź�����ָ�� */
	struct sem_queue *sem_pending;			/* �������ź������� */
	struct sem_queue **sem_pending_last;	/* last pending operation? */
	struct sem_undo	*undo;					/* ��������������� */
	unsigned short	sem_nsems;				/* �������ź��������� */
};

/* Include the definition of semid64_ds */
#include <asm/sembuf.h>

/* semop system calls takes an array of these. */
/**
 * @brief �ṹ�� - semopϵͳ���ýṹ������?
 */
struct sembuf {
	unsigned short  sem_num;	/* �������ź������� */
	short			sem_op;		/* �ź�������:-1 -> �ȴ�������1 -> �����źŲ��� */
	short			sem_flg;	/* ��������ͨ��ΪSEM_UNDO��ʹ����ϵͳ�����źţ����ڽ���û���ͷŸ��ź�������ֹʱ���ͷ��ź��� */
};

/* arg for semctl system calls. */
/**
 * @brief ������ - semctlϵͳ�������ò���
 */
union semun {
	int val;					/* ���õ��ź���ֵ - ���� SETVAL */
	struct semid_ds *buf;		/* ������ - ���� IPC_STAT & IPC_SET */
	unsigned short *array;		/* ���� - ���� GETALL & SETALL */
	struct seminfo *__buf;		/* ������ -  ���� IPC_INFO */
	void *__pad;
};

/**
 * @brief �ṹ�� - �ź�����Ϣ
 */
struct  seminfo {
	int semmap;
	int semmni;
	int semmns;
	int semmnu;
	int semmsl;
	int semopm;
	int semume;
	int semusz;
	int semvmx;
	int semaem;
};

#define SEMMNI  128             /* <= IPCMNI  max # of semaphore identifiers */
#define SEMMSL  250             /* <= 8 000 max num of semaphores per id */
#define SEMMNS  (SEMMNI*SEMMSL) /* <= INT_MAX max # of semaphores in system */
#define SEMOPM  32				/* <= 1 000 max num of ops per semop call */
#define SEMVMX  32767           /* <= 32767 semaphore maximum value */
#define SEMAEM  SEMVMX          /* adjust on exit max value */

/* unused */
#define SEMUME  SEMOPM          /* max num of undo entries per process */
#define SEMMNU  SEMMNS          /* num of undo structures system wide */
#define SEMMAP  SEMMNS          /* # of entries in semaphore map */
#define SEMUSZ  20				/* sizeof struct sem_undo */

//#ifdef __KERNEL__

/**
 * @brief �ṹ�� - �ź���
 */
struct sem {
	int	semval;		/* �ź���ֵ */
	int	sempid;		/* ���һ�β������źŵĽ���PID */
};

/**
 * @brief �ṹ�� - �ź�������
 */
struct sem_array {
	struct kern_ipc_perm	sem_perm;				/* �ź���IPCȨ�� */
	time_t					sem_otime;				/* ���һ���ź�������ʱ�� */
	time_t					sem_ctime;				/* ���һ�θĶ�ʱ�� */
	struct sem				*sem_base;				/* �ź������� */
	struct sem_queue		*sem_pending;			/* �������ź������� */
	struct sem_queue		**sem_pending_last;		/* ���һ����������� */
	struct sem_undo			*undo;					/* ��������������� */
	unsigned long			sem_nsems;				/* �ź������е��ź����� */
};

/**
 * @brief �ṹ�� - �ź������У�����ϵͳ�е�˯�߽���
 */
struct sem_queue {
	struct sem_queue*	next;	 /* ��һ���ź������� */
	struct sem_queue**  prev;	 /* ��һ���ź�������, *(q->prev) == q */
	struct task_struct*	sleeper; /* ��ǰ���� */
	struct sem_undo* 	undo;	 /* �������� */
	int    				pid;	 /* �������PID */
	int    				status;	 /* �������״̬ */
	struct sem_array* 	sma;	 /* ���ڲ������ź������� */
	int					id;		 /* �ڲ��ź���ID */
	struct sembuf* 		sops;	 /* ������������� */
	int					nsops;	 /* �ܲ������� */
	int					alter;	 /* operation will alter semaphore */
};

/**
 * @brief �ṹ�� - �ź������������б��ڽ��̽���ʱ�Զ�ִ��
 */
struct sem_undo {
	struct sem_undo*	proc_next;	/* ���̵���һ���������� */
	struct sem_undo*	id_next;	/* �ź���������һ���������� */
	int					semid;		/* �ź�����id */
	short*				semadj;		/* �ź����ĵ������� */
};

asmlinkage long sys_semget (key_t key, int nsems, int semflg);
asmlinkage long sys_semop (int semid, struct sembuf *sops, unsigned nsops);
asmlinkage long sys_semctl (int semid, int semnum, int cmd, union semun arg);

#endif /* __KERNEL__ */

#endif /* _LINUX_SEM_H */
