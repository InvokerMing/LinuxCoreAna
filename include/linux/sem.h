#ifndef _LINUX_SEM_H
#define _LINUX_SEM_H

#include <linux/ipc.h>

/* semop 操作符 */
#define SEM_UNDO        0x1000  /* 退出时撤销操作 */

/* semctl 命令定义 */
#define GETPID  11       /* 获取信号量PID */
#define GETVAL  12       /* 获取信号量值's */
#define GETALL  13       /* 获取所有信号量 */
#define GETNCNT 14       /* 获取信号量N数 */
#define GETZCNT 15       /* 获取信号量Z数 */
#define SETVAL  16       /* 置信号量值 */
#define SETALL  17       /* 置所有信号量's */

/* ipcs 控制命令 */
#define SEM_STAT 18
#define SEM_INFO 19

/**
 * @brief 结构体 - 管理信号量，信号量全局结构体
 * 原作者注：Obsolete, used only for backwards compatibility and libc5 compiles
 * 翻译：作废，仅用于向后兼容和libc5编译
 */
struct semid_ds {
	struct ipc_perm	sem_perm;				/* 信号量IPC权限 */
	__kernel_time_t	sem_otime;				/* 最后一次semop时间 */
	__kernel_time_t	sem_ctime;				/* 最后一次改动time */
	struct sem	*sem_base;					/* 指向数组中第一个信号量的指针 */
	struct sem_queue *sem_pending;			/* 待处理信号量队列 */
	struct sem_queue **sem_pending_last;	/* last pending operation? */
	struct sem_undo	*undo;					/* 欲撤销请求的数组 */
	unsigned short	sem_nsems;				/* 数组中信号量的数量 */
};

/* Include the definition of semid64_ds */
#include <asm/sembuf.h>

/* semop system calls takes an array of these. */
/**
 * @brief 结构体 - semop系统调用结构体数组?
 */
struct sembuf {
	unsigned short  sem_num;	/* 数组中信号量索引 */
	short			sem_op;		/* 信号量操作:-1 -> 等待操作；1 -> 发送信号操作 */
	short			sem_flg;	/* 操作符，通常为SEM_UNDO，使操作系统跟踪信号，并在进程没有释放该信号量而终止时，释放信号量 */
};

/* arg for semctl system calls. */
/**
 * @brief 共用体 - semctl系统调用所用参数
 */
union semun {
	int val;					/* 欲置的信号量值 - 用于 SETVAL */
	struct semid_ds *buf;		/* 缓冲区 - 用于 IPC_STAT & IPC_SET */
	unsigned short *array;		/* 数组 - 用于 GETALL & SETALL */
	struct seminfo *__buf;		/* 缓冲区 -  用于 IPC_INFO */
	void *__pad;
};

/**
 * @brief 结构体 - 信号量信息
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
 * @brief 结构体 - 信号量
 */
struct sem {
	int	semval;		/* 信号量值 */
	int	sempid;		/* 最后一次操作本信号的进程PID */
};

/**
 * @brief 结构体 - 信号量数组
 */
struct sem_array {
	struct kern_ipc_perm	sem_perm;				/* 信号量IPC权限 */
	time_t					sem_otime;				/* 最后一次信号量操作时间 */
	time_t					sem_ctime;				/* 最后一次改动时间 */
	struct sem				*sem_base;				/* 信号量数组 */
	struct sem_queue		*sem_pending;			/* 待操作信号量队列 */
	struct sem_queue		**sem_pending_last;		/* 最后一个待处理操作 */
	struct sem_undo			*undo;					/* 欲撤销请求的数组 */
	unsigned long			sem_nsems;				/* 信号量集中的信号量数 */
};

/**
 * @brief 结构体 - 信号量队列，用于系统中的睡眠进程
 */
struct sem_queue {
	struct sem_queue*	next;	 /* 下一个信号量队列 */
	struct sem_queue**  prev;	 /* 上一个信号量队列, *(q->prev) == q */
	struct task_struct*	sleeper; /* 当前进程 */
	struct sem_undo* 	undo;	 /* 撤销请求 */
	int    				pid;	 /* 请求进程PID */
	int    				status;	 /* 操作完成状态 */
	struct sem_array* 	sma;	 /* 用于操作的信号量数组 */
	int					id;		 /* 内部信号量ID */
	struct sembuf* 		sops;	 /* 待处理操作数组 */
	int					nsops;	 /* 总操作数量 */
	int					alter;	 /* operation will alter semaphore */
};

/**
 * @brief 结构体 - 信号量撤销请求列表，在进程结束时自动执行
 */
struct sem_undo {
	struct sem_undo*	proc_next;	/* 进程的下一个撤销请求 */
	struct sem_undo*	id_next;	/* 信号量集的下一个撤销请求 */
	int					semid;		/* 信号量集id */
	short*				semadj;		/* 信号量的调整数组 */
};

asmlinkage long sys_semget (key_t key, int nsems, int semflg);
asmlinkage long sys_semop (int semid, struct sembuf *sops, unsigned nsops);
asmlinkage long sys_semctl (int semid, int semnum, int cmd, union semun arg);

#endif /* __KERNEL__ */

#endif /* _LINUX_SEM_H */
