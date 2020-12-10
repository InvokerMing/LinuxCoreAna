/*
 * linux/ipc/util.h
 * Copyright (C) 1999 Christoph Rohland
 *
 * ipc helper functions (c) 1999 Manfred Spraul <manfreds@colorfullife.com>
 */

#define USHRT_MAX 0xffff
#define SEQ_MULTIPLIER	(IPCMNI)

void sem_init (void);
void msg_init (void);
void shm_init (void);

struct ipc_ids {
	int size;
	int in_use;
	int max_id;
	unsigned short seq;
	unsigned short seq_max;
	struct semaphore sem;	
	spinlock_t ary;
	struct ipc_id* entries;
};

/* IPC管理，存放所有同种IPC方式总结构体 */
struct ipc_id {
	struct kern_ipc_perm* p;
};


void __init ipc_init_ids(struct ipc_ids* ids, int size);

/* must be called with ids->sem acquired.*/
int ipc_findkey(struct ipc_ids* ids, key_t key);
int ipc_addid(struct ipc_ids* ids, struct kern_ipc_perm* new, int size);

/* must be called with both locks acquired. */
struct kern_ipc_perm* ipc_rmid(struct ipc_ids* ids, int id);

int ipcperms (struct kern_ipc_perm *ipcp, short flg);

/* for rare, potentially huge allocations.
 * both function can sleep
 */
void* ipc_alloc(int size);
void ipc_free(void* ptr, int size);

extern inline void ipc_lockall(struct ipc_ids* ids)
{
	spin_lock(&ids->ary);
}

extern inline struct kern_ipc_perm* ipc_get(struct ipc_ids* ids, int id)
{
	struct kern_ipc_perm* out;
	int lid = id % SEQ_MULTIPLIER;
	if(lid >= ids->size)
		return NULL;

	out = ids->entries[lid].p;
	return out;
}

extern inline void ipc_unlockall(struct ipc_ids* ids)
{
	spin_unlock(&ids->ary);
}


extern inline struct kern_ipc_perm* ipc_lock(struct ipc_ids* ids, int id)
{
	struct kern_ipc_perm* out;
	int lid = id % SEQ_MULTIPLIER;
	if(lid >= ids->size)
		return NULL;

	spin_lock(&ids->ary);
	out = ids->entries[lid].p;
	if(out==NULL)
		spin_unlock(&ids->ary);
	return out;
}

extern inline void ipc_unlock(struct ipc_ids* ids, int id)
{
	spin_unlock(&ids->ary);
}

extern inline int ipc_buildid(struct ipc_ids* ids, int id, int seq)
{
	/* SEQ_MULTIPLIER是可分配的最大资源数，seq为位置序列号，id为在ids->entries->p[id]的位置索引值。
	 * 而每分配一个资源，seq加1，这样就保证后面分配的标志符号总是比前面的要大，
	 * 除非是seq超过最大值seq_max，最大限度的减小了错误引用资源的概率。
	 */
	return SEQ_MULTIPLIER*seq + id;
}

extern inline int ipc_checkid(struct ipc_ids* ids, struct kern_ipc_perm* ipcp, int uid)
{
	if(uid/SEQ_MULTIPLIER != ipcp->seq)
		return 1;
	return 0;
}

void kernel_to_ipc64_perm(struct kern_ipc_perm *in, struct ipc64_perm *out);
void ipc64_perm_to_ipc_perm(struct ipc64_perm *in, struct ipc_perm *out);

#ifdef __ia64__
  /* On IA-64, we always use the "64-bit version" of the IPC structures.  */ 
# define ipc_parse_version(cmd)	IPC_64
#else
int ipc_parse_version (int *cmd);
#endif
