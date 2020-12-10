/*
 * linux/ipc/msg.c
 * Copyright (C) 1992 Krishna Balasubramanian
 *
 * Removed all the remaining kerneld mess
 * Catch the -EFAULT stuff properly
 * Use GFP_KERNEL for messages as in 1.2
 * Fixed up the unchecked user space derefs
 * Copyright (C) 1998 Alan Cox & Andi Kleen
 *
 * /proc/sysvipc/msg support (c) 1999 Dragos Acostachioaie <dragos@iname.com>
 *
 * mostly rewritten, threaded and wake-one semantics added
 * MSGMAX limit removed, sysctl's added
 * (c) 1999 Manfred Spraul <manfreds@colorfullife.com>
 */


#include <linux/config.h>
#include <linux/slab.h>
#include <linux/msg.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm-i386/uaccess.h> //<asm/uaccess.h>
#include "util.h"

/* sysctl所需常量 */
int msg_ctlmax = MSGMAX;
int msg_ctlmnb = MSGMNB;
int msg_ctlmni = MSGMNI;

/**
 * @brief 结构体 - 消息接收者
 */
struct msg_receiver {
	struct list_head r_list;		/* 用于连接结构体的链表头指针 */
	struct task_struct* r_tsk;		/* 消息接收者的任务 */
	int r_mode;						/* 模式 */
	long r_msgtype;					/* 消息类别 */
	long r_maxsize;					/* 消息最大容量 */

	struct msg_msg* volatile r_msg;	/* 接收的消息 */
};

/**
 * @brief 结构体 - 消息发送者
 */
struct msg_sender {
	struct list_head list;		/* 用于连接结构体的链表头指针 */
	struct task_struct* tsk;	/* 进程控制块 */
};

/**
 * @brief 结构体 - 用于连接消息的下一条消息的单向链表
 */
struct msg_msgseg {
	struct msg_msgseg* next;
	/* the next part of the message follows immediately */
};

/**
 * @brief 结构体 - 消息
 */
struct msg_msg {
	struct list_head m_list;	/* 用于连接结构体的链表头指针 */
	long  m_type;				/* 消息类别 */
	int m_ts;					/* 消息文本大小 */
	struct msg_msgseg* next;	/* 下一条消息 */
	/* the actual message follows immediately */
};

#define DATALEN_MSG	(PAGE_SIZE-sizeof(struct msg_msg))
#define DATALEN_SEG	(PAGE_SIZE-sizeof(struct msg_msgseg))

/**
 * @brief 结构体 - 消息队列
 */
struct msg_queue {
	struct kern_ipc_perm q_perm;        /* IPC许可权限 */
	time_t q_stime;						/* 最后一条消息发送时间 */
	time_t q_rtime;						/* 最后一条消息接受时间 */
	time_t q_ctime;						/* 最后一次改动时间 */	
	unsigned long q_cbytes;				/* 队列中的当前字节数 */
	unsigned long q_qnum;				/* 队列中的消息数 */
	unsigned long q_qbytes;				/* 队列中的最大字节数 */
	pid_t q_lspid;						/* 最后一条发送消息的进程ID */
	pid_t q_lrpid;						/* 最后一条接收消息的进程ID */

	struct list_head q_messages;		/* 消息队列中 */
	struct list_head q_receivers;		/* 接收信号进程等待队列 */
	struct list_head q_senders;			/* 发送消息进程等待队列 */
};

#define SEARCH_ANY			1
#define SEARCH_EQUAL		2
#define SEARCH_NOTEQUAL		3
#define SEARCH_LESSEQUAL	4

static atomic_t msg_bytes = ATOMIC_INIT(0);
static atomic_t msg_hdrs = ATOMIC_INIT(0);

static struct ipc_ids msg_ids;

#define msg_lock(id)	((struct msg_queue*)ipc_lock(&msg_ids,id))
#define msg_unlock(id)	ipc_unlock(&msg_ids,id)
#define msg_rmid(id)	((struct msg_queue*)ipc_rmid(&msg_ids,id))
#define msg_checkid(msq, msgid)	\
	ipc_checkid(&msg_ids,&msq->q_perm,msgid)
#define msg_buildid(id, seq) \
	ipc_buildid(&msg_ids, id, seq)

static void freeque(int id);
static int newque(key_t key, int msgflg);
#ifdef CONFIG_PROC_FS
static int sysvipc_msg_read_proc(char* buffer, char** start, off_t offset, int length, int* eof, void* data);
#endif

// init
void __init msg_init(void)
{
	ipc_init_ids(&msg_ids, msg_ctlmni);

#ifdef CONFIG_PROC_FS
	create_proc_read_entry("sysvipc/msg", 0, 0, sysvipc_msg_read_proc, NULL);
#endif
}

/**
 * @brief 创建一个新的消息队列
 * @param key 
 * @param msgflg 
 *
 * @return 
 *		若成功，返回消息队列ID
 *      若为消息结构体分配内存失败，返回内存溢出错误[-ENOMEM = -12]
 *		若IPC数组添加ID失败，返回设备无空余空间错误[-ENOSPC = -28]
 */
static int newque(key_t key, int msgflg)
{
	int id;
	struct msg_queue* msq;

	// 分配内存、IPC_ID
	msq = (struct msg_queue*)kmalloc(sizeof(*msq), GFP_KERNEL);
	if (!msq)
		return -ENOMEM;
	id = ipc_addid(&msg_ids, &msq->q_perm, msg_ctlmni);
	if (id == -1) {
		kfree(msq);
		return -ENOSPC;
	}
	msq->q_perm.mode = (msgflg & S_IRWXUGO);
	msq->q_perm.key = key;

	// 初始化属性
	msq->q_stime = msq->q_rtime = 0;
	msq->q_ctime = CURRENT_TIME;
	msq->q_cbytes = msq->q_qnum = 0;
	msq->q_qbytes = msg_ctlmnb;
	msq->q_lspid = msq->q_lrpid = 0;
	INIT_LIST_HEAD(&msq->q_messages);
	INIT_LIST_HEAD(&msq->q_receivers);
	INIT_LIST_HEAD(&msq->q_senders);
	msg_unlock(id);

	//创建消息队列ID并返回
	return msg_buildid(id, msq->q_perm.seq);
}

/**
 * @brief 释放指定消息所占内存空间/资源
 * @param msg 指定消息的指针
 */
static void free_msg(struct msg_msg* msg)
{
	struct msg_msgseg* seg;
	seg = msg->next;
	kfree(msg);
	// 释放整个消息队列
	while (seg != NULL) {
		struct msg_msgseg* tmp = seg->next;
		kfree(seg);
		seg = tmp;
	}
}

/**
 * @brief 读取所有消息
 * @param src 消息源地址
 * @param len 消息长度
 *
 * @return 
 *		若成功，返回消息链表的头指针
 *		若为消息结构体分配内存失败，返回内存溢出错误指针[-ENOMEM = -12]
 *      若读取数据失败，返回地址错误指针[-EFAULT = -14]
 */
static struct msg_msg* load_msg(void* src, int len)
{
	struct msg_msg* msg;
	struct msg_msgseg** pseg;
	int err;
	int alen;

	// 边界检测
	alen = len;
	if (alen > DATALEN_MSG)
		alen = DATALEN_MSG;

	// 为消息分配内存
	msg = (struct msg_msg*)kmalloc(sizeof(*msg) + alen, GFP_KERNEL);
	if (msg == NULL)
		return ERR_PTR(-ENOMEM);

	msg->next = NULL;

	// 读取第一条消息
	if (copy_from_user(msg + 1, src, alen)) {
		err = -EFAULT;
		goto out_err;
	}

	// 读取该消息后的所有消息，以链表的形式连接在第一条消息末尾
	len -= alen;
	src = ((char*)src) + alen;
	pseg = &msg->next;
	while (len > 0) {
		struct msg_msgseg* seg;
		alen = len;
		if (alen > DATALEN_SEG)
			alen = DATALEN_SEG;
		seg = (struct msg_msgseg*)kmalloc(sizeof(*seg) + alen, GFP_KERNEL);
		if (seg == NULL) {
			err = -ENOMEM;
			goto out_err;
		}
		*pseg = seg;
		seg->next = NULL;
		if (copy_from_user(seg + 1, src, alen)) {
			err = -EFAULT;
			goto out_err;
		}
		pseg = &seg->next;
		len -= alen;
		src = ((char*)src) + alen;
	}
	// 返回消息链表头指针
	return msg;

out_err:
	free_msg(msg);
	return ERR_PTR(err);
}

/**
 * @brief 存储消息（链表）
 * @param dest 消息存储地址
 * @param msg 消息
 * @param len 消息长度
 * 
 * @return 
 *      若成功，返回0
 *      若存储消息失败，返回-1
 */
static int store_msg(void* dest, struct msg_msg* msg, int len)
{
	int alen;
	struct msg_msgseg* seg;

	// 边界检测
	alen = len;
	if (alen > DATALEN_MSG)
		alen = DATALEN_MSG;

	// 存储第一条消息
	if (copy_to_user(dest, msg + 1, alen))
		return -1;

	// 将后面所有消息以链表形式连接在第一条消息之后存储
	len -= alen;
	dest = ((char*)dest) + alen;
	seg = msg->next;
	while (len > 0) {
		alen = len;
		if (alen > DATALEN_SEG)
			alen = DATALEN_SEG;
		if (copy_to_user(dest, seg + 1, alen))
			return -1;
		len -= alen;
		dest = ((char*)dest) + alen;
		seg = seg->next;
	}
	return 0;
}

/**
 * @brief 添加消息发送者
 * @param msq 消息队列
 * @param mss 消息发送者
 */
static inline void ss_add(struct msg_queue* msq, struct msg_sender* mss)
{
	mss->tsk = current;
	current->state = TASK_INTERRUPTIBLE;
	list_add_tail(&mss->list, &msq->q_senders);
}

/**
 * @brief 删除消息发送者
 * @param mss 消息发送者
 */
static inline void ss_del(struct msg_sender* mss)
{
	if (mss->list.next != NULL)
		list_del(&mss->list);
}

/**
 * @brief 唤醒消息发送者
 * @param h 消息发送者链表头指针
 * @param kill [1] - ?; [0] - ?
 */
static void ss_wakeup(struct list_head* h, int kill)
{
	struct list_head* tmp;

	// 遍历所有消息发送者进行唤醒
	tmp = h->next;
	while (tmp != h) {
		struct msg_sender* mss;

		mss = list_entry(tmp, struct msg_sender, list);
		tmp = tmp->next;
		if (kill)
			mss->list.next = NULL;
		wake_up_process(mss->tsk);
	}
}

/**
 * @brief 使所有正在等待此队列接收消息的进程都出错返回
 * @param msq 消息队列
 * @param res 错误标识符（将全部消息接收者的接收消息置为指定错误）
 */
static void expunge_all(struct msg_queue* msq, int res)
{
	struct list_head* tmp;

	// 遍历消息队列进行清除、置错操作
	tmp = msq->q_receivers.next;
	while (tmp != &msq->q_receivers) {
		struct msg_receiver* msr;

		msr = list_entry(tmp, struct msg_receiver, r_list);
		tmp = tmp->next;
		msr->r_msg = ERR_PTR(res);
		wake_up_process(msr->r_tsk);
	}
}

/**
 * @brief 释放消息队列所占资源
 * @param id 消息队列id
 */
static void freeque(int id)
{
	struct msg_queue* msq;
	struct list_head* tmp;

	msq = msg_rmid(id);

	// 停止消息队列收发消息、唤醒并解锁
	expunge_all(msq, -EIDRM);
	ss_wakeup(&msq->q_senders, 1);
	msg_unlock(id);

	// 遍历消息队列中的消息进行释放
	tmp = msq->q_messages.next;
	while (tmp != &msq->q_messages) {
		struct msg_msg* msg = list_entry(tmp, struct msg_msg, m_list);
		tmp = tmp->next;
		atomic_dec(&msg_hdrs);
		free_msg(msg);
	}
	atomic_sub(msq->q_cbytes, &msg_bytes);
	kfree(msq);
}

/**
 * @brief 系统函数 - 获取指定消息队列，若该消息队列不存在，则创建一个新的消息队列
 * @param key 消息队列标识符
 * @param msgflg 消息队列操作标识符
 *					IPC_CREAT：创建新的消息队列
 *					IPC_EXCL：与IPC_CREAT一同使用，表示如果要创建的消息队列已经存在，则返回错误、
 *					IPC_NOWAIT：读写消息队列要求无法满足时，不阻塞
 * 
 * @return 
 *		若成功，返回消息队列标识符
 *      若创建新消息队列失败，返回-2[-ENOENT = -2]
 *      若要创建的新消息队列已存在，返回-17[-EEXIST = -17]
 *      若无IPC权限进行操	作，返回-13[-EACCES = -13]
 *	    若操作失败或发生其他错误，返回-1[-EPERM = -1]
 */
asmlinkage long sys_msgget(key_t key, int msgflg)
{
	int id, ret = -EPERM;
	struct msg_queue* msq;

	down(&msg_ids.sem); // 请求信号量
	if (key == IPC_PRIVATE) // 用户设定IPC_PRIVATE时，无条件创建一个消息队列
		ret = newque(key, msgflg);

	// 边界、错误检测，无错误则创建消息队列，有错误则返回对应错误
	else if ((id = ipc_findkey(&msg_ids, key)) == -1) {
		if (!(msgflg & IPC_CREAT))
			ret = -ENOENT;
		else
			ret = newque(key, msgflg);
	}
	else if (msgflg & IPC_CREAT && msgflg & IPC_EXCL) {
		ret = -EEXIST;
	}
	else {
		msq = msg_lock(id);
		if (msq == NULL)
			BUG();
		if (ipcperms(&msq->q_perm, msgflg))
			ret = -EACCES;
		else
			ret = msg_buildid(id, msq->q_perm.seq);
		msg_unlock(id);
	}
	up(&msg_ids.sem); // 对请求的信号量进行处理
	return ret;
}

/**
 * @brief 将全部消息队列发送至用户空间
 * @param buf 目标用户空间地址
 * @param in 管理消息队列总结构体
 * @param version IPC版本 - IPC_64：新版本，支持32位UID以及更大的消息等		IPC_OLD：老版本，几乎不支持32位UID
 * 
 * @return 
 *		若成功，返回0
 *		若发送失败，返回发送失败的字节数
 *		若参数错误，返回-22[-EINVAL = -22]
 */
static inline unsigned long copy_msqid_to_user(void* buf, struct msqid64_ds* in, int version)
{
	switch (version) {
	case IPC_64:
		// 返回消息队列发送结果
		return copy_to_user(buf, in, sizeof(*in));
	case IPC_OLD:
	{
		struct msqid_ds out;

		memset(&out, 0, sizeof(out));

		ipc64_perm_to_ipc_perm(&in->msg_perm, &out.msg_perm);

		out.msg_stime = in->msg_stime;
		out.msg_rtime = in->msg_rtime;
		out.msg_ctime = in->msg_ctime;

		if (in->msg_cbytes > USHRT_MAX)
			out.msg_cbytes = USHRT_MAX;
		else
			out.msg_cbytes = in->msg_cbytes;
		out.msg_lcbytes = in->msg_cbytes;

		if (in->msg_qnum > USHRT_MAX)
			out.msg_qnum = USHRT_MAX;
		else
			out.msg_qnum = in->msg_qnum;

		if (in->msg_qbytes > USHRT_MAX)
			out.msg_qbytes = USHRT_MAX;
		else
			out.msg_qbytes = in->msg_qbytes;
		out.msg_lqbytes = in->msg_qbytes;

		out.msg_lspid = in->msg_lspid;
		out.msg_lrpid = in->msg_lrpid;

		return copy_to_user(buf, &out, sizeof(out));
	}
	default:
		return -EINVAL;
	}
}

/**
 * @brief 结构体 - 用于接收管理消息队列结构体?
 */
struct msq_setbuf {
	unsigned long	qbytes;		/* ? */
	uid_t		uid;			/* 用户ID */
	gid_t		gid;			/* 用户组ID */
	mode_t		mode;			/* 模式 */
};

/**
 * @brief 获取来自用户空间的全部消息队列
 * @param out 管理消息队列总结构体
 * @param buf 内核空间消息队列源地址
 * @param version IPC版本 - IPC_64：新版本，支持32位UID以及更大的消息等		IPC_OLD：老版本，几乎不支持32位UID
 */
static inline unsigned long copy_msqid_from_user(struct msq_setbuf* out, void* buf, int version)
{
	switch (version) {
	case IPC_64:
	{
		struct msqid64_ds tbuf;

		if (copy_from_user(&tbuf, buf, sizeof(tbuf)))
			return -EFAULT;

		// 初始化属性
		out->qbytes = tbuf.msg_qbytes;
		out->uid = tbuf.msg_perm.uid;
		out->gid = tbuf.msg_perm.gid;
		out->mode = tbuf.msg_perm.mode;

		return 0;
	}
	case IPC_OLD:
	{
		struct msqid_ds tbuf_old;

		if (copy_from_user(&tbuf_old, buf, sizeof(tbuf_old)))
			return -EFAULT;

		out->uid = tbuf_old.msg_perm.uid;
		out->gid = tbuf_old.msg_perm.gid;
		out->mode = tbuf_old.msg_perm.mode;

		if (tbuf_old.msg_qbytes == 0)
			out->qbytes = tbuf_old.msg_lqbytes;
		else
			out->qbytes = tbuf_old.msg_qbytes;

		return 0;
	}
	default:
		return -EINVAL;
	}
}

/**
 * @brief 获取和设置消息队列的属性
 * @param msqid 消息队列标识符
 * @param cmd	IPC_STAT / MSG_STAT：获得msgid的消息队列头数据到buf中
 * 				IPC_SET：设置消息队列的属性
 *				IPC_INFO / MSG_INFO：统计信息
 *				IPC_RMID：删除消息队列
 * @param buf：消息队列管理结构体，请参见消息队列内核结构说明部分
 *
 * @return 
 * 	若成功，返回0
 * 	若失败，返回-
 *		EACCES：参数cmd为IPC_STAT，却无权限读取该消息队列
 * 		EFAULT：参数buf指向无效的内存地址
 * 		EIDRM：标识符为msqid的消息队列已被删除
 * 		EINVAL：无效的参数cmd或msqid
 * 		EPERM：参数cmd为IPC_SET或IPC_RMID，却无足够的权限执行
 */
asmlinkage long sys_msgctl(int msqid, int cmd, struct msqid_ds* buf)
{
	int err, version;
	struct msg_queue* msq;
	struct msq_setbuf setbuf;
	struct kern_ipc_perm* ipcp;

	if (msqid < 0 || cmd < 0)
		return -EINVAL;

	version = ipc_parse_version(&cmd);

	switch (cmd) {
	// INFO操作
	case IPC_INFO:
	case MSG_INFO:
	{
		struct msginfo msginfo;
		int max_id;
		if (!buf)
			return -EFAULT;

		/* We must not return kernel stack data.
		 * due to padding, it's not enough
		 * to set all member fields.
		 */

		// 设置、读取-属性、信息
		memset(&msginfo, 0, sizeof(msginfo));
		msginfo.msgmni = msg_ctlmni;
		msginfo.msgmax = msg_ctlmax;
		msginfo.msgmnb = msg_ctlmnb;
		msginfo.msgssz = MSGSSZ;
		msginfo.msgseg = MSGSEG;
		down(&msg_ids.sem); //请求信号量
		if (cmd == MSG_INFO) {
			msginfo.msgpool = msg_ids.in_use;
			msginfo.msgmap = atomic_read(&msg_hdrs);
			msginfo.msgtql = atomic_read(&msg_bytes);
		}
		else {
			msginfo.msgmap = MSGMAP;
			msginfo.msgpool = MSGPOOL;
			msginfo.msgtql = MSGTQL;
		}
		max_id = msg_ids.max_id;
		up(&msg_ids.sem); // 对请求的信号量进行处理
		if (copy_to_user(buf, &msginfo, sizeof(struct msginfo)))
			return -EFAULT;
		return (max_id < 0) ? 0 : max_id;
	}
	// STAT操作
	case MSG_STAT:
	case IPC_STAT:
	{
		struct msqid64_ds tbuf;
		int success_return;
		// 异常检测
		if (!buf)
			return -EFAULT;
		if (cmd == MSG_STAT && msqid >= msg_ids.size)
			return -EINVAL;

		memset(&tbuf, 0, sizeof(tbuf));

		// 锁消息队列
		msq = msg_lock(msqid);
		if (msq == NULL)
			return -EINVAL;

		if (cmd == MSG_STAT) {
			success_return = msg_buildid(msqid, msq->q_perm.seq);
		}
		else {
			err = -EIDRM;
			if (msg_checkid(msq, msqid))
				goto out_unlock; // 解锁消息队列并结束函数
			success_return = 0;
		}
		err = -EACCES;
		if (ipcperms(&msq->q_perm, S_IRUGO))
			goto out_unlock;

		// 向指定内存写入消息队列头数据
		kernel_to_ipc64_perm(&msq->q_perm, &tbuf.msg_perm);
		tbuf.msg_stime = msq->q_stime;
		tbuf.msg_rtime = msq->q_rtime;
		tbuf.msg_ctime = msq->q_ctime;
		tbuf.msg_cbytes = msq->q_cbytes;
		tbuf.msg_qnum = msq->q_qnum;
		tbuf.msg_qbytes = msq->q_qbytes;
		tbuf.msg_lspid = msq->q_lspid;
		tbuf.msg_lrpid = msq->q_lrpid;
		msg_unlock(msqid);
		if (copy_msqid_to_user(buf, &tbuf, version))
			return -EFAULT;
		return success_return;
	}
	// SET操作异常检测
	case IPC_SET:
		if (!buf)
			return -EFAULT;
		if (copy_msqid_from_user(&setbuf, buf, version))
			return -EFAULT;
		break;
	case IPC_RMID:
		break;
	default:
		return  -EINVAL;
	}

	down(&msg_ids.sem);
	msq = msg_lock(msqid);
	err = -EINVAL;
	if (msq == NULL)
		goto out_up;

	err = -EIDRM;
	if (msg_checkid(msq, msqid))
		goto out_unlock_up;
	ipcp = &msq->q_perm;
	err = -EPERM;
	if (current->euid != ipcp->cuid &&
		current->euid != ipcp->uid && !capable(CAP_SYS_ADMIN))
		/* We _could_ check for CAP_CHOWN above, but we don't */
		goto out_unlock_up;

	switch (cmd) {
	case IPC_SET:
	{
		if (setbuf.qbytes > msg_ctlmnb && !capable(CAP_SYS_RESOURCE))
			goto out_unlock_up;
		msq->q_qbytes = setbuf.qbytes;

		// 设置消息队列属性
		ipcp->uid = setbuf.uid;
		ipcp->gid = setbuf.gid;
		ipcp->mode = (ipcp->mode & ~S_IRWXUGO) |
			(S_IRWXUGO & setbuf.mode);
		msq->q_ctime = CURRENT_TIME;
		/* sleeping receivers might be excluded by
		 * stricter permissions.
		 */
		expunge_all(msq, -EAGAIN);
		/* sleeping senders might be able to send
		 * due to a larger queue size.
		 */
		ss_wakeup(&msq->q_senders, 0); //将所有正在等待此队列发送报文的进程都唤醒,进行新一轮尝试
		msg_unlock(msqid);
		break;
	}
	case IPC_RMID:
		freeque(msqid);
		break;
	}
	err = 0;
out_up:
	up(&msg_ids.sem);
	return err;
out_unlock_up:
	msg_unlock(msqid);
	goto out_up;
out_unlock:
	msg_unlock(msqid);
	return err;
}

/**
 * @brief 比较消息类别
 * @param msg 消息
 * @param type 欲比较的消息类别
 * @param mode 判断模式
 *					SEARCH_ANY：恒成功
 *					SEARCH_LESSEQUAL：判断消息的类别是否小于等于欲比较的消息类别
 * 					SEARCH_EQUAL：判断消息的类别是否等于欲比较的消息类别
 * 					SEARCH_NOTEQUAL：判断消息的类别是否不等于欲比较的消息类别
 * 
 * @return 
 *		若成功，返回1
 *		若失败，返回0
 */
static int testmsg(struct msg_msg* msg, long type, int mode)
{
	switch (mode)
	{
	case SEARCH_ANY:
		return 1;
	case SEARCH_LESSEQUAL:
		if (msg->m_type <= type)
			return 1;
		break;
	case SEARCH_EQUAL:
		if (msg->m_type == type)
			return 1;
		break;
	case SEARCH_NOTEQUAL:
		if (msg->m_type != type)
			return 1;
		break;
	}
	return 0;
}

/**
 * @brief 判断是否有相关进程正在读指定消息队列中的消息
 * @param msq 消息队列
 * @param msg 消息
 * 
 * @return 
 * 
 */
int inline pipelined_send(struct msg_queue* msq, struct msg_msg* msg)
{
	struct list_head* tmp;

	tmp = msq->q_receivers.next; // 聚集正在睡眠等待接收的读进程
	while (tmp != &msq->q_receivers) { //如果有正在睡眠等待接受的读消息进程
		struct msg_receiver* msr;
		msr = list_entry(tmp, struct msg_receiver, r_list);
		tmp = tmp->next;
		if (testmsg(msg, msr->r_msgtype, msr->r_mode)) { //类型是否匹配
			list_del(&msr->r_list);
			if (msr->r_maxsize < msg->m_ts) { // 读的缓冲区是否够用
				msr->r_msg = ERR_PTR(-E2BIG);
				wake_up_process(msr->r_tsk); // 不够用则唤醒进程
			}
			else { // 够用则读取
				msr->r_msg = msg;
				msq->q_lrpid = msr->r_tsk->pid;
				msq->q_rtime = CURRENT_TIME;
				wake_up_process(msr->r_tsk);
				return 1;
			}
		}
	}
	return 0;
}

/**
 * @brief 将msgp消息写入到标识符为msqid的消息队列
 * @param msqid 消息队列标识符
 * @param msgp 发送给队列的消息
 * @param msgsz 要发送消息的大小，不含消息类型占用的4个字节,即mtext的长度
 * @param msgflg 若为0：当消息队列满时，msgsnd将会阻塞，直到消息能写进消息队列
 * 			  若为IPC_NOWAIT：当消息队列已满的时候，msgsnd函数不等待立即返回
 * 			  若为IPC_NOERROR：若发送的消息大于size字节，则把该消息截断，截断部分将被丢弃，且不通知发送进程。
 * @return
 *		若成功，返回0
 *		若失败，返回-
 * 			EAGAIN：参数msgflg 设为IPC_NOWAIT，而消息队列已满
 * 			EIDRM：标识符为msqid的消息队列已被删除
 * 			EACCES：无权限写入消息队列
 * 			EFAULT：参数msgp指向无效的内存地址
 * 			EINTR：队列已满而处于等待情况下被信号中断
 * 			EINVAL：无效的参数msqid、msgsz或参数消息类型type小于0
 */
asmlinkage long sys_msgsnd(int msqid, struct msgbuf* msgp, size_t msgsz, int msgflg)
{
	struct msg_queue* msq;
	struct msg_msg* msg;
	long mtype;
	int err;

	// 边界、异常检测
	if (msgsz > msg_ctlmax || (long)msgsz < 0 || msqid < 0)
		return -EINVAL;
	if (get_user(mtype, &msgp->mtype))
		return -EFAULT;
	if (mtype < 1)
		return -EINVAL;

	msg = load_msg(msgp->mtext, msgsz); // 分配内存缓冲区保存消息
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	msg->m_type = mtype;
	msg->m_ts = msgsz;

	msq = msg_lock(msqid); //根据给定的消息找到相应的消息队列,将其上锁
	err = -EINVAL;
	if (msq == NULL)
		goto out_free;
// 重试
retry:
	err = -EIDRM;
	if (msg_checkid(msq, msqid))
		goto out_unlock_free;

	err = -EACCES;
	if (ipcperms(&msq->q_perm, S_IWUGO))
		goto out_unlock_free;

	if (msgsz + msq->q_cbytes > msq->q_qbytes ||
		1 + msq->q_qnum > msq->q_qbytes) {
		struct msg_sender s;

		if (msgflg & IPC_NOWAIT) {
			err = -EAGAIN;
			goto out_unlock_free;
		}
		ss_add(msq, &s); // 挂载到消息队列q_sender链,这样可以通过此链找到休眠正在等待发送的进程
		msg_unlock(msqid);
		schedule(); // 调度
		current->state = TASK_RUNNING;

		msq = msg_lock(msqid);
		err = -EIDRM;
		if (msq == NULL)
			goto out_free;
		ss_del(&s); // 删除

		if (signal_pending(current)) {
			err = -EINTR;
			goto out_unlock_free;
		}
		goto retry;
	}

	msq->q_lspid = current->pid;
	msq->q_stime = CURRENT_TIME;

	if (!pipelined_send(msq, msg)) { // 如果无相关进程正在读这个消息，则放入队列
		list_add_tail(&msg->m_list, &msq->q_messages);
		msq->q_cbytes += msgsz;
		msq->q_qnum++;
		atomic_add(msgsz, &msg_bytes);
		atomic_inc(&msg_hdrs);
	}

	err = 0;
	msg = NULL;

out_unlock_free:
	msg_unlock(msqid);
out_free:
	if (msg != NULL)
		free_msg(msg);
	return err;
}

/**
 * @brief 模式转换
 * @param msgtyp 消息类别
 *					若=0：接收第一个消息
 *					若>0：接收类型等于msgtyp的第一个消息
 *					若<0：接收类型等于或者小于msgtyp绝对值的第一个消息
 * @param msgflg 标识符 - MSG_EXCEPT
 * 
 * @return 
 *		若msgtyp等于0，返回SEARCH_ANY
 *		若msgtyp小于0，返回SEARCH_LESSEQUAL
 *		若msgtyp大于0，且msgflg为MSG_EXCEPT，返回SEARCH_NOTEQUAL
 *		若msgtyp大于0，且msgflg不为MSG_EXCEPT，返回SEARCH_EQUAL
 */
int inline convert_mode(long* msgtyp, int msgflg)
{
	/*
	 *  find message of correct type.
	 *  msgtyp = 0 => get first.
	 *  msgtyp > 0 => get first message of matching type.
	 *  msgtyp < 0 => get message with least type must be < abs(msgtype).
	 */
	if (*msgtyp == 0)
		return SEARCH_ANY;
	if (*msgtyp < 0) {
		*msgtyp = -(*msgtyp);
		return SEARCH_LESSEQUAL;
	}
	if (msgflg & MSG_EXCEPT)
		return SEARCH_NOTEQUAL;
	return SEARCH_EQUAL;
}

/**
 * @brief 从标识符为msqid的消息队列读取消息并存于msgp中，读取后把此消息从消息队列中删除
 * @param msqid 消息队列标识符
 * @param msgp 存放消息的结构体，结构体类型要与msgsnd函数发送的类型相同
 * @param msgsz 要接收消息的大小，不含消息类型占用的4个字节
 * @param msgtyp 若=0：接收第一个消息
 * 			  若>0：接收类型等于msgtyp的第一个消息
 * 			  若<0：接收类型等于或者小于msgtyp绝对值的第一个消息
 * @param msgflg 若为0: 阻塞式接收消息，没有该类型的消息msgrcv函数一直阻塞等待
 * 			  若为IPC_NOWAIT：如果没有返回条件的消息调用立即返回，此时错误码为ENOMSG
 * 			  若为IPC_EXCEPT：与msgtype配合使用返回队列中第一个类型不为msgtype的消息
 * 			  若为IPC_NOERROR：如果队列中满足条件的消息内容大于所请求的size字节，则把该消息截断，截断部分将被丢弃
 *
 * @return 
 * 	若成功，则返回实际读取到的消息数据长度
 * 	若失败，返回-
 * 		EINVAL：消息长度值越界
 * 		E2BIG：消息数据长度大于msgsz而msgflag没有设置IPC_NOERROR
 * 		EIDRM：标识符为msqid的消息队列已被删除
 * 		EACCES：无权限读取该消息队列
 * 		EFAULT：参数msgp指向无效的内存地址
 * 		ENOMSG：参数msgflg设为IPC_NOWAIT，而消息队列中无消息可读
 * 		EINTR：等待读取队列内的消息情况下被信号中断
 */
asmlinkage long sys_msgrcv(int msqid, struct msgbuf* msgp, size_t msgsz,
	long msgtyp, int msgflg)
{
	struct msg_queue* msq;
	struct msg_receiver msr_d;
	struct list_head* tmp;
	struct msg_msg* msg, * found_msg;
	int err;
	int mode;

	// 异常检测
	if (msqid < 0 || (long)msgsz < 0)
		return -EINVAL;
	mode = convert_mode(&msgtyp, msgflg);

	msq = msg_lock(msqid); // 找到并锁指定消息队列
	if (msq == NULL)
		return -EINVAL;
// 重试
retry:
	err = -EIDRM;
	if (msg_checkid(msq, msqid))
		goto out_unlock;

	err = -EACCES;
	if (ipcperms(&msq->q_perm, S_IRUGO))
		goto out_unlock;

	tmp = msq->q_messages.next;
	found_msg = NULL;
	while (tmp != &msq->q_messages) {
		msg = list_entry(tmp, struct msg_msg, m_list);
		if (testmsg(msg, msgtyp, mode)) {
			found_msg = msg;
			if (mode == SEARCH_LESSEQUAL && msg->m_type != 1) {
				found_msg = msg; // 查找到了消息
				msgtyp = msg->m_type - 1; // 将type减到比这个消息的类型值更小，看能否找到更小的
			}
			else {
				found_msg = msg;
				break;
			}
		}
		tmp = tmp->next;
	}
	if (found_msg) {
		msg = found_msg;
		if ((msgsz < msg->m_ts) && !(msgflg & MSG_NOERROR)) {
			err = -E2BIG;
			goto out_unlock;
		}
		list_del(&msg->m_list); // 将该消息从队列中删除
		msq->q_qnum--;
		msq->q_rtime = CURRENT_TIME;
		msq->q_lrpid = current->pid;
		msq->q_cbytes -= msg->m_ts;
		atomic_sub(msg->m_ts, &msg_bytes);
		atomic_dec(&msg_hdrs);
		ss_wakeup(&msq->q_senders, 0); // 取出消息后，将发送的睡眠等待进程全部唤醒
		msg_unlock(msqid); // 解锁消息队列
out_success:
		msgsz = (msgsz > msg->m_ts) ? msg->m_ts : msgsz;
		if (put_user(msg->m_type, &msgp->mtype) ||
			store_msg(msgp->mtext, msg, msgsz)) { // 实际接收的消息类型，通过put_user送回用户空间并存储
			msgsz = -EFAULT;
		}
		free_msg(msg); // 释放内核空间内存
		return msgsz;
	}
	// 消息队列还没有消息可供接收
	else
	{
		struct msg_queue* t;
		/* no message waiting. Prepare for pipelined
		 * receive.
		 */
		if (msgflg & IPC_NOWAIT) {
			err = -ENOMSG;
			goto out_unlock;
		}
		list_add_tail(&msr_d.r_list, &msq->q_receivers);
		msr_d.r_tsk = current;
		msr_d.r_msgtype = msgtyp;
		msr_d.r_mode = mode;
		if (msgflg & MSG_NOERROR)
			msr_d.r_maxsize = INT_MAX;
		else
			msr_d.r_maxsize = msgsz;
		msr_d.r_msg = ERR_PTR(-EAGAIN);
		current->state = TASK_INTERRUPTIBLE;
		msg_unlock(msqid);

		// 当前进程一旦睡眠，以下需要等待进程通过pipelined_send()向其发送消息，并且选择这个进程作为接收进程才会被唤醒
		schedule();
		current->state = TASK_RUNNING;

		msg = (struct msg_msg*)msr_d.r_msg;
		if (!IS_ERR(msg))
			goto out_success;

		// 以下是因为缓冲区太小，唤醒了睡眠进程依旧无法接收，而是被信号唤醒的错误处理
		t = msg_lock(msqid); // 对消息加锁，隐藏着等待，可能被其他进程抢先锁住该队列
		if (t == NULL)
			msqid = -1;
		msg = (struct msg_msg*)msr_d.r_msg;
		// 在锁住队列之前,还有可能接收到其他进程pipelined_send发来的报文
		if (!IS_ERR(msg)) {
			/* our message arived while we waited for
			 * the spinlock. Process it.
			 */
			 // 所以还需要检查下是否成功接收到报文
			if (msqid != -1)
				msg_unlock(msqid);
			goto out_success;
		}
		err = PTR_ERR(msg); // 将本进程的msg_receiver结构拖链，并且看是否有信号处理
		if (err == -EAGAIN) {
			if (msqid == -1)
				BUG();
			list_del(&msr_d.r_list);
			if (signal_pending(current))
				err = -EINTR;
			else
				goto retry; // 如果没有信号处理，则跳转到retry重新开始
		}
	}
out_unlock:
	if (msqid != -1)
		msg_unlock(msqid);
	return err;
}

/**
 * @brief 读取系统消息进程
 * @param buffer 是从驱动层向应用层返回的数据区；当有用户读此/proc/xxx的文件时，由系统分配一页的缓存区，驱动使用read_proc此写入数据。
 * @param start 表示写在此页的哪里，若数据不超过一页，则赋值为NULL
 * @param offset 表示文件指针的偏移
 * @param length 表示要读多少个字节
 * @param eof 输出参数
 * @param data 由驱动内部使用
 * 
 * @return 
 *		返回值为可读取到的字节数
*/
#ifdef CONFIG_PROC_FS
static int sysvipc_msg_read_proc(char* buffer, char** start, off_t offset, int length, int* eof, void* data)
{
	off_t pos = 0;
	off_t begin = 0;
	int i, len = 0;

	down(&msg_ids.sem);
	len += sprintf(buffer, "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n");

	for (i = 0; i <= msg_ids.max_id; i++) {
		struct msg_queue* msq;
		msq = msg_lock(i);
		if (msq != NULL) {
			len += sprintf(buffer + len, "%10d %10d  %4o  %10lu %10lu %5u %5u %5u %5u %5u %5u %10lu %10lu %10lu\n",
				msq->q_perm.key,
				msg_buildid(i, msq->q_perm.seq),
				msq->q_perm.mode,
				msq->q_cbytes,
				msq->q_qnum,
				msq->q_lspid,
				msq->q_lrpid,
				msq->q_perm.uid,
				msq->q_perm.gid,
				msq->q_perm.cuid,
				msq->q_perm.cgid,
				msq->q_stime,
				msq->q_rtime,
				msq->q_ctime);
			msg_unlock(i);

			pos += len;
			if (pos < offset) {
				len = 0;
				begin = pos;
			}
			if (pos > offset + length)
				goto done;
		}

	}
	*eof = 1;
done:
	up(&msg_ids.sem);
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if (len > length)
		len = length;
	if (len < 0)
		len = 0;
	return len;
}
#endif
