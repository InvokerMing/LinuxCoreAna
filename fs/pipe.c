/*
 *  linux/fs/pipe.c
 *
 *  Copyright (C) 1991, 1992, 1999  Linus Torvalds
 */

#include <linux/mm.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

 /*
  * We use a start+len construction, which provides full use of the
  * allocated memory.
  * -- Florian Coosmann (FGC)
  *
  * Reads with count = 0 should always return 0.
  * -- Julian Bradfield 1999-06-07.
  */

  /* Drop the inode semaphore and wait for a pipe event, atomically */
  /*删除inode信号量并以原子方式等待管道事件*/
void pipe_wait(struct inode* inode)
{
	DECLARE_WAITQUEUE(wait, current);
	current->state = TASK_INTERRUPTIBLE; /*任务可中断*/
	add_wait_queue(PIPE_WAIT(*inode), &wait);
	up(PIPE_SEM(*inode));/*唤醒睡眠的进程*/
	schedule();
	remove_wait_queue(PIPE_WAIT(*inode), &wait);
	current->state = TASK_RUNNING; /*任务运行*/
	down(PIPE_SEM(*inode));/*使得调用者睡眠*/
}
/*管道读操作:(管道为空)管道不允许seek操作,
 *管道如果为空但通过pipe_writers判断, 没有写的file对象那就直接返回
 *.管道为空并且设置了非阻塞, 直接返回
 *.管道数据为空, 但有相关fd会进行写操作.休眠等待被唤醒读取数据
 *.管道不为空, 有3种情况, 管道读取到了要求长度, 刚好为空或者有剩余, 直接返回
 *.管道读取的数据没有达到要求, , 并且设置了非阻塞, 那就读多少返回多少
 *如果管道读取的数据没达到要求(读取数据大于剩余数据), 并且还有写fd在等待, 并且没有设置非阻塞标志
 *则唤醒写fd进程, 继续循环读.直到读完或者file对象没了(数据还未达到要求).
*/
static ssize_t
pipe_read(struct file* filp, char* buf, size_t count, loff_t* ppos)
{
	struct inode* inode = filp->f_dentry->d_inode;/*获取当前文件目录的信号*/
	ssize_t size, read, ret;

	/* Seeks are not allowed on pipes.  */
	/*管道上不允许seek操作。*/
	ret = -ESPIPE;/*非非法搜索*/
	read = 0;
	if (ppos != &filp->f_pos)/*ppos必须指向filp->f_pos*/
		goto out_nolock;

	/* Always return 0 on null read.  */
	/*读取空值时始终返回0。*/
	ret = 0;
	if (count == 0)
		goto out_nolock;

	/* Get the pipe semaphore */
	ret = -ERESTARTSYS;
	if (down_interruptible(PIPE_SEM(*inode)))/*信号是否被打断*/
		goto out_nolock;

	if (PIPE_EMPTY(*inode)) {//管道中的字节数如果等于0,表示为空管道
	do_more_read:
		ret = 0;
		if (!PIPE_WRITERS(*inode))//如果管道无人写,那就等于写端关闭,那么客户端也要关闭
			goto out;

		ret = -EAGAIN;
		if (filp->f_flags & O_NONBLOCK)//设置非阻塞直接返回,因为管道为空
			goto out;

		for (;;) {
			PIPE_WAITING_READERS(*inode)++;
			pipe_wait(inode); //休眠, 因为没有数据可读
			PIPE_WAITING_READERS(*inode)--;
			ret = -ERESTARTSYS;
			if (signal_pending(current)) //当前进程有信号未处理
				goto out;
			ret = 0;
			if (!PIPE_EMPTY(*inode))//如果管道不为空,跳出这循环
				break;
			if (!PIPE_WRITERS(*inode))//没有写端,直接跳出
				goto out;
		}
	}

	/* Read what data is available.  */
	/*读取可用的数据。*/
	ret = -EFAULT;//如果读取
	while (count > 0 && (size = PIPE_LEN(*inode))) {//count表示剩余数不为0,并且pipe还有数据
		char* pipebuf = PIPE_BASE(*inode) + PIPE_START(*inode);//起始位置
		ssize_t chars = PIPE_MAX_RCHUNK(*inode);//start到base

		if (chars > count)//如果start到base的数据大于count
			chars = count;
		if (chars > size)
			chars = size;
		//有3种情况.(1)读取到要求长度,刚好或者还有剩余,直接返回要求长度,否则返回实际长度
		if (copy_to_user(buf, pipebuf, chars))
			goto out;

		read += chars;//read等于实际读取长度
		PIPE_START(*inode) += chars;//起始位置更改
		PIPE_START(*inode) &= (PIPE_SIZE - 1);//对齐
		PIPE_LEN(*inode) -= chars;//长度更改
		count -= chars;//要求长度-chars长度
		buf += chars;//用户缓冲+chars
	}

	/* Cache behaviour optimization */
	if (!PIPE_LEN(*inode))//如果长度为0,就把start设置到页开头
		PIPE_START(*inode) = 0;
	//如果读取的数据不够要求的长度并且还有等待写进程并且未设置阻塞
	if (count && PIPE_WAITING_WRITERS(*inode) && !(filp->f_flags & O_NONBLOCK)) {
		/*
		 * We know that we are going to sleep: signal
		 * writers synchronously that there is more
		 * room.
		 */
		wake_up_interruptible_sync(PIPE_WAIT(*inode));//唤醒
		if (!PIPE_EMPTY(*inode))//管道必须为空
			BUG();
		goto do_more_read;//继续读
	}
	/* Signal writers asynchronously that there is more room.  */
	/*信号写入程序异步地表示有更多的空间。*/
	wake_up_interruptible(PIPE_WAIT(*inode));

	ret = read;
out:
	up(PIPE_SEM(*inode));
out_nolock:
	if (read)
		ret = read;
	return ret;
}
/*管道写相关操作:(以下阻塞未默认设置)
 *写入的数据参数为0, 直接返回
 *判断了管道没有读的fd, 直接返回并发送SIGPIPE信号表示管道破裂
 *是否超过了管道的缓存大小, 超过了则不保证其原子性并将free设置为1, 并将要读取的字节限制为一页大小, 这时候能有多大空间就写多少
 *字节, 余下的等消费者多一些字节再继续写
 *设置了不阻塞位, 但管道剩余空间小于要写入空间直接退出
 *如果要写入的字节大于整个缓冲区剩余空间, 那当前写管道进程睡眠, 直到缓冲区有剩余空间
 *如果写入的字节数等于要求的字节数, 那就返回
 */
static ssize_t
pipe_write(struct file* filp, const char* buf, size_t count, loff_t* ppos)
{
	struct inode* inode = filp->f_dentry->d_inode;
	ssize_t free, written, ret;

	/* Seeks are not allowed on pipes.  */
	ret = -ESPIPE;
	written = 0;
	if (ppos != &filp->f_pos)
		goto out_nolock;

	/* Null write succeeds.  */
	ret = 0;
	if (count == 0)//写的数据要求为0,直接跳到out_nolock
		goto out_nolock;

	ret = -ERESTARTSYS;
	if (down_interruptible(PIPE_SEM(*inode)))//枷锁信号量数据(count)不为0，则把其减1，并返回，调用成功；否则调用__down进行等待，调用者进行睡眠。

		goto out_nolock;

	/* No readers yields SIGPIPE.  */
	if (!PIPE_READERS(*inode))//如果没有读的fd了,直接发送sigpipe信号
		goto sigpipe;

	/* If count <= PIPE_BUF, we have to make it atomic.  */
	free = (count <= PIPE_BUF ? count : 1);//是否超过缓冲区大小,超过设置为1

	/* Wait, or check for, available space.  */
	if (filp->f_flags & O_NONBLOCK) {//表示即使读不到东西,也不该阻塞
		ret = -EAGAIN;
		if (PIPE_FREE(*inode) < free)//管道剩余的空间小于要写入的数据,直接退出
			goto out;
	}
	else {
		while (PIPE_FREE(*inode) < free) {//如果要写入的字节数大于整个缓冲区的大小，那就睡眠
			PIPE_WAITING_WRITERS(*inode)++;//等待写++
			pipe_wait(inode);//睡眠
			PIPE_WAITING_WRITERS(*inode)--;
			ret = -ERESTARTSYS;
			if (signal_pending(current))//有信号要处理
				goto out;

			if (!PIPE_READERS(*inode))//如果不存在读的fd,发送sigpipe信号
				goto sigpipe;
		}
	}

	/* Copy into available space.  */
	ret = -EFAULT;
	while (count > 0) {
		int space;
		char* pipebuf = PIPE_BASE(*inode) + PIPE_END(*inode);
		ssize_t chars = PIPE_MAX_WCHUNK(*inode);
		//如果没有剩余空间了，那么就只说明，要写的字节大于缓冲区的总大小，执行下面的do_while循环
		if ((space = PIPE_FREE(*inode)) != 0) {//space获取剩余空间
			if (chars > count)
				chars = count;
			if (chars > space)
				chars = space;//space与count中选取最小的那个

			if (copy_from_user(pipebuf, buf, chars))//拷贝到管道
				goto out;

			written += chars;//写入多少数据
			PIPE_LEN(*inode) += chars;//长度++
			count -= chars;
			buf += chars;
			space = PIPE_FREE(*inode);
			continue;
		}
		//如果剩余空间等于0
		ret = written;
		if (filp->f_flags & O_NONBLOCK)
			break;

		do {
			/*
			 * Synchronous wake-up: it knows that this process
			 * is going to give up this CPU, so it doesnt have
			 * to do idle reschedules.同步唤醒：它知道这个进程将放弃这个CPU，所以它不必进行空闲的重新调度。
			 */
			wake_up_interruptible_sync(PIPE_WAIT(*inode));//唤醒等待的进程
			PIPE_WAITING_WRITERS(*inode)++;
			pipe_wait(inode);//睡眠等待
			PIPE_WAITING_WRITERS(*inode)--;
			if (signal_pending(current))//唤醒很可能是有信号
				goto out;
			if (!PIPE_READERS(*inode))//如果没inode读管道
				goto sigpipe;
		} while (!PIPE_FREE(*inode));//如果管道一直是满的,继续do_while循环,直到有剩余空间
		ret = -EFAULT;
	}

	/* Signal readers asynchronously that there is more data.  */
	wake_up_interruptible(PIPE_WAIT(*inode));//唤醒等待读的进程

	inode->i_ctime = inode->i_mtime = CURRENT_TIME;
	mark_inode_dirty(inode);

out:
	up(PIPE_SEM(*inode));
out_nolock:
	if (written)
		ret = written;
	return ret;

sigpipe://读端都关闭了,那就发送sigpipe信号
	if (written)
		goto out;
	up(PIPE_SEM(*inode));
	send_sig(SIGPIPE, current, 0);
	return -EPIPE;
}

static loff_t
//返回当前文件偏移量：新的偏移量（成功）， - 1（失败）
pipe_lseek(struct file* file, loff_t offset, int orig)
{
	return -ESPIPE;
}

static ssize_t
//bad_pipe_w函数；对写入端描述符执行read操作，内核就会执行bad_pipe_r函数。
//这两个函数比较简单，都是直接返回-EBADF。
//对应的read和write调用都会失败，返回-1，并置errno为EBADF。
bad_pipe_r(struct file* filp, char* buf, size_t count, loff_t* ppos)
{
	return -EBADF;
}

static ssize_t
bad_pipe_w(struct file* filp, const char* buf, size_t count, loff_t* ppos)
{
	return -EBADF;
}

static int
//ioctl是设备驱动程序中对设备的I/O通道进行管理的函数
pipe_ioctl(struct inode* pino, struct file* filp,
	unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FIONREAD:
		return put_user(PIPE_LEN(*pino), (int*)arg);
	default:
		return -EINVAL;
	}
}

/* No kernel lock held - fine */
static unsigned int
/*poll轮询函数
 *监听这个文件描述符需要监听可读、可写或者异常事件；
 *当有可读、可写和异常事件发生时，在select调用过程中，
 *内核会修改相应的这三个文件描述符集合中的没有事件发生的文件描述符标记位为0
 */
	pipe_poll(struct file* filp, poll_table* wait)
{
	unsigned int mask;
	struct inode* inode = filp->f_dentry->d_inode;

	poll_wait(filp, PIPE_WAIT(*inode), wait);

	/* Reading only -- no need for acquiring the semaphore.  */
	mask = POLLIN | POLLRDNORM;
	if (PIPE_EMPTY(*inode))
		mask = POLLOUT | POLLWRNORM;
	if (!PIPE_WRITERS(*inode) && filp->f_version != PIPE_WCOUNTER(*inode))
		mask |= POLLHUP;
	if (!PIPE_READERS(*inode))
		mask |= POLLERR;

	return mask;
}

/* FIXME: most Unices do not set POLLERR for fifos */
#define fifo_poll pipe_poll

static int
pipe_release(struct inode* inode, int decr, int decw)
{
	down(PIPE_SEM(*inode));
	PIPE_READERS(*inode) -= decr;//共享计数
	PIPE_WRITERS(*inode) -= decw;//共享计数
	if (!PIPE_READERS(*inode) && !PIPE_WRITERS(*inode)) {//如果读端和写端的相关fd都关闭了
		struct pipe_inode_info* info = inode->i_pipe;
		inode->i_pipe = NULL;
		free_page((unsigned long)info->base);//将页面释放
		kfree(info);
	}
	else {
		wake_up_interruptible(PIPE_WAIT(*inode));
	}
	up(PIPE_SEM(*inode));

	return 0;
}

static int
pipe_read_release(struct inode* inode, struct file* filp)
{
	return pipe_release(inode, 1, 0);//1表示读的相关描述符减1,因为关闭,写端设置为0
}

static int
pipe_write_release(struct inode* inode, struct file* filp)
{
	return pipe_release(inode, 0, 1);
}

static int
pipe_rdwr_release(struct inode* inode, struct file* filp)
{
	int decr, decw;

	decr = (filp->f_mode & FMODE_READ) != 0;
	decw = (filp->f_mode & FMODE_WRITE) != 0;
	return pipe_release(inode, decr, decw);
}

static int
pipe_read_open(struct inode* inode, struct file* filp)
{
	/* We could have perhaps used atomic_t, but this and friends
	   below are the only places.  So it doesn't seem worthwhile.  */
	down(PIPE_SEM(*inode));
	PIPE_READERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

static int
pipe_write_open(struct inode* inode, struct file* filp)
{
	down(PIPE_SEM(*inode));
	PIPE_WRITERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

static int
//读写方式打开
pipe_rdwr_open(struct inode* inode, struct file* filp)
{
	down(PIPE_SEM(*inode));
	if (filp->f_mode & FMODE_READ)
		PIPE_READERS(*inode)++;
	if (filp->f_mode & FMODE_WRITE)
		PIPE_WRITERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

/*fifo命名管道的实现 让两个不相干的进程找到带有pipe属性的inode
 我们自然就想到利用磁盘文件
 * The file_operations structs are not static because they
 * are also used in linux/fs/fifo.c to do operations on FIFOs.
 */
struct file_operations read_fifo_fops = {
	llseek:		pipe_lseek,
	read : pipe_read,
	write : bad_pipe_w,
	poll : fifo_poll,//fifo创建的文件只是让读写进程能找到相同的inode，进而操作相同的pipe缓冲区。
	ioctl : pipe_ioctl,
	open : pipe_read_open,
	release : pipe_read_release,
};

struct file_operations write_fifo_fops = {
	llseek:		pipe_lseek,
	read : bad_pipe_r,
	write : pipe_write,
	poll : fifo_poll,
	ioctl : pipe_ioctl,
	open : pipe_write_open,
	release : pipe_write_release,
};

struct file_operations rdwr_fifo_fops = {
	llseek:		pipe_lseek,
	read : pipe_read,
	write : pipe_write,
	poll : fifo_poll,
	ioctl : pipe_ioctl,
	open : pipe_rdwr_open,
	release : pipe_rdwr_release,
};

struct file_operations read_pipe_fops = {
	llseek:		pipe_lseek,
	read : pipe_read,
	write : bad_pipe_w,
	poll : pipe_poll,
	ioctl : pipe_ioctl,
	open : pipe_read_open,
	release : pipe_read_release,
};

struct file_operations write_pipe_fops = {
	llseek:		pipe_lseek,
	read : bad_pipe_r,
	write : pipe_write,
	poll : pipe_poll,
	ioctl : pipe_ioctl,
	open : pipe_write_open,
	release : pipe_write_release,
};

struct file_operations rdwr_pipe_fops = {
	llseek:		pipe_lseek,
	read : pipe_read,
	write : pipe_write,
	poll : pipe_poll,
	ioctl : pipe_ioctl,
	open : pipe_rdwr_open,
	release : pipe_rdwr_release,
};
//例化一个带有pipe属性的inode
struct inode* pipe_new(struct inode* inode)
{
	unsigned long page;// 申请一个内存页，作为pipe的缓存

	page = __get_free_page(GFP_USER);
	if (!page)
		return NULL;
	// 为pipe_inode_info结构体分配内存
	inode->i_pipe = kmalloc(sizeof(struct pipe_inode_info), GFP_KERNEL);
	if (!inode->i_pipe)
		goto fail_page;
	// 初始化pipe_inode_info属性
	init_waitqueue_head(PIPE_WAIT(*inode));
	PIPE_BASE(*inode) = (char*)page;
	PIPE_START(*inode) = PIPE_LEN(*inode) = 0;
	PIPE_READERS(*inode) = PIPE_WRITERS(*inode) = 0;
	PIPE_WAITING_READERS(*inode) = PIPE_WAITING_WRITERS(*inode) = 0;
	PIPE_RCOUNTER(*inode) = PIPE_WCOUNTER(*inode) = 1;

	return inode;
fail_page:
	free_page(page);
	return NULL;
}

static struct vfsmount* pipe_mnt;
static int pipefs_delete_dentry(struct dentry* dentry)
{
	return 1;
}
static struct dentry_operations pipefs_dentry_operations = {
	d_delete:	pipefs_delete_dentry,
};
//获取管道的inode结构
static struct inode* get_pipe_inode(void)
{
	//　从pipefs超级块中分配一个inode
	struct inode* inode = new_inode(pipe_mnt->mnt_sb);

	if (!inode)
		goto fail_inode;
	// pipe_new函数主要用来为这个inode初始化pipe属性，就是pipe_inode_info结构体
	if (!pipe_new(inode))
		goto fail_iput;
	PIPE_READERS(*inode) = PIPE_WRITERS(*inode) = 1;
	inode->i_fop = &rdwr_pipe_fops;//设置pipefs的inode操作函数集合，rdwr_pipe_fops
	// 为结构体，包含读写管道所有操作
	/*
	 * Mark the inode dirty from the very beginning,
	 * that way it will never be moved to the dirty
	 * list because "mark_inode_dirty()" will think
	 * that it already _is_ on the dirty list.
	 */
	inode->i_state = I_DIRTY;
	inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
	inode->i_uid = current->fsuid;
	inode->i_gid = current->fsgid;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_blksize = PAGE_SIZE;
	return inode;

fail_iput:
	iput(inode);
fail_inode:
	return NULL;
}
/*pipe的建立的实现
 *对于每个管道来说，内核都创建一个inode结点对象，两个file对象，一个用于读，一个用于写。
 */
int do_pipe(int* fd)
{
	struct qstr this;
	char name[32];
	struct dentry* dentry;
	struct inode* inode;
	struct file* f1, * f2;
	int error;
	int i, j;

	error = -ENFILE;
	f1 = get_empty_filp();//获取文件对象1
	if (!f1)
		goto no_files;

	f2 = get_empty_filp();//获取文件对象2
	if (!f2)
		goto close_f1;

	inode = get_pipe_inode();//获取pipe的inode结点
	if (!inode)
		goto close_f12;

	error = get_unused_fd();//获取没有使用的fd1
	if (error < 0)
		goto close_f12_inode;
	i = error;

	error = get_unused_fd();//获取没有使用的fd2
	if (error < 0)
		goto close_f12_inode_i;
	j = error;

	error = -ENOMEM;
	sprintf(name, "[%lu]", inode->i_ino);//设置索引节点号
	this.name = name;
	this.len = strlen(name);
	this.hash = inode->i_ino; /* will go */
	dentry = d_alloc(pipe_mnt->mnt_sb->s_root, &this); //获取一个目录对象
	if (!dentry)
		goto close_f12_inode_i_j;
	dentry->d_op = &pipefs_dentry_operations;//把目录对象和inode结点联系在一起
	d_add(dentry, inode);
	f1->f_vfsmnt = f2->f_vfsmnt = mntget(mntget(pipe_mnt));
	f1->f_dentry = f2->f_dentry = dget(dentry);

	/* 给读描述符的文件对象赋值read file */
	f1->f_pos = f2->f_pos = 0;//读的位置从0偏移量开始
	f1->f_flags = O_RDONLY;//只读
	f1->f_op = &read_pipe_fops;//读操作时执行的函数
	f1->f_mode = 1;//读模式
	f1->f_version = 0;

	/* write file */
	f2->f_flags = O_WRONLY;//只写
	f2->f_op = &write_pipe_fops; //写操作执行函数
	f2->f_mode = 2; //写模式
	f2->f_version = 0;

	fd_install(i, f1);//给文件对象f1中的fd赋值
	fd_install(j, f2);//给文件对象f2中的fd赋值
	fd[0] = i; //把值赋给用户空间
	fd[1] = j;//把值赋给用户空间
	return 0;

close_f12_inode_i_j:
	put_unused_fd(j);
close_f12_inode_i:
	put_unused_fd(i);
close_f12_inode:
	free_page((unsigned long)PIPE_BASE(*inode));
	kfree(inode->i_pipe);
	inode->i_pipe = NULL;
	iput(inode);
close_f12:
	put_filp(f2);
close_f1:
	put_filp(f1);
no_files:
	return error;
}

/*
 * pipefs should _never_ be mounted by userland - too much of security hassle,
 * no real gain from having the whole whorehouse mounted. So we don't need
 * any operations on the root directory. However, we need a non-trivial
 * d_name - pipe: will go nicely and kill the special-casing in procfs.
 */
static int pipefs_statfs(struct super_block* sb, struct statfs* buf)
{
	buf->f_type = PIPEFS_MAGIC;
	buf->f_bsize = 1024;
	buf->f_namelen = 255;
	return 0;
}
static struct super_operations pipefs_ops = {
	statfs:		pipefs_statfs,
};
//管道超级块
static struct super_block* pipefs_read_super(struct super_block* sb, void* data, int silent)
{
	struct inode* root = new_inode(sb);//生成管道文件系统的根目录的内存inode
	if (!root)
		return NULL;
	root->i_mode = S_IFDIR | S_IRUSR | S_IWUSR;
	root->i_uid = root->i_gid = 0;
	root->i_atime = root->i_mtime = root->i_ctime = CURRENT_TIME;
	sb->s_blocksize = 1024;
	sb->s_blocksize_bits = 10;
	sb->s_magic = PIPEFS_MAGIC;
	sb->s_op = &pipefs_ops; //设置超级块sb的s_ob域的值为pipefs_ops结构的指针。
	sb->s_root = d_alloc(NULL, &(const struct qstr) { "pipe:", 5, 0 });//设置超级块的s_root域，s_root域的类型是struct dentry*,指向根目录的对象
	if (!sb->s_root) {
		iput(root);
		return NULL;
	}
	sb->s_root->d_sb = sb;
	sb->s_root->d_parent = sb->s_root;//将刚分配的目录项对象与前面生成的根目录inode连接起来
	d_instantiate(sb->s_root, root);
	return sb;
}

static DECLARE_FSTYPE(pipe_fs_type, "pipefs", pipefs_read_super, FS_NOMOUNT);

static int __init init_pipe_fs(void)
{
	int err = register_filesystem(&pipe_fs_type);
	if (!err) {
		pipe_mnt = kern_mount(&pipe_fs_type);
		err = PTR_ERR(pipe_mnt);
		if (IS_ERR(pipe_mnt))
			unregister_filesystem(&pipe_fs_type);
		else
			err = 0;
	}
	return err;
}

static void __exit exit_pipe_fs(void)
{
	unregister_filesystem(&pipe_fs_type);
	mntput(pipe_mnt);
}

module_init(init_pipe_fs)
module_exit(exit_pipe_fs)