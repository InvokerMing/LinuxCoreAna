struct pipe_inode_info {
	wait_queue_head_t wait;//�ܵ��ȴ�����
	char* base;
	unsigned int len;
	unsigned int start;//��ǰ�ܵ�����������λ��
	unsigned int readers;//�����̵ı�־������
	unsigned int writers;//д���̵ı�־������
	unsigned int waiting_readers;//�ڵȴ�������˯�ߵ�д���̵ĸ���
	unsigned int waiting_writers;
	unsigned int r_counter;//��readers���ƣ������ȴ�д��FIFO�Ľ�����ʹ��
	unsigned int w_counter;//��writers���ƣ������ȴ�д��FIFO�Ľ���ʱʹ��
};

/* Differs from PIPE_BUF in that PIPE_SIZE is the length of the actual
   memory allocation, whereas PIPE_BUF makes atomicity guarantees.  */
#define PIPE_SIZE		PAGE_SIZE

#define PIPE_SEM(inode)		(&(inode).i_sem)
#define PIPE_WAIT(inode)	(&(inode).i_pipe->wait)
#define PIPE_BASE(inode)	((inode).i_pipe->base)
#define PIPE_START(inode)	((inode).i_pipe->start)
#define PIPE_LEN(inode)		((inode).i_pipe->len)
#define PIPE_READERS(inode)	((inode).i_pipe->readers)
#define PIPE_WRITERS(inode)	((inode).i_pipe->writers)
#define PIPE_WAITING_READERS(inode)	((inode).i_pipe->waiting_readers)
#define PIPE_WAITING_WRITERS(inode)	((inode).i_pipe->waiting_writers)
#define PIPE_RCOUNTER(inode)	((inode).i_pipe->r_counter)
#define PIPE_WCOUNTER(inode)	((inode).i_pipe->w_counter)

#define PIPE_EMPTY(inode)	(PIPE_LEN(inode) == 0)
#define PIPE_FULL(inode)	(PIPE_LEN(inode) == PIPE_SIZE)
#define PIPE_FREE(inode)	(PIPE_SIZE - PIPE_LEN(inode))
#define PIPE_END(inode)	((PIPE_START(inode) + PIPE_LEN(inode)) & (PIPE_SIZE-1))
#define PIPE_MAX_RCHUNK(inode)	(PIPE_SIZE - PIPE_START(inode))
#define PIPE_MAX_WCHUNK(inode)	(PIPE_SIZE - PIPE_END(inode))

   /* Drop the inode semaphore and wait for a pipe event, atomically */
void pipe_wait(struct inode* inode);

struct inode* pipe_new(struct inode* inode);

#endif