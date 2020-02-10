/*
 *      Copyright (C) 2001  Moxa Inc.
 *      All rights reserved.
 *
 *      Moxa NPort/Async Server UNIX Real TTY daemon program.
 *
 *      Usage: npreal2d_redund [-t reset-time]
 *
 */

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/param.h>
#include	<netinet/in.h>
#include	<netinet/tcp.h>
#include	<netdb.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<errno.h>
#include	<time.h>
#include	<string.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<signal.h>
#include	<sys/ioctl.h>
#include	<sys/sysinfo.h>
#include    <pthread.h>
#ifdef	STREAM
#include	<sys/ptms.h>
#endif
#ifdef	SSL_ON
#include	<openssl/ssl.h>
#endif

#include	<arpa/inet.h>
#include	"redund.h"
#include    "npreal2d.h"
//#include	"misc.h"

#define		CON_TIME			1000000 /* connection time   : micro-second */
#define		RE_TIME				5000000 /* reconnection time : micro-second */
//#define		Gsession			0x01
/* the define of KeepAlive */
int8_t Gsession = 0x00;
int Gsession_cnt = 0;
int Gkeep_alive = 1;  			/* open keepalive */
int Gkeep_idle = 1;   			/* idle time (sec)*/
int Gkeep_interval = 3;			/* interval time (sec) */
int Gkeep_count = 2;			/* try how many time */
pthread_mutex_t Gmutex = PTHREAD_MUTEX_INITIALIZER;

int connect_nonb(int fd, struct sockaddr_in *sockaddr, socklen_t socklen, int usec);

int redund_send_data(int fd, int fd_bk, const char *sbuf, ssize_t len, struct expect_struct *expect, TTYINFO *infop);
int redund_send_cmd(int fd, int fd_bk, const char *sbuf, ssize_t len, struct expect_struct *expect);
int redund_add_hdr(const char *sbuf, char *dbuf, ssize_t len, struct expect_struct *expect);
void redund_add_hdr_data(int fd, const char *sbuf, char *dbuf, ssize_t len, struct expect_struct *expect, TTYINFO *infop);

int redund_recv_data(int fd, int fd_bk, char *sbuf, ssize_t len, struct expect_struct *expect, TTYINFO *infop); 
int redund_recv_cmd(int fd, int fd_bk, char *sbuf, ssize_t len, struct expect_struct *expect, TTYINFO *infop);

int redund_data_init(int fd, struct expect_struct *expect);
int redund_cmd_init(int fd, struct expect_struct *expect);

int redund_reconnect(void *infop);
/* wrap for redund */
int do_redund_send_data(TTYINFO *infop, SERVINFO *servp, struct sysinfo *sys_info, fd_set *wfd); 
int do_redund_recv_data(TTYINFO *infop, SERVINFO *servp, struct sysinfo *sys_info, fd_set *rfd);
int do_redund_send_cmd(TTYINFO *infop, int n);
int do_redund_recv_cmd(TTYINFO *infop, char *cmd_buf, fd_set *rfd);
int do_redund_reconnect(TTYINFO *infop);

void redund_connect_check(TTYINFO *infopp);
void redund_close(TTYINFO *infop);
void redund_connect(TTYINFO *infop);
void redund_open(TTYINFO *infop);
void _OpenTty(TTYINFO *infop);

/* poll_nport_send & poll_npoll_recv */
void redund_poll_nport_recv(int af_type);
void redund_poll_nport_send(SERVINFO *servp);

#define 	REDUND_INIT			0
#define 	REDUND_MPT_OPEN		1
#define 	REDUND_CONN_FAIL 	2
#define 	REDUND_TCP_OPEN		3
#define 	REDUND_TCP_CONN		4
#ifdef SSL_ON
#define 	REDUND_SSL_CONN	 	5
#define 	REDUND_TCP_CLOSE 	6
#define 	REDUND_TCP_WAIT		7
#define 	REDUND_MPT_REOPEN	8
#define 	REDUND_TTY_WAIT		9
#define 	REDUND_RW_DATA		10
#define 	REDUND_REMOTE_LISTEN	11
#else
#define 	REDUND_TCP_CLOSE 	5
#define 	REDUND_TCP_WAIT		6
#define 	REDUND_MPT_REOPEN	7
#define 	REDUND_TTY_WAIT		8
#define 	REDUND_RW_DATA		9
#define 	REDUND_REMOTE_LISTEN	10
#endif

#define 	CONNECT_OK			0
#define 	CONNECT_FAIL		1
#define 	CLOSE_OK			2

#define 	TCP_LISTEN			1
#define 	TCP_CONNECTED		4

#define 	ERROR_MPT_OPEN	0x0001
#define 	ERROR_TCP_OPEN	0x0002
#define 	ERROR_TCP_CONN	0x0004
#define 	ERROR_FORK		0x0008

#define 	REDUND_SIZE		1024	/* temporary data buffer size */
#define 	MAX_TTYS	256			/* max. handling TTYs number */
#define		MAX_PORTS	16			/* max. port of server is 16 */

#define		IS_IPV4		0
#define		IS_IPV6		1

extern int		ttys, servers;
extern TTYINFO 	ttys_info[MAX_TTYS];
extern SERVINFO	serv_info[MAX_TTYS];
extern char		EventLog[160];		/* Event log file name */
extern int		maxfd;
extern int      timeout_time;
extern int		polling_time; 	    /* default disable polling function */
extern int		polling_fd;
extern int      polling_nport_fd[2];
extern int		Restart_daemon;
static int	    No_tty_defined;
static int      enable_ipv6 = 1;    /* 2 enable ipv6, 1 disenable ipv6 */

#define EN_IPV6   2
#define DIS_IPV6  1

void redund_handle_ttys() /* child process ok */
{
	int			i, n, m, maxfd, t0, sndx, len, len1, j, ret;
	int			k;
	TTYINFO   * infop, *infop_tmp;
	SERVINFO  *	servp;
	fd_set		rfd, wfd, efd;
	struct timeval	tm;
	char		cmd_buf[CMD_REDUND_SIZE], buf[100];
	ConnMsg 	msg;
	int			tcp_wait_count;
	struct sysinfo	sys_info;
	int			test;

	signal(SIGPIPE, SIG_IGN);	/* add for "broken pipe" error */

	while (1)
	{
		if (Restart_daemon == 1)
		{
			for ( i=0, infop=&ttys_info[0]; i<ttys; i+=1, infop+=1 )
			{
				if (!infop->redundant_mode)
					continue;
				if (infop->tty_used_timestamp)
				{
					ioctl(infop->mpt_fd,
							_IOC(_IOC_READ|_IOC_WRITE,'m',CMD_DISCONNECTED,0),
							0);
				}
				infop->reconn_flag = 1;
			}
			return;
		}
		tm.tv_sec = 3;
		tm.tv_usec = 0;
		FD_ZERO(&rfd);
		FD_ZERO(&wfd);
		FD_ZERO(&efd);
		maxfd = -1;
		sndx = -1;
		tcp_wait_count = 0;
		for ( i=0, infop=&ttys_info[0]; i<ttys; i+=1, infop+=1 )
		{
			if (!infop->redundant_mode)
				continue;

			//This is a test code to generate many logs
			//{
			//	char msg[256];
			//	sprintf(msg, "RED> %d, %s, %s, %s", __LINE__, __FUNCTION__, __FUNCTION__, __FUNCTION__);
			//	log_event(msg);
			//}

			if ( infop->state == REDUND_INIT ||
					infop->state == REDUND_MPT_OPEN ||
					infop->state == REDUND_MPT_REOPEN )
			{
				_OpenTty(infop);
			}

			if ( infop->state == REDUND_CONN_FAIL )
			{
				sysinfo(&sys_info);
				if ( (sys_info.uptime - infop->time_out) >= 1 ) {
					infop->state = REDUND_TCP_OPEN;
				}
			}

			if ( infop->state == REDUND_TCP_OPEN )
				redund_open(infop);

			if ( infop->state == REDUND_TCP_CONN )
				redund_connect(infop);

			if ( infop->state == REDUND_TCP_CLOSE )
				redund_close(infop);

			if ( infop->state == REDUND_TCP_WAIT )
			{
				redund_connect_check(infop);
				if ( infop->state == REDUND_TCP_WAIT )
					tcp_wait_count++;
			}

			if ( infop->state < REDUND_TTY_WAIT )
			{
				tm.tv_sec = 1;
			}
			else if ( infop->state == REDUND_REMOTE_LISTEN)
			{
				redund_close(infop);
				continue;
			}
			if (infop->mpt_fd >= 0)
				FD_SET(infop->mpt_fd, &efd);
			if ( infop->mpt_fd > maxfd )
				maxfd = infop->mpt_fd;

			servp = &serv_info[infop->serv_index];
			if ( (infop->state >= REDUND_RW_DATA)&&polling_time )
			{
				if (!infop->first_servertime)
				{
					sysinfo(&sys_info);
					infop->first_servertime = sys_info.uptime - 1;
					servp->last_servertime = (time_t)((int32_t)(sys_info.uptime - 1));
				}
				if ( sndx < 0 )
				{
					sysinfo(&sys_info);
					if ( ((time_t)((int32_t)sys_info.uptime) - servp->next_sendtime) > 0 )
					{
						sndx = infop->serv_index;
						FD_SET(polling_fd, &wfd);
					}
					if (((time_t)((int32_t)sys_info.uptime)-servp->last_servertime)>timeout_time)
					{
#if 0
						infop->first_servertime = 0;
						infop->state = REDUND_REMOTE_LISTEN;
						infop->time_out = sys_info.uptime;
						servp->start_item = 0;
#endif
					}
				}

				FD_SET(polling_fd, &rfd);
				if ( polling_fd > maxfd )
					maxfd = polling_fd;
				for(n=0; n<enable_ipv6; n++)
				{
					FD_SET(polling_nport_fd[n], &rfd);
					if ( polling_nport_fd[n] > maxfd )
						maxfd = polling_nport_fd[n];
				}
			} /* if ( (infop->state >= REDUND_RW_DATA)&&polling_time ) */

			if (infop->state >= REDUND_RW_DATA)
			{
				pthread_mutex_lock(&Gmutex);
				if ((infop->lost_cnt == 2) && (infop->stop_tx == 0)) {
					infop->redund.data.ack = 0;
					infop->redund.data.seq = 0;
					infop->redund.data.nport_ack = 0;
					infop->redund.cmd.ack = 0;
					infop->redund.cmd.seq = 0;
					infop->redund.cmd.nport_ack = 0;
					infop->stop_tx = 1;
					infop->mpt_datakeep = 0;
					infop->mpt_dataofs = 0;
				}

				if (infop->stop_tx) {
					if (infop->redund.connect[0] || infop->redund.connect[1]) {
						infop->stop_tx = 0;
					}
				}

				if (infop->mpt_fd > maxfd)
					maxfd = infop->mpt_fd;

				if (infop->redund.connect[0]) {
					if (infop->redund.sock_data[0] > maxfd)
						maxfd = infop->redund.sock_data[0];
					if (infop->redund.sock_cmd[0] > maxfd)
						maxfd = infop->redund.sock_cmd[0];
				}
				if (infop->redund.connect[1]) {
					if (infop->redund.sock_data[1] > maxfd)
						maxfd = infop->redund.sock_data[1];
					if (infop->redund.sock_cmd[1] > maxfd)
						maxfd = infop->redund.sock_cmd[1];
				}
				if ((infop->mpt_datakeep) && (!infop->stop_tx))
				{
					if (infop->redund.connect[0]) {
						FD_SET(infop->redund.sock_data[0], &wfd);
					}
					if (infop->redund.connect[1]) {
						FD_SET(infop->redund.sock_data[1], &wfd);
					}
				}
				else
				{
					FD_SET(infop->mpt_fd, &rfd);
				}

				if ( infop->sock_datakeep )
				{
					FD_SET(infop->mpt_fd, &wfd);
				}
				else
				{
					if (infop->redund.connect[0]) {
						FD_SET(infop->redund.sock_data[0], &rfd);
					}
					if (infop->redund.connect[1]) {
						FD_SET(infop->redund.sock_data[1], &rfd);
					}
				}
				if (infop->redund.connect[0]) {
					FD_SET(infop->redund.sock_cmd[0], &rfd);
				}
				if (infop->redund.connect[1]) {
					FD_SET(infop->redund.sock_cmd[1], &rfd);
				}
				pthread_mutex_unlock(&Gmutex);
			} /* if (infop->state >= REDUND_RW_DATA) */
		} /* for ( i=0, infop=&ttys_info[0]; i<ttys; i+=1, infop+=1 ) */
		if (tcp_wait_count)
		{
			tm.tv_sec = 0;
			tm.tv_usec = 20000;
		}

		if ((j= select(maxfd+1, &rfd, &wfd, &efd, &tm)) <= 0 )
			continue;

		for ( i=0, infop=&ttys_info[0]; i<ttys; i+=1, infop+=1 )
		{
			if (!infop->redundant_mode)
				continue;
			if ( infop->mpt_fd < 0)
				continue;
			if ( (infop->mpt_fd)&&FD_ISSET(infop->mpt_fd, &efd) )
			{ /* cmd ready */
				if ((n=ioctl(infop->mpt_fd,
						_IOC(_IOC_READ|_IOC_WRITE,'m',CMD_RETRIEVE,CMD_REDUND_SIZE),
						infop->mpt_cmdbuf)) > 0)
				{
					if (infop->mpt_cmdbuf[0] == NPREAL_ASPP_COMMAND_SET)
					{
						do_redund_send_cmd(infop, n);
					}
					else if (infop->mpt_cmdbuf[0] == NPREAL_LOCAL_COMMAND_SET)
					{
						switch (infop->mpt_cmdbuf[1])
						{
						case LOCAL_CMD_TTY_USED:
							if (infop->state != REDUND_TTY_WAIT)
							{
#ifdef SSL_ON
								if (infop->ssl_enable)
								{
									SSL_shutdown(infop->pssl);
									SSL_free(infop->pssl);
									infop->pssl = NULL;
								}
#endif
								shutdown(infop->redund.sock_data[0], 2);
								shutdown(infop->redund.sock_cmd[0], 2);
								close(infop->redund.sock_data[0]);
								close(infop->redund.sock_cmd[0]);
								infop->redund.sock_data[0] = -1;
								infop->redund.sock_cmd[0] = -1;
								shutdown(infop->redund.sock_data[1], 2);
								shutdown(infop->redund.sock_cmd[1], 2);

								close(infop->redund.sock_data[1]);
								close(infop->redund.sock_cmd[1]);
								infop->redund.sock_data[1] = -1;
								infop->redund.sock_cmd[1] = -1;
								infop->local_tcp_port = 0;
								infop->local_cmd_port = 0;
								sprintf(cmd_buf, "Repeat connection!, %d, %s\n", infop->tcp_port, infop->ip_addr_s);
								log_event(cmd_buf);
								sleep(1);
							}
							infop->state = REDUND_TCP_OPEN;
							infop->redund.close[0] = 0;
							infop->redund.close[1] = 0;
							infop->redund.thread[0] = 0;
							infop->redund.thread[1] = 0;
							infop->redund.data.repush_seq[0] = -1;
							infop->redund.data.repush_seq[1] = -1;
							infop->redund.cmd.repush_seq[0] = -1;
							infop->redund.cmd.repush_seq[1] = -1;
							infop->redund.data.last_seq = -1;
							infop->redund.cmd.last_seq = -1;

							sysinfo(&sys_info);
							infop->tty_used_timestamp = sys_info.uptime;
							infop->lost_cnt = 0;
							continue;
						case LOCAL_CMD_TTY_UNUSED:  /* when utility calling close(fd) */
#ifdef SSL_ON
							if (infop->ssl_enable)
							{
								SSL_shutdown(infop->pssl);
								SSL_free(infop->pssl);
								infop->pssl = NULL;
							}
#endif
							infop->redund.close[0] = 1;
							infop->redund.close[1] = 1;
							shutdown(infop->redund.sock_data[1], 2);
							shutdown(infop->redund.sock_cmd[1], 2);
							close(infop->redund.sock_data[1]);
							close(infop->redund.sock_cmd[1]);
							infop->redund.sock_data[1] = -1;
							infop->redund.sock_cmd[1] = -1;
							shutdown(infop->redund.sock_data[0], 2);
							shutdown(infop->redund.sock_cmd[0], 2);
							close(infop->redund.sock_data[0]);
							close(infop->redund.sock_cmd[0]);
							infop->redund.sock_data[0] = -1;
							infop->redund.sock_cmd[0] = -1;
							infop->local_tcp_port = 0;
							infop->local_cmd_port = 0;
							cmd_buf[0] = NPREAL_LOCAL_COMMAND_SET;
							cmd_buf[1] = LOCAL_CMD_TTY_UNUSED;
							ioctl(infop->mpt_fd,
									_IOC(_IOC_READ|_IOC_WRITE,'m',CMD_RESPONSE,2),
									cmd_buf);
							infop->sock_datakeep = 0;
							infop->sock_dataofs = 0;
							infop->mpt_datakeep = 0;
							infop->mpt_dataofs = 0;
							if ((infop->state < REDUND_RW_DATA) && !(infop->error_flags & ERROR_TCP_CONN))
							{
								sprintf(cmd_buf, "Socket connect fail (%s,TCP port %d) !",
										infop->ip_addr_s,
										infop->tcp_port);
								log_event(cmd_buf);
							}
							infop->state = REDUND_TTY_WAIT;
							infop->tty_used_timestamp = 0;
							infop->first_servertime = 0;
							memset(&infop->redund.data, 0, sizeof(struct expect_struct));
							memset(&infop->redund.cmd, 0, sizeof(struct expect_struct));
							infop->redund.data_open[0] = 0;
							infop->redund.data_open[1] = 0;
							infop->redund.cmd_open[0] = 0;
							infop->redund.cmd_open[1] = 0;
							infop->redund.connect[0] = 0;
							infop->redund.connect[1] = 0;
							infop->redund.data.last_seq = -1;
							infop->redund.cmd.last_seq = -1;
							infop->redund.wlen = 0;
							infop->redund.rlen = 0;
							infop->redund.host_ack = 0;
							infop->redund.reconnect[0] = 0;							
							infop->redund.reconnect[1] = 0;							
							Gsession_cnt = 0;
							continue;
						}
					}
				}
			} /* if ( (infop->mpt_fd)&&FD_ISSET(infop->mpt_fd, &efd) ) */

			if ( infop->state < REDUND_RW_DATA )
				continue;

			ret = do_redund_recv_cmd(infop, cmd_buf, &rfd);
			if ( FD_ISSET(infop->mpt_fd, &rfd) )
			{
				m = infop->mpt_datakeep + infop->mpt_dataofs;
				n = read(infop->mpt_fd,
						infop->mpt_bufptr + m,
						REDUND_SIZE - m);
				if ( n > 0 )
					infop->mpt_datakeep += n;
			}
			ret = do_redund_recv_data(infop, servp ,&sys_info ,&rfd);

#if 0
			if (ret < 0 && ret == -2) {
				for (k = 0, infop_tmp = &ttys_info[0]; k < ttys; k += 1, infop_tmp += 1) {
					if (infop_tmp->redund.connect[0] > 0 || infop_tmp->redund.connect[1] > 0) {
						close(infop_tmp->redund.sock_data[1]);
						close(infop_tmp->redund.sock_cmd[1]);
						infop_tmp->redund.connect[1] = 0;
					}
				}
			} else if (ret < 0 && ret == -1) {
				for (k = 0, infop_tmp = &ttys_info[0]; k < ttys; k += 1, infop_tmp += 1) {
					if (infop_tmp->redund.connect[0] > 0 || infop_tmp->redund.connect[1] > 0) {
						close(infop_tmp->redund.sock_data[0]);
						close(infop_tmp->redund.sock_cmd[0]);
						infop_tmp->redund.connect[0] = 0;
					}
				}
			}
#endif

			if ( FD_ISSET(infop->mpt_fd, &wfd) )
			{
				n = write(infop->mpt_fd,
						infop->sock_bufptr+infop->sock_dataofs,
						infop->sock_datakeep);
				if ( n > 0 )
				{
					infop->sock_datakeep -= n;
					if ( infop->sock_datakeep )
						infop->sock_dataofs += n;
					else
						infop->sock_dataofs = 0;
				}
			}
			ret = do_redund_send_data(infop, servp ,&sys_info ,&wfd);

#if 0
			for (k = 0, infop_tmp = &ttys_info[0]; k < ttys; k += 1, infop_tmp += 1) {
				if (infop_tmp->redund.connect[0] > 0 || infop_tmp->redund.connect[1] > 0) {
					if (infop_tmp->redund.connect[0] == 0 || infop_tmp->redund.connect[1] == 0)
						do_redund_reconnect(infop_tmp);
				}
			}
#else
			do_redund_reconnect(infop);
#endif			
		} /* for ( i=0, infop=&ttys_info[0]; i<ttys; i+=1, infop+=1 ) */

		if ( polling_time == 0 )
			continue;
#if 1
		if ((sndx >= 0) && FD_ISSET(polling_fd, &wfd)) {
			redund_poll_nport_send(&serv_info[sndx]);
		}
		if (FD_ISSET(polling_fd, &rfd)) {
		}
		for (n = 0; n < enable_ipv6; n++) {
			if (FD_ISSET(polling_nport_fd[n], &rfd)) {
				redund_poll_nport_recv(n);
			}
		}
#endif
	} /* while (1) */
}

void _OpenTty(infop)
TTYINFO *	infop;
{
    char	buf[80];

	infop->redund.data.repush_seq[0] = -1;
	infop->redund.data.repush_seq[1] = -1;
	infop->redund.cmd.repush_seq[0] = -1;
	infop->redund.cmd.repush_seq[1] = -1;
	infop->redund.data.last_seq = -1;
	infop->redund.cmd.last_seq = -1;
    infop->redund.close[0] = 0;
    infop->redund.close[1] = 0;
    infop->redund.thread[0] = 0;
    infop->redund.thread[1] = 0;

    if ( infop->mpt_fd >= 0 )
    {
        struct	net_node_setting nd_settings;
        int	tty_status = 0;
        infop->reconn_flag = 1;
        nd_settings.server_type = infop->server_type;
        nd_settings.disable_fifo = infop->disable_fifo;
        ioctl(infop->mpt_fd,
              _IOC(_IOC_READ|_IOC_WRITE,'m',CMD_NET_SETTING,
                   sizeof(struct net_node_setting)),
              &nd_settings);
        // Get the status which is contained the INUSE state.
        ioctl(infop->mpt_fd,
              _IOC(_IOC_READ|_IOC_WRITE,'m',CMD_GET_TTY_STATUS,
                   sizeof(int)),&tty_status);
        if (infop->tty_used_timestamp == 0)
        {
            if (!tty_status)
            {
                infop->state = REDUND_TTY_WAIT;
            }
            else
            {
                ioctl(infop->mpt_fd,
                      _IOC(_IOC_READ|_IOC_WRITE,'m',CMD_DISCONNECTED,0),
                     0);
                infop->state = REDUND_TCP_OPEN;

            }
        }
        else {
            infop->state = REDUND_TCP_OPEN;
		}
    }
    else
    {
        infop->mpt_fd = open(infop->mpt_name, O_RDWR);
        if ( infop->mpt_fd < 0 )
        {
            sprintf(buf, "Master tty open fail (%s) !",
                    infop->mpt_name);
            log_event(buf);
            infop->error_flags |= ERROR_MPT_OPEN;
        }
        // If open is success, state will be changed next turn during above if() condition.

    }
}
#define SOCK_BUF 1048
void redund_open(infop)
TTYINFO *	infop;
{
    char	buf[256];
    int		on = 1;
    int 	af;
	int		ret;
	int		inter = 1;
    af = infop->af;

	/* open first data socket */
    infop->redund.sock_data[0] = socket(af, SOCK_STREAM, 0);

    if (infop->redund.sock_data[0] >= 0) {
        infop->redund.data_open[0] = 1;
    }
	/* open second data socket */
    infop->redund.sock_data[1] = socket(af, SOCK_STREAM, 0);

    if (infop->redund.sock_data[1] >= 0) {
        infop->redund.data_open[1] = 1;
    } 
	/* open first cmd socket */
    infop->redund.sock_cmd[0] = socket(af, SOCK_STREAM, 0);
    if (infop->redund.sock_cmd[0] >= 0) {
        if (setsockopt(infop->redund.sock_cmd[0], SOL_SOCKET, 
					   SO_KEEPALIVE, (char *)&on, sizeof(on)) < 0) {
        	log_event("Set TCP keep alive fail !");
		}
        ret = setsockopt(infop->redund.sock_cmd[0], SOL_TCP, TCP_KEEPIDLE,
                         &Gkeep_idle,
                         sizeof(Gkeep_idle));
        if (ret < 0)
            printf("setsockopt SO_KEEPIDLE error! %d\n", ret);

        ret = setsockopt(infop->redund.sock_cmd[0], SOL_TCP, TCP_KEEPINTVL,
                         &(Gkeep_interval),
                         sizeof(Gkeep_interval));
        if (ret < 0)
            printf("setsockopt SO_KEEPINTVL error! %d\n", ret);

        ret = setsockopt(infop->redund.sock_cmd[0], SOL_TCP, TCP_KEEPCNT,
                         &(Gkeep_count),
                         sizeof(Gkeep_count));
        if (ret < 0)
        	printf("setsockopt SO_KEEPCNT error! %d\n", ret);
#if 0
		if (strlen(infop->scope_id) > 0) {
			if (setsockopt(infop->redund.sock_cmd[0], SOL_SOCKET, 
						   SO_BINDTODEVICE, infop->scope_id, strlen(infop->scope_id)) < 0) {
			    log_event("Set TCP bind to device fail !");		
			}
		}
#endif
        infop->redund.cmd_open[0] = 1;
    }
	/* open second cmd socket */
	 infop->redund.sock_cmd[1] = socket(af, SOCK_STREAM, 0);

    if (infop->redund.sock_cmd[1] >= 0) {
		if (setsockopt(infop->redund.sock_cmd[1], SOL_SOCKET, 
					   SO_KEEPALIVE, (char *)&on, sizeof(on)) < 0) {
        	log_event("Set TCP keep alive fail !");
		}
        ret = setsockopt(infop->redund.sock_cmd[1], SOL_TCP, TCP_KEEPIDLE,
                         &Gkeep_idle,
                         sizeof(Gkeep_idle));
        if (ret < 0)
            printf("setsockopt SO_KEEPIDLE error! %d\n", ret);

        ret = setsockopt(infop->redund.sock_cmd[1], SOL_TCP, TCP_KEEPINTVL,
                         &Gkeep_interval,
                         sizeof(Gkeep_interval));
        if (ret < 0)
            printf("setsockopt SO_KEEPINTVL error! %d\n", ret);

        ret = setsockopt(infop->redund.sock_cmd[1], SOL_TCP, TCP_KEEPCNT,
                         &Gkeep_count,
                         sizeof(Gkeep_count));
        if (ret < 0)
	        printf("setsockopt SO_KEEPCNT error! %d\n", ret);
#if 0
		if (strlen(infop->scope_id) > 0) {
			if (setsockopt(infop->redund.sock_cmd[1], SOL_SOCKET, 
						   SO_BINDTODEVICE, infop->scope_id, strlen(infop->scope_id)) < 0) {
			    log_event("Set TCP bind to device fail !");		
			}
		}
#endif
        infop->redund.cmd_open[1] = 1;
    }

	/* check the first connection ok or no */
    if ((infop->redund.sock_data[0] < 0) || (infop->redund.sock_cmd[0] < 0))
    {
        close(infop->redund.sock_data[0]);
        close(infop->redund.sock_cmd[0]);
        if ( !(infop->error_flags & ERROR_TCP_OPEN) )
        {
            if (infop->redund.sock_data[0] < 0)
            {
                sprintf(buf, "Socket one open fail (%s, TCP port %d) !",
                        infop->ip_addr_s,
                        infop->tcp_port);
                log_event(buf);
            }
            if (infop->redund.sock_cmd[0] < 0)
            {
                sprintf(buf, "Socket one open fail (%s, TCP port %d) !",
    	                infop->ip_addr_s,
        	            infop->cmd_port);
	            log_event(buf);
            }
            infop->error_flags |= ERROR_TCP_OPEN;
        }
		/* first pair fail */
        infop->redund.sock_data[0] = -1;
        infop->redund.sock_cmd[0] = -1;
		infop->redund.data_open[0] = 0;
    }

	/* check the second connection ok or no */
    if ((infop->redund.sock_data[1] < 0) || (infop->redund.sock_cmd[1] < 0))
    {
        close(infop->redund.sock_data[1]);
        close(infop->redund.sock_cmd[1]);
        if ( !(infop->error_flags & ERROR_TCP_OPEN) )
        {
            if (infop->redund.sock_data[1] < 0)
            {
                sprintf(buf, "Socket two open fail (%s, TCP port %d) !",
                        infop->ip_addr_s,
                        infop->tcp_port);
                log_event(buf);
            }
            if (infop->redund.sock_cmd[1] < 0)
            {
                sprintf(buf, "Socket two open fail (%s, TCP port %d) !",
    	                infop->ip_addr_s,
        	            infop->cmd_port);
	            log_event(buf);
            }
            infop->error_flags |= ERROR_TCP_OPEN;
        }
		/* second pair fail */
        infop->redund.sock_data[1] = -1;
        infop->redund.sock_cmd[1] = -1;
		infop->redund.data_open[1] = 0;
    }

	if ((infop->redund.cmd_open[0] && infop->redund.data_open[0])
		 || (infop->redund.cmd_open[1] && infop->redund.data_open[1]))
		infop->state = REDUND_TCP_CONN;
	else
		infop->state = REDUND_TCP_OPEN;
}

void redund_connect(infop)
TTYINFO *	infop;
{
	int			childpid, n;
	ConnMsg 		msg;
	union sock_addr sock, sock_bk;
	int ret;

	infop->redund.data.ack = 0;
	infop->redund.data.seq = 0;
	infop->redund.data.nport_ack = 0;
	infop->redund.cmd.ack = 0;
	infop->redund.cmd.seq = 0;
	infop->redund.cmd.nport_ack = 0;
	if (infop->af == AF_INET6 && enable_ipv6 == DIS_IPV6) {
		//printf("[AP]edund_connect return\n");
		return;
	}
	infop->state = REDUND_TCP_WAIT;
	infop->tcp_wait_id++;

	if ((childpid = fork()) == 0) {
#if 1
		/* child process */
		/* Try to connect to data/cmd socket. Once sockets are connected, write CONNECT_OK msg via pipeline */
		/* The parent who has REDUND_TCP_WAIT state will be notified a connected status from this the msg. */
		msg.tcp_wait_id = infop->tcp_wait_id;
		close(infop->pipe_port[0]);
		msg.status = CONNECT_FAIL;

		if (infop->af == AF_INET) {
			sock.sin.sin_family = AF_INET;
			sock.sin.sin_addr.s_addr = *(u_long*)infop->ip6_addr;
			sock.sin.sin_port = htons(infop->cmd_port);
		} else {
			memset(&sock.sin6, 0, sizeof(sock));
			sock.sin6.sin6_family = AF_INET6;
			sock.sin6.sin6_port = htons(infop->cmd_port);
			memcpy(sock.sin6.sin6_addr.s6_addr, infop->ip6_addr, 16);
		}
		if (connect_nonb(infop->redund.sock_cmd[0], (struct sockaddr_in*)&sock, sizeof(sock), CON_TIME) >= 0) {
			if (infop->af == AF_INET) {
				sock.sin.sin_family = AF_INET;
				sock.sin.sin_addr.s_addr = *(u_long*)infop->ip6_addr;
				sock.sin.sin_port = htons(infop->tcp_port);
			} else {
				sock.sin6.sin6_family = AF_INET6;
				sock.sin6.sin6_port = htons(infop->tcp_port);
				memcpy(sock.sin6.sin6_addr.s6_addr, infop->ip6_addr, 16);
			}
			if (connect_nonb(infop->redund.sock_data[0], (struct sockaddr_in*)&sock, sizeof(sock), CON_TIME) >= 0) {
				if (infop->af == AF_INET6) {
					int rand[16];
					if (write(infop->redund.sock_cmd[0], rand, 16) >= 0) {
						if (read(infop->redund.sock_cmd[0], rand, 16) != 16) {
							msg.infop = infop;
							write(infop->pipe_port[1], (char *)&msg, sizeof(ConnMsg));
							close(infop->pipe_port[1]);
							exit(0);
						}
					}
				}
				if (redund_data_init(infop->redund.sock_data[0], &infop->redund.data) > 0) {
					if (redund_cmd_init(infop->redund.sock_cmd[0], &infop->redund.cmd) > 0) {
						infop->redund.connect[0] = 1;
						infop->redund.session = Gsession;
					} else {
						infop->redund.connect[0] = 0;					
					}
				} else {
					infop->redund.connect[0] = 0;
				}
			}
		}
#endif
		msg.tcp_wait_id = infop->tcp_wait_id;
		close(infop->pipe_port[0]);
		msg.status = CONNECT_FAIL;
		if (infop->af == AF_INET) {
			sock_bk.sin.sin_family = AF_INET;
			sock_bk.sin.sin_addr.s_addr = *(u_long*)infop->redund.ip6_addr;
			sock_bk.sin.sin_port = htons(infop->cmd_port);
		} else {
			memset(&sock_bk.sin6, 0, sizeof(sock_bk));
			sock_bk.sin6.sin6_family = AF_INET6;
			sock_bk.sin6.sin6_port = htons(infop->cmd_port);
			memcpy(sock_bk.sin6.sin6_addr.s6_addr, infop->redund.ip6_addr, 16);
		}
		if ((ret = connect_nonb(infop->redund.sock_cmd[1], (struct sockaddr_in*)&sock_bk, sizeof(sock_bk), CON_TIME)) >= 0) {
			if (infop->af == AF_INET) {
				sock_bk.sin.sin_family = AF_INET;
				sock_bk.sin.sin_addr.s_addr = *(u_long*)infop->redund.ip6_addr;
				sock_bk.sin.sin_port = htons(infop->tcp_port);
			} else {
				sock_bk.sin6.sin6_family = AF_INET6;
				sock_bk.sin6.sin6_port = htons(infop->tcp_port);
				memcpy(sock_bk.sin6.sin6_addr.s6_addr, infop->redund.ip6_addr, 16);
			}
			if (connect_nonb(infop->redund.sock_data[1], (struct sockaddr_in*)&sock_bk, sizeof(sock_bk), CON_TIME) >= 0) {
				if (infop->af == AF_INET6) {
					int rand[16];
					if (write(infop->redund.sock_cmd[1], rand, 16) >= 0) {
						if (read(infop->redund.sock_cmd[1], rand, 16) != 16) {
							msg.infop = infop;
							write(infop->pipe_port[1], (char *)&msg, sizeof(ConnMsg));
							close(infop->pipe_port[1]);
							exit(0);
						}
					}
				}
				if (redund_data_init(infop->redund.sock_data[1], &infop->redund.data) > 0) {
					if (redund_cmd_init(infop->redund.sock_cmd[1], &infop->redund.cmd) > 0) {
						infop->redund.connect[1] = 1;
						infop->redund.session = Gsession;
					} else {
						infop->redund.connect[1] = 0;
					}			
				} else {
					infop->redund.connect[1] = 0;
				}
			}
		} else { 

		} 
		msg.connect[0] = infop->redund.connect[0];
		msg.connect[1] = infop->redund.connect[1];
		msg.session = Gsession;
		if (infop->redund.connect[0] || infop->redund.connect[1])
			msg.status = CONNECT_OK;
		msg.infop = infop;
		write(infop->pipe_port[1], (char *)&msg, sizeof(ConnMsg));
		close(infop->pipe_port[1]);
		exit(0);
	} else if (childpid < 0) {
		infop->state = REDUND_TCP_CONN;

		if (!(infop->error_flags & ERROR_FORK)) {
			log_event("Can't fork child process !");
			infop->error_flags |= ERROR_FORK;
		}
	}
}

void redund_close(infop)
TTYINFO *	infop;
{
    struct sockaddr_in	sin;
    int			childpid;
    ConnMsg 		msg;

    infop->state = REDUND_TCP_WAIT;
    infop->tcp_wait_id++;
    if ( (childpid = fork()) == 0 )
    {	/* child process */
        msg.tcp_wait_id = infop->tcp_wait_id;
        close(infop->pipe_port[0]);
#ifdef SSL_ON
        if (infop->ssl_enable)
        {
            SSL_shutdown(infop->pssl);
            SSL_free(infop->pssl);
            infop->pssl = NULL;
        }
#endif
        close(infop->redund.sock_data[0]);
        close(infop->redund.sock_cmd[0]);
        close(infop->redund.sock_data[1]);
        close(infop->redund.sock_cmd[1]);
        sleep(1);
        msg.status = CLOSE_OK;
        msg.infop = infop;
        write(infop->pipe_port[1], (char *)&msg, sizeof(ConnMsg));
        close(infop->pipe_port[1]);
        exit(0);
    }
    else if ( childpid < 0 )
    {
        infop->state = REDUND_TCP_CLOSE;
        if ( !(infop->error_flags & ERROR_FORK) )
        {
            log_event("Can't fork child process !");
            infop->error_flags |= ERROR_FORK;
        }
    }

    if ( infop->state != REDUND_TCP_CLOSE )
    {
#ifdef SSL_ON
        if (infop->ssl_enable)
        {
            SSL_shutdown(infop->pssl);
            SSL_free(infop->pssl);
            infop->pssl = NULL;
        }
#endif
        close(infop->redund.sock_data[0]);
        close(infop->redund.sock_cmd[0]);
        close(infop->redund.sock_data[1]);
        close(infop->redund.sock_cmd[1]);
	infop->redund.sock_data[0] = -1;
	infop->redund.sock_cmd[0] = -1;
	infop->redund.sock_data[1] = -1;
	infop->redund.sock_cmd[1] = -1;

        infop->local_tcp_port = 0;
        infop->local_cmd_port = 0;
    }
}

void redund_connect_check(TTYINFO *infopp)
{
    ConnMsg 	msg;
    TTYINFO *	infop;
    char		buf[256];
    int ret;
    struct sysinfo	sys_info;
    struct sockaddr_in	local_sin;
	struct sockaddr_in6	local_sin6;
    socklen_t		socklen = sizeof(local_sin);
	struct sockaddr * ptr;

    if ((ret=read(infopp->pipe_port[0], (char *)&msg, sizeof(ConnMsg))) == sizeof(ConnMsg))
    {
        infop = msg.infop;
		Gsession = msg.session;
		Gsession_cnt = 1;
		infop->redund.session = msg.session;
		infop->redund.connect[0] = msg.connect[0];
		infop->redund.connect[1] = msg.connect[1];
		if (!infop->redund.connect[0]) {
			infop->lost_cnt++;
			close(infop->redund.sock_data[0]);
			close(infop->redund.sock_cmd[0]);
			infop->redund.sock_data[0] = -1;
			infop->redund.sock_cmd[0] = -1;

		}
		if (!infop->redund.connect[1]) {
			infop->lost_cnt++;
			close(infop->redund.sock_data[1]);
			close(infop->redund.sock_cmd[1]);
			infop->redund.sock_data[1] = -1;
			infop->redund.sock_cmd[1] = -1;
		}
        if ( (infop->state == REDUND_TCP_WAIT)&&(infop->tcp_wait_id == msg.tcp_wait_id) )
        {
        	ptr = (infop->af == AF_INET) ? (struct sockaddr*)&local_sin : (struct sockaddr*)&local_sin6;
			socklen = (infop->af == AF_INET) ? sizeof(local_sin) : sizeof(local_sin6);
            if ( msg.status == CONNECT_OK )
            {
        		if (infop->redund.connect[0])
        			getsockname(infop->redund.sock_data[0], ptr, &socklen);
        		else
        			getsockname(infop->redund.sock_data[1], ptr, &socklen);

				if(infop->af == AF_INET)
	                infop->local_tcp_port = ntohs(local_sin.sin_port);
				else
					infop->local_tcp_port = ntohs(local_sin6.sin6_port);

				if (infop->redund.connect[0])
        			getsockname(infop->redund.sock_cmd[0], ptr, &socklen);
        		else
        			getsockname(infop->redund.sock_cmd[1], ptr, &socklen);

				if(infop->af == AF_INET)
					infop->local_cmd_port = ntohs(local_sin.sin_port);
				else
					infop->local_cmd_port = ntohs(local_sin6.sin6_port);
                
				infop->state = REDUND_RW_DATA;

                infop->error_flags = 0;
                buf[0] = NPREAL_LOCAL_COMMAND_SET;
                buf[1] = LOCAL_CMD_TTY_USED;
                ioctl(infop->mpt_fd,
                      _IOC(_IOC_READ|_IOC_WRITE,'m',CMD_CONNECTED,0),
                      0);
                ioctl(infop->mpt_fd,
                      _IOC(_IOC_READ|_IOC_WRITE,'m',CMD_RESPONSE,2),
                      buf);
#ifdef SSL_ON
                if (infop->ssl_enable)
                {
                    infop->pssl = SSL_new(sslc_ctx);
                    if (infop->pssl != NULL)
                    {
                        if (SSL_set_fd(infop->pssl, infop->redund.sock_data[0]))
                        {
                            SSL_set_connect_state(infop->pssl);
                        }
                        else
                        {
                            log_event("SSL_set_fd() error!");
                        }
                    }
                    else
                    {
                        log_event("SSL_new() error!");
                    }
                    sysinfo(&sys_info);
                    infop->ssl_time = sys_info.uptime;
                    infop->state = REDUND_SSL_CONN;
                    /*if (SSL_connect(infop->pssl) < 0){
                    				printf("SSL_connect() error.\n");
                    	SSL_free(infop->pssl);
                    }*/
                }
#endif
            }
            else if ( msg.status == CLOSE_OK )
            {
                infop->error_flags = 0;
                infop->redund.sock_data[0] = -1;
                infop->redund.sock_cmd[0] = -1;
                infop->redund.sock_data[1] = -1;
                infop->redund.sock_cmd[1] = -1;
                if(infop->reconn_flag == 1) {       /*reconnect or not*/
                    infop->state = REDUND_TCP_OPEN;
				}
                else if(infop->reconn_flag == 0) {
                    infop->state = REDUND_TTY_WAIT;
				}
                ioctl(infop->mpt_fd,
                      _IOC(_IOC_READ|_IOC_WRITE,'m',CMD_DISCONNECTED,0),
                      0);
            }
            else
            {
                close(infop->redund.sock_data[1]);
                close(infop->redund.sock_cmd[1]);
                infop->redund.sock_data[1] = -1;
                infop->redund.sock_cmd[1] = -1;
                close(infop->redund.sock_data[0]);
                close(infop->redund.sock_cmd[0]);
                infop->redund.sock_data[0] = -1;
                infop->redund.sock_cmd[0] = -1;
                infop->local_tcp_port = 0;
                infop->local_cmd_port = 0;
                infop->state = REDUND_CONN_FAIL;
                sysinfo(&sys_info);
                infop->time_out = sys_info.uptime;
                ioctl(infop->mpt_fd,
                      _IOC(_IOC_READ|_IOC_WRITE,'m',CMD_DISCONNECTED,0),
                      0);
                if ( !(infop->error_flags & ERROR_TCP_CONN) && ((sys_info.uptime - infop->tty_used_timestamp) > 60))
                {
                    sprintf(buf, "ConnectCheck> Socket connect fail (%s,TCP port %d) !",
                            infop->ip_addr_s,
                            infop->tcp_port);
                    log_event(buf);
                    infop->error_flags |= ERROR_TCP_CONN;
                }
            }
        }
    }
}

int redund_data_init(int fd, struct expect_struct *expect)
{
    int len1, len2, len3, i;
    unsigned char rbuffer[HEADER_LEN];
    unsigned char wbuffer[HEADER_LEN];

    len1 = len2 = len3 = 0; /* Redundant SYNC Step len */

    if (fd < 0)
    	return -1;

    len1 = recv(fd, rbuffer, HEADER_LEN, 0);
	if (len1 != 12) {
		return -1;
	}
	if (Gsession_cnt == 0) {
		Gsession_cnt = 1;
		Gsession = rbuffer[5];
	}
#if 1
	memcpy(wbuffer, rbuffer, HEADER_LEN);
	wbuffer[5] = Gsession;
	len2 = send(fd, wbuffer, HEADER_LEN, 0);
	if (len2 != 12) {
		return -1;
	}

    len3 = recv(fd, rbuffer, HEADER_LEN, 0);
	if (len3 != 12) {
		return -1;
	}
#endif
    return RET_OK;
}

int redund_cmd_init(int fd, struct expect_struct *expect)
{
    int len1, len2, len3, i;
    unsigned char rbuffer[HEADER_LEN];
    unsigned char wbuffer[HEADER_LEN];

    len1 = len2 = len3 = 0; /* Redundant SYNC Step len */
 
    if (fd < 0)
	return -1;

    len1 = recv(fd, rbuffer, HEADER_LEN, 0);
	if (len1 != 12) {
		return -1;
	}

	memcpy(wbuffer, rbuffer, HEADER_LEN);
	wbuffer[5] = Gsession;	
    len2 = send(fd, wbuffer, HEADER_LEN, 0);
	if (len2 != 12) {
		return -1;
	}

    len3 = recv(fd, rbuffer, HEADER_LEN, 0);
	if (len3 != 12) {
		return -1;
	}

    return RET_OK;
}

int redund_add_hdr(const char *sbuf, char *dbuf, ssize_t len, struct expect_struct *expect)
{
    struct _redund_packet pkt;
    int ret;
    int i;

    pkt.hdr = (struct redund_hdr *) dbuf;
	pkt.data = (char *) &dbuf[HEADER_LEN];

    pkt.hdr->mark = REDUNDANT_MARK;
    pkt.hdr->version = REDUNDANT_VERSION;
    pkt.hdr->hdr_len = REDUNDANT_HDRLEN;
    pkt.hdr->flags = REDUNDANT_PUSH;
    pkt.hdr->session = Gsession;
    pkt.hdr->seq_no = expect->seq;

	if (expect->last_seq == pkt.hdr->seq_no)
		pkt.hdr->seq_no++;
	expect->last_seq = pkt.hdr->seq_no;

    pkt.hdr->ack_no = expect->ack;
    pkt.hdr->len = HEADER_LEN + len;
    
	expect->nport_ack = pkt.hdr->seq_no + 1;

    if (len)
        memcpy(pkt.data, sbuf, len);

    return 0;
}

int redund_send_cmd(int fd, int fd_bk, const char *sbuf, ssize_t len, struct expect_struct *expect)
{
    int i;
    int ret, total_len1, total_len2;
    char dbuf[2048];
    struct redund_packet resp;

    total_len1 = total_len2 = 0;
	
    ret = redund_add_hdr(sbuf, dbuf, len, expect);
	
	/* send command to NPort */
	if (fd) 
	    	total_len1 = send(fd, dbuf, HEADER_LEN + len, 0);

	if (fd_bk) 
		total_len2 = send(fd_bk, dbuf, HEADER_LEN + len, 0);

    if ((total_len1 < 0) || (total_len1 != HEADER_LEN + len)) {
    	if ((total_len2 < 0) || (total_len2 != HEADER_LEN + len)) {
        	//printf("redundant send_cmd fail\n");
        	return 0;
		}
    }
	if (total_len1 == total_len2)
		return total_len1;
	else if (total_len1 > 0 && total_len2 <= 0)
		return total_len1;
	else if (total_len2 > 0 && total_len1 <= 0)
		return total_len2;
}

int redund_recv_cmd(int fd, int fd_bk ,char *sbuf, ssize_t len, struct expect_struct *expect, TTYINFO *infop)
{
    int i;
    int ret, data_len, total_len1, total_len2, ret_len;
    char dbuf[BUF_SIZE], dbuf1[BUF_SIZE], dbuf2[BUF_SIZE], respbuf[BUF_SIZE];
    struct _redund_packet pkt;
    struct _redund_packet resp;
    struct timeval tm;
    fd_set rfd, wfd, efd;
    uint16_t tmp;
	
    data_len = 0;
    total_len1 = 0;
    total_len2 = 0;

	if (fd) {
    	total_len1 = recv(fd, dbuf1, len, 0);
		if (total_len1 <= 0) {
			return -1;
		}
		memcpy(dbuf, dbuf1, total_len1);
	}
	if (fd_bk) {
    	total_len2 = recv(fd_bk, dbuf2, len, 0);
		if (total_len2 <= 0) {
			return -1;
		}
		memcpy(dbuf, dbuf2, total_len2);
	}
		
    pkt.hdr = (struct redund_hdr *) dbuf;
	pkt.data = (char *) &dbuf[HEADER_LEN];

#if 1
	if ((pkt.hdr->seq_no != expect->ack) && ((pkt.hdr->flags & REDUNDANT_PUSH))) { 
		return 0;	
	}
#if 0
    if (pkt.hdr->flags & REDUNDANT_PUSH) { /* nport repush*/
        if (1) {
        /* when no net-line unplug and plug ,we need to recv
           from net-one or net-two and ack to net-one or net-two */
            if (fd) {
                infop->redund.cmd.push_seq[0] = pkt.hdr->seq_no;
                if (infop->redund.cmd.push_seq[0] == infop->redund.cmd.push_seq[1]) {
					return 0;
                } else {
					;
                }
            }
            if (fd_bk) {
                infop->redund.cmd.push_seq[1] = pkt.hdr->seq_no;
                if (infop->redund.cmd.push_seq[1] == infop->redund.cmd.push_seq[0]) {
                    return 0;
                } else {
					;
                }
            }
        }
    }
#endif
#endif

    if (pkt.hdr->len > HEADER_LEN) {
        for (i = 0; i < (pkt.hdr->len - HEADER_LEN); i ++) {
            sbuf[i] = dbuf[HEADER_LEN + i];
        }
    }
#if 0
	else if (pkt.hdr->len == HEADER_LEN) {
        for (i = 0; i < HEADER_LEN; i ++) {
            respbuf[i] = dbuf[i];
        }
    }
#endif
    /* importand rule for redundant send */
    resp.hdr = (struct redund_hdr *) respbuf;
	resp.data = (char *) &respbuf[HEADER_LEN];

    resp.hdr->mark = REDUNDANT_MARK;
    resp.hdr->version = REDUNDANT_VERSION;
    resp.hdr->hdr_len = REDUNDANT_HDRLEN;
    resp.hdr->flags = REDUNDANT_ACK;
    resp.hdr->session = Gsession;
    if (pkt.hdr->flags == REDUNDANT_REPUSH) { /* nport repush*/
        resp.hdr->len = HEADER_LEN;
        if (1) {
        /* when no net-line unplug and plug ,we need to recv
           from net-one or net-two and ack to net-one or net-two */
            if (fd) {
                infop->redund.cmd.repush_seq[0] = pkt.hdr->seq_no;
                if (infop->redund.cmd.repush_seq[0] == infop->redund.cmd.repush_seq[1]) {
                    ;
                } else {
#if 1
                    expect->ack = pkt.hdr->seq_no + 1;
                    resp.hdr->ack_no = expect->ack;
                    expect->seq = pkt.hdr->ack_no;
#else
                    resp.hdr->ack_no = pkt.hdr->seq_no + 1;
                    resp.hdr->seq_no = pkt.hdr->seq_no;
                    expect->ack = pkt.hdr->seq_no + 1;
                    expect->seq = pkt.hdr->seq_no + 1;
#endif
                }
                ret = send(fd, respbuf, HEADER_LEN, 0);
            }
            if (fd_bk) {
                infop->redund.cmd.repush_seq[1] = pkt.hdr->seq_no;
                if (infop->redund.cmd.repush_seq[1] == infop->redund.cmd.repush_seq[0]) {
                    ;
                } else {
#if 1
                    expect->ack = pkt.hdr->seq_no + 1;
                    resp.hdr->ack_no = expect->ack;
                    expect->seq = pkt.hdr->ack_no;
#else
                    resp.hdr->ack_no = pkt.hdr->seq_no + 1;
                    resp.hdr->seq_no = pkt.hdr->seq_no;
                    expect->ack = pkt.hdr->seq_no + 1;
                    expect->seq = pkt.hdr->seq_no + 1;
#endif
                }
                ret = send(fd_bk, respbuf, HEADER_LEN, 0);
            }
        }
#if MOXA_DEBUG
        if (fd)
        printf("[AP]NPort(%s) net-one REPush cmd to Driver, len = %d, nport seq = %d(%x)(%x)last=(%d), nport flags = %d,driver ack = %d,(%x)(%x)(%x)(%x)\n",
                    infop->ttyname2, pkt.hdr->len,
                    pkt.hdr->seq_no,dbuf[6]&0x00ff, dbuf[7]&0x00ff , infop->redund.debug_seq, pkt.hdr->flags, expect->ack,
                    dbuf[12],dbuf[13],dbuf[14],dbuf[15]);
        if (fd_bk)
        printf("[AP]NPort(%s) net-two REPush cmd to Driver, len = %d, nport seq = %d(%x)(%x)last=(%d), nport flags = %d,driver ack = %d,(%x)(%x)(%x)(%x)\n",
                    infop->ttyname2, pkt.hdr->len,
                    pkt.hdr->seq_no,dbuf[6]&0x00ff, dbuf[7]&0x00ff , infop->redund.debug_seq, pkt.hdr->flags, expect->ack,
                    dbuf[12],dbuf[13],dbuf[14],dbuf[15]);
#endif

		return pkt.hdr->len - HEADER_LEN;
    }

	if (pkt.hdr->ack_no == (expect->nport_ack)) {
		if (pkt.hdr->flags == REDUNDANT_ACK) {
			expect->seq = pkt.hdr->ack_no;
			return 0;
		}
		expect->ack = pkt.hdr->seq_no + 1;
		resp.hdr->ack_no = expect->ack;
		expect->seq = pkt.hdr->ack_no;
		//expect->seq = resp.hdr->ack_no;
	}

    resp.hdr->seq_no = 0x00;
    resp.hdr->len = HEADER_LEN;

	if (pkt.data[0] == 0x27) {

		memcpy(resp.data, pkt.data, pkt.hdr->len - HEADER_LEN);
		resp.data[0] = 0x28;
		resp.hdr->flags |= REDUNDANT_PUSH;
		expect->seq = pkt.hdr->ack_no;
		expect->nport_ack = expect->seq + 1;
		resp.hdr->seq_no = expect->seq;
		resp.hdr->len = pkt.hdr->len;

	} else {
        expect->ack = pkt.hdr->seq_no + 1;
        resp.hdr->ack_no = expect->ack;

    }

#if 0
    resp.hdr->seq_no = pkt.hdr->seq_no;	
    resp.hdr->ack_no = pkt.hdr->seq_no+1;
    expect->ack = pkt.hdr->seq_no+1;
    expect->seq = pkt.hdr->seq_no+1;
    expect->nport_ack = pkt.hdr->seq_no+1;
#endif
 	
re_send:
	if (fd) 
    		total_len1 = send(fd, respbuf, resp.hdr->len, 0);
	
	if (fd_bk) 
		total_len2 = send(fd_bk, respbuf, resp.hdr->len, 0);	

    if (total_len1 < 0 || total_len2 < 0) {
        goto re_send;
    }

	ret_len = pkt.hdr->len - HEADER_LEN;

	return ret_len;
}

void redund_add_hdr_data(int fd, const char *sbuf, char *dbuf, ssize_t len, struct expect_struct *expect, TTYINFO *infop)
{
    struct _redund_packet pkt;
    int ret;
    int i;

    pkt.hdr = (struct redund_hdr *) dbuf;
	pkt.data = (char *) &dbuf[HEADER_LEN];

    pkt.hdr->mark = REDUNDANT_MARK;
    pkt.hdr->version = REDUNDANT_VERSION;
    pkt.hdr->hdr_len = REDUNDANT_HDRLEN;
    pkt.hdr->flags = REDUNDANT_PUSH;
    pkt.hdr->session = Gsession;
    pkt.hdr->seq_no = expect->seq;
    pkt.hdr->ack_no = expect->ack;
    pkt.hdr->len = HEADER_LEN + len;

	expect->nport_ack = pkt.hdr->seq_no + 1;
    if (len)
        memcpy(pkt.data, sbuf, len);
	if (infop->redund.host_ack) {
    	pkt.hdr->flags |= REDUNDANT_ACK;
		infop->redund.host_ack = 0;
	}

}

int redund_send_data(int fd, int fd_bk, const char *sbuf, ssize_t len, struct expect_struct *expect, TTYINFO *infop)
{
    int i;
    int total_len1, total_len2;
    struct _redund_packet pkt;
    char dbuf[2048];
	total_len1 = 0;

    redund_add_hdr_data(fd, sbuf, dbuf, len, expect, infop);
	
    pkt.hdr = (struct redund_hdr *) dbuf;

	/* send command to NPort */
	if (fd) 
		total_len1 = send(fd, dbuf, HEADER_LEN + len, MSG_DONTWAIT);
	
	if (fd_bk) 
		total_len2 = send(fd_bk, dbuf, HEADER_LEN + len, MSG_DONTWAIT);

	if ((total_len1 == total_len2))
		return total_len1 - HEADER_LEN;

	if (total_len1 > total_len2) {
		return total_len1 - HEADER_LEN;
	}
	if (total_len1 < total_len2) {
		return total_len2 - HEADER_LEN;
	}
	if (total_len1 < 0 && total_len2 < 0)
		return 0;

	return len;
}

int redund_recv_data(int fd, int fd_bk, char *sbuf, ssize_t len, 
					 struct expect_struct *expect, TTYINFO *infop)
{
    int i;
    int ret, data_len, total_len, ret_len;
    char dbuf[2048], respbuf[2048];
	char dbuf2[2048];
	int	total_len2;
    struct _redund_packet pkt;
    struct _redund_packet resp;
    struct timeval tm;
    fd_set rfd, wfd, efd;
    uint16_t tmp;
	int test;
	
    data_len = 0;
    total_len = 0;

	if (fd) {
    	total_len = recv(fd, dbuf, HEADER_LEN, 0);
		if (total_len <= 0)
			return -1;
	}
	if (fd_bk) {
    	total_len = recv(fd_bk, dbuf, HEADER_LEN, 0);
		if (total_len <= 0)
			return -1;
	}

    pkt.hdr = (struct redund_hdr *) dbuf;
	pkt.data = (char *) &dbuf[HEADER_LEN];

	infop->redund.debug_seq = pkt.hdr->seq_no;

    /* importand rule for redundant send */

    resp.hdr = (struct redund_hdr *) respbuf;
	
	resp.data = (char *) &respbuf[HEADER_LEN];

    resp.hdr->mark = REDUNDANT_MARK;
    resp.hdr->version = REDUNDANT_VERSION;
    resp.hdr->hdr_len = REDUNDANT_HDRLEN;
    resp.hdr->flags = REDUNDANT_ACK;
    resp.hdr->session = Gsession;
    resp.hdr->seq_no = 0x00;
    resp.hdr->len = HEADER_LEN;

	if (pkt.hdr->mark != REDUNDANT_MARK || total_len <= 0 || pkt.hdr->flags > 0x08) {
#if MOXA_DEBUG
		if (fd) {
			printf("[AP](%s)net_one recv len = %d, pkt.hdr->flags = %d, pkt.hdr->seq_no = %d, driver->ack = %d, nport->ack = %d\n", 
					infop->ttyname2,
					total_len, 
					pkt.hdr->flags, pkt.hdr->seq_no, expect->ack, expect->nport_ack);
		}
		if (fd_bk) {
			printf("[AP](%s)net_two recv len = %d, pkt.hdr->flags = %d, pkt.hdr->seq_no = %d, driver->ack = %d, nport->ack = %d\n", 
					infop->ttyname2,
					total_len, 
					pkt.hdr->flags, pkt.hdr->seq_no, expect->ack, expect->nport_ack);
		}
#endif
		return -1;
	}
#if MOXA_DEBUG
#if 0
	printf("[AP]recv len = %d, len2 = %d, ack_no = %d, pkt.hdr->len = %d, pkt.hdr->flags = %d, pkt.hdr->seq_no = %d, expect->ack = %d, nport->ack = %d\n", 
					total_len, total_len, 
					pkt.hdr->ack_no, pkt.hdr->len, pkt.hdr->flags, pkt.hdr->seq_no, expect->ack, expect->nport_ack);
#endif
#endif

	if ((pkt.hdr->seq_no != expect->ack) && ((pkt.hdr->flags & REDUNDANT_PUSH))) { 
		if (fd) {
			total_len += recv(fd, dbuf2, pkt.hdr->len - HEADER_LEN, 0);
			if (total_len <= 0)
				return -1;
		}
		if (fd_bk) {
			total_len += recv(fd_bk, dbuf2, pkt.hdr->len - HEADER_LEN, 0);
			if (total_len <= 0)
				return -1;
		}
		return 0;
	} 
    if (pkt.hdr->ack_no == (expect->nport_ack)) {  /* nport ack */
        if (pkt.hdr->flags == REDUNDANT_ACK) {
            expect->seq = pkt.hdr->ack_no;
            infop->mpt_datakeep -= infop->redund.wlen;
            if (infop->mpt_datakeep)
            	infop->mpt_dataofs += infop->redund.wlen;
           	else {
            	infop->mpt_dataofs = 0;
				infop->redund.wlen = 0;
			}
            return 0;
		} else if (pkt.hdr->flags == (REDUNDANT_PUSH | REDUNDANT_ACK)) {
			expect->seq = pkt.hdr->ack_no;
            infop->mpt_datakeep -= infop->redund.wlen;
            if (infop->mpt_datakeep)
            	infop->mpt_dataofs += infop->redund.wlen;
           	else {
            	infop->mpt_dataofs = 0;
				infop->redund.wlen = 0;
			}
			if (fd) {
				total_len += recv(fd, sbuf, pkt.hdr->len - HEADER_LEN, 0);
				if (total_len <= 0)
					return -1;
			}
			if (fd_bk) {
				total_len += recv(fd_bk, sbuf, pkt.hdr->len - HEADER_LEN, 0);
				if (total_len <= 0)
					return -1;
			}
		    expect->ack = pkt.hdr->seq_no + 1;
    		resp.hdr->ack_no = expect->ack;
        	expect->seq = pkt.hdr->ack_no;
			infop->redund.host_ack = 1;
		}
    } else {
		;
    }  

	if (pkt.hdr->flags == REDUNDANT_PUSH) { /* nport push */
		if (fd) {
			total_len += recv(fd, sbuf, pkt.hdr->len - HEADER_LEN, 0);
			if (total_len <= 0)
				return -1;
		}
		if (fd_bk) {
			total_len += recv(fd_bk, sbuf, pkt.hdr->len - HEADER_LEN, 0);
			if (total_len <= 0)
				return -1;
		}
	    expect->ack = pkt.hdr->seq_no + 1;
    	resp.hdr->ack_no = expect->ack;
        expect->seq = pkt.hdr->ack_no;
		infop->redund.host_ack = 1;
#if 0
		if (infop->redund.host_ack == 1) {
			if (fd)
	    		ret = send(fd, respbuf, resp.hdr->len, 0);
			if (fd_bk)
    			ret = send(fd_bk, respbuf, resp.hdr->len, 0);
			infop->redund.host_ack = 0;
		}
#endif
	}
#if 1
	if (pkt.hdr->flags == REDUNDANT_REPUSH) { /* nport repush*/
		if (fd) {
			infop->redund.data.repush_seq[0] = pkt.hdr->seq_no;
			if (infop->redund.data.repush_seq[0] == infop->redund.data.repush_seq[1]) {
				total_len += recv(fd, dbuf2, pkt.hdr->len - HEADER_LEN, 0);
			} else {
	   	    	    	total_len += recv(fd, sbuf, pkt.hdr->len - HEADER_LEN, 0);
			        expect->ack = pkt.hdr->seq_no + 1;
		    		resp.hdr->ack_no = expect->ack;
		        	expect->seq = pkt.hdr->ack_no;
			    	infop->redund.host_ack = 1;
		        	infop->redund.host_ack = 0;
			}
		        ret = send(fd, respbuf, resp.hdr->len, 0);
		}
		if (fd_bk) {
			infop->redund.data.repush_seq[1] = pkt.hdr->seq_no;
			if (infop->redund.data.repush_seq[1] == infop->redund.data.repush_seq[0]) {
				total_len += recv(fd_bk, dbuf2, pkt.hdr->len - HEADER_LEN, 0);
			} else {
		    	    	    total_len += recv(fd_bk, sbuf, pkt.hdr->len - HEADER_LEN, 0);
				    expect->ack = pkt.hdr->seq_no + 1;
		    		    resp.hdr->ack_no = expect->ack;
				    expect->seq = pkt.hdr->ack_no;
			    	    infop->redund.host_ack = 1;
		      	            infop->redund.host_ack = 0;
			}
		        ret = send(fd_bk, respbuf, resp.hdr->len, 0);
		}

#if 0
		if (infop->redund.reconnect[0]) { 
		/* net-one unplug and plug again. we need to recv data from net-two 
 		   and ack to net-two (workaround) */
			if (fd_bk) {
				total_len += recv(fd_bk, sbuf, pkt.hdr->len - HEADER_LEN, 0);
				if (total_len <= 0)
					return -1;
		    	expect->ack = pkt.hdr->seq_no + 1;
   				resp.hdr->ack_no = expect->ack;
   	    		expect->seq = pkt.hdr->ack_no;
				infop->redund.host_ack = 1;
   				ret = send(fd_bk, respbuf, resp.hdr->len, 0);
				infop->redund.host_ack = 0;
			}
			if (fd) {
				total_len += recv(fd, dbuf2, pkt.hdr->len - HEADER_LEN, 0);	
				if (total_len <= 0)
					return -1;
			}
		}
		else if (infop->redund.reconnect[1]) {
		/* net-two unplug and plug again. we need to recv data from net-one 
  		   and ack to net-one (workaround) */
			if (fd) {
				total_len += recv(fd, sbuf, pkt.hdr->len - HEADER_LEN, 0);
				if (total_len <= 0)
					return -1;
		    	expect->ack = pkt.hdr->seq_no + 1;
   				resp.hdr->ack_no = expect->ack;
   	    		expect->seq = pkt.hdr->ack_no;
				infop->redund.host_ack = 1;
   				ret = send(fd, respbuf, resp.hdr->len, 0);
				infop->redund.host_ack = 0;
			}
			if (fd_bk) {
				total_len += recv(fd_bk, dbuf2, pkt.hdr->len - HEADER_LEN, 0);	
				if (total_len <= 0)
					return -1;
			}
		} else if ((!infop->redund.reconnect[0]) && (!infop->redund.reconnect[1])) {
		/* when no net-line unplug and plug ,we need to recv
 		   from net-one or net-two and ack to net-one or net-two */
			if (fd) {
				infop->redund.data.repush_seq[0] = pkt.hdr->seq_no;
				if (infop->redund.data.repush_seq[0] == infop->redund.data.repush_seq[1]) {
					total_len += recv(fd, dbuf2, pkt.hdr->len - HEADER_LEN, 0);
				} else {
    	    	    total_len += recv(fd, sbuf, pkt.hdr->len - HEADER_LEN, 0);
			        expect->ack = pkt.hdr->seq_no + 1;
	    		    resp.hdr->ack_no = expect->ack;
	        		expect->seq = pkt.hdr->ack_no;
		    	    infop->redund.host_ack = 1;
    		        ret = send(fd, respbuf, resp.hdr->len, 0);
	        	    infop->redund.host_ack = 0;
				}
			}
			if (fd_bk) {
				infop->redund.data.repush_seq[1] = pkt.hdr->seq_no;
				if (infop->redund.data.repush_seq[1] == infop->redund.data.repush_seq[0]) {
					total_len += recv(fd_bk, dbuf2, pkt.hdr->len - HEADER_LEN, 0);
				} else {
    	    	    total_len += recv(fd_bk, sbuf, pkt.hdr->len - HEADER_LEN, 0);
			        expect->ack = pkt.hdr->seq_no + 1;
	    		    resp.hdr->ack_no = expect->ack;
        			expect->seq = pkt.hdr->ack_no;
		    	    infop->redund.host_ack = 1;
    		        ret = send(fd_bk, respbuf, resp.hdr->len, 0);
	    	        infop->redund.host_ack = 0;
				}
			}
		}
#endif
#if MOXA_DEBUG
		if (fd)
			printf("[AP]NPort(%s) net-one REPush data to Driver, len = %d, nport seq = %d(%x)(%x)last=(%d), nport flags = %d,driver ack = %d\n", 
					infop->ttyname2, pkt.hdr->len, 
					pkt.hdr->seq_no,dbuf[6]&0x00ff, dbuf[7]&0x00ff , infop->redund.debug_seq, pkt.hdr->flags, expect->ack);
		if (fd_bk)
			printf("[AP]NPort(%s) net-two REPush data to Driver, len = %d, nport seq = %d(%x)(%x)last=(%d), nport flags = %d,driver ack = %d\n", 
					infop->ttyname2, pkt.hdr->len, 
					pkt.hdr->seq_no,dbuf[6]&0x00ff, dbuf[7]&0x00ff , infop->redund.debug_seq, pkt.hdr->flags, expect->ack);
#endif
		return 0;
	}
#endif
	ret_len = pkt.hdr->len - HEADER_LEN;
	return ret_len;
}

int do_redund_send_data(TTYINFO *infop, SERVINFO *servp, struct sysinfo *sys_info, fd_set *wfd)
{ 
	if (FD_ISSET(infop->redund.sock_data[0], wfd)) {
		if (!infop->redund.wlen && infop->mpt_datakeep)
			infop->redund.wlen = redund_send_data(infop->redund.sock_data[0],
								 infop->redund.sock_data[1],
							     infop->mpt_bufptr + infop->mpt_dataofs, 
								 infop->mpt_datakeep, 
								 &infop->redund.data, infop);
        if (infop->redund.wlen >= 0) {
        	sysinfo(sys_info);
        	servp = &serv_info[infop->serv_index];
        	servp->last_servertime = (time_t)((int32_t)(sys_info->uptime - 1));
        } else if (infop->redund.wlen < 0) {
        	log_event("Can not write data");
    	}
	}
	else if (FD_ISSET(infop->redund.sock_data[1], wfd)) {
		if (!infop->redund.wlen && infop->mpt_datakeep) 
			infop->redund.wlen = redund_send_data(infop->redund.sock_data[0],
								 infop->redund.sock_data[1],
							     infop->mpt_bufptr + infop->mpt_dataofs, 
								 infop->mpt_datakeep, 
								 &infop->redund.data, infop);
        if (infop->redund.wlen >= 0) {
        	sysinfo(sys_info);
        	servp = &serv_info[infop->serv_index];
        	servp->last_servertime = (time_t)((int32_t)(sys_info->uptime - 1));
        } else if (infop->redund.wlen < 0) {
        	log_event("Can not write data");
    	}
	}
}

int do_redund_recv_data(TTYINFO *infop, SERVINFO *servp, struct sysinfo *sys_info, fd_set *rfd)
{
	int m, n;

	m = 0;
	n = 0;

	pthread_mutex_lock(&Gmutex);
	if (infop->redund.connect[0] && FD_ISSET(infop->redund.sock_data[0], rfd)) {
		pthread_mutex_unlock(&Gmutex);

	    m = infop->sock_datakeep + infop->sock_dataofs;
		n = redund_recv_data(infop->redund.sock_data[0], 
							 0,
							 infop->sock_bufptr + m,
							 (2048)- m,
							 &infop->redund.data, infop);
        if (n >= 0) {
        	infop->sock_datakeep += n;
        	infop->state = REDUND_RW_DATA;
            sysinfo(sys_info);
            servp = &serv_info[infop->serv_index];
            servp->last_servertime = (time_t)((int32_t)(sys_info->uptime - 1));
			return n;
        } else if (n < 0) {
   			pthread_mutex_lock(&Gmutex);
			//if (infop->redund.connect[1] && infop->redund.connect[0] != 0) {
			if (infop->redund.connect[0]) {
        			infop->sock_datakeep = 0;
				infop->redund.connect[0] = 0;
				close(infop->redund.sock_cmd[0]);
				close(infop->redund.sock_data[0]);
				infop->redund.sock_cmd[0] = -1;
				infop->redund.sock_data[0] = -1;
			}
			pthread_mutex_unlock(&Gmutex);
			return 0;
		}
	}
	else if (infop->redund.connect[1] && FD_ISSET(infop->redund.sock_data[1], rfd)) {
		pthread_mutex_unlock(&Gmutex);

	    m = infop->sock_datakeep + infop->sock_dataofs;
		n = redund_recv_data(0, 
							 infop->redund.sock_data[1],
							 infop->sock_bufptr + m,
							 (2048)- m,
							 &infop->redund.data, infop);
        if (n >= 0) {
        	infop->sock_datakeep += n;
        	infop->state = REDUND_RW_DATA;
            sysinfo(sys_info);
            servp = &serv_info[infop->serv_index];
            servp->last_servertime = (time_t)((int32_t)(sys_info->uptime - 1));
			return n;
        } else if (n < 0) {
 			pthread_mutex_lock(&Gmutex);
  			//if (infop->redund.connect[0] && infop->redund.connect[1] != 0) {
			if (infop->redund.connect[1]) {
			     	infop->sock_datakeep = 0;
				infop->redund.connect[1] = 0;
				close(infop->redund.sock_cmd[1]);
				close(infop->redund.sock_data[1]);
				infop->redund.sock_cmd[1] = -1;
				infop->redund.sock_data[1] = -1;
			}
			pthread_mutex_unlock(&Gmutex);
			return 0;
		}
	}
	pthread_mutex_unlock(&Gmutex);
	return n;
}

int do_redund_send_cmd(TTYINFO *infop, int n)
{
	redund_send_cmd(infop->redund.sock_cmd[0], 
					infop->redund.sock_cmd[1],
			    	infop->mpt_cmdbuf + 1, 
					n - 1, 
					&infop->redund.cmd);
}

int do_redund_recv_cmd(TTYINFO *infop, char *cmd_buf, fd_set *rfd)
{
	int n, len, len1;

	len = 0; 
	len1 = 0;
	n = 0;

	if (1) {
		pthread_mutex_lock(&Gmutex);
		if (infop->redund.connect[0] && FD_ISSET(infop->redund.sock_cmd[0], rfd)) {
			pthread_mutex_unlock(&Gmutex);
			len = redund_recv_cmd(infop->redund.sock_cmd[0],
					0,
					infop->sock_cmdbuf,
					CMD_REDUND_SIZE,
					&infop->redund.cmd, infop);
			if (len < 0) {
				pthread_mutex_lock(&Gmutex);

				if(infop->lost_cnt != 2){
					infop->lost_cnt = (infop->lost_cnt + 1) & 0x3;
				}

				//if (infop->redund.connect[1] && infop->redund.connect[0] != 0) {
				if (infop->redund.connect[0]) {
					close(infop->redund.sock_cmd[0]);
					close(infop->redund.sock_data[0]);
					infop->redund.connect[0] = 0;
					infop->redund.sock_cmd[0] = -1;
					infop->redund.sock_data[0] = -1;
				}
				pthread_mutex_unlock(&Gmutex);
				return 0;
			}
		}
		else if (infop->redund.connect[1] && FD_ISSET(infop->redund.sock_cmd[1], rfd)) {
			pthread_mutex_unlock(&Gmutex);
			len = redund_recv_cmd(0,
					infop->redund.sock_cmd[1],
					infop->sock_cmdbuf,
					CMD_REDUND_SIZE,
					&infop->redund.cmd, infop);
			if (len < 0) {
				pthread_mutex_lock(&Gmutex);
				if(infop->lost_cnt != 2){
					infop->lost_cnt = (infop->lost_cnt + 1) & 0x3;
				}

				//if (infop->redund.connect[0] && infop->redund.connect[1] != 0) {
				if (infop->redund.connect[1]) {
					close(infop->redund.sock_cmd[1]);
					close(infop->redund.sock_data[1]);
					infop->redund.connect[1] = 0;
					infop->redund.sock_cmd[1] = -1;
					infop->redund.sock_data[1] = -1;
				}
				pthread_mutex_unlock(&Gmutex);
				return 0;
			}
		}
		pthread_mutex_unlock(&Gmutex);

		n = 0;
		while (len > 0) {
			switch (infop->sock_cmdbuf[n]) {
			case ASPP_CMD_NOTIFY :
			case ASPP_CMD_WAIT_OQUEUE :
			case ASPP_CMD_OQUEUE :
			case ASPP_CMD_IQUEUE :
				len1 = 4;

				break;
			case ASPP_CMD_LSTATUS :
			case ASPP_CMD_PORT_INIT :
				len1 = 5;
				break;
			case ASPP_CMD_FLOWCTRL:
			case ASPP_CMD_IOCTL:
			case ASPP_CMD_SETBAUD:
			case ASPP_CMD_LINECTRL:
			case ASPP_CMD_START_BREAK:
			case ASPP_CMD_STOP_BREAK:
			case ASPP_CMD_START_NOTIFY:
			case ASPP_CMD_STOP_NOTIFY:
			case ASPP_CMD_FLUSH:
			case ASPP_CMD_HOST:
			case ASPP_CMD_TX_FIFO:
			case ASPP_CMD_XONXOFF:
			case ASPP_CMD_SETXON:
			case ASPP_CMD_SETXOFF:
				len1 = 3;

				break;
			default :
				len1 = len;

				break;
			}

			if ((len1 > 0) && ((n + len1) < CMD_REDUND_SIZE)) {
				cmd_buf[0] = NPREAL_ASPP_COMMAND_SET;
				memcpy(&cmd_buf[1], &infop->sock_cmdbuf[n], len1);
				ioctl(infop->mpt_fd,
						_IOC(_IOC_READ | _IOC_WRITE, 'm', CMD_RESPONSE, len1 + 1),
						cmd_buf);
			}
			n += len1;
			len -= len1;
		}
	}

	return 0;
}

void redund_init_fail(TTYINFO *infop, int lan_num)
{
	close(infop->redund.sock_data[lan_num]);
	close(infop->redund.sock_cmd[lan_num]);

	pthread_mutex_lock(&Gmutex);
	infop->redund.sock_data[lan_num] = -1;
	infop->redund.sock_cmd[lan_num] = -1;
	infop->redund.data_open[lan_num] = 0;
	infop->redund.cmd_open[lan_num] = 0;
	infop->redund.connect[lan_num] = 0;
	pthread_mutex_unlock(&Gmutex);
}

int redund_reconnect(void *infopp)
{
	int ret;
	int on;
	union sock_addr sock, sock_bk;
	TTYINFO *infop;
	int		inter = 1, i;
	struct timeval start, end;
	struct sigaction act;

	infop = (TTYINFO *) infopp;

	on = 1;

	// ignore SIGPIPE
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGPIPE, &act, NULL);

	pthread_detach(pthread_self());

	while (1) {
		sleep(1);
#if 1	
	if (infop->redund.close[0] || infop->redund.close[1]) {
		pthread_exit(NULL);
	}
#endif

	pthread_mutex_lock(&Gmutex);
	if (infop->redund.connect[0] && infop->redund.connect[1]) {
		infop->redund.thread_id[0] = 0;
		infop->redund.thread[0] = 0;
		pthread_mutex_unlock(&Gmutex);
		pthread_exit(NULL);
		break;
	}else
		pthread_mutex_unlock(&Gmutex);

	pthread_mutex_lock(&Gmutex);
	if (!infop->redund.connect[0]) {
		pthread_mutex_unlock(&Gmutex);
		/* socket open one-line cmd and data port */
		//close(infop->redund.sock_cmd[0]);
		//close(infop->redund.sock_data[0]);
		infop->redund.sock_data[0] = socket(infop->af, SOCK_STREAM, 0);	
		infop->redund.sock_cmd[0] = socket(infop->af, SOCK_STREAM, 0);

    	if (infop->redund.sock_cmd[0] >= 0) {
			if (setsockopt(infop->redund.sock_cmd[0], SOL_SOCKET,
		               SO_KEEPALIVE, &on, sizeof(on)) < 0) {
	    	        log_event("Set TCP keep alive fail !");
			}
			ret = setsockopt(infop->redund.sock_cmd[0], SOL_TCP, TCP_KEEPIDLE,
	    	                     &Gkeep_idle,
			                 sizeof(Gkeep_idle));
			if (ret < 0)
		    	printf("setsockopt SO_KEEPIDLE error! %d\n", ret);

			ret = setsockopt(infop->redund.sock_cmd[0], SOL_TCP, TCP_KEEPINTVL,
		    	             &(Gkeep_interval),
		        	         sizeof(Gkeep_interval));
			if (ret < 0)
	    	        printf("setsockopt SO_KEEPINTVL error! %d\n", ret);

			ret = setsockopt(infop->redund.sock_cmd[0], SOL_TCP, TCP_KEEPCNT,
		    	             &(Gkeep_count),
		        	         sizeof(Gkeep_count));
			if (ret < 0)
	    	    	printf("setsockopt SO_KEEPCNT error! %d\n", ret);

	}
		/* connect one-line cmd and data port */
        if (infop->af == AF_INET) {
            sock.sin.sin_family = AF_INET;
            sock.sin.sin_addr.s_addr = *(u_long*)infop->ip6_addr;
            sock.sin.sin_port = htons(infop->cmd_port);
        }
        if ((ret = connect_nonb(infop->redund.sock_cmd[0], (struct sockaddr_in*)&sock, sizeof(sock), RE_TIME)) >= 0) {
	        if (infop->af == AF_INET) {
	        	sock.sin.sin_family = AF_INET;
	    	        sock.sin.sin_addr.s_addr = *(u_long*)infop->ip6_addr;
	      		sock.sin.sin_port = htons(infop->tcp_port);
		}
	            if ((ret = connect_nonb(infop->redund.sock_data[0], (struct sockaddr_in*)&sock, sizeof(sock), RE_TIME)) >= 0) {
				if ((redund_data_init(infop->redund.sock_data[0], &infop->redund.data)) > 0) {
                			if ((redund_cmd_init(infop->redund.sock_cmd[0], &infop->redund.cmd)) > 0) {
						pthread_mutex_lock(&Gmutex);
						infop->lost_cnt--;
						infop->redund.connect[0] = 1;
						infop->redund.data_open[0] = 1;
						infop->redund.cmd_open[0] = 1;
						pthread_mutex_unlock(&Gmutex);
                    			} else {
						redund_init_fail(infop, 0);
					}
                		} else {
					redund_init_fail(infop, 0);
				}
			} else {
				redund_init_fail(infop, 0);
			}
		} else {	
			redund_init_fail(infop, 0);
		}	
	} else
		pthread_mutex_unlock(&Gmutex);	

	pthread_mutex_lock(&Gmutex);
	if (!infop->redund.connect[1]) {
		pthread_mutex_unlock(&Gmutex);
		/* close two-line cmd and data port */
		/* socket open two-line cmd and data port */
		//close(infop->redund.sock_cmd[1]);
		//close(infop->redund.sock_data[1]);
		infop->redund.sock_data[1] = socket(infop->af, SOCK_STREAM, 0);		
		infop->redund.sock_cmd[1] = socket(infop->af, SOCK_STREAM, 0);
    		if (infop->redund.sock_cmd[1] >= 0) {
			if (setsockopt(infop->redund.sock_cmd[1], SOL_SOCKET,
		               SO_KEEPALIVE, (char *)&on, sizeof(on)) < 0) {
		    	        log_event("Set TCP keep alive fail !");
			}
			ret = setsockopt(infop->redund.sock_cmd[1], SOL_TCP, TCP_KEEPIDLE,
	    	                     &Gkeep_idle,
			                 sizeof(Gkeep_idle));
			if (ret < 0)
			    	printf("setsockopt SO_KEEPIDLE error! %d\n", ret);

			ret = setsockopt(infop->redund.sock_cmd[1], SOL_TCP, TCP_KEEPINTVL,
		    	             &Gkeep_interval,
		        	         sizeof(Gkeep_interval));
			if (ret < 0)
			    	printf("setsockopt SO_KEEPINTVL error! %d\n", ret);

			ret = setsockopt(infop->redund.sock_cmd[1], SOL_TCP, TCP_KEEPCNT,
		    	             &Gkeep_count,
		        	         sizeof(Gkeep_count));
			if (ret < 0)
				printf("setsockopt SO_KEEPCNT error! %d\n", ret);
		}
		/* connect two-line cmd and data port */
        if (infop->af == AF_INET) {
            sock.sin.sin_family = AF_INET;
            sock.sin.sin_addr.s_addr = *(u_long*)infop->redund.ip6_addr;
            sock.sin.sin_port = htons(infop->cmd_port);
        }
        if ((ret = connect_nonb(infop->redund.sock_cmd[1], (struct sockaddr_in*)&sock, sizeof(sock), RE_TIME)) >= 0) {
	        if (infop->af == AF_INET) {
	        	sock.sin.sin_family = AF_INET;
    		        sock.sin.sin_addr.s_addr = *(u_long*)infop->redund.ip6_addr;
     		    	sock.sin.sin_port = htons(infop->tcp_port);
		}
            if ((ret = connect_nonb(infop->redund.sock_data[1], (struct sockaddr_in*)&sock, sizeof(sock), RE_TIME)) >= 0) {
				if ((redund_data_init(infop->redund.sock_data[1], &infop->redund.data)) > 0) {
                    			if ((redund_cmd_init(infop->redund.sock_cmd[1], &infop->redund.cmd)) > 0)  {
						pthread_mutex_lock(&Gmutex);
						infop->lost_cnt--;
						infop->redund.connect[1] = 1;
						infop->redund.data_open[1] = 1;
						infop->redund.cmd_open[1] = 1;
						pthread_mutex_unlock(&Gmutex);

                    			} else {
						redund_init_fail(infop, 1);
					}
		                } else {
					redund_init_fail(infop, 1);
				}
			} else {
				redund_init_fail(infop, 1);
			}	
		} else {
			redund_init_fail(infop, 1);
		}
	}else
		pthread_mutex_unlock(&Gmutex);
	}
}

#if 1
int do_redund_reconnect(TTYINFO * infop)
{
	int ret;

	pthread_mutex_lock(&Gmutex);
	if (!infop->redund.connect[0] || !infop->redund.connect[1]) {
		if (!infop->redund.thread[0]) {
			pthread_mutex_unlock(&Gmutex);
create_again:
			ret = pthread_create(&infop->redund.thread_id[0], NULL, (void *)redund_reconnect, (void *)infop);
			if (ret != 0) {
				goto create_again;
			} else { 
				pthread_mutex_lock(&Gmutex);
				infop->redund.thread[0] = 1;
				pthread_mutex_unlock(&Gmutex);
			}
		}
	}	
	pthread_mutex_unlock(&Gmutex);
}
#else
int do_redund_reconnect(TTYINFO * infop)
{
	int ret;

	pthread_mutex_lock(&Gmutex);
	if (!infop->redund.connect[0] && !infop->redund.close[0] && !infop->redund.thread[0]) {
		pthread_mutex_unlock(&Gmutex);
create_again1:
		ret = pthread_create(&infop->redund.thread_id[0], NULL, (void *)redund_reconnect, (void *)infop);
		pthread_detach(infop->redund.thread_id[0]);
		if (ret != 0) {
			goto create_again1;
		} else { 
			pthread_mutex_lock(&Gmutex);
			infop->redund.thread[0] = 1;
			pthread_mutex_unlock(&Gmutex);
		}
	}	
	else if (!infop->redund.connect[1] && !infop->redund.close[1] && !infop->redund.thread[1]) {
		pthread_mutex_unlock(&Gmutex);
create_again2:
		ret = pthread_create(&infop->redund.thread_id[1], NULL, (void *)redund_reconnect, (void *)infop);
		pthread_detach(infop->redund.thread_id[1]);
		if (ret != 0) {
			goto create_again2;
		} else {
			pthread_mutex_lock(&Gmutex);
			infop->redund.thread[1] = 1;
			pthread_mutex_unlock(&Gmutex);
		}
	}
	pthread_mutex_unlock(&Gmutex);
}
#endif

int connect_nonb(int client_fd, struct sockaddr_in *server_addr, socklen_t slen, int nsec)
{
    int ret;
    int flags, n, error;
    socklen_t len;
    fd_set rset, wset;
    struct timeval tval;

    if (client_fd < 0)
    	return -1;

    flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

    error = 0;

    if (n = connect(client_fd, (struct sockaddr *)server_addr,
              sizeof(struct sockaddr)) < 0) {
        if (errno != EINPROGRESS) {
            //printf("connect fail (%d), (%s)\n", n, strerror(errno));
            return -1;
        }
    }

    if (n == 0)
        goto done;

    FD_ZERO(&rset);
    FD_SET(client_fd, &rset);
    wset = rset;
    tval.tv_sec = 0;
    tval.tv_usec = nsec;

    if ((n = select(client_fd + 1, &rset, &wset, NULL, nsec ? &tval : NULL)) == 0) {
        errno = ETIMEDOUT;
        //printf("connect_nonb select fail\n");
        return -1;
    }

    if (FD_ISSET(client_fd, &rset) || FD_ISSET(client_fd, &wset)) {
        len = sizeof(error);
        if (getsockopt(client_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            return -1;
            //printf("getsockopt fail\n");
        }
    } else {
        //printf("select eroor: sockfd not set\n");
    }

done:
    fcntl(client_fd, F_SETFL, flags);

    if (error) {
        errno = error;
        return -1;
    }

    return 0;
}

void redund_poll_nport_send(SERVINFO *servp)
{
    union   sock_addr to;
    int             len;
    unsigned char   msg[32];
    DSCI_HEADER     *dsci_headerp;
    DSCI_DA_DATA    *dscidata_p;
    EX_HEADER       *exheader;
    struct sysinfo      sys_info;
    int af = servp->af;

    if (servp->dev_type)
        return;
    if(af == AF_INET6 && enable_ipv6 == DIS_IPV6)
        return;
#ifndef STREAM
    bzero(msg, 28);
#endif
#ifdef  STREAM
    memset (msg, 0, 28);
#endif
    sysinfo(&sys_info);
    if ( servp->ap_id == 0 )
    {   /* send dsc_search */
        servp->next_sendtime = (time_t)((int32_t)(sys_info.uptime + 5 ));
        servp->dsci_ver = 0xFFFF;
        dsci_headerp=(DSCI_HEADER*)&msg[0];
        dsci_headerp->opcode = 0x01; /* dsc_search */
        dsci_headerp->result = 0;
        dsci_headerp->length = htons(8);
        dsci_headerp->id = 0;
        len = 8;
        if(af == AF_INET6)
        {
            dsci_headerp->opcode = DSCI_IPV6;
            dsci_headerp->length = htons(28);
            exheader = (EX_HEADER*)&msg[20];
            exheader->ex_vision = EX_VERSION;
            memset(exheader->reservd, 0, 3);
            exheader->catalog = htons(KERNEL_FUN);
            exheader->subcode = htons(DSC_ENUMSEARCH);
            len = 28;
        }
    }
else if (servp->dsci_ver == 0xFFFF)
    {   /* send getkernelinfo */
        servp->next_sendtime = (time_t)((int32_t)(sys_info.uptime + 5 ));
        dsci_headerp=(DSCI_HEADER*)&msg[0];
        dsci_headerp->opcode = 0x16; /* getkernelinfo */
        dsci_headerp->result = 0;
        dsci_headerp->length = htons(20);
        dsci_headerp->id = 0;

        dscidata_p=(DSCI_DA_DATA*)&msg[8];
        dscidata_p->ap_id = htonl(servp->ap_id);
        dscidata_p->hw_id = htons(servp->hw_id);
        memcpy((void*)dscidata_p->mac, (void*)servp->mac, 6);
        len = 20;
    }
    else if (servp->dsci_ver == 0)
    {        /* send dsc_GetNetstat */
        servp->next_sendtime = (time_t)((int32_t)(sys_info.uptime + polling_time ));
        dsci_headerp=(DSCI_HEADER*)&msg[0];
        dsci_headerp->opcode = 0x14; /* dsc_GetNetstat */
        dsci_headerp->result = 0;
        dsci_headerp->length = htons(22);
        dsci_headerp->id = htonl((uint32_t)sys_info.uptime);

        dscidata_p=(DSCI_DA_DATA*)&msg[8];
        dscidata_p->ap_id = htonl(servp->ap_id);
        dscidata_p->hw_id = htons(servp->hw_id);
        memcpy((void*)dscidata_p->mac, (void*)servp->mac, 6);
        msg[20] = 128;   /* max number of sockets */
        msg[21] = 0;     /* max number of sockets */
        len = 22;
    }
    else
    {   // send dsc_GetNetstat_ex
        int addr;
        servp->next_sendtime = (time_t)((int32_t)(sys_info.uptime + polling_time ));
        dsci_headerp=(DSCI_HEADER*)&msg[0];
        dsci_headerp->opcode = (af == AF_INET) ? 0x1D : DSCI_IPV6; // dsc_GetNetstat_ex : DSCI IPv6
        dsci_headerp->result = 0;
        dsci_headerp->length = (af == AF_INET) ? htons(24) : htons(32);
        dsci_headerp->id = htonl((uint32_t)sys_info.uptime);

        dscidata_p=(DSCI_DA_DATA*)&msg[8];
        dscidata_p->ap_id = htonl(servp->ap_id);
        dscidata_p->hw_id = htons(servp->hw_id);
        memcpy((void*)dscidata_p->mac, (void*)servp->mac, 6);
        if(af == AF_INET6)
        {
            exheader = (EX_HEADER*)&msg[20];
            exheader->ex_vision = EX_VERSION;
            memset(exheader->reservd, 0, 3);
            exheader->catalog = htons(NETWORK_CONFIG);
            exheader->subcode = htons(DSC_GETNETSTAT_V6);
		}
        addr = (af == AF_INET) ? 20 : 28;  //max socket address for ipv4 or ipv6

        msg[addr] = 0x00;   // max number of sockets
        msg[addr+1] = (af == AF_INET) ? 0xFF : MAX_SOCK_V6;   // max number of sockets

        if(servp->af == AF_INET)
        {
            msg[addr+2] = (unsigned char)servp->start_item; // start item
            msg[addr+3] = 0;                    // start item
        }
        else
        {
            msg[addr+3] = (unsigned char)servp->start_item; // start item
            msg[addr+2] = 0;                    // start item
        }

        len = (af == AF_INET) ? 24 : 32;
    }
    memset(&to, 0, sizeof(to));
    if(af == AF_INET)
    {
        to.sin.sin_family = AF_INET;
        to.sin.sin_port = htons(4800);
        to.sin.sin_addr.s_addr = *(u_long*)servp->ip6_addr;
    }
    else
    {
        to.sin6.sin6_family = AF_INET6;
        to.sin6.sin6_port = htons(4800);
        memcpy(to.sin6.sin6_addr.s6_addr, servp->ip6_addr, 16);
    }
    sendto(polling_nport_fd[((af == AF_INET) ? 0 : 1)], msg, len, 0, (struct sockaddr *)&to, sizeof(to));
}

void redund_poll_nport_recv(int af_type)
{
    union sock_addr from;
    int             retlen, len, n, m, i, nstat, connected_tcp, connected_cmd, listening_tcp, listening_cmd;
    int32_t         t;
    SERVINFO *      servp;
    TTYINFO *       infop;
    char   msg[2100];
    DSCI_HEADER     *dsci_headerp;
    DSCI_RET_HEADER *dsci_retp;
    DSCI_NET_STAT   *desc_netstatp;
    DSCI_NET_STAT_IPV6 *desc_netstatp_ipv6;
    struct sysinfo  sys_info;
    u_short         next_item = 0;
    int             addr;

#ifdef  AIX
    if ( (retlen=recvfrom(polling_nport_fd[af_type], msg, sizeof(msg), 0, (struct sockaddr *)&from, (socklen_t *)&len))
#else
#ifdef  SCO
    if ( (retlen=recvfrom(polling_nport_fd[af_type], msg, sizeof(msg), 0, (struct sockaddr *)&from, &len))
#endif
#ifndef SCO
            len = sizeof(from);
            if ( (retlen=recvfrom(polling_nport_fd[af_type], msg, sizeof(msg), 0, (struct sockaddr *)&from, (socklen_t *)&len))
#endif
#endif
            != 24 && ((retlen-24)%16) && retlen != 36 && ((retlen - 44)%16) && ((retlen-32)%40) )
        return;
    dsci_headerp = (DSCI_HEADER*)&msg[0];
    if ( (dsci_headerp->opcode == 0x81 &&
             ( (ntohs(dsci_headerp->length) != 24 ) && (ntohs(dsci_headerp->length) != 40) )) ||
         (dsci_headerp->opcode == 0x94 && ((ntohs(dsci_headerp->length)-24)%16) != 0) ||
         (dsci_headerp->opcode == 0x96 && ntohs(dsci_headerp->length) != 36) ||
         (dsci_headerp->opcode == 0x9d && ((ntohs(dsci_headerp->length)-24)%16) != 0) ||
         (dsci_headerp->opcode == DSCI_IPV6_RESPONS &&
             ((((ntohs(dsci_headerp->length)-44)%16) != 0) &&  //dsci ipv6 enum search return 
              (((ntohs(dsci_headerp->length)-32)%40) != 0))) ) //dsci ipv6 GetNetstat_V6 return
        return;
    if ( dsci_headerp->result!=0 ||
        ( (from.sin.sin_port != ntohs(4800)) && (from.sin6.sin6_port != htons(4800)) ) )
        return;

    for ( n=0, servp=serv_info; n<servers; n++, servp++ )
    {
        if(af_type == 0)
        {
            if ( from.sin.sin_addr.s_addr == *(u_long*)servp->ip6_addr )
                break;
        }
        else
        {
            if(memcmp(from.sin6.sin6_addr.s6_addr, servp->ip6_addr, 16) == 0)
                break;
        }
    }
    if ( n == servers )
        return;

    sysinfo(&sys_info);
    dsci_retp=(DSCI_RET_HEADER*)&msg[8];
    if ( dsci_headerp->opcode == 0x81 ||
        ((dsci_headerp->opcode == DSCI_IPV6_RESPONS) && ((htons(dsci_headerp->length)-44)%16 == 0)))
    {     // dsc_search respons
        char tmpbuf[4096];
        servp->ap_id = ntohl(dsci_retp->ap_id);
        servp->hw_id = ntohs(dsci_retp->hw_id);
        memcpy((void*)servp->mac, (void*)dsci_retp->mac, 6);
        servp->last_servertime = (time_t)((int32_t)(sys_info.uptime - 1));

        inet_ntop(servp->af, servp->ip6_addr, (char *)&msg[96], 50);
        sprintf(tmpbuf, "%s is alive", &msg[96]);
        log_event(tmpbuf);
        return;
    }
    else if ( dsci_headerp->opcode == 0x96 )
    {     // getkernelinfo respons
        servp->last_servertime = (time_t)((int32_t)(sys_info.uptime - 1));
        servp->dsci_ver = *(u_short *)(&msg[34]);
        return;
    }

    if (dsci_headerp->opcode == 0x9D
        || (dsci_headerp->opcode == DSCI_IPV6_RESPONS && ((ntohs(dsci_headerp->length)-32)%40) == 0) )
    {
        if(servp->af == AF_INET)
        {
            next_item = (int)msg[23];   /* for big&little endian machine */
            next_item = (next_item << 8) | ((int)msg[22] & 0xff);
        }
        else
        {
            next_item = msg[30];
            next_item = (next_item << 8) | ((int)msg[31] & 0xff);
        }

        if (next_item)
            servp->start_item = next_item;
        else
            servp->start_item = 0;
    }

    t = ntohl(dsci_headerp->id);
    if (  t - servp->last_servertime  <= 0 )
        return;
    if ( (servp->ap_id != ntohl(dsci_retp->ap_id)) ||
            (servp->hw_id != ntohs(dsci_retp->hw_id)) )
    {
        servp->ap_id = 0;
        sysinfo(&sys_info);
        servp->next_sendtime = (time_t)((int32_t)(sys_info.uptime - 1 ));
        return;
    }
    m = 0;
    servp->last_servertime = t;
    addr = (servp->af == AF_INET)? 21 : 29;
    nstat = (int)msg[addr]; /* for big&little endian machine */
    nstat = (nstat << 8) | ((int)msg[addr-1] & 0xff);
    addr = (servp->af == AF_INET) ? 128 : 35;
    if(nstat > addr){            /* the value can not over 128 */
        nstat = addr;            /*for ipv6, the value can not over 35*/
    }
    for ( n=0, infop=ttys_info; n<ttys; n++, infop++ )
    {
        u_short local_port, remote_port;
        unsigned char status;
        if(servp->af == AF_INET)
        {
            if ( *(u_long*)infop->ip6_addr != *(u_long*)servp->ip6_addr )
                continue;
        }
        else if(servp->af == AF_INET6)
        {
            if(memcmp(infop->ip6_addr, servp->ip6_addr, 16) != 0)
                continue;
        }

        for (i=0, connected_tcp = connected_cmd = listening_tcp = listening_cmd = 0; i<nstat; i++)
        {
            if(servp->af == AF_INET)
            {
                desc_netstatp=(DSCI_NET_STAT*)&msg[24+i*16];
                local_port = desc_netstatp->local_port;
                remote_port = desc_netstatp->remote_port;
                status = desc_netstatp->status;
            }
            else if(servp->af == AF_INET6)
            {
                unsigned char *buf;
                desc_netstatp_ipv6 = (DSCI_NET_STAT_IPV6*)&msg[32+i*40];
                buf = (unsigned char *)&desc_netstatp_ipv6->local_port;
                local_port = buf[0]*0x100 + buf[1];
                buf = (unsigned char *)&desc_netstatp_ipv6->remote_ip;
                remote_port = buf[0]*0x100 + buf[1];
                status = desc_netstatp_ipv6->status;
            }
               if ( !(infop->local_tcp_port && infop->tcp_port == local_port) &&
                    !(infop->local_cmd_port && infop->cmd_port == local_port))
                continue;

#if 0
            if (infop->local_tcp_port && infop->tcp_port == desc_netstatp->local_port)
                printf("hit data port (%d, %d)\n", infop->tcp_port, infop->local_tcp_port);
            else if (infop->local_cmd_port && infop->cmd_port == desc_netstatp->local_port)
                printf("hit command port (%d, %d)\n", infop->cmd_port, infop->local_cmd_port);
#endif

            if (infop->tcp_port == local_port && status == TCP_LISTEN && infop->state == REDUND_RW_DATA)
                listening_tcp = 1;
            else if (infop->cmd_port == local_port && status == TCP_LISTEN && infop->state == REDUND_RW_DATA)
                listening_cmd = 1;
            else if (infop->local_tcp_port == remote_port && status == TCP_CONNECTED)
                connected_tcp = 1;
            else if (infop->local_cmd_port == remote_port && status == TCP_CONNECTED)
                connected_cmd = 1;
        }

        if ( (listening_tcp == 1 || listening_cmd == 1) && (!connected_tcp || !connected_cmd))
        {
            if (servp->dsci_ver == 0 || (servp->dsci_ver != 0 && next_item == 0))
            {
                m++;
//                infop->state = REDUND_REMOTE_LISTEN;
            }

            sysinfo(&sys_info);
            infop->time_out = sys_info.uptime;
        }
    }
    if ( m )
    {
        char ip_buf[50];
        int size;
        size = sizeof(ip_buf);
        sprintf(msg, "Ports reset of NPort(Async) Server %s !", 
		inet_ntop(servp->af, servp->ip6_addr, ip_buf, size));
        log_event(msg);
    }
}



