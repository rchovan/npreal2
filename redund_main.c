/*
 *	Copyright (C) 2001  Moxa Inc.
 *	All rights reserved.
 *
 *	Moxa NPort/Async Server UNIX Real TTY daemon program.
 *
 *	Usage: npreal2d_redund [-t reset-time]
 *
 */

#include	"np_ver.h"

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/param.h>
#include	<netinet/in.h>
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
#ifdef	STREAM
#include	<sys/ptms.h>
#endif
#ifdef	SSL_ON
#include	<openssl/ssl.h>
#endif

#include	<resolv.h> // for res_init()
#include	<arpa/inet.h>
#include	"redund.h"
#include	"npreal2d.h"
//#include	"misc.h"

void _log_event_backup(char *log_pathname, char *msg);
int ipv4_str_to_ip(char *str, ulong *ip);
int ipv6_str_to_ip(char *str, unsigned char *ip);

#define DNS_NAME_RESOLVE 1

/* The mode which daemon will be waken up */
int		Graw_mode = 0;
int		Gredund_mode = 0;

int		ttys, servers;
TTYINFO 	ttys_info[MAX_TTYS]; /* tty info which is initiated by reading from configuration. */
SERVINFO	serv_info[MAX_TTYS];
char		EventLog[160];		/* Event log file name */
int		pipefd[2];
int		maxfd;
int     timeout_time = 0;
int		polling_time=0; 	/* default disable polling function */
int		polling_fd;
int     polling_nport_fd[2];
int		Restart_daemon;
static	int	No_tty_defined;
static	int enable_ipv6=1;  /*2 enable ipv6, 1 disenable ipv6*/
#define EN_IPV6   2
#define DIS_IPV6  1
#ifdef	STREAM
extern	char	*ptsname();
#endif
#ifdef	SSL_ON
static void ssl_init(void);
SSL_CTX *sslc_ctx;
#endif

#ifndef	STREAM
void	restart_handle ();
void	wait_handle ();
void	connect_wait_handle ();
#endif
#ifdef	STREAM
void	restart_handle (int);
void	wait_handle (int);
void	connect_wait_handle (int);
#endif

int poll_async_server_init();
void moxattyd_daemon_start();
int	moxattyd_read_config(char *cmdpath);

/*
 *	MOXA TTY daemon main program
 */
void main(argc, argv)
int	argc;
char *	argv[];
{
	TTYINFO *	infop;
	char ver[100];
	int		i;
	Restart_daemon = 0;
	No_tty_defined = 0;
	polling_fd = -1; /* Add by Ying */

	for(i=0; i<2; i++)
		polling_nport_fd[i] = -1;
	while (1)
	{
		if (Restart_daemon)
		{
			/* Add by Ying */
			if (polling_fd >= 0)
			{
				close(polling_fd);
				polling_fd = -1;
			}
			for(i=0; i<2; i++)
			{
				if (polling_nport_fd[i] >= 0)
				{
					close(polling_nport_fd[i]);
					polling_nport_fd[i] = -1;
				}
			}
			/* */

			infop = ttys_info;
			//            close (pipefd[0]);
			//            close (pipefd[1]);
			for (i = 0;i < ttys;i++)
			{
				infop->reconn_flag = 1;
				if (infop->sock_fd >= 0)
				{
#ifdef SSL_ON
					if (infop->ssl_enable)
					{
						SSL_shutdown(infop->pssl);
						SSL_free(infop->pssl);
						infop->pssl = NULL;
					}
#endif
					close(infop->sock_fd);
				}
				if (infop->sock_cmd_fd >= 0)
					close(infop->sock_cmd_fd);
				if (infop->mpt_fd >= 0)
					close(infop->mpt_fd);
				infop++;
				close(infop->pipe_port[0]);
				close(infop->pipe_port[1]);
			}
		} /* if (Restart_daemon) */

		if (Restart_daemon == 1)
		{
#ifndef	STREAM
			signal (SIGTERM, ( (void (*)()) wait_handle) );
#endif
#ifdef	STREAM
			signal (SIGTERM, wait_handle);
#endif
			pause();
		} /* if (Restart_daemon == 1) */

		/*
		 * Read the poll time & the pesudo TTYs configuation file.
		 */

		if ( (argc > 2) && (strcmp(argv[1], "-t") == 0) )
		{
			// The unit of -t is minute.
			timeout_time = 60 * atoi(argv[2]);
			polling_time = timeout_time;
			if ( polling_time >= 60 )
			{
				polling_time = (polling_time - 20) / 4;
			}
		}

		if ( moxattyd_read_config(argv[0]) <= 0 )
		{
			if (!No_tty_defined)
			{
				log_event ("Not any tty defined");
				No_tty_defined = 1;
			}
			break;
			//			usleep(1000);
			//			continue;
		}
		No_tty_defined = 0;
		/*
		 * Initialize this Moxa TTYs daemon process.
		 */
		if (!Restart_daemon)
			moxattyd_daemon_start();

		/*
		 * Initialize polling async server function.
		 */
		if ( polling_time && (poll_async_server_init() < 0) )
		{
			continue;
		}

		/*
		 * Open PIPE, set read to O_NDELAY mode.
		 */
		//

		infop = ttys_info;
		for (i = 0;i < ttys;i++) {
			if ( pipe(infop->pipe_port) < 0 )
			{
				log_event("pipe error !");
				continue;
			}
#ifdef	O_NDELAY
			fcntl(infop->pipe_port[0], F_SETFL, fcntl(infop->pipe_port[0], F_GETFL) | O_NDELAY);
#endif
			infop++;
		}

		signal(SIGCLD, SIG_IGN); /* Ignore signal if child process terminate. */

		Restart_daemon = 0;
		sprintf(ver, "MOXA Real TTY daemon program starting (%s %s)...", NPREAL_VERSION, NPREAL_BUILD);
		log_event(ver);
#ifndef	STREAM
		signal (SIGTERM, ( (void (*)())restart_handle) );
#endif
#ifdef	STREAM
		signal (SIGTERM, restart_handle);
#endif

		/*
		 * Handle Moxa TTYs data communication.
		 */
#ifdef SSL_ON
		ssl_init();
#endif
		if (Gredund_mode)
			redund_handle_ttys(); /* child process ok */
	}
}

int resolve_dns_host_name(infop)
TTYINFO *infop;
{
	int ret;
	struct addrinfo *result = NULL, *rp;
	struct addrinfo hints;
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
	char msg[255]={0};
	ulong addr_ipv4;
	u_char addr_ipv6[16];
	int ret1 = NP_RET_SUCCESS;
	int ret2 = NP_RET_SUCCESS;

	do{
		if( ipv4_str_to_ip(infop->ip_addr_s, &addr_ipv4)==NP_RET_SUCCESS ){
			*(ulong*)infop->ip6_addr = addr_ipv4;
			infop->af = AF_INET;
			ret1 = NP_RET_SUCCESS;
			break;

		} else if(ipv6_str_to_ip(infop->ip_addr_s, addr_ipv6)==NP_RET_SUCCESS )	{
			memcpy(infop->ip6_addr, addr_ipv6, sizeof(infop->ip6_addr));
			infop->af = AF_INET6;
			ret1 = NP_RET_SUCCESS;
			break;
		}

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
		hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
		hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */

		ret = getaddrinfo(infop->ip_addr_s, NULL, &hints, &result);
		if( ret==EAI_AGAIN || ret==EAI_NONAME ){
			// Sometimes, this error occurred. It means DNS server or DNS configuration are wrong temporarily.
			sleep(1);
			res_init(); // init name resolver again!

			ret = getaddrinfo(infop->ip_addr_s, NULL, &hints, &result);
			if (ret != 0) {
				sprintf(msg, "getaddrinfo: %s @ %d, %s\n", gai_strerror(ret), __LINE__, __FUNCTION__);
				log_event(msg);
				ret1 = NP_RET_ERROR;
				break;
			}
		}

		memset(infop->ip6_addr, 0, sizeof(infop->ip6_addr));

		for (rp = result; rp != NULL; rp = rp->ai_next) {

			if(rp->ai_family == AF_INET)
			{
				ipv4 = (struct sockaddr_in *)rp->ai_addr;
				*(ulong*)infop->ip6_addr = ((struct in_addr *)&ipv4->sin_addr)->s_addr;
				infop->af = AF_INET;
				// IPv4 address is translated.

				//{
				//	char ipAddress[INET_ADDRSTRLEN];
				//	inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, INET_ADDRSTRLEN);
				//	sprintf(msg, "ipAddress: %s @ %d, %s\n", ipAddress, __LINE__, __FUNCTION__);
				//	log_event(msg);
				//}
				break;

			} else if(rp->ai_family == AF_INET6)
			{
				ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
				memcpy(infop->ip6_addr, ((struct in6_addr *)&ipv6->sin6_addr)->s6_addr, 16);
				infop->af = AF_INET6;

				//{
				//	char ipAddress[INET6_ADDRSTRLEN];
				//	inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipAddress, INET6_ADDRSTRLEN);
				//	sprintf(msg, "ipAddress: %s @ %d, %s\n", ipAddress, __LINE__, __FUNCTION__);
				//	log_event(msg);
				//}
				break;
			}
		}
		freeaddrinfo(result);           /* No longer needed */

		if (rp == NULL) {               /* No address succeeded */
			sprintf(msg, "No available host is found. @ %d, %s\n", __LINE__, __FUNCTION__);
			log_event(msg);
			ret1 = NP_RET_ERROR;
			break;
		}
	} while(0);

	while(infop->redundant_mode) {

		if( ipv4_str_to_ip(infop->redund.redund_ip, &addr_ipv4)==NP_RET_SUCCESS ){
			*(u_long*)infop->redund.ip6_addr = addr_ipv4;
			//{
			//	char ipAddress[INET_ADDRSTRLEN];
			//	inet_ntop(AF_INET, &(addr_ipv4), ipAddress, INET_ADDRSTRLEN);
			//	sprintf(msg, "ipAddress: %s @ %d, %s\n", ipAddress, __LINE__, __FUNCTION__);
			//	log_event(msg);
			//}
			ret2 = NP_RET_SUCCESS;
			break;
		} else if(ipv6_str_to_ip(infop->redund.redund_ip, addr_ipv6)==NP_RET_SUCCESS )	{
			memcpy(infop->redund.ip6_addr, addr_ipv6, sizeof(infop->redund.ip6_addr));
			ret2 = NP_RET_SUCCESS;
			break;
		}

		hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */

		ret = getaddrinfo(infop->redund.redund_ip, NULL, &hints, &result);
		if( ret==EAI_AGAIN || ret==EAI_NONAME ){
			// Sometimes, this error occurred. It means DNS server or DNS configuration are wrong temporarily.
			sleep(1);
			res_init(); // init name resolver again!

			ret = getaddrinfo(infop->redund.redund_ip, NULL, &hints, &result);
			if (ret != 0) {
				sprintf(msg, "getaddrinfo: %s @ %d, %s\n", gai_strerror(ret), __LINE__, __FUNCTION__);
				log_event(msg);
				ret2 = NP_RET_ERROR;
			}
		}

		*(ulong*)infop->redund.redund_ip = 0;
		memset(infop->redund.ip6_addr, 0, sizeof(infop->redund.ip6_addr));

		for (rp = result; rp != NULL; rp = rp->ai_next) {

			if(rp->ai_family == AF_INET)
			{
				ipv4 = (struct sockaddr_in *)rp->ai_addr;
				*(ulong*)infop->redund.ip6_addr = ((struct in_addr *)&ipv4->sin_addr)->s_addr;
				infop->af = AF_INET;

				// IPv4 address is translated.

				//{
				//	char ipAddress[INET_ADDRSTRLEN];
				//	inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, INET_ADDRSTRLEN);
				//	sprintf(msg, "ipAddress: %s @ %d, %s\n", ipAddress, __LINE__, __FUNCTION__);
				//	log_event(msg);
				//}
				break;
			} else if(rp->ai_family == AF_INET6)
			{
				ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
				memcpy(infop->redund.ip6_addr, ((struct in6_addr *)&ipv6->sin6_addr)->s6_addr, 16);
				infop->af = AF_INET6;
				//{
				//	char ipAddress[INET6_ADDRSTRLEN];
				//	inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipAddress, INET6_ADDRSTRLEN);
				//	sprintf(msg, "ipAddress: %s @ %d, %s\n", ipAddress, __LINE__, __FUNCTION__);
				//	log_event(msg);
				//}
				break;
			}
		}

		if (rp == NULL) {               /* No address succeeded */
			sprintf(msg, "No available host is found. @ %d, %s\n", __LINE__, __FUNCTION__);
			log_event(msg);
			ret2 = NP_RET_ERROR;
			break;
		}

		freeaddrinfo(result);           /* No longer needed */
		break;
	}

	if( ret1!=NP_RET_SUCCESS || ret2!=NP_RET_SUCCESS ){
		return NP_RET_ERROR;
	} else {
		return NP_RET_SUCCESS;
	}
}


#ifndef DNS_NAME_RESOLVE

int lib_name2ip6(infop)
TTYINFO *infop;
{
	int ret;
	struct addrinfo *result = NULL, *rp;
	struct addrinfo hints;
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
	char msg[255]={0};
	int error_cnt = 10;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */

	ret = getaddrinfo(infop->ip_addr_s, NULL, &hints, &result);
	if( ret==EAI_AGAIN ){
		// TODO: Figure out the cause of error. Ask user to do correct configuration or friendly warning messages.
		// Sometimes, this error occurred. It means DNS server or DNS configuration are wrong temporarily.
		do{
			ret = getaddrinfo(infop->ip_addr_s, NULL, &hints, &result);
			sleep(1);
		} while( ret==EAI_AGAIN && --error_cnt>0 );
	}

	if (ret != 0) {
		sprintf(msg, "getaddrinfo: %s @ %d, %s\n", gai_strerror(ret), __LINE__, __FUNCTION__);
		log_event(msg);
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {

		if(rp->ai_family == AF_INET)
		{
			ipv4 = (struct sockaddr_in *)rp->ai_addr;
			*(u_long*)infop->ip6_addr = ((struct in_addr *)&ipv4->sin_addr)->s_addr;
			infop->af = AF_INET;
			// IPv4 address is translated.

			//{
			//	char ipAddress[INET_ADDRSTRLEN];
			//	inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, INET_ADDRSTRLEN);
			//	sprintf(msg, "ipAddress: %s @ %d, %s\n", ipAddress, __LINE__, __FUNCTION__);
			//	log_event(msg);
			//}
			break;

		} else if(rp->ai_family == AF_INET6)
		{
			ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
			memcpy(infop->ip6_addr, ((struct in6_addr *)&ipv6->sin6_addr)->s6_addr, 16);
			infop->af = AF_INET6;

			//{
			//	char ipAddress[INET6_ADDRSTRLEN];
			//	inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipAddress, INET6_ADDRSTRLEN);
			//	sprintf(msg, "ipAddress: %s @ %d, %s\n", ipAddress, __LINE__, __FUNCTION__);
			//	log_event(msg);
			//}
			break;
		}
	}
	freeaddrinfo(result);           /* No longer needed */

	if (rp == NULL) {               /* No address succeeded */
    	sprintf(msg, "No available host is found. @ %d, %s\n", __LINE__, __FUNCTION__);
    	log_event(msg);
		return -1;
	}

	if (infop->redundant_mode) {

		hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */

		ret = getaddrinfo(infop->redund.redund_ip, NULL, &hints, &result);
		if (ret != 0) {
			sprintf(msg, "getaddrinfo: %s @ %d, %s\n", gai_strerror(ret), __LINE__, __FUNCTION__);
			log_event(msg);
			return -1;
		}

		for (rp = result; rp != NULL; rp = rp->ai_next) {

			if(rp->ai_family == AF_INET)
			{
				ipv4 = (struct sockaddr_in *)rp->ai_addr;
				*(u_long*)infop->redund.ip6_addr = ((struct in_addr *)&ipv4->sin_addr)->s_addr;
				infop->af = AF_INET;

				// IPv4 address is translated.

				//{
				//	char ipAddress[INET_ADDRSTRLEN];
				//	inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, INET_ADDRSTRLEN);
				//	sprintf(msg, "ipAddress: %s @ %d, %s\n", ipAddress, __LINE__, __FUNCTION__);
				//	log_event(msg);
				//}
				break;
			}
		}

		if (rp == NULL) {               /* No address succeeded */
	    	sprintf(msg, "No available host is found. @ %d, %s\n", __LINE__, __FUNCTION__);
	    	log_event(msg);
			return -1;
		}

		freeaddrinfo(result);           /* No longer needed */
	}

	return 0;
}
#endif

/*
 *	Prepare LOG file and read the config TTY records.
 *
 */
int	moxattyd_read_config(cmdpath)
char *	cmdpath;
{
	int		n, data, cmd;
	FILE *		ConfigFd;
	struct hostent *host;
	TTYINFO *	infop;
	char		workpath[128], buf[160];
	char		ttyname[160],tcpport[16],cmdport[16];
	char		ttyname2[160], curname[160], scope_id[10];
	int			redundant_mode;
	int32_t		server_type,disable_fifo;
#ifdef SSL_ON
	int32_t		ssl_enable;
#else
	int32_t            temp;
#endif

	redundant_mode = 0;
	// Scott: 2005-10-03
	// The original design will lead to an incorrect workpath.
	// Use fixed path instead.
	sprintf(workpath, "/usr/lib/npreal2/driver");

	/*
	 * Prepare the full-path file names of LOG/Configuration.
	 */
	sprintf(buf,"%s/npreal2d.cf", workpath);        /* Config file name */
	sprintf(EventLog,"%s/npreal2d.log", workpath);  /* Log file name */

	/*
	 * Open configuration file:
	 */
	ConfigFd = fopen(buf, "r");
	if ( ConfigFd == NULL )
	{
		log_event("Can't open configuration file (npreal2d.cf) !");
		return(-1);			/* Can't open file ! */
	}

	/*
	 * old configuration file format.
	 *"Device Id" "Server IP addr/Name" "data_port" "cmd_port" "Server Type"
	 * ex:
	 *  0	       192.168.1.1	950	966 2500
	 *	1	       tty_server	951	967 303
	 *	2	       192.168.1.1	950	966 311
	 *
	 *
	 * Read configuration & the data format of every data line is :
	 * [Minor] [ServerIP]	   [Data] [Cmd] [FIFO] [ttyName] [coutName]
	 *  0      192.168.1.1     950    966   1      ttyr00    cur00
	 *  1      192.168.1.1     951    967   1      ttyr01    cur01
	 *  2      192.168.1.1     952    968   1      ttyr02    cur02
	 *
	 * Security data format
	 * [Minor] [ServerIP]	             [Data] [Cmd] [FIFO] [SSL] [ttyName] [coutName] [interface]
	 *  0      192.168.1.1               950    966   1      0     ttyr00    cur00
	 *  1      192.168.1.1               951    967   1      0     ttyr01    cur01
	 *  2      192.168.1.1               952    968   1      1     ttyr02    cur02
	 *  3      fe80::216:d4ff:fe80:63e6  950    966   1      0     ttyr03    cur03       eth0
	 */
	ttys = 0;
	infop = ttys_info;
	while ( ttys < MAX_TTYS )
	{
		if ( fgets(buf, sizeof(buf), ConfigFd) == NULL )
			break;				/* end of file */
		memset(&infop->redund, 0, sizeof(struct redund_struct));
		server_type = disable_fifo = 0;
#ifdef SSL_ON
		ssl_enable = 0;
#endif
		n = sscanf(buf, "%s%s%s%s%d%d%s%s%s%d%s",
				ttyname,
				infop->ip_addr_s,
				tcpport,
				cmdport,
				&disable_fifo,
#ifdef SSL_ON
				&ssl_enable,
#else
				&temp,
#endif
				ttyname2,
				curname,
				scope_id,
				&infop->redundant_mode,
				infop->redund.redund_ip);
		//		printf("[AP] [ttyname = %s],[tcpport = %s],[ip1 = %s],[ip2 = %s]\n", ttyname, tcpport,
		//								 infop->ip_addr_s,
		//								 infop->redund.redund_ip);
		if(n != 10 && n != 11)
		{
			continue;
		}

		if (ttyname[0]=='#')
			continue;
		Graw_mode = 1;
		Gredund_mode = 1;

		/* in npreal2d.cf, [FIFO] is set to 1 if user is tend to */
		/* enable fifo, so the value of disable_fifo must be set to 0*/
		/* vice versa */
		if (disable_fifo == 1)
		{
			disable_fifo = 0;
		}
		else
		{
			disable_fifo = 1;
		}

		//        server_type = CN2500;
		sprintf(infop->mpt_name,"/proc/npreal2/%s",ttyname);

#ifdef DNS_NAME_RESOLVE
		resolve_dns_host_name(infop);

#else
		if(lib_name2ip6(infop) == -1)
		{
			log_event("ip address fail!!");
			continue;
		}
		if(infop->af == AF_INET)
		{
			if ( *(u_long*)infop->ip6_addr == (uint32_t)0xFFFFFFFF )
				continue;
		}
#endif

		if ( (data = atoi(tcpport)) <= 0 || data >= 10000 )
			continue;
		if ( (cmd = atoi(cmdport)) <= 0 || cmd >= 10000 )
			continue;

		if((strncmp(infop->ip_addr_s, "fe80", 4) == 0) || (strncmp(infop->ip_addr_s, "FE80", 4) == 0))
		{
			if(strlen(scope_id) == 0)
			{
				break;
			}
			strcpy(infop->scope_id, scope_id);
		}
		else
		{
			memset(infop->scope_id, 0, 10);
		}
		infop->tcp_port = data;
		infop->cmd_port = cmd;
		infop->mpt_fd = -1;
		infop->sock_fd = -1;
		infop->sock_cmd_fd = -1;
		infop->state = STATE_INIT;
		infop->mpt_bufptr = (char *)malloc(BUFFER_SIZE * 2);
		if ( infop->mpt_bufptr == (char *)NULL )
		{
			log_event("Alocate memory fail !");
			break;
		}
		infop->sock_bufptr = infop->mpt_bufptr + BUFFER_SIZE;
		infop->mpt_datakeep = 0;
		infop->mpt_dataofs = 0;
		infop->mpt_cmdkeep = 0;
		infop->sock_datakeep = 0;
		infop->sock_dataofs = 0;
		infop->sock_cmdkeep = 0;
		infop->error_flags = 0;
		strcpy(infop->ttyname, ttyname);
		strcpy(infop->ttyname2, ttyname2);
		strcpy(infop->curname, curname);
		infop->server_type = server_type;
		infop->disable_fifo = disable_fifo;
		infop->tcp_wait_id = 0;
		if (!Restart_daemon)
			infop->tty_used_timestamp = 0;
		infop->first_servertime = 0;
#ifdef	SSL_ON
		infop->pssl = NULL;
		infop->ssl_enable = ssl_enable;
#endif
		infop++;
		ttys++;
	} /* while ( ttys < MAX_TTYS ) */

	/*
	 * Close configuration file:
	 */
	fclose(ConfigFd);
	if ( ttys == 0 )
		log_event("Have no any TTY configured record !");
	return(ttys);
}

/*
 *	Initialize a daemon process & detach a daemon process from login
 *	session context.
 */
void moxattyd_daemon_start()
{
    register int	childpid, fd;

    /*
     * If we were started by init (process 1) from the /etc/inittab file
     * there's no need to detach.
     * This test is unreliable due to an unavoidable ambiguity if the
     * process is started by some other process and orphaned (i.e., if
     * the parent process terminates before we are started).
     */
    if ( getppid() == 1 )
        goto next;

    /*
     * Ignore the terminal stop signals.
     */
#ifdef	SIGTTOU
    signal(SIGTTOU, SIG_IGN);
#endif
#ifdef	SIGTTIN
    signal(SIGTTIN, SIG_IGN);
#endif
#ifdef	SIGTSTP
    signal(SIGTSTP, SIG_IGN);
#endif

    /*
     * If we were not started in the background, fork and let the parent
     * exit. This also guarantees the first child is not a process group
     * leader.
     */
    if ( (childpid = fork()) < 0 )
    {
        log_event("Can't fork first child !");
        exit(0);
    }
    else if ( childpid > 0 )
        exit(0);		/* parent process */

    /*
     * Disassociate from controlling terminal and process group.
     * Ensure the process can't reacquire a new controlling terminal.
     */
#ifdef	TIOCNOTTY

    if ( (fd = open("/dev/tty", O_RDWR)) >= 0 )
    {
        ioctl(fd, TIOCNOTTY, (char *)NULL);
        close(fd);
    }

#else

    if ( setpgrp() == -1 )
    {
        log_event("Can't change process group !");
        exit(0);
    }
    signal(SIGHUP, SIG_IGN);	/* immune from pgrp leader death */
    if ( (childpid = fork()) < 0 )
    {
        log_event("Can't fork second child !");
        exit(0);
    }
    else if ( childpid > 0 )
        exit(0);		/* parent process */

#endif

next:
    /*
     * Close any open files descriptors.
     */
#if 1 
    close(0);
    close(1);
    close(2);
#endif
    errno = 0;

    /*
     * Move the current directory to root, to make sure we aren't on a
     * mounted filesystem.
     */
    chdir("/");

    /*
     * Clear any inherited file mode creation mask.
     */
    umask(0);
}

/*
 * Initialize the polling Server UDP socket & server IP table.
 */
int poll_async_server_init()
{
    int			i, n, udp_port;
    struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
    struct sysinfo		sys_info;
	int af;
	
	int family[] = {AF_INET, AF_INET6};
	struct sockaddr * ptr;
	int len;

    servers = 0;
	af = ttys_info[0].af;
    for ( i=0; i<ttys; i++ )
    {
    	for ( n=0; n<servers; n++ )
        {
        	// These loop will store IP for last tty port. It also align variable 'n' for later usage.
            if ( *(u_long*)serv_info[n].ip6_addr == *(u_long*)ttys_info[i].ip6_addr )
                break;
			else if(memcmp(serv_info[n].ip6_addr, ttys_info[i].ip6_addr, 16) == 0)
				break;
        }
        if ( n == servers )
        {
        	// For each tty, it initiate server parameters here.
            sysinfo(&sys_info);
            ttys_info[i].serv_index = servers;
			if(ttys_info[i].af == AF_INET)
	            *(u_long*)serv_info[servers].ip6_addr = *(u_long*)ttys_info[i].ip6_addr;
			else
				memcpy(serv_info[servers].ip6_addr, ttys_info[i].ip6_addr, 16);
			serv_info[servers].af = ttys_info[i].af;
            serv_info[servers].dev_type = 0;
            serv_info[servers].serial_no = 0;
            serv_info[servers].last_servertime = (time_t)((int32_t)(sys_info.uptime - 2));
            serv_info[servers].next_sendtime = (time_t)((int32_t)(sys_info.uptime - 1));
            serv_info[servers].ap_id = 0;
            serv_info[servers].hw_id = 0;
            serv_info[servers].dsci_ver= 0xFFFF;
            serv_info[servers].start_item= 0;
            servers++;
        }
        else
            ttys_info[i].serv_index = n; // Scott added: 2005-03-02
    }

	for(i=0; i<2; i++)
	{
		ptr = (i == IS_IPV4)? (struct sockaddr*)&sin : (struct sockaddr*)&sin6;
		len = (i == IS_IPV4)? sizeof(sin) : sizeof(sin6);
		
	    if ( (polling_nport_fd[i] = socket(family[i], SOCK_DGRAM, 0)) < 0 )
	    {
	        log_event("Can not open the polling_nport_fd socket !");
			if(i == IS_IPV6)
			{
				polling_nport_fd[1] = -1;
				enable_ipv6 = DIS_IPV6;
			    break;
			}
	        return(-1);
	    }
		if(i == IS_IPV4)
		{
		    sin.sin_family = AF_INET;
		    sin.sin_port = 0;
		    sin.sin_addr.s_addr = INADDR_ANY;
		}
		else
		{
			memset(&sin6, 0, sizeof(sin6));
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = 0;
		}
	    if (bind(polling_nport_fd[i], ptr, len) == 0)
	    {
#ifdef	FIONBIO
	        fcntl(polling_nport_fd[i], FIONBIO);
#endif
	    }
	    else
	    {
	    	for(n=0; n<=i; n++)
	    	{
		        close(polling_nport_fd[n]);
		        polling_nport_fd[n] = -1;
	    	}
	        log_event("Can not bind the polling NPort UDP port !");
	        return(-1);
	    }
	}
    if ( (polling_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
    {
        log_event("Can not open the polling UDP socket !");
        return(-1);
    }

    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = INADDR_ANY;

    if (bind(polling_fd, (struct sockaddr*)&sin, sizeof(sin)) == 0)
    {
#ifdef	FIONBIO
        fcntl(polling_fd, FIONBIO);
#endif
    }
	else
	{
	    close(polling_fd);
	    polling_fd = -1; /* Add by Ying */
		for(i=0; i<2; i++)
		{
			close(polling_nport_fd[i]);
		    polling_nport_fd[i] = -1;
		}
	    log_event("Can not bind the polling UDP port !");
	    return(-1);
	}
	return 0;
}

void log_event(msg)
char *	msg;
{
    if (Restart_daemon)
        return;

    _log_event_backup(EventLog, msg);
}

#ifndef	STREAM
void	restart_handle ()
#endif
#ifdef	STREAM
void	restart_handle (int sig)
#endif
{
    Restart_daemon = 1;
#ifndef	STREAM
    signal (SIGTERM, ( (void (*)()) wait_handle) );
#endif
#ifdef	STREAM
    sig = sig;
    signal (SIGTERM, wait_handle);
#endif
}

#ifndef	STREAM
void	wait_handle ()
#endif
#ifdef	STREAM
void	wait_handle (int sig)
#endif
{
    Restart_daemon = 2;
#ifndef	STREAM
    signal (SIGTERM, ( (void (*)()) wait_handle) );
#endif
#ifdef	STREAM
    sig = sig;
    signal (SIGTERM, wait_handle);
#endif
}

#ifndef	STREAM
void	connect_wait_handle ()
#endif
#ifdef	STREAM
void	connect_wait_handle (int sig)
#endif
{
#ifndef	STREAM
    signal (SIGUSR1, ( (void (*)()) connect_wait_handle) );
#endif
#ifdef	STREAM
    sig = sig;
    signal (SIGUSR1, connect_wait_handle);
#endif
}

#ifdef	SSL_ON
static void ssl_init(void)
{
    SSLeay_add_ssl_algorithms();

#ifdef SSL_VER2
    sslc_ctx = SSL_CTX_new(SSLv2_client_method());
#else
#ifdef SSL_VER3
    sslc_ctx = SSL_CTX_new(SSLv3_client_method());
    ;
#else
    sslc_ctx = SSL_CTX_new(SSLv23_client_method());
#endif
#endif

    /* For blocking mode: cause read/write operations to only return after the handshake and successful completion. */
    SSL_CTX_set_mode(sslc_ctx, SSL_MODE_AUTO_RETRY);
}
#endif

void _log_event_backup(char *log_pathname, char *msg)
{
#define MAX_BACKUP_FILE 16
#define MAX_LOG_SIZE 10485760L
	FILE *		fd;
	time_t		t;
	struct tm	*tt;
	char		tmp[256];
	unsigned long sz = 0;
    static int bak_no = 0;

	t = time(0);
	tt = localtime(&t);
	/*
	 * Open Log file as append mode.
	 */
	fd = fopen(log_pathname, "a+");
	if ( fd )
	{
		sprintf(tmp, "%02d-%02d-%4d %02d:%02d:%02d  ",
				tt->tm_mon + 1, tt->tm_mday, tt->tm_year+1900,
				tt->tm_hour, tt->tm_min, tt->tm_sec);
		fputs(tmp, fd);
		fputs(msg, fd);
		fputs("\n", fd);
		fseek(fd, 0L, SEEK_END);
		sz = ftell(fd);
		fclose(fd);

		if(sz > (MAX_LOG_SIZE)){
			//TODO: Solve strange problem that I call below command and get program crash.
			//sprintf(tmp, "mv --backup= %s.bak %s.bak.old", EventLog, EventLog);
			//system(tmp);

			//if( bak_no==0 ){
			{
				int f_no=1;
				FILE * bak_fd;
				struct stat st_last={0};
				struct stat st_curr;

				// Look for the available backup number to save.
				while(1){
					sprintf(tmp, "%s.~%d~", log_pathname, f_no);
					bak_fd = fopen(tmp, "r");
					if( bak_fd==NULL ){
						bak_no = f_no;
						break;
					}
					fclose(bak_fd);
					stat( tmp, &st_curr );
					if( st_curr.st_mtime < st_last.st_mtime ){
						bak_no = f_no;
						break;
					}
					st_last = st_curr;
					f_no++;

					if( f_no>MAX_BACKUP_FILE ){
						f_no = 1;
					}
				}
			}

			//sprintf(tmp, "cp %s %s.~%d~", EventLog, EventLog, bak_no++);
			sprintf(tmp, "cp %s %s.~%d~", log_pathname, log_pathname, bak_no);
			system(tmp);
			sprintf(tmp, "rm -rf %s", log_pathname);
			system(tmp);

			//if( bak_no>MAX_BACKUP_FILE ){
			//	bak_no = 1;
			//}
		}
	}
}

int	ipv4_str_to_ip(char *str, ulong *ip)
{
	int	i;
	unsigned long	m;

	/* if is space, I will save as 0xFFFFFFFF */
	*ip = 0xFFFFFFFFL;

	for (i = 0; i < 4; i++)
	{
		if ((*str < '0') || (*str > '9'))
			return NP_RET_ERROR;

		m = *str++ - '0';
		if ((*str >= '0') && (*str <= '9'))
		{
			m = m * 10;
			m += (*str++ - '0');
			if ((*str >= '0') && (*str <= '9'))
			{
				m = m * 10;
				m += (*str++ - '0');
				if ((*str >= '0') && (*str <= '9'))
					return NP_RET_ERROR;
			}
		}

		if (m > 255)
			return NP_RET_ERROR;

		if ((*str++ != '.') && (i < 3))
			return NP_RET_ERROR;

		m <<= (i * 8);

		if (i == 0)
			m |= 0xFFFFFF00L;
		else if ( i == 1 )
			m |= 0xFFFF00FFL;
		else if ( i == 2 )
			m |= 0xFF00FFFFL;
		else
			m |= 0x00FFFFFFL;

		*ip &= m;
	}

	return NP_RET_SUCCESS;
}

int	ipv6_str_to_ip(char *str, unsigned char *ip)
{
	int	i;
	char tmp[IP6_ADDR_LEN + 1];

	memset(ip, 0x0, 16);

	for (i = 0; i < IP6_ADDR_LEN; i++, str++)
	{
		if (((*str >= '0') && (*str <= '9')) ||
				((*str >= 'a') && (*str <= 'f')) ||
				((*str >= 'A') && (*str <= 'F')) || (*str == ':'))
			tmp[i] = *str;
		else
			break;
	}
	tmp[i] = '\0';

	if (!inet_pton(AF_INET6, tmp, ip))
		return NP_RET_ERROR;

	return NP_RET_SUCCESS;
}
