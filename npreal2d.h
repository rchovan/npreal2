
#ifndef _NPREAL2D_H
#define _NPREAL2D_H

#include    "redund.h"

#undef      FD_SETSIZE
#define     FD_SETSIZE      1024

#define NPREAL_ASPP_COMMAND_SET     1
#define NPREAL_LOCAL_COMMAND_SET    2

/* local command set */
#define LOCAL_CMD_TTY_USED      1
#define LOCAL_CMD_TTY_UNUSED        2
#define NPREAL_NET_CONNECTED        3
#define NPREAL_NET_DISCONNECTED     4
#define NPREAL_NET_SETTING      5

/*
 *  * Moxa tty definition
 *   */
#define ASPP_CMD_NOTIFY     0x26
#define ASPP_CMD_POLLING    0x27
#define ASPP_CMD_ALIVE      0x28

#define ASPP_CMD_IOCTL      16
#define ASPP_CMD_FLOWCTRL   17
#define ASPP_CMD_LSTATUS    19
#define ASPP_CMD_LINECTRL   18
#define ASPP_CMD_FLUSH      20
#define ASPP_CMD_OQUEUE     22
#define ASPP_CMD_SETBAUD    23
#define ASPP_CMD_START_BREAK    33
#define ASPP_CMD_STOP_BREAK 34
#define ASPP_CMD_START_NOTIFY   36
#define ASPP_CMD_STOP_NOTIFY    37
#define ASPP_CMD_HOST       43
#define ASPP_CMD_PORT_INIT  44
#define ASPP_CMD_WAIT_OQUEUE    47

#define ASPP_CMD_IQUEUE     21
#define ASPP_CMD_XONXOFF    24
#define ASPP_CMD_PORT_RESET 32
#define ASPP_CMD_RESENT_TIME    46
#define ASPP_CMD_TX_FIFO    48
#define ASPP_CMD_SETXON     51
#define ASPP_CMD_SETXOFF    52


#define CMD_RETRIEVE        1
#define CMD_RESPONSE        2
#define CMD_CONNECTED       3
#define CMD_DISCONNECTED    4
#define CMD_NET_SETTING     5
#define CMD_GET_TTY_STATUS  6
/* The following defines the server type */

#define DE311   311
#define DE301   301
#define DE302   302
#define DE304   304
#define DE331   331
#define DE332   332
#define DE334   334
#define DE303   303
#define DE308   308
#define DE309   309
#define CN2100  2100
#define CN2500  2500

#define     CMD_BUFFER_SIZE 84  /* temporary cmd buffer size    */

/*dsci command for ipv6*/
#define EX_VERSION          1
#define DSCI_IPV6           0x79
#define DSCI_IPV6_RESPONS   0xF9
/* CATALOG */
#define KERNEL_FUN      0x0001
#define NETWORK_CONFIG  0x0002
/* SUBCODE */
#define DSC_ENUMSEARCH       0x0001
#define DSC_GETNETSTAT_V6    0x0004

#define MAX_SOCK_V6     64

#define IPADDR2 1
#define BUF_LEN 1024
#define HEADER_LEN 12
#define REDUNDANT_MARK 0xbeef
#define REDUNDANT_VERSION 0x01
#define REDUNDANT_HDRLEN 0x0c
#define REDUNDANT_PUSH 0x02
#define REDUNDANT_ACK 0x04
#define ACK_BIT 8 

#define MAX_DNS_NAME_LEN	255

#define NP_RET_SUCCESS		(0)
#define NP_RET_ERROR		(-1)

#define IP6_ADDR_LEN		39

struct net_node_setting
{
    int32_t server_type;
    int32_t disable_fifo;
};

typedef struct _TTYINFO
{
    char        mpt_name[40];   /* Master pseudo TTY name   */
    char        ip_addr_s[40];  /* print format of IP address */
    struct  	redund_struct redund;
    char        redundant_ip_addr_s[40];    /* print format of IP address for redundant_mode */
    int         redundant_mode;
    u_char  ip6_addr[16];   /* Server IP address        */
    int     af;             /*IP type*/
    char    scope_id[10];
    int     reconn_flag;      /*1:reconnect 0:not reconnect*/
    int32_t     server_type;
    int32_t     disable_fifo;
    int     tcp_port;   /* Server TCP port for data */
    int     cmd_port;   /* Server TCP port  for cmd */
    int     local_tcp_port; /* Client TCP port for data */
    int     local_cmd_port; /* Client TCP port for cmd  */
    int     mpt_fd;     /* Master pseudo tty file handle*/
    int     sock_fd;    /* TCP Socket handle        */
    int     sock_cmd_fd;    /* TCP Socket handlefor cmd */
    int     state;      /* TCP connection state     */
    char *      mpt_bufptr; /* Master pseudo TTY data buffer*/
    int     mpt_datakeep;
    int     mpt_dataofs;
    char *      sock_bufptr;    /* TCP socket data buffer   */
    int     sock_datakeep;
    int     sock_dataofs;
    char        mpt_cmdbuf[CMD_BUFFER_SIZE];/* TTY cmd buffer*/
    int     mpt_cmdkeep;
    char        sock_cmdbuf[CMD_BUFFER_SIZE];/* TCP cmd buffer  */
    int     sock_cmdkeep;
    int     error_flags;
    time_t      time_out;   /* Using for TCP connection check */
    int     serv_index;
    char        tcp_wait_id;
    time_t      tty_used_timestamp;
    time_t      first_servertime;
	int			static_param;	/* Keep the content of this structure when it is set to 1 for dynamically changing server count. */
#ifdef  SSL_ON
    SSL *   pssl;
    int     ssl_enable;
    time_t      ssl_time;
#endif
    int     pipe_port[2];
	char	ttyname[160];
	char	ttyname2[160];
	char	curname[160];
	int	alive_check_cnt;
	int	stop_tx;
	int		lost_cnt;
}
TTYINFO;

typedef struct _ConnMsg
{
    TTYINFO *   infop;
    int     status;
    char        tcp_wait_id;
	int		connect[2];
	int8_t	session;
}
ConnMsg;

typedef struct _SERVERINFO
{
    u_char      ip6_addr[16];
    int         af;

    u_short     dev_type;
    u_short     serial_no;
    time_t      last_servertime;
    time_t      next_sendtime;

//Below is for DSCI protocol.

    uint32_t        ap_id;
    u_short         hw_id;
    unsigned char   mac[6];
    u_short         dsci_ver;
    u_short         start_item;
}
SERVINFO;

typedef struct _DSCI_HEADER
{
    unsigned char   opcode;
    unsigned char   result;
    u_short         length;
    uint32_t        id;
}
DSCI_HEADER;

typedef struct _DSCI_RET_HEADER
{
    uint32_t        ap_id;
    u_short         hw_id;
    unsigned char   mac[6];
}
DSCI_RET_HEADER;

typedef struct _DSCI_DA_DATA
{
    uint32_t        ap_id;
    u_short         hw_id;
    unsigned char   mac[6];
}
DSCI_DA_DATA;

typedef struct _DSCI_NET_STAT
{
    uint32_t        remote_ip;
    uint32_t        local_ip;
    u_short         remote_port;
    u_short         local_port;
    char            sock_type;
    unsigned char   status;
    unsigned char   reverse[2];
}
DSCI_NET_STAT;

typedef struct _DSCI_NET_STAT_IPV6
{
    u_char          remote_ip[16];
    u_char          local_ip[16];
    u_short         remote_port;
    u_short         local_port;
    char            sock_type;
    unsigned char   status;
    unsigned char   reverse[2];
}
DSCI_NET_STAT_IPV6;

typedef struct _EX_HEADER
{
    u_char      ex_vision;
    char        reservd[3];
    u_short     catalog;
    u_short     subcode;
}EX_HEADER;

union sock_addr
{
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

#define     STATE_INIT      0
#define     STATE_MPT_OPEN      1
#define     STATE_CONN_FAIL     2
#define     STATE_TCP_OPEN      3
#define     STATE_TCP_CONN      4
#ifdef SSL_ON
#define     STATE_SSL_CONN      5
#define     STATE_TCP_CLOSE     6
#define     STATE_TCP_WAIT      7
#define     STATE_MPT_REOPEN    8
#define     STATE_TTY_WAIT      9
#define     STATE_RW_DATA       10
#define     STATE_REMOTE_LISTEN 11
#else
#define     STATE_TCP_CLOSE     5
#define     STATE_TCP_WAIT      6
#define     STATE_MPT_REOPEN    7
#define     STATE_TTY_WAIT      8
#define     STATE_RW_DATA       9
#define     STATE_REMOTE_LISTEN 10
#endif

#define     CONNECT_OK  0
#define     CONNECT_FAIL    1
#define     CLOSE_OK    2

#define     TCP_LISTEN  1
#define     TCP_CONNECTED   4

#define     ERROR_MPT_OPEN  0x0001
#define     ERROR_TCP_OPEN  0x0002
#define     ERROR_TCP_CONN  0x0004
#define     ERROR_FORK  0x0008

#define     BUFFER_SIZE 1024    /* temporary data buffer size   */
#define     MAX_TTYS    256 /* max. handling TTYs number    */
#define     MAX_PORTS   16  /* max. port of server is 16    */

#define     IS_IPV4     0
#define     IS_IPV6     1

#ifdef OFFLINE_POLLING
#define POLLING_ALIVE_TIME	30
#endif

void log_event(char *msg);

#endif /* _NPREAL2D_H */
