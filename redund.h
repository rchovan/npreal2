
#ifndef _REDUND_H
#define _REDUND_H



#define IPADDR2 1
#define BUF_SIZE 2048
#define REDUND_SIZE 1024 
#define CMD_REDUND_SIZE 84
#define HEADER_LEN 12
#define REDUNDANT_MARK 0xbeef
#define REDUNDANT_VERSION 0x01
#define REDUNDANT_HDRLEN 0x0c
#define REDUNDANT_PUSH 0x02
#define REDUNDANT_ACK 0x04
#define REDUNDANT_REPUSH 0x08
#define ACK_BIT 8 

struct redund_hdr
{
        uint16_t mark;
        uint8_t  version;
        uint8_t  hdr_len;
        uint8_t  flags;
        int8_t   session;
        uint16_t seq_no;
        uint16_t ack_no;
        uint16_t len;
};

struct redund_packet
{
        struct redund_hdr hdr;
        char   * data;
};

struct _redund_packet
{
        struct redund_hdr * hdr;
        char   * data;
};

struct expect_struct
{
        uint16_t ack;  /* Driver ack */
        uint16_t seq;  /* Driver seq */
        uint16_t last_seq;  /* Driver seq */
        uint16_t nport_ack; /* Nport ack */
    	uint16_t repush_seq[2]; /* repush_seq number */
};
struct redund_struct
{
	struct expect_struct data;
	struct expect_struct cmd;
	
	char redund_ip[40];
	u_char ip6_addr[16];
	int	sock_data[2];
	int	sock_cmd[2];

	int	data_open[2]; /* redund_open */
	int cmd_open[2];

	int connect[2]; /* redund_connect */
	int close[2]; /* redund_connect */

	//int	disdata[2];
	int reconnect[2]; /* redund_reconnect */

    uint16_t debug_seq;
	pthread_t thread_id[2];
	int thread[2];	

	int wlen;
	int rlen;
	int host_ack;
	int8_t session;
};
#if 0
int pack_redundant(int fd, char *buf, ssize_t len);
int pack_data_redundant(int fd, char *buf, ssize_t len, uint16_t seq);
int unpack_redundant(char *buf, ssize_t len);

int redund_add_hdr_1(int fd, char *sbuf, char **dbuf, ssize_t len, struct expect_struct *expect);

int redund_send(int fd, const char *sbuf, ssize_t len, struct expect_struct *expect);
int redund_send_data(int fd, const char *sbuf, ssize_t len, struct expect_struct *expect);
int redund_send_cmd(int fd, const char *sbuf, ssize_t len, struct expect_struct *expect);
int redund_add_hdr(int fd, const char *sbuf, char *dbuf, ssize_t len, struct expect_struct *expect);
int redund_add_hdr_data(int fd, const char *sbuf, char *dbuf, ssize_t len, struct expect_struct *expect);
int redund_send_check(int fd, char *buf, struct expect_struct *expect);

int redund_recv(int fd, char *sbuf, ssize_t len, struct expect_struct *expect);
int redund_recv_data(int fd, char *sbuf, ssize_t len, struct expect_struct *expect, int datakeep, int dataofs);
int redund_recv_cmd(int fd, char *sbuf, ssize_t len, struct expect_struct *expect);
int redund_de_hdr(int fd, const char *sbuf, char *dbuf, ssize_t len, struct expect_struct *expect);
int redund_recv_check(int fd, char *buf, struct expect_struct *expect);

int redund_data_init(int fd, struct expect_struct *expect);
int redund_cmd_init(int fd, struct expect_struct *expect);
int data_port_init2(int fd);
int cmd_port_init(int fd);

int cmd_port_check_alive(int fd);
int send_cmd_port_ls(int fd);
#endif
#define			RET_OK				1
#define         REDUND_INIT       	0
#define         REDUND_MPT_OPEN   	1
#define         REDUND_CONN_FAIL  	2
#define         REDUND_TCP_OPEN   	3
#define         REDUND_TCP_CONN          4
#define         REDUND_TCP_CLOSE         5
#define         REDUND_TCP_WAIT          6
#define         REDUND_MPT_REOPEN        7
#define         REDUND_TTY_WAIT          8
#define         REDUND_RW_DATA           9
#define         REDUND_REMOTE_LISTEN     10

#define         REDUND_CONNECT_OK      0
#define         REDUND_CONNECT_FAIL    1
#define         REDUND_CLOSE_OK        2

#define         REDUND_TCP_LISTEN      1
#define         REDUND_TCP_CONNECTED   4

#define         REDUND_ERROR_MPT_OPEN  0x0001
#define         REDUND_ERROR_TCP_OPEN  0x0002
#define         REDUND_ERROR_TCP_CONN  0x0004
#define         REDUND_ERROR_FORK      0x0008

extern void redund_handle_ttys();

#endif /* _REDUND_H */
