#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <string.h>
#include "misc.h"
#include "npreal2d.h"

//TODO: shared misc library is added into project. Some other shared code should remove into this library for reusibility.

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
