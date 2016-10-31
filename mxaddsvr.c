#include "nport.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <termios.h>
#include <linux/version.h>
#include <stdio.h>

#define     ER_ARG      -10
#define		REALCOM_MODE 0
#define		REDUNDANT_MODE 1
#define		REDUNDANT 1

int minor[256];
char *tmptty, *tmpcout;
int idx;
int dataport, cmdport;
char scope_id_s[20] = "0";
char Gredundant_ip[40];

int getch()
{
	int ch;
	struct termios oldt, newt;
	
	tcgetattr(STDIN_FILENO, &oldt);
	memcpy(&newt, &oldt, sizeof(newt));
	newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL | ECHOPRT
			 | ECHOKE | ICRNL);

	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

	return ch;	
}

char* concate(char *str, char *c, char *ret)
{
    memset(ret, '\0', 20);
    sprintf(ret, "%s%s", str, c);
    return;
}


int getMinor()
{
    int i, j;
    for (i=0; i<256; i++)
    {
        for (j=0; j<idx; j++)
        {
            if (i == minor[j])
            {
                break;
            }
        }
        if (j == idx)
        {
            minor[idx++] = i;
            return i;
        }
    }
    if (i >= 256)
    {
        return -1;
    }
}


void c_hex(int c, char *ret)
{

    if (c >= 10)
    {
        switch (c)
        {
        case 10:
            sprintf(ret, "a");
            break;
        case 11:
            sprintf(ret, "b");
            break;
        case 12:
            sprintf(ret, "c");
            break;
        case 13:
            sprintf(ret, "d");
            break;
        case 14:
            sprintf(ret, "e");
            break;
        case 15:
            sprintf(ret, "f");
            break;
        }
        return;
    }
    else
    {
        sprintf(ret, "%d", c);
        return;
    }
}


void getTty(char *ret)
{
    int i, j;
    char *x1, *x2;
    x1 = (char*)malloc(sizeof(char *));
    x2 = (char*)malloc(sizeof(char *));

    for (i=0; i<16; i++)
    {
        for (j=0; j<16; j++)
        {
            c_hex(i, x1);
            c_hex(j, x2);
            sprintf(ret, "ttyr%s%s", x1, x2);
            if (strstr(tmptty, ret) == NULL)
            {
                sprintf(tmptty, "%s[%s]", tmptty, ret);
                free (x1);
                free (x2);
                return;
            }
        }
    }
    free (x1);
    free (x2);
    return;
}



void getCout(char *ret)
{
    int i, j;
    char *x1, *x2;
    x1 = (char*)malloc(sizeof(char *));
    x2 = (char*)malloc(sizeof(char *));

    for (i=0; i<16; i++)
    {
        for (j=0; j<16; j++)
        {
            c_hex(i, x1);
            c_hex(j, x2);
            sprintf(ret, "cur%s%s", x1, x2);
            if (strstr(tmpcout, ret) == NULL)
            {
                sprintf(tmpcout, "%s[%s]", tmpcout, ret);
                free (x1);
                free (x2);
                return;
            }
        }
    }
    free (x1);
    free (x2);
    return;
}


void showMinor()
{
    int s;
    for (s=0; s<idx; s++)
    {
        printf("minor[%d] = (%d)\n", s, minor[s]);
    }
}


int check_usage(int arg, char *argv[], int mode)
{
    int i;
    char buf[10];
    int scope_id;
    int ret;

	ret = 0;
	
	switch (mode) {
#if 0
	case REDUNDANT_MODE:
		printf("-----------------------Redundant Mode------------------------------\n");
    	if(arg > 2) {
        	if((strncmp(argv[1], "fe80", 4) == 0) || (strncmp(argv[1], "FE80", 4) == 0) || 
		   	(strncmp(argv[1], "Fe80", 4) == 0) || (strncmp(argv[1], "fE80", 4) == 0))
            	scope_id = 1;
        	else
            	scope_id = 0;
    	}
 
    	if (arg == 5 + scope_id) {
        	dataport = 950;
        	cmdport = 966;
			if(scope_id)
				strcpy(scope_id_s, argv[3]);
	#if REDUNDANT
	#if 1 
		} else if (arg = 4 + scope_id) {
			dataport = 950;
			cmdport = 966;
		    memset(Gredundant_ip, '\0', 40);
    	
			if (strlen(argv[3]) > 39) {
    			printf("The server name length over 39!\n\n");
   
				return ER_ARG;
    		}
			
	    	sprintf(Gredundant_ip, "%s", argv[3]);
			printf("IP2 = %s\n", Gredundant_ip);
    		if (strcmp(Gredundant_ip, "255.255.255.255") == 0) {
        		printf("Invalid IP Address!\n\n");
            
				return ER_ARG;
    		}		

			if(scope_id)
				strcpy(scope_id_s, argv[3]);
			ret =  REDUNDANT_MODE;
	#endif
	#endif
    	} else if (arg == 5 + scope_id) {
        	memset(buf, '\0', 10);
	        strcpy(buf, argv[3]);   // data port
    	    for (i = 0; i < strlen(buf); i++)
        	{
            	if (!isdigit(buf[i]))
	            {
    	            printf("\nArgument error: [data port] is not a digital number.\n\n");
        	        return ER_ARG;
            	}
	        }
    	    dataport = atoi(buf);

        	memset(buf, '\0', 10);
	        strcpy(buf, argv[4]);   // cmd port
    	    for (i = 0; i < strlen(buf); i++)
        	{
            	if (!isdigit(buf[i]))
	            {
    	            printf("\nArgument error: [command port] is not a digital number.\n\n");
        	        return ER_ARG;
            	}
	        }
    	    cmdport = atoi(buf);
			if(scope_id)
				strcpy(scope_id_s, argv[5]);
	    } else {
    	    printf("usage: ./mxaddsvr [ip] [totalport] ([redundant ip]) ([data port] [cmd port]) ([interface])\n");
        	printf("[ip]\n");
	        printf("\tNPort IP Address or Domain Name\n\n");
    	    printf("[totalport]\n");
        	printf("\tTotal number of ports to add. If [data port/cmd port] isn't specified,\n\tthe mapping would start from NPort 1st serial port.\n\n");
	        printf("[data port/cmd port]\n");
    	    printf("\tSpecify the mapping tcp port number. 1st=950/966, 2nd=951/967...\n\n");
        	printf("[interface]\n");
	        printf("\tSpecify the interface for IPv6 link-local address mapping.\n");
    	    printf("Example:\n");
        	printf("\tNPort=NPort 5210, 2 ports, 192.168.8.51:\n");
	        printf("\t#./mxaddsvr 192.168.8.51 2\n\n");

    	    printf("\tNPort 6650-32, 32 ports, Ethernet device is eth0\n");
        	printf("\tlink-local address:fe80::290:e8ff:fe50:1601\n");
	        printf("\tglobal address:2001:b021:12:0:290:e8ff:fe50:1601\n\n");

    	    printf("\t#./mxaddsvr fe80::290:e8ff:fe50:1601 32 eth0\n");
        	printf("\t#./mxaddsvr 2001:b021:12:0:290:e8ff:fe50:1601 32\n");

	        return ER_ARG;
    	}

		break;
#endif
	case REALCOM_MODE:
    	if(arg > 2) {
        	if((strncmp(argv[1], "fe80", 4) == 0) || (strncmp(argv[1], "FE80", 4) == 0) || 
		   	(strncmp(argv[1], "Fe80", 4) == 0) || (strncmp(argv[1], "fE80", 4) == 0))
            	scope_id = 1;
        	else
            	scope_id = 0;
    	}
 
    	if (arg == 3 + scope_id) {
        	dataport = 950;
        	cmdport = 966;
			if(scope_id)
				strcpy(scope_id_s, argv[3]);
	#if REDUNDANT
	#if 0
		} else if (arg = 4 + scope_id) {
			dataport = 950;
			cmdport = 966;
		    memset(Gredundant_ip, '\0', 40);
    	
			if (strlen(argv[3]) > 39) {
    			printf("The server name length over 39!\n\n");
   
				return ER_ARG;
    		}

	    	sprintf(Gredundant_ip, "%s", argv[3]);

    		if (strcmp(Gredundant_ip, "255.255.255.255") == 0) {
        		printf("Invalid IP Address!\n\n");
            
				return ER_ARG;
    		}		

			if(scope_id)
				strcpy(scope_id_s, argv[3]);
			ret =  REDUNDANT_MODE;
	#endif
	#endif
    	} else if (arg == 5 + scope_id) {
        	memset(buf, '\0', 10);
	        strcpy(buf, argv[3]);   // data port
    	    for (i = 0; i < strlen(buf); i++)
        	{
            	if (!isdigit(buf[i]))
	            {
    	            printf("\nArgument error: [data port] is not a digital number.\n\n");
        	        return ER_ARG;
            	}
	        }
    	    dataport = atoi(buf);

        	memset(buf, '\0', 10);
	        strcpy(buf, argv[4]);   // cmd port
    	    for (i = 0; i < strlen(buf); i++)
        	{
            	if (!isdigit(buf[i]))
	            {
    	            printf("\nArgument error: [command port] is not a digital number.\n\n");
        	        return ER_ARG;
            	}
	        }
    	    cmdport = atoi(buf);
			if(scope_id)
				strcpy(scope_id_s, argv[5]);
	    } else {
		printf("Real COM Mode\n");
    	    	printf("usage: ./mxaddsvr [ip] [totalport] ([data port] [cmd port]) ([interface])\n");
        	printf("[ip]\n");
	        printf("\tNPort IP Address or Domain Name\n\n");
    	    	printf("[totalport]\n");
        	printf("\tTotal number of ports to add. If [data port/cmd port] isn't specified,\n\tthe mapping would start from NPort 1st serial port.\n\n");
	        printf("[data port/cmd port]\n");
    	    	printf("\tSpecify the mapping tcp port number. 1st=950/966, 2nd=951/967...\n\n");
        	printf("[interface]\n");
	        printf("\tSpecify the interface for IPv6 link-local address mapping.\n");
    	    	printf("Example:\n");
        	printf("\tNPort=NPort 5210, 2 ports, 192.168.8.51:\n");
	        printf("\t#./mxaddsvr 192.168.8.51 2\n\n");

    	    	printf("\tNPort 6650-32, 32 ports, Ethernet device is eth0\n");
        	printf("\tlink-local address:fe80::290:e8ff:fe50:1601\n");
	        printf("\tglobal address:2001:b021:12:0:290:e8ff:fe50:1601\n\n");

    	    	printf("\t#./mxaddsvr fe80::290:e8ff:fe50:1601 32 eth0\n");
        	printf("\t#./mxaddsvr 2001:b021:12:0:290:e8ff:fe50:1601 32\n");
		printf("\nType ANY key to continue...");
		getch();	
    		system("clear");
	        printf("Redundant COM Mode\n");
	        printf("usage: ./mxaddsvr -r [ip1] [ip2] [totalport] ([data port] [cmd port])\n");
        	printf("[ip1]\n");
	        printf("\tNPort IP1 Address\n\n");
        	printf("[ip2]\n");
	        printf("\tNPort IP2 Address\n\n");
    	    	printf("[totalport]\n");
        	printf("\tTotal number of ports to add. If [data port/cmd port] isn't specified,\n\tthe mapping would start from NPort 1st serial port.\n\n");
	        printf("[data port/cmd port]\n");
    	    	printf("\tSpecify the mapping tcp port number. 1st=950/966, 2nd=951/967...\n\n");
    	    	printf("Example:\n");
        	printf("\tNPort=NPort 2610-16-2AC, 16 ports, 192.168.32.11, 192.168,126,123\n");
	        printf("\t#./mxaddsvr -r 192.168.32.11 192.168.126.123 16\n\n");

	        return ER_ARG;
    	}

		break;
	}

    return ret;
}

int main(int arg, char *argv[])
{
    int i, j;
    int total, len, overwrite, fifo, mn, ssl;
    int ttymajor, calloutmajor;
    char c;
    char *tmpstr, *tmp1, *tmp2;
    char tmpm[10], tmpt[40], tmpc[40], major[40], tmp_mode[40], tmp_redund_ip[40];
    char ip[40];
    char ip_buf[40];
    char buf[10];
    struct in_addr addr;
    unsigned long ipaddr;
    FILE *f, *ft, *frc, *fos;
    char *os = "linux";
    int mode, tmp_i = 0, ret;

    mode = REALCOM_MODE;
    overwrite = -1;
    system("clear");

    if (arg > 1) {
        if (strcmp(argv[1], "-r") == 0) {
	    mode = REDUNDANT_MODE;	
        } 

        if (mode == REDUNDANT_MODE && arg < 5) {
	    printf("Redundant COM Mode\n");
	    printf("usage: ./mxaddsvr -r [ip1] [ip2] [totalport]\n");

	return 0;
        }
    }
    ret = check_usage(arg, argv, mode);
    if (ret < 0)
 	return 0;

    printf("\nAdding Server...\n\n");

    memset(ip, '\0', 40);
    if(strlen(argv[1]) > 39){
    	printf("The server name length over 39!\n\n");
        return -1;
    }

	switch (mode) {
	case REALCOM_MODE:
	    sprintf(ip, "%s", argv[1]);
    	/*
        ipaddr = inet_addr(argv[1]);
        addr.s_addr = ipaddr;
        sprintf(tip, "%s", inet_ntoa(addr));
        if ((strcmp(ip, "255.255.255.255") == 0) || (ipaddr < 0)) {
            printf("Invalid IP Address !\n\n");
            return -1;
        }else if(strcmp(tip, ip) != 0){
            printf("Invalid IP Address !\n\n");
            return -1;
        }
    	*/
    	if (strcmp(ip, "255.255.255.255") == 0)
    	{
        	printf("Invalid IP Address!\n\n");
	        return -1;
    	}
		/*	
	    strcpy(ip_buf, ip);
    	if(!inet_pton(AF_INET, ip_buf, &addr))
	    {
    	    strcpy(ip_buf, ip);
        	if(!inet_pton(AF_INET6, ip, &addr))
	        {
    	        printf("Invalid IP Address !\n\n");
        	    return -1;
        	}
    	}
	*/	
		break;
	case REDUNDANT_MODE:
	    sprintf(ip, "%s", argv[2]);

    	if (strcmp(ip, "255.255.255.255") == 0) {
        	printf("Invalid IP Address!\n\n");
	        return -1;
    	}

	    sprintf(Gredundant_ip, "%s", argv[3]);

    	if (strcmp(Gredundant_ip, "255.255.255.255") == 0) {
        	printf("Invalid IP Address!\n\n");
	        return -1;
    	}
		break;
	}
    tmpstr = (char *)malloc(256);
    len = 256;
    tmp1 = (char *)malloc(40);
    tmp2 = (char *)malloc(40);
    tmptty = (char *)malloc(2560);
    tmpcout = (char *)malloc(2560);

    memset(minor, -1, sizeof(int)*256);
    idx = 0;

    /* get OS */
    fos = fopen ("/etc/redhat-release", "r");
    if (fos != NULL)
    {
        fclose(fos);
        os = "linux";
    }
    else
    {
        fos = fopen ("/etc/SuSE-release", "r");
        if (fos != NULL)
        {
            fclose(fos);
            os = "SuSE";
        }
        else
        {
            fos = fopen ("/etc/debian_version", "r");
            if (fos != NULL)
            {
                fclose(fos);
                os = "debian";
            }
            else
            {
                fos = fopen ("/etc/gentoo-release", "r");
                if (fos != NULL)
                {
                    fclose(fos);
                    os = "gentoo";
                }
            }
        }
    }

    sprintf(tmpstr, "%s/npreal2d.cf", DRIVERPATH);
    f = fopen (tmpstr, "r");
    if (f == NULL)
    {
        printf("file open error_3\n");
        free(tmpstr);
        free(tmp1);
        free(tmp2);
        free(tmptty);
        free(tmpcout);
        return(0);
    }
    ft = fopen ("/tmp/npr_tmpfile2", "w");
    if (ft == NULL)
    {
        printf("file open error_4\n");
        free(tmpstr);
        free(tmp1);
        free(tmp2);
        free(tmptty);
        free(tmpcout);
        return(0);
    }

    for (;;)
    {
		//printf("tmp_i = %d\n", tmp_i);
        /* end of file */
        if (getline (&tmpstr, (size_t*)&len, f) < 0)
        {
			//printf("getline = %d\n", tmp_i);
            break;
        }
		tmp_i++;
        /* comment */
        if (strstr(tmpstr, "#") != NULL)
        {
            fputs (tmpstr, ft);
            continue;
        }

        memset(major, '\0', 20);
        sscanf(tmpstr, "%s", major);

        if (strstr(major, "ttymajor") != NULL)
        {
            ttymajor = atoi(strstr(major, "=")+1);
            fputs (tmpstr, ft);
            continue;
        }

        if (strstr(major, "calloutmajor") != NULL )
        {
            calloutmajor = atoi(strstr(major, "=")+1);
            fputs (tmpstr, ft);
            continue;
        }
        concate(ip, "\t", tmp1);
        concate(ip, " ", tmp2);
        if (strstr(tmpstr, tmp1) != NULL ||
                strstr(tmpstr, tmp2) != NULL)
        {
            if (overwrite == -1)
            {
                printf("The specified server has been configured before, \nare you sure to overwrite the settings [y/N]? ");
                scanf("%c", &c);
                if (c != 'Y' && c != 'y')
                {
                    overwrite = -2;
                }
                else
                {
                    overwrite = 1;
                }
            }
        }
        else
        {
            fputs (tmpstr, ft);
        }

        /* gather info (minor, ttyname, callout) */
#if REDUNDANT
		switch (mode) {
		case REDUNDANT_MODE:
        	sscanf(tmpstr, "%s%s%s%s%s%s%s%s%s%s", tmpm, tmpt, tmpt, tmpt, tmpt, tmpt, tmpt, tmpc, tmp_mode, tmp_redund_ip);

			break;
		case REALCOM_MODE:
        	sscanf(tmpstr, "%s%s%s%s%s%s%s%s", tmpm, tmpt, tmpt, tmpt, tmpt, tmpt, tmpt, tmpc);

			break;
		}
#else
        sscanf(tmpstr, "%s%s%s%s%s%s%s%s", tmpm, tmpt, tmpt, tmpt, tmpt, tmpt, tmpt, tmpc);
#endif
        sprintf(tmptty, "%s[%s]", tmptty, tmpt);
        sprintf(tmpcout, "%s[%s]", tmpcout, tmpc);
        minor[idx] = atoi(tmpm);
        idx++;
    }
    fclose(ft);
    fclose(f);

	switch (mode) {
	case REALCOM_MODE:
    	total = atoi(argv[2]);

		break;
	case REDUNDANT_MODE:
    	total = atoi(argv[4]);
		if (arg == 5) {
			dataport = 950;
			cmdport = 966;
		} else {
		   	memset(buf, '\0', 10);
	        strcpy(buf, argv[5]);   // data port
    	    for (i = 0; i < strlen(buf); i++)
        	{
            	if (!isdigit(buf[i]))
	            {
    	            printf("\nArgument error: [data port] is not a digital number.\n\n");
        	        return ER_ARG;
            	}
	        }
    	    dataport = atoi(buf);

        	memset(buf, '\0', 10);
	        strcpy(buf, argv[6]);   // cmd port
    	    for (i = 0; i < strlen(buf); i++)
        	{
            	if (!isdigit(buf[i]))
	            {
    	            printf("\nArgument error: [command port] is not a digital number.\n\n");
        	        return ER_ARG;
            	}
	        }
    	    cmdport = atoi(buf);
		}
		break;
	}

    if(total > 32){
    	total = 32;
    }
    if ((idx + total) > 256)
    {
        printf("The number of installed port exceeds the maxinum(256). \nPlease Check the configuration file.\n\nmxaddsvr Abort!!\n\n");
        free(tmpstr);
        free(tmp1);
        free(tmp2);
        free(tmptty);
        free(tmpcout);
        return 0;
    }

    if (overwrite == -2)
    {
        printf("\n");
        free(tmpstr);
        free(tmp1);
        free(tmp2);
        free(tmptty);
        free(tmpcout);
        return 0;
    }

    sprintf(tmpstr, "cp -f /tmp/npr_tmpfile2 %s/npreal2d.cf", DRIVERPATH);
    system(tmpstr);
    system("rm -f /tmp/npr_tmpfile2");

    sprintf(tmpstr, "%s/npreal2d.cf", DRIVERPATH);
    f = fopen (tmpstr, "a+");
    if (f == NULL)
    {
        printf("Opening configuration file error...\n");
        free(tmpstr);
        free(tmp1);
        free(tmp2);
        free(tmptty);
        free(tmpcout);
        return(0);
    }

    fifo = 1;
    ssl = 0;
    memset(tmpstr, 0, sizeof(tmpstr));

	for (i = 0; i < total; i++)
    {
        mn = getMinor();
        getTty(tmp1);
        getCout(tmp2);
        sprintf(tmpt, "%s", tmp1);
        sprintf(tmpc, "%s", tmp2);
        printf("%s, %s\n", tmpt, tmpc);
        if(i > 15){
        	dataport = 966;
        	cmdport = 982;
        }
#if REDUNDANT
		if (mode == REALCOM_MODE)
        	sprintf (tmpstr, "%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%d\t\n", mn, ip, dataport+i, cmdport+i, fifo, ssl, tmpt, tmpc, scope_id_s, mode);
		else if (mode == REDUNDANT_MODE)
        	sprintf (tmpstr, "%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%d\t%s\n", mn, ip, dataport+i, cmdport+i, fifo, ssl, tmpt, tmpc, scope_id_s, mode, 
																			 Gredundant_ip);
#else
        	sprintf (tmpstr, "%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n", mn, ip, dataport+i, cmdport+i, fifo, ssl, tmpt, tmpc, scope_id_s);
#endif
        fputs (tmpstr, f);
        sprintf(tmpstr, "%s/mxrmnod /dev/%s", DRIVERPATH, tmpt);
        system(tmpstr);
        sprintf(tmpstr, "%s/mxrmnod /dev/%s", DRIVERPATH, tmpc);
        system(tmpstr);

    }
    fclose(f);
	if (mode == REALCOM_MODE)
    	printf("Added RealCom server: ip : %s\n\n", ip);
	else if (mode == REDUNDANT_MODE)
    	printf("Added Redundant server: ip1 : %s, ip2 : %s\n\n", ip, Gredundant_ip);
    sprintf(tmpstr, "%s/mxloadsvr", DRIVERPATH);
    system(tmpstr);

    if (os == "linux")
    {
        system("chmod +x /etc/rc.d/rc.local");
    }
    else if (os == "debian")
    {
        system("chmod +x /etc/init.d/npreals");
    }
    else if (os == "SuSE")
    {
        system("chmod +x /etc/rc.d/boot.local");
    }

    free(tmpstr);
    free(tmp1);
    free(tmp2);
    free(tmptty);
    free(tmpcout);
    return 0;
}


