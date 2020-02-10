#include "nport.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

#define     ER_ARG  -10

#define VERSION_CODE(ver,rel,seq)	((ver << 16) | (rel << 8) | seq)

#define TMP_STR_LEN 1024

unsigned long filelength(int f)
{
    unsigned long sz = lseek(f,0,SEEK_END);
    lseek(f,0,SEEK_SET);
    return sz;
}

char svrList[256][50];
int total[256];
int idx;


int check_usage(int arg, char *argv[])
{
    if (arg > 2)
    {
        printf("mxdelsvr [ip]\n\n");
        return ER_ARG;
    }
    return 0;
}

void GetIP(unsigned long ip, char *ret)
{
    struct in_addr ad;

    ad.s_addr = ip;
    sprintf(ret, "%s", inet_ntoa(ad));

}

//
// Check system init process
// return 0: systemd, 1: init
//
int isinitproc()
{
    int ret;
    char name[5];
    FILE *f;

    // check the init process is "init" or "systemd"
    system("ps --no-headers -o comm 1 > /usr/lib/npreal2/tmp/chk_init_proc 2>&1");

    f = fopen("/usr/lib/npreal2/tmp/chk_init_proc", "r");
    if (f == NULL) {
        printf("[1] file open error\n");
        return 1;
    }

    fgets(name, 5, f);
    fclose(f);

    ret = strncmp("init", name, 4);
    if (ret == 0) {
        system("rm -f /usr/lib/npreal2/tmp/chk_init_proc > /dev/null 2>&1");
        return 1;
    }

    system("rm -f /usr/lib/npreal2/tmp/chk_init_proc > /dev/null 2>&1");

    return 0;
}

int main(int arg, char *argv[])
{
    int i, j;
    int len, daemon, is_init_proc;
    struct in_addr ad;
    char *tmpstr, *tmp, *os, c[5];
    char token[50], tty[20], cout[20], major[20], del[50];
    FILE *f, *ft;

    if (check_usage(arg, argv) != 0)
    {
        return 0;
    }

    system("clear");
    printf("\nDelete Server ...\n");

    idx = 0;
    daemon = 0;
    tmpstr = (char *)malloc(TMP_STR_LEN);
    len = 1024;
    tmp = (char *)malloc(20);
    is_init_proc = isinitproc();

    if (arg == 2)
    {

        sprintf(del, "%s", argv[1]);
        sprintf(tmpstr, "%s/npreal2d.cf", DRIVERPATH);
        f = fopen (tmpstr, "r");
        if (f == NULL)
        {
            printf("file open error\n");
            free(tmpstr);
            free(tmp);
            return(0);
        }

        /* search the del server */
        for (;;)
        {
            if (getline (&tmpstr, (size_t*)&len, f) < 0)
            {
                break;
            }
            if (strstr(tmpstr, "#") != NULL)
            {
                continue;
            }
            memset(major, '\0', 20);
            sscanf(tmpstr, "%s", major);
            if (strstr(major, "ttymajor") != NULL ||
                    strstr(major, "calloutmajor") != NULL )
            {
                continue;
            }

            // scan only 2 parameters...
            sscanf(tmpstr, "%s%s", token, token);

            if (strcmp(token, del) == 0)
            {
            	// If the ip token is same as argv[1] (=del[])...
                idx = 1;
                break;
            }
        }
        fclose (f);

        if (idx == 0)
        {
            printf("The speicified ip is not installed.\n\n");
            free(tmpstr);
            free(tmp);
            return 0;
        }

    }
    else
    {

        memset(svrList, 0x0, 256*50);
        memset(total, 0x0, 256*sizeof(int));
        sprintf(tmpstr, "%s/mxcfmat", DRIVERPATH);
        system(tmpstr);

        sprintf(tmpstr, "%s/npreal2d.cf", DRIVERPATH);
        f = fopen (tmpstr, "r");
        if (f == NULL)
        {
            printf("file open error\n");
            free(tmpstr);
            free(tmp);
            return(0);
        }

        /* print the list of installed server */
        for (;;)
        {
            if (getline (&tmpstr, (size_t*)&len, f) < 0)
            {
                break;
            }
            if (strstr(tmpstr, "#") != NULL)
            {
                continue;
            }
            memset(major, '\0', 20);
            sscanf(tmpstr, "%s", major);
            if (strstr(major, "ttymajor") != NULL ||
                    strstr(major, "calloutmajor") != NULL )
            {
                continue;
            }

            sscanf(tmpstr, "%s%s", token, token);
            for (i=0; i<idx; i++)
            {
                if (!strcmp(svrList[i],token))
                {
                    total[i]++;
                    break;
                }
            }
            if (i == idx)
            {
                strcpy(svrList[idx], token);
                total[idx]++;
                idx++;
            }
        }

        fclose (f);

        if (idx == 0)
        {
            printf("No NPort server is installed.\n\n");
            free(tmpstr);
            free(tmp);
            return 0;
        }

        printf("\n[Index]\t%-40s\t[Port(s)]\n", "[Server IP]");
        for (i=0; i<idx; i++)
        {
//    	    ad.s_addr = svrList[i];
            printf("  (%d)\t%-40s\t  %d\n", i+1, svrList[i], total[i]);
        }
printf("  (q)\tExit\n");
        printf("\nSelect: ");
        scanf("%s", c);

        if (atoi(c)<=0 || atoi(c)>idx)
        {
            printf("Please run mxdelsvr again!!\n\n");
            free(tmpstr);
            free(tmp);
            return 0;
        }

        memset(tmp, '\0', 20);
//       GetIP(svrList[atoi(c)-1], tmp);
        strcpy(del, svrList[atoi(c)-1]);
    }

    sprintf(tmpstr, "%s/npreal2d.cf", DRIVERPATH);
    f = fopen (tmpstr, "r");
    if (f == NULL)
    {
        printf("file open error\n");
        free(tmpstr);
        free(tmp);
        return(0);
    }
    ft = fopen ("/usr/lib/npreal2/tmp/nprtmp_cf", "w");
    if (ft == NULL)
    {
        printf("file open error\n");
        free(tmpstr);
        free(tmp);
        return(0);
    }

    /* delete specified device file configured in npreal2d.cf */
    memset(tmpstr, '\0', 1024);
    sprintf(tmpstr, "awk '$0 !~ /#/' %s/npreal2d.cf |", DRIVERPATH);
    sprintf(tmpstr, "%s awk '$7 != \"\" ' |", tmpstr);
    sprintf(tmpstr, "%s awk '$8 != \"\" ' |", tmpstr);
    sprintf(tmpstr, "%s awk '$2 == \"%s\" ' |", tmpstr, del);
    sprintf(tmpstr, "%s awk '{system(\"%s/mxrmnod \"$7); system(\"%s/mxrmnod \"$8)}'", tmpstr, DRIVERPATH, DRIVERPATH);
    system(tmpstr);

    /* Delete the server selected by user,  */
    /* and remove the relevant device files */
    for (;;)
    {
        if (getline (&tmpstr, (size_t*)&len, f) < 0)
        {
            break;
        }
        if (strstr(tmpstr, "#") != NULL)
        {
            fputs (tmpstr, ft);
            continue;
        }
        memset(major, '\0', 20);
        sscanf(tmpstr, "%s", major);
        if (strstr(major, "ttymajor") != NULL ||
                strstr(major, "calloutmajor") != NULL )
        {
            fputs (tmpstr, ft);
            continue;
        }

        sscanf(tmpstr, "%s%s", token, token);
        if (strcmp(token, del) != 0)
        {
            fputs (tmpstr, ft);

            /* daemon is a flag which is used to delete the */
            /* daemon start string in /etc/rc.d/rc.local */
            daemon = 1;

        }
    }

    fclose(ft);
    fclose (f);

    os = "linux";
    f = fopen ("/etc/redhat-release", "r");
    if (f != NULL)
    {
        fclose(f);
#if (LINUX_VERSION_CODE == VERSION_CODE(3,10,0))
        os = "linux_rh";
#else
		os = "linux";
#endif
    }
    else
    {
        f = fopen ("/etc/SuSE-release", "r");
        if (f != NULL)
        {
            fclose(f);
            os = "SuSE";
        }
        else
        {
            f = fopen ("/etc/debian_version", "r");
            if (f != NULL)
            {
            	fclose(f);
                os = "debian";
            } /* else {
                            printf("Your Operating System is NOT supported.\n\n");
                            free(tmpstr);
                            free(tmp);
                            return -1;
                        } */
        }
    }


    if (!daemon)
    {
        if (os == "linux")
        {   
            if (is_init_proc) {
                system("grep -v mxloadsvr /etc/rc.d/rc.local > /usr/lib/npreal2/tmp/nprtmp_rclocal");
                system("cp -f /usr/lib/npreal2/tmp/nprtmp_rclocal /etc/rc.d/rc.local > /dev/null 2>&1");
             } else {
                system("grep -v mxloadsvr /usr/lib/npreal2/driver/load_npreal2.sh > /usr/lib/npreal2/tmp/nprtmp_rclocal");
                system("cp -f /usr/lib/npreal2/tmp/nprtmp_rclocal /usr/lib/npreal2/driver/load_npreal2.sh > /dev/null 2>&1");
             }

             system("rm -f /usr/lib/npreal2/tmp/nprtmp_rclocal");
             
        }
        else if (os == "linux_rh")
        {
            system("grep -v mxloadsvr /etc/init.d/npreals > /usr/lib/npreal2/tmp/nprtmp_rclocal");
            system("cp -f /usr/lib/npreal2/tmp/nprtmp_rclocal /etc/init.d/npreals > /dev/null 2>&1");
            system("rm -f /usr/lib/npreal2/tmp/nprtmp_rclocal");
        	system("chkconfig --del /etc/init.d/npreals > /dev/null 2>&1");

        }
        else if (os == "debian")
        {
            system("grep -v mxloadsvr /etc/init.d/npreals > /usr/lib/npreal2/tmp/nprtmp_rclocal");
            system("cp -f /usr/lib/npreal2/tmp/nprtmp_rclocal /etc/init.d/npreals > /dev/null 2>&1");
            system("rm -f /usr/lib/npreal2/tmp/nprtmp_rclocal");
            system("update-rc.d npreals defaults 90");

        }
        else if (os == "SuSE")
        {
            system("grep -v mxloadsvr /etc/rc.d/boot.local > /usr/lib/npreal2/tmp/nprtmp_rclocal");
            system("cp -f /usr/lib/npreal2/tmp/nprtmp_rclocal /etc/rc.d/boot.local > /dev/null 2>&1");
            system("rm -f /usr/lib/npreal2/tmp/nprtmp_rclocal");

        }
    }

    sprintf(tmpstr, "cp -f /usr/lib/npreal2/tmp/nprtmp_cf %s/npreal2d.cf", DRIVERPATH);
    system(tmpstr);
    system("rm -f /usr/lib/npreal2/tmp/nprtmp_cf");

    printf("Deleting server: %s\n\n", del);
	{
		int daemon_flag=0;

		// If npreal2d is exist then trigger the -USR1 instead of running mxloadsvr
		do{
			/* check if daemon is running or not */
			memset(tmpstr, '\0', TMP_STR_LEN);
			sprintf(tmpstr, "ps -ef | grep npreal2d | grep -v grep");
			sprintf(tmpstr, "%s > /usr/lib/npreal2/tmp/nprtmp_checkdaemon", tmpstr);
			system(tmpstr);

			f = fopen ("/usr/lib/npreal2/tmp/nprtmp_checkdaemon", "r");
			if (f == NULL)
			{
				printf("Failed to open nprtmp_checkdaemon.\n");
				system("rm -f /usr/lib/npreal2/tmp/nprtmp_checkdaemon ");
				break;
			}
			if (filelength(fileno(f)) != 0)
			{
				daemon_flag = 1; /* Means any npreal2d is running now. */
			}
			else
			{
				daemon_flag = 0;
			}
			fclose(f);

			system("rm -f /usr/lib/npreal2/tmp/nprtmp_checkdaemon ");
		} while (FALSE);

		if( daemon_flag ){
		    memset(tmpstr, '\0', TMP_STR_LEN);
		    sprintf(tmpstr, "ps -ef | grep npreal2d | grep -v npreal2d_redund | awk '$0 !~ /grep/ {system(\"kill -USR1 \"$2)}'");
		    system(tmpstr);
		} else {
			sprintf(tmpstr, "%s/mxloadsvr", DRIVERPATH);
			system(tmpstr);
		}

		// If npreal2d.cf is empty, then kill all npreal2d processes
		do {

		    /* check if npreal2d.cf is empty or not */
			system("rm -f /usr/lib/npreal2/tmp/nprtmp_checkcf");

		    sprintf(tmpstr, "%s/mxcfmat", DRIVERPATH);
		    system(tmpstr);

		    memset(tmpstr, '\0', TMP_STR_LEN);
		    sprintf(tmpstr, "grep -v \"#\" %s/npreal2d.cf |", DRIVERPATH);
		    sprintf(tmpstr, "%s grep -v \"ttymajor\" |", tmpstr);
		    sprintf(tmpstr, "%s grep -v \"calloutmajor\" > /usr/lib/npreal2/tmp/nprtmp_checkcf", tmpstr);
		    system(tmpstr);

		    memset(tmpstr, '\0', TMP_STR_LEN);
		    sprintf(tmpstr, "/usr/lib/npreal2/tmp/nprtmp_checkcf");

		    f = fopen (tmpstr, "r");
		    if (f == NULL)
		    {
		    	printf("Failed to open nprtmp_checkcf.\n");
		    	system("rm -f /usr/lib/npreal2/tmp/nprtmp_checkcf");
		        break;
		    }
		    if (filelength(fileno(f)) == 0)
		    {
		        /* Means configurations are not exist */
			    memset(tmpstr, '\0', TMP_STR_LEN);
			    sprintf(tmpstr, "ps -ef | grep npreal2d | awk '$0 !~ /grep/ {system(\"kill -9 \"$2)}'");
			    system(tmpstr);

		    }
		    fclose(f);

		} while (FALSE);
	}

    if (os == "linux")
    {
        if (is_init_proc) {
            system("chmod +x /etc/rc.d/rc.local");
        } else {
            system("chmod +x /usr/lib/npreal2/driver/load_npreal2.sh");
        }
    }
    else if (os == "linux_rh")
    {
        system("chmod +x /etc/init.d/npreals");
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
    free(tmp);
    return 0;
}


