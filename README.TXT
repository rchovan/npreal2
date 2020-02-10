========================================================================
                         MOXA Linux Real TTY Driver

                              README file

  Date: 10-18-2019
  Copyright (C) 2004, MOXA Inc. All rights reserved.
========================================================================
Content

1. Introduction
2. OS Supports
3. System Requirement
4. Procedure
5. Hardware Installation
6. Installing the Driver File
7. Mapping TTY Ports
8. Settings for Secure Real COM Mode
9. Remove Mapped TTY Ports
10. TTY Naming Rule
11. Removing the Driver
12. Modification of "npreal2d.cf"
13. Modification of Initializing Script
14. Enable background polling feature
15. Troubleshooting
16. Limitation
17. Technical Support
------------------------------------------------------------------------
1. Introduction
    The purpose of this driver is to map NPort serial port to host tty
    port. Using this driver, you can use NPort serial port as local
    tty port.

    Real TTY only support installation by building kernel module. Users 
    should be familiar with Linux kernel. For the distribuion user, the
    kernel source, headers, or images are required and they are normally
    offered by distribution website. User may refer the distribution
    manual to prepare for building kernel module.
 
2. OS Supports
    This driver can run under following systems.
    a. Primary Linux distribution (kernel 5.0 or later)
       (Support IPV4 and IPV6)
    
    Following distributions are tested when releasing.
	a. Arch(5.2.11)
	b. VM-Ubuntu 19.04 x64 (5.0.0)
	c. Ubuntu 19.04 x64 (5.0.0)
	d. Ubuntu 19.10 x64 (5.3.0)
	e. Fedora 30 x64 (5.0.9)

3. System Requirement
    To install this driver, you will need NPort Server and one of the
    following system.

     -  kernel 3.0 or above and the kernel source package
     -  gcc-2.7.2.1 or above
     -  ld.so-1.7.14 or above
     -  libc.so-5 or above
     -  binutils-2.7.0 or above
     -  make-3.74 or above
     -  gunzip-1.2.4 or above
     -  gawk-3.1.1.9 or above
     -  openssl-1.0.0 or above (For Secure Real COM Mode only)
     -  libssl-dev-1.0.0 or above (For Secure Real COM Mode only)
     
    Additional requirements for Raspbian
     -  gcc-4.8.3 or above 
     -  ncurses-devel-5.9 or above
     -  rpi-source, read the instruction from it's website.
        (https://github.com/notro/rpi-source/wiki)

    Note:
     - rpi-source is a 3rd party package offering integrated kernel resouce
       for building driver. Real TTY are tested with this package and working
       well. However the requirements may be various for different Raspbian
       version. Please read the manual of Raspbian and rpi-source to
       understand the knowhow and limitation.
     - Real TTY driver with Raspbian Jessie(4.4.50) and Buster(4.19) are
       tested on Pi 2/3.

4. Procedure
    To map NPort serial port to host tty port, you need to:
    1. Setup NPort.
      Make sure the IP configuration is correct and you can access
      the NPort (ping, telnet...) successfully and then configure 
      the NPort serial port to Real COM Mode. 

    2. Install driver files into the host.
      Refer to "6. Installing the Driver File" below for details.

    3. Map NPort serial port to host's tty port.
      Refer to "7. Mapping TTY Ports" below for details.

5. Hardware Installation
    Before proceeding with the software installation, make sure you 
    have completed the hardware installation, as described in an 
    earlier chapter of this manual. 
    
    The default IP address for NPort Server is 192.168.127.254.

    For NPort Wireless series, the default IP address of the Ethernet
    interface is 192.168.126.254, and the default IP address of the
    Wireless LAN interface is 192.168.127.254.

    !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!
      After installing the hardware, you MUST configure the 
      NPort operating mode to Real COM Mode. If you want to  
      communication with security, please enable secure mode
      in both NPort and Real TTY configuration.
    !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!

6. Installing the Driver File
    a. Copy the driver file from website, under the product page.
    b. Log in to the console as a super user (root).
    c. Execute "cd " to change to the home directory.
    d. Copy the driver file npreal2xx.tgz to the home directory.
    e. Execute "tar xvfz npreal2xx.tgz" to copy all files into the system.
    f. Execute "./moxa/mxinst" for Linux kernel 3.x or 4.x.
	
    !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE 1!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	  For Red Hat AS/ES/WS and Fedora Core1, extra argument is 
	  needed: # /tmp/moxa/mxinst SP1 
    !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE 1!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    
    !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE 2!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	  If you use driver in 64-bits environment, you may use extra 
	  argument m64, SP1_m64 or mppc64.(the SP1_m64 is for Red Hat 
	  AS/ES/WS and Fedora Core1 64-bits environment; The mppc64
          is for PowerPC64 only.) Ex.
	  # /tmp/moxa/mxinst m64
    !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE 2!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    g. The shell script will install the driver files automatically.

    After installing the driver, you will be able to see several 
    files in the "/usr/lib/npreal2/driver" folder, including:

     - mxaddsvr (Add Server, map tty port)
     - mxsetsec (Set secure communication mode)
     - mxdelsvr (Delete Server, un-map tty port)
     - mxloadsvr (Reload Server)
     - mxuninst (Remove tty port and driver files)

    At this point, you will be ready to map the NPort serial port to 
    the system tty port. See "7. Mapping TTY Ports" below for detailed 
    instructions.

7. Mapping TTY Ports
    7.1 Real COM Mode
	  Before mapping tty ports, you must set the operation mode of your 
      NPort to Real COM Mode. We provide two ways to map tty ports.
   
    a. Mapping tty ports automatically
      After logging in as a super user, enter the directory 
      "/usr/lib/npreal2/driver" and then execute "mxaddsvr" to map the 
      target NPort serial port to the host tty ports. 
      The syntax of "mxaddsvr" is:

       mxaddsvr [NPort IP Address] [Total Ports] ([Data port] [Cmd port])

      Example 1:
       # cd /usr/lib/npreal2/driver
       # ./mxaddsvr 192.168.3.4 16

      Example 2:
       # cd /usr/lib/npreal2/driver
       # ./mxaddsvr 192.168.3.4 16 4001 966

      In Example 1, 16 tty ports will be added, all with IP 192.168.3.4, 
      but with data ports equal to (950, 951, ..., 965), and command ports 
      equal to (966, 967, 968, ..., 981). 
      
      In Example 2, 16 tty ports will be added, all with IP 192.168.3.4, 
      but with data ports equal to (4001, 4002, ..., 4016), and command 
      ports equal to (966, 967, 968, ..., 981). 
      
    b. Mapping tty ports manually
      After entering the directory "/usr/lib/npreal2/driver", you can modify 
      "npreal2d.cf" to map NPort serial ports to tty ports, and then execute 
      "mxloadsvr" to activate the modifications.
      
      The following tasks will be performed:
     
       - Modify npreal2d.cf
       - Create tty ports in the directory "/dev" with major & minor number 
         configured in "npreal2d.cf"
       - Stop and then restart the driver.

	7.2 Redundant COM Mode
	  Before mapping tty ports, you must set the operation mode of your 
      NPORT to Redundant COM Mode and make sure your device is CN2600 
      series. 
	  We provide a new command to map tty ports to be Redundant COM Mode.

    a. Mapping tty ports
      mxaddsvr -r [NPort IP1 Address] [NPort IP2 Address] [Total Ports]

	  Example :
		# cd /usr/lib/npreal2/driver
	    # ./mxaddsvr -r 192.168.32.134 192.168.126.123 16
		
	  In Example, 16 tty ports will be added, all with 
	  IP1 192.168.32.134 and IP2 192.168.32.126, but with data ports 
          equal to (950, 951, ..., 965), and command ports 
          equal to (966, 967, 968, ..., 981).

8. Settings for Secure Real COM Mode
   a. Check necessary library for Secure Real COM Mode
     User should visit https://www.openssl.org or the official website
     of your Linux distribution to install openssl library libssl.so.

     A simple way to test if you have libssl.so, please type 'ldconfig -p'
     command and the result should like below example.

       # ldconfig -p | grep libssl.so
            libssl.so (libc6) => /usr/lib/i386-linux-gnu/libssl.so

   b. Enable or disable the secure mode
     A script mxsetsec is used to set secure mode enable/disable.
	
     !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!
     This function is support NPort 6000 series only.
     If your model is not NPort 6000 series, you could ignore this chapter.
     !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!
	
     The syntax of "mxsetsec" is:
    
     mxsetsec
    
     Example:
       # cd /usr/lib/npreal2/driver
       # ./mxsetsec

9. Remove Mapped TTY Ports
    As with the "8. Mapping TTY Ports" task, we provide two ways to remove
    mapped tty ports:
   
    a. Remove the mapped tty ports automatically
      After logging in as root, enter the directory "/usr/lib/npreal2/driver" 
      and then execute "mxdelsvr" to delete a server. 
      The syntax of "mxdelsvr" is:

      mxdelsvr [IP]  ; For Real COM mode.
      mxdelsvr [IP1] ; For Redundant COM mode.
      
      Example:
       # cd /usr/lib/npreal2/driver
       # ./mxdelsvr 192.168.3.4
           
      If you don't include the IP address in the command line, a numbered 
      list of IP addresses for servers currently installed, along with the 
      total number of ports for each server, will be listed on the screen.
      To remove the tty ports for a particular server, type the number next 
      to the server's IP address and then hit Enter. The following tasks 
      will be performed:
    
       - Modify the npreal2d.cf 
       - Remove the relevant tty ports in directory "/dev"
       - Stop and then restart the driver.  
      
    b. Remove the mapped tty ports manually
      After entering the directory "/usr/lib/npreal2/driver", you can 
      modify "npreal2d.cf" to delete servers and ports manually, and then 
      execute "mxloadsvr" to activate the modifications.

	  
10. TTY Naming Rule
     The tty name of the Real TTY driver is configured in npreal2d.cf. 
     The pre-defined tty name is ttyrXX, and the callout name is curXX. 
     The naming convention is illustrated as follows:

     Nport Server     TTY Name                Callout Name
     1st(4port)       ttyr00 - ttyr03         cur00 - cur03
     2nd(8port)       ttyr04 - ttyr0b         cur04 - cur0b
     3rd(16port)      ttyr0c - ttyr1b         cur0c - cur1b
     4th(8port)       ttyr1c - ttyr23         cur1c - cur23
     ...(etc.)

     !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!
	   1. Callout Device is obsolete in Linux 2.6. That is, you 
	      cannot open Callout Device on Linux 2.6.
	   2. ttyr0 - ttyr9 or some tty names represented by decimal
	      number are created for kernel compatibility reason. User
	      must use tty port name combine with hexadecimal digits
	      for correct operation.   
     !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!
 
11. Removing the Driver
     Removing the driver will remove all driver files, mapped tty ports, 
     and unload the driver. To do this, enter the directory 
     "/usr/lib/npreal2/driver", and then execute "mxuninst" to uninstall 
     the driver. This program will perform the following tasks:
    
      - Unload the driver.
      - Delete all files and directories in "/usr/lib/npreal2"
      - Delete directory "/usr/lib/npreal2"
      - Modify the system initialization script file.

12. Modification of "npreal2d.cf"
     !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!
       "npreal2d.cf" is the driver configuration file. Please 
       backup this file before making any modification.
     !!!!!!!!!!!!!!!!!!!!!!!!!!!! NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!

     The configuration file is named "npreal2d.cf" in directory
     "/usr/lib/npreal2/driver", all relevant information about
     mapped tty ports will be appended in this file. you are
     allowed to modify this file if you want to modify the setting
     manually.

     We illustrate some circumstances that you may encounter in the
     following section. Please read the CAUTION section before
     reading the section a and section b.

     [CAUTION]:
      In modifying "npreal2d.cf",
      1. Please don't type any space or [TAB] character between
         ttymajor and '=' and the number.
      2. Please don't type any space or [TAB] character between
         calloutmajor and '=' and the number.
      3. Please type only one [TAB] character to seperate the 
         columns of the settings.

     a. Major Number
       The Real TTY driver allows you to change the major number
       manually. So you can modify the major number in "npreal2d.cf".
       And then execute the program "mxloadsvr" with an
       argument "module". For example:

        # cd /usr/lib/npreal2/driver
        # ./mxloadsvr module

       The driver will remove the module and reload the driver with
       new major number configured in "npreal2d.cf". The connections
       will be closed after the new driver is loaded.
       The following actions will be performed.

        - Unload driver.
        - Re-create all device files configured in "npreal2d.cf"
          with new major number.
        - Load driver.

     b. TTY Name & Callout Name
       Similar to the previous section, modification of tty name and
       callout name will be activated after executing "mxloadsvr".
       Since we do not modify the major number, so the driver will not
       be reloaded. We merely need to execute "mxloadsvr" to reload
       the settings without any argument.
       The following actions will be performed.

        - Close connections.
        - Re-create all device files configured in "nperal2d.cf".
        - Open the connections.

13. Modification of Initializing Script
     a. For Red Hat
       The script file "/etc/rc.d/rc.local" will be executed when Linux
       boots up. Therefore the driver will append the instructions which
       is used to load Real TTY driver in the script file.

     b. For Debian
       All script files in directory "/etc/init.d/" will be
       executed when Linux boots up. The Real TTY driver will copy
       the initialinzing script file to that directory and update
       the symbolic link to the script so that if the system boots
       up next time, the system will perform the relevant actions
       which are described in the script.
	   
           Caution:
             If the Debian system boots without nport driver loaded, please
             execute following command with root administration to resolve this
             problem:
	   
	       # update-rc.d npreals defaults

             Starting with Debian 6.0, the insserv command is used instead as
             below instruction.

               # insserv /etc/init.d/npreals

     c. For SuSE
       The initializing script file in SuSE is "/etc/rc.d/boot.local".
       The driver will append the instructions which is used to load
       Real TTY driver in the script file.

     d. For Gentoo
       The initializing script file in Gentoo is "/etc/conf.d/local.start".
       The driver will append the instructions which is used to load
       Real TTY driver in the script file.

14. Enable background polling feature
	If you don't want your program been blocked when open tty port with NPort
    not exist, you should enable this feature. This feature will polling NPort
    device in background to eliminate the time your program been blocked.
       
    Following steps shows how to enable this feature

    a. Copy the driver file from website, under the product page.
    b. Log in to the console as a super user (root).
    c. Execute "cd " to change to the home directory.
    d. Copy the driver file npreal2xx.tgz to the home directory.
    e. Execute "tar xvfz npreal2xx.tgz" to copy all files into the system.
    f. Execute "./moxa/mxinst polling".
	
15. Troubleshooting
    1. Open multiple tty concurrently in secure mdoe
       Since openssl cause internal system call error when opening multiple
       tty concurrently, the opening might be failed. If application requires
       to open tty concurrently, re-install driver with "concurrent_open"
       parameter. E.g. "./moxa/mxinst concurrent_open"
       Driver will take longer time to detecte network disconnection with this
       setting.

16. Limitation
    1. Redundant COM Mode
       NPort driver needs ONE minute the most to synchronize with NPort device
       after the LAN port resumes connection.
       Therefore, during the maximum one minute synchronization if any one
       network connection loses again, data lose might happen. 

17. Technical Support
     If you have any technical questions, please send your question by
     the following ways with detail description of the symptom.

     Email: support@moxa.com.tw

-End-
