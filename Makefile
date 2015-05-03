
PATH1="."
##############################################################
# Linux Kernel 2.6 and 3.0
##############################################################
ifneq	"$(findstring 2.4., $(shell uname -a))" "2.4."

all: module npreal2d npreal2d_redund tools
SP1: module npreal2d npreal2d_redund tools
ssl: module SSLnpreal2d npreal2d_redund tools
SP1_ssl: module SSLnpreal2d npreal2d_redund tools
ssl64: module SSL64npreal2d npreal2d_redund tools
SP1_ssl64: module SSL64npreal2d npreal2d_redund tools
ppc64: module ppc64npreal2d npreal2d_redund tools

CC+=$(POLLING) 

npreal2d: npreal2d.o
	cc npreal2d.o -o npreal2d
	strip	npreal2d

npreal2d.o : npreal2d.c npreal2d.h
	$(CC) -c npreal2d.c

npreal2d_redund: 	redund_main.o redund.o
	cc	redund_main.o redund.o -lpthread -o npreal2d_redund
	strip	npreal2d_redund

redund_main.o:	redund_main.c npreal2d.h redund.h
	$(CC) -c redund_main.c

redund.o:	redund.c redund.h npreal2d.h
	$(CC) -c redund.c

SSLnpreal2d: 	SSLnpreal2d.o
	cc	npreal2d.o -o npreal2d libssl.so 
	strip	npreal2d

SSLnpreal2d.o:	npreal2d.c
	$(CC) -c -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include
	
SSL64npreal2d: 	SSL64npreal2d.o
	cc	-m64 npreal2d.o -o npreal2d libssl.so 
	strip	npreal2d

SSL64npreal2d.o:	npreal2d.c
	$(CC) -c -m64 -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include
	
ppc64npreal2d: 	ppc64npreal2d.o
	cc	-mpowerpc64 npreal2d.o -o npreal2d libssl.so 
	strip	npreal2d

ppc64npreal2d.o:	npreal2d.c
	$(CC) -c -mpowerpc64 -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include

ifeq	"$(findstring 2.6.15-1.2054, $(shell uname -r))" "2.6.15-1.2054"
CFLAGS  += -DFEDORA
endif

ifneq ($(KERNELRELEASE),)
obj-m := npreal2.o
else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

module:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	cp -p npreal2.ko /lib/modules/$(shell uname -r)/kernel/drivers/char/
#	cp -p npreal2.ko /lib/modules/$(shell uname -r)/misc/
	depmod -a

endif

tools: mxaddsvr mxdelsvr mxcfmat mxloadsvr mxsetsec

mxaddsvr: mxaddsvr.c
	$(CC) -o mxaddsvr mxaddsvr.c
	strip mxaddsvr

mxdelsvr: mxdelsvr.c
	$(CC) -o mxdelsvr mxdelsvr.c
	strip mxdelsvr

mxcfmat: mxcfmat.c
	$(CC) -o mxcfmat mxcfmat.c
	strip mxcfmat

mxloadsvr: mxloadsvr.c
	$(CC) -o mxloadsvr mxloadsvr.c
	strip mxloadsvr
	
mxsetsec: mxsetsec.c
	$(CC) -o mxsetsec mxsetsec.c
	strip mxsetsec
	
clean:
	rm -f *.o
	rm -rf ./.tmp_versions
	rm -f npreal2.mod*
	rm -f .npreal2*
	rm -f npreal2.ko
	rm -f *.order
	rm -f npreal2d
	rm -f npreal2d_redund
	rm -f /lib/modules/$(shell uname -r)/kernel/drivers/char/npreal2.ko
	rm -f /lib/modules/$(shell uname -r)/misc/npreal2.ko
	rm -f mxaddsvr
	rm -f mxdelsvr
	rm -f mxcfmat
	rm -f mxloadsvr
	rm -f mxsetsec
	rm -f Module.symvers
	

else     
##############################################################
# Linux Kernel 2.4
##############################################################

CC=cc -DLINUX $(POLLING) 
ARCH=$(shell uname -m | sed s/i.86/i86/)
VERSION=$(shell uname -r | sed s/smp//)

ifeq	($(ARCH),i86)
OPTS=-DMODVERSIONS -DMODULE -D__KERNEL__ -Wall -Wstrict-prototypes -O2 \
-fomit-frame-pointer -pipe -march=i486 \
-I/usr/src/linux-$(VERSION)/include -I/usr/src/linux-2.4/include -I/usr/src/linux/include
else
ifeq	($(ARCH),x86_64)
OPTS=-DMODVERSIONS -DMODULE -D__KERNEL__ -Wall -Wstrict-prototypes -O2 \
-fomit-frame-pointer -pipe -m64 -mcmodel=kernel \
-I/usr/src/linux-$(VERSION)/include -I/usr/src/linux-2.4/include -I/usr/src/linux/include
else 
OPTS=-DMODVERSIONS -DMODULE -D__KERNEL__ -Wall -Wstrict-prototypes -O2 \
-fomit-frame-pointer -pipe -I/usr/src/linux/include -ffixed-8
endif
endif


ifeq	"$(findstring SMP, $(shell uname -a))" "SMP"
OPTS+=-D__SMP__
endif

ifeq	"$(findstring SMP, $(shell cat /proc/version))" "debian"
OPTS+=-D_DEBIAN_
endif



all: module npreal2d npreal2d_redund tools
SP1: modulesp1 npreal2d npreal2d_redund tools
ssl: module SSLnpreal2d npreal2d_redund tools
SP1_ssl: modulesp1 SSLnpreal2d npreal2d_redund tools
ssl64: module SSL64npreal2d npreal2d_redund tools
SP1_ssl64: modulesp1 SSL64npreal2d npreal2d_redund tools
ppc64: modulesp1 ppc64npreal2d npreal2d_redund tools

SSLnpreal2d: 	SSLnpreal2d.o
	cc	npreal2d.o -o npreal2d libssl.so 
	strip	npreal2d

SSLnpreal2d.o:	npreal2d.c
	$(CC) -c -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include
	
SSL64npreal2d: 	SSL64npreal2d.o
	cc	-m64 npreal2d.o -o npreal2d libssl.so 
	strip	npreal2d

SSL64npreal2d.o:	npreal2d.c
	$(CC) -c -m64 -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include
	
ppc64npreal2d: 	ppc64npreal2d.o
	cc	-mpowerpc64 npreal2d.o -o npreal2d libssl.so 
	strip	npreal2d

ppc64npreal2d.o:	npreal2d.c
	$(CC) -c -mpowerpc64 -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include

npreal2d: 	npreal2d.o
	cc	npreal2d.o -o npreal2d
	strip	npreal2d

npreal2d.o:	npreal2d.c npreal2d.h
	$(CC) -c npreal2d.c

npreal2d_redund:	redund_main.o redund.o
	cc -lpthread redund_main.o redund.o -o npreal2d_redund
	strip	npreal2d_redund

redund_main.o:	redund_main.c npreal2d.h redund.h
	$(CC) -c redund_main.c

redund.o:	redund.c redund.h npreal2d.h
	$(CC) -c redund.c

module:
	$(CC) -c $(OPTS) npreal2.c
	cp -p npreal2.o /lib/modules/$(shell uname -r)/kernel/drivers/char/
	cp -p npreal2.o /lib/modules/$(shell uname -r)/misc/
	depmod -a

modulesp1:
	$(CC) -c $(OPTS) -DSP1 npreal2.c
	cp -p npreal2.o /lib/modules/$(shell uname -r)/kernel/drivers/char/
	cp -p npreal2.o /lib/modules/$(shell uname -r)/misc/
	depmod -a
	
tools: mxaddsvr mxdelsvr mxcfmat mxloadsvr mxsetsec

mxaddsvr: mxaddsvr.c
	$(CC) -o mxaddsvr mxaddsvr.c
	strip mxaddsvr

mxdelsvr: mxdelsvr.c
	$(CC) -o mxdelsvr mxdelsvr.c
	strip mxdelsvr

mxcfmat: mxcfmat.c
	$(CC) -o mxcfmat mxcfmat.c
	strip mxcfmat

mxloadsvr: mxloadsvr.c
	$(CC) -o mxloadsvr mxloadsvr.c
	strip mxloadsvr

mxsetsec: mxsetsec.c
	$(CC) -o mxsetsec mxsetsec.c
	strip mxsetsec

clean:
	rm -rf *.o
	rm -f npreal2d
	rm -f /lib/modules/$(shell uname -r)/kernel/drivers/char/npreal2.ko
	rm -f /lib/modules/$(shell uname -r)/misc/npreal2.ko
	rm -f mxaddsvr
	rm -f mxdelsvr
	rm -f mxcfmat
	rm -f mxloadsvr
	rm -f mxsetsec
	rm -f *.order
	rm -f libssl.so
endif
