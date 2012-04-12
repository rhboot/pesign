
all : clean
	make-certs PeterJones pjones@redhat.com all codesign 1.3.6.1.4.1.311.10.3.1
	@rm -rvf /etc/pki/pesign/*
	pk12util -d /etc/pki/pesign/ -i PeterJones.p12
	certutil -d /etc/pki/pesign/ -A -i PeterJones.crt -n PeterJones -t u

clean :
	@rm -vf *.c?? *.p?? *.k?? *.txt *.old *.attr *.db  *.srl

