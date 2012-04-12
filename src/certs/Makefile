
all : clean
	make-certs PeterJones pjones@redhat.com all tls-client email
	pk12util -d /etc/pki/pesign/ -i PeterJones.p12

clean :
	@rm -vf *.c?? *.p?? *.k?? *.txt *.old *.attr *.db  *.srl

