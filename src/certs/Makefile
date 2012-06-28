NICKNAME := $(shell whoami)
EMAIL := ${NICKNAME}@localhost

all : clean
	./make-certs ${NICKNAME} ${EMAIL} all codesign 1.3.6.1.4.1.311.10.3.1
	@rm -rvf /etc/pki/pesign/*
	certutil -A -n 'my CA' -d /etc/pki/pesign -t CT,CT,CT -i ca.crt
	pk12util -d /etc/pki/pesign/ -i ${NICKNAME}.p12
	certutil -d /etc/pki/pesign/ -A -i ${NICKNAME}.crt -n ${NICKNAME} -t u

clean :
	@rm -vf *.c?? *.p?? *.k?? *.txt *.old *.attr *.db  *.srl

