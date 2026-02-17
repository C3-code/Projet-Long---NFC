nfc_lib.so: nfc_lib.c nfc_lib.h
	gcc -fPIC -shared -o libnfccard.so nfc_lib_new_keys.c -lnfc -lfreefare

start_rest_api: nfc_lib.so rest.py
	python3 read.py

clean: rm *.so
