server.exe : decode_headers.obj handle_connection.obj server.obj tables.obj base64.obj headers.obj utilities.obj \
			 DumpHexMem.obj handle_tls_connection.obj cipher_table.obj tls_messages.obj tls_encryption.obj tls_MD5Hash.obj \
			 ASN1_Decoder.obj X509_Decoder.obj RSA_PublicCrypto.obj
	link /DEBUG /out:server.exe $** ws2_32.lib

.obj : $*.c http_server.h homeserver.h
	cl /Zi /c $@ 

headers.obj : headers.c headers.h	
	cl /Zi /c headers.c

clean :
	@del *.obj
	@del *.exe
	@del *.ilk
	@del *.pdb
