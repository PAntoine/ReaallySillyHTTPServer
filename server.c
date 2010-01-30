/*********************************************************************************
 * Name: Reaaly Poor Server
 *
 * Description:
 * 
 * This is a reaally poor HTTP server.
 *
 * The main reason for this abomination existing is for me to learn the magic of
 * HTTP servers. It is not intended for use in the real world, but its existence
 * and small size means that you can play with the source code and break stuff
 * intentionally for testing.
 *
 * It does nothing clever whatsoever! It handles connections in threads, it barely
 * tidies up after itself. But, it is reasonably small and I hope does not have
 * to large a memory foot print.
 *
 * I would not use this for any real projects, use Apache it works!
 *
 *--------------------------------------------------------------------------------
 * Date  : 7th March 2009
 * Author: Peter Antoine. 
 *
 * Copyright 2009 (c) Peter Antoine
 * Released under the Artistic Licence.
 *********************************************************************************/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>

#include "http_server.h"
#include "X509_encoding.h"
#include "RSA_PublicCrypto.h"

#define	HTTP_PORT		80
#define	HTTPS_PORT		443


/* TODO: DEBUG remove */
extern void	DumpHexMem(char* memory,unsigned long dumpSize);


extern char			*status_code[];

extern unsigned int status_code_size[SC_MAX_CODES];

CONNECTION_DETAILS	details[MAX_CONNECTIONS];

unsigned int	cert_size;
unsigned char	cert_buffer[MAX_CERT_SIZE];

unsigned int	key_size;
unsigned char	key_buffer[MAX_KEY_SIZE];


void	handle_connection(unsigned int connection);
void	handle_tls_connection(unsigned int connection);

PEM_NAME_ENTRY	pem_start[] =
{
	{"-----BEGIN CERTIFICATE-----",	sizeof("-----BEGIN CERTIFICATE-----")-1},	
	{"-----BEGIN RSA PRIVATE KEY-----",	sizeof("-----BEGIN RSA PRIVATE KEY-----")-1}	
};

PEM_NAME_ENTRY	pem_stop[] =
{
	{"-----END CERTIFICATE-----",	sizeof("-----END CERTIFICATE-----")-1},	
	{"-----END RSA PRIVATE KEY-----",	sizeof("-----END RSA PRIVATE KEY-----")-1}	
};

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  X509_LoadPem
 *  Description:  This function will load a PEM (Base64 Encoded ceritificate).
 *-------------------------------------------------------------------------------------*/
int	LoadPemFile ( PEM_FILE_TYPES type, unsigned char *filename, unsigned char* buffer, unsigned int buffer_size )
{
	int				result = 0;
	int				found_start = 0;
	int				offset = 0;
	FILE*			infile;
	unsigned char	line[100];

	infile = fopen(filename,"r");
	
	if (infile != NULL)
	{
		while (!feof(infile))
		{
			if (fgets(line,100,infile) != NULL)
			{
				if (!found_start)
				{
					if (strncmp(line,pem_start[type].type_name,pem_start[type].type_name_length) == 0)
					{
						found_start = 1;
					}
				}
				else if (strncmp(line,pem_stop[type].type_name,pem_stop[type].type_name_length) == 0)
				{
					break;
				}
				else
				{
					offset += decode_base64(&buffer[offset],buffer_size - offset,line,strlen(line)-1);
				}
			}
		}
	}

	return offset;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  MAIN
 *  Description:  Hopefully it does what you expect a Main function to do?
 *-------------------------------------------------------------------------------------*/
void	main(int argc,char *argv[])
{
	int			start = 1;
	int			closed = 0;
	int			secure = 0;
	int			failed = 0;
	int			key_file = 0;
	int			cert_file = 0;
	int			pem_format = 0;
	int			connection_number = 0;
	int			writable,err,size,count,in_size;
	int			trans_left,sleep_count;
	char		buffer[1024];
	char		key_filename[256];
	char		cert_filename[256];
	float		mbpersec;
	WORD		wVersionRequested;	
	fd_set		set_s_out;
	SOCKET		s_listen,s_in;
	HANDLE		thread[MAX_CONNECTIONS];
	clock_t		startclock,endclock;
	WSADATA 	wsaData;
	SOCKADDR_IN	sin_in,sin_listen,sin_addr;
	struct timeval	waittime;
	RSA_PRIVATE_KEY	key;
	X509_CERTIFICATE certificate;

	printf("%s\nBy Peter Antoine\n\nCopyright (c) 2010 Peter Antoine\nReleased under the Artistic Licence\n",SERVER_NAME);

	memset(&key,0,sizeof(RSA_PRIVATE_KEY));
	memset(&certificate,0,sizeof(X509_CERTIFICATE));

	if (argc > 0)
	{
		while ((start < argc) && !failed)
		{
			if (argv[start][0] == '-')
			{

				switch(argv[start][1])
				{
					case 's': secure = 1; 	break;
					case 'p': pem_format = 1; break;
					case 'b': pem_format = 0; break;	/* I know pointless but makes the command line more readable - no unknown magic */


					/* the certificate file */
					case 'c':	if (cert_file)
									failed = 2;

							  	else if (argv[start][2] != '\0')
									strncpy(cert_filename,&argv[start][2],256);

								else if (argv[start+1][0] != '-' || (argv[start+1][0] == '-' && argv[start+1][1] == '\0'))
									strncpy(cert_filename,argv[++start],256);
								else
									failed = 1;

								cert_file = 1;
								break;

					/* the key file */
					case 'k':	if (key_file)
									failed = 2;

							  	else if (argv[start][2] != '\0')
									strncpy(key_filename,&argv[start][2],256);

								else if (argv[start+1][0] != '-' || (argv[start+1][0] == '-' && argv[start+1][1] == '\0'))
									strncpy(key_filename,argv[++start],256);
								else
									failed = 1;

								key_file = 1;
								break;

					default:
							failed = 3;
				}

				start++;
			}
			else
			{
				failed = 4;
				printf("start: %d %s\n",start,argv[start]);
			}
		}
	}

	if ((secure && !(cert_file && key_file)) || (!secure && (cert_file || key_file)))	
	{
		failed = 1;
	}

	if (failed)
	{
		printf("Failed bad parameter\n");
		printf("Usage:\n");
		printf("      -s                   - Secure (needs a certificate file)\n");
		printf("      -b                   - Load security files in Raw BER format (default)\n");
		printf("      -p                   - Load security files in PEM format\n");
		printf("      -c <filename>        - certificate file name\n");
		printf("      -k <filename>        - key file name\n");
	
		exit(1);
	}

	if (cert_file)
	{
		if (pem_format)
		{
			if((cert_size = LoadPemFile(PEMFT_CERTIFICATE,cert_filename,cert_buffer,MAX_CERT_SIZE)) == 0)
			{
				printf("Failed to read the certificate file.\n");
				exit(1);
			}
			if((cert_size = LoadPemFile(PEMFT_RSA_PRIVATE_KEY,key_filename,key_buffer,MAX_KEY_SIZE)) == 0)
			{
				printf("Failed to read the key file.\n");
				exit(1);
			}
		}else{
			/* read the binary file */
			printf("The code needs to be written to read the binary cert -- I am too lazy.\n");
			exit(1);
		}

		/* ok, we have read the file successfully */
		if (!X509_DecodeCertificate(&certificate,cert_buffer))
		{
			printf("Failed to decode the certificate.\n");
			exit(1);
		}

		if (!RSA_LoadPublicKey(&key,key_buffer))
		{
			printf("Failed to decode the private key\n");
			exit(1);
		}

	}

	/* Need to initialise the status code sizes before the 
	 * server needs to use them.
	 */
	for (count=0;count<SC_MAX_CODES;count++)
	{
		status_code_size[count] = strlen(status_code[count]);
	}

	/* windows nonsense that is needed before you can talk to
	 * the windows 2 sockets.
	 */ 
	wVersionRequested = MAKEWORD( 2, 2 ); 
	err = WSAStartup( wVersionRequested, &wsaData );
	
	if ( err != 0 ) 
	{	
		printf("Unable to find the WinSock DLL\n");
		return;
	}
	
	/* now lets talk to the sockets */
	s_listen = socket(AF_INET,SOCK_STREAM,0);

	if (s_listen == INVALID_SOCKET)
	{
		printf("Socket failed to open.\n");
	}else{
		/* now create a connection to the remote system
		 * we will connect to the address (to the local IP address: port 712)
		 */
		sin_listen.sin_family = AF_INET;
		if (secure)
			sin_listen.sin_port   = htons(HTTPS_PORT);
		else
			sin_listen.sin_port   = htons(HTTP_PORT);

		sin_listen.sin_addr.s_addr = htonl(INADDR_ANY);

		if (bind(s_listen,(LPSOCKADDR)&sin_listen,sizeof(sin_listen)) == SOCKET_ERROR)
		{
			printf("Failed to bind to local socket. %d \n",WSAGetLastError());
		}else{
			size = sizeof(sin_addr);
	
			/* lets keep listening for incoming connections */
			while(!closed)
			{
				if (listen(s_listen,5) == SOCKET_ERROR)
				{
					printf("Failed to listen to socket\n");
				}else{
					s_in = accept(s_listen,(LPSOCKADDR)&sin_in,NULL);

					if (s_in == INVALID_SOCKET)
					{
						printf("failed to open accept listening socket\n");
					}else{
						printf("trying to handle a connection\n");
						memset(&details[connection_number],0,sizeof(CONNECTION_DETAILS));

						details[connection_number].connection	= connection_number;
						details[connection_number].socket 		= s_in;
						details[connection_number].in_use		= 1;
						details[connection_number].user[0]		= 0;
						details[connection_number].retry_count  = 0;
						details[connection_number].passwd[0]	= 0;

						if (secure)
							thread[connection_number] = CreateThread(	NULL, 
																		0, 
																		(LPTHREAD_START_ROUTINE)handle_tls_connection, 
																		(void*)connection_number, 
																		0, 
																		NULL);
						else
							thread[connection_number] = CreateThread(	NULL, 
																		0, 
																		(LPTHREAD_START_ROUTINE)handle_connection, 
																		(void*)connection_number, 
																		0, 
																		NULL);

						connection_number = (connection_number + 1) % MAX_CONNECTIONS;
					}
				}
			}
		}

		if(closesocket(s_listen) == SOCKET_ERROR)
			printf("Socket failed to close\n");
	}

	/* must call this or we waste resources */
	WSACleanup();
}





