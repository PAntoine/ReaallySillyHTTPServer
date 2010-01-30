/***************************************************************************************
 *
 *       Filename:  handle_tls_connection.c
 *
 *    Description:  This function will handle the tls negotiation.
 *
 *        Version:  1.0
 *        Created:  18/03/2009 08:37:35
 *       Revision:  none
 *
 *         Author:  Peter Antoine
 *          Email:  me@peterantoine.me.uk
 *
 *------------------------------------------------------------------------------------- 
 *                         Copyright (c) 2009 : Peter Antoine
 *                        Released under the Artistic License.
 ***************************************************************************************/

#include "http_server.h"

/*------------------------------------------------------------*
 * connection data connections
 *------------------------------------------------------------*/
extern CONNECTION_DETAILS	details[MAX_CONNECTIONS];

extern unsigned char	connection_buffer[MAX_CONNECTIONS][BUFFER_SIZE];
extern int				buff_pos[MAX_CONNECTIONS];
extern int				data_read[MAX_CONNECTIONS];
extern char				send_buffer[MAX_CONNECTIONS][2048];
extern CIPHER_LIST		ciphers[];
extern unsigned int		cert_size;
extern unsigned char	cert_buffer[MAX_CERT_SIZE];


void	DumpHexMem(char* memory,unsigned long dumpSize);


unsigned int	tls_SelectCipher(unsigned int type, unsigned int size, char* cipher_line);


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_Put24Bit
 *  Description:  This function will convert the value to a 3 byte big-endian value.
 *-------------------------------------------------------------------------------------*/
void tls_Put24Bit ( unsigned char* buffer, unsigned int value )
{
	buffer[0] = ((value & 0x00ff0000) >> 16);
	buffer[1] = ((value & 0x0000ff00) >> 8);
	buffer[2] = (value & 0x000000ff);
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_PutWord
 *  Description:  This function will convert the value to a 2 byte big-endian value.
 *-------------------------------------------------------------------------------------*/
void tls_PutWord ( unsigned char* buffer, unsigned short value )
{
	buffer[0] = ((value & 0xff00) >> 8);
	buffer[1] = (value & 0x00ff);
}
/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_decode_hello
 *  Description:  This function will handle the TLS hello. It will handle both the
 *  			  TLS headers and the SSLv2 packaged header.
 *-------------------------------------------------------------------------------------*/
int	tls_DecodeHello(unsigned int connection)
{
	unsigned int	offset = 0;
	unsigned int	result = 0;
	unsigned int	msg_length;
	unsigned int	cipher_length;
	unsigned int	session_id_len;
	unsigned int	challenge_len;

	if (do_read(connection))
	{
		printf("done the read\n");
		DumpHexMem(connection_buffer[connection],data_read[connection]);

		if (connection_buffer[connection][0] == CT_HANDSHAKE)
		{
			printf("found a non VERSION 2 header\n");
			/* we have something after a VERSION 2 hello */
			details[connection].sec_details.client_version_major = connection_buffer[connection][1];
			details[connection].sec_details.client_version_minor = connection_buffer[connection][2];

			msg_length		= UINT16(connection_buffer[connection][3], connection_buffer[connection][4]);

			if (connection_buffer[connection][5] == HT_CLIENT_HELLO)
			{
				printf("client hello\n");
				offset = 5;
				session_id_len	= connection_buffer[connection][TLS_SHO_SESSION_ID];
				cipher_length	= UINT16(connection_buffer[connection][TLS_SHO_SESSION_ID + 1 + session_id_len], connection_buffer[connection][TLS_SHO_SESSION_ID + 1 + session_id_len + 1]);

				details[connection].sec_details.cipher = tls_SelectCipher(	TLS_HEADER,
																			cipher_length,
																			&connection_buffer[connection][TLS_SHO_SESSION_ID + 1 + session_id_len + 2]);

				if (details[connection].sec_details.cipher > 0)
				{
					/* we have a valid hello */
					result = 1;
				}

				printf("msg: %d session:%d cipher length:%d cipher selected: %d\n",msg_length,session_id_len,cipher_length,details[connection].sec_details.cipher);
			}

		}
		else if ((connection_buffer[connection][buff_pos[connection]] & VERSION_2_HEADER) != 0)
		{
			/* client hello is the SSLv2 style */
			msg_length = ((connection_buffer[connection][buff_pos[connection]] & 0x7F) << 8 |
						  (connection_buffer[connection][buff_pos[connection]+1]));

			/* it must have the  message type 1 -- ClientHello */
			if (connection_buffer[connection][buff_pos[connection]+2] == 1)
			{
				if (data_read[connection] < msg_length)
				{
					/* Pain in the a*se, it needs to do a partial buffer read */
					printf("Its a pain --- not playing \n");
				}
				else
				{
					/* normal code -- Lets decode the ClientHello */
					details[connection].sec_details.client_version_major = connection_buffer[connection][buff_pos[connection]+3];
					details[connection].sec_details.client_version_minor = connection_buffer[connection][buff_pos[connection]+4];

					cipher_length = UINT16(	connection_buffer[connection][buff_pos[connection]+5],
											connection_buffer[connection][buff_pos[connection]+6]);

					if (details[connection].sec_details.client_version_major != 3 || 
						details[connection].sec_details.client_version_minor > 3)
					{
						/* This server is at most 3.3 (must be a major 3) */
						details[connection].sec_details.client_version_major = 3;
						details[connection].sec_details.client_version_minor = 3;
					}

					session_id_len	= UINT16( 	connection_buffer[connection][buff_pos[connection]+7],
												connection_buffer[connection][buff_pos[connection]+8]);

					challenge_len	= UINT16(	connection_buffer[connection][buff_pos[connection]+9],
												connection_buffer[connection][buff_pos[connection]+10]);

					/* adjust the buff_pos before we carry on */
					buff_pos[connection] += 11;

					details[connection].sec_details.cipher = tls_SelectCipher(	VERSION_2_HEADER,
																				cipher_length,
																				&connection_buffer[connection][buff_pos[connection]]);

					if (details[connection].sec_details.cipher > 0)
					{
						printf("cipher selected: %d\n",details[connection].sec_details.cipher);
	
						/* now get the session_id */
						buff_pos[connection] += cipher_length;

						/* ignore the session id, it should be zero, we dont allow V2
						 * hellos to resume sessions, so even if we get a session id
						 * then we just plain ignore it.
						 */

						/* and get the challenge */
						buff_pos[connection] += session_id_len;

						memcpy(	&details[connection].sec_details.client_random[32-challenge_len],
								&connection_buffer[connection][buff_pos[connection]],
								challenge_len);

						/* we have a valid hello */
						result = 1;

						DumpHexMem((char*)&details[connection].sec_details,sizeof(TLS_SECURITY));
					}
				}
			}
		}
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_DecodeClientReply
 *  Description:  This function will handle the second half of the TLS negotiation for
 *                the clients reply to the servers hello.
 *-------------------------------------------------------------------------------------*/
int tls_DecodeClientReply (unsigned int connection)
{
	int result = 0;
	unsigned int	size;
	unsigned int 	offset = 0;
	unsigned char 	*temp_pointer;

	if (do_read(connection))
	{
		printf("done the read\n");
		DumpHexMem(connection_buffer[connection],data_read[connection]);

		if (connection_buffer[connection][TLS_CONTENT_TYPE] == CT_HANDSHAKE && connection_buffer[connection][TLS_HT_TYPE] == HT_CERTIFICATE)
		{
			printf("found the client certificate \n");
			/*TODO: OK. Need to handle the client certificate  --- ignoring for now */
		}

		if (connection_buffer[connection][offset + TLS_CONTENT_TYPE] == CT_HANDSHAKE && connection_buffer[connection][offset + TLS_HT_TYPE] == HT_CLIENT_KEY_EXCHANGE)
		{
			temp_pointer = &connection_buffer[connection][offset];
			size = UINT24(temp_pointer[TLS_HT_SIZE_BYTE_1],temp_pointer[TLS_HT_SIZE_BYTE_2],temp_pointer[TLS_HT_SIZE_BYTE_3]);

			if (ciphers[details[connection].sec_details.cipher].key_exchange_algorithm == KEA_RSA)
			{
				printf("RSA KEA\n");
				/* clause: 7.4.7.1 warning to check to see if a compliant size precedes the key */
				if ((size - 2) == UINT16(temp_pointer[TLS_HT_DATA_START],temp_pointer[TLS_HT_DATA_START+1]))
				{
					/* skip the size */
					temp_pointer += 2;
					size -= 2;
				}
			}

			if (size <= 512)
			{
				details[connection].sec_details.client_key_size = size;
				memcpy(details[connection].sec_details.client_key,&temp_pointer[TLS_HT_DATA_START],size);

				printf("Key is:\n");
				DumpHexMem(details[connection].sec_details.client_key,details[connection].sec_details.client_key_size);
			}
			else
			{
				/* key size too big, fail */
			}

			offset += 5 + UINT16(connection_buffer[connection][offset + TLS_CT_SIZE_MSB],connection_buffer[connection][offset + TLS_CT_SIZE_LSB]);
		}

		printf("offset: %d\n",offset);

		if (connection_buffer[connection][offset + TLS_CONTENT_TYPE] == CT_HANDSHAKE && connection_buffer[connection][offset + TLS_HT_TYPE] == HT_CERTIFICATE_VERIFY)
		{
			printf("found the certificate verify message\n");
			/* TODO: handle this */
		}

		DumpHexMem(&connection_buffer[connection][offset],20);
		if (connection_buffer[connection][offset + TLS_CONTENT_TYPE] == CT_CHANGE_CIPHER_SPEC)
		{
			/* I know this is pointless checking, but why not? */
			temp_pointer = &connection_buffer[connection][offset];
			size = UINT16(temp_pointer[TLS_CT_SIZE_MSB],temp_pointer[TLS_CT_SIZE_LSB]);

			if (size == 1 && temp_pointer[TLS_CT_START] == 1)
			{
				/* we are golden */
				printf("we are golden\n");
			}

			offset += 5 + size;
		}
		printf("size: %d\n", size);
		DumpHexMem(&connection_buffer[connection][offset],20);

		/*-----------------------------------------------*
		 * If we have received the change cipher spec
		 * message then the following message is encrypted
		 * using the negotiated stuff.
		 *-----------------------------------------------*/

		if (connection_buffer[connection][offset + TLS_CONTENT_TYPE] == CT_HANDSHAKE)
		{
			temp_pointer = &connection_buffer[connection][offset];
			size = UINT16(temp_pointer[TLS_CT_SIZE_MSB],temp_pointer[TLS_CT_SIZE_LSB]);

			DumpHexMem(temp_pointer + 5,size);
//			tls_decryptData(connection,temp_pointer + 5,size);
	
			result = 1;
		}
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_negotiation
 *  Description:  This function will handle the TLS negotiation.
 *                I am taking some liberties with the read, I expect to have more
 *                then a few chars in the buffer. I may be wrong and if I don't then
 *                I'll fix that when it starts failing!
 *-------------------------------------------------------------------------------------*/
int	tls_negotiation(unsigned int connection)
{
	int	result = 0;
	CERTIFICATE	cert_list[2];

	if (tls_DecodeHello(connection))
	{
		tls_SendServerHello(connection);
		printf("size: %d\n",cert_size);

		cert_list[0].size 			= cert_size;
		cert_list[0].certificate	= cert_buffer;

		tls_SendCertificate(connection,1,cert_list);
		tls_SendServerHelloDone(connection);

		if (tls_DecodeClientReply(connection))
		{
			/* we have a valid connection - let the client know we accept */
			tls_SendChangeCipher(connection);
			tls_SendFinished(connection);

			result = 1;
		}
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  handle_tls_connection
 *  Description:  This is the main function that handles the secure TLS connection.
 *-------------------------------------------------------------------------------------*/
void	handle_tls_connection(unsigned int connection)
{
	printf("here\n");

	if (tls_negotiation(connection))
	{
		printf("tls negotiation finished \n");
		/* do the boring http stuff */
	}
}


