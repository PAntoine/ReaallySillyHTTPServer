/***************************************************************************************
 *
 *       Filename:  tls_messages
 *
 *    Description:  This file holds the functions that create the specific TLS messages.
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

#include <stdio.h>
#include <memory.h>
#include "http_server.h"

/*-----------------------------------------------------------------------------*
 *  external definitions
 *-----------------------------------------------------------------------------*/
extern CONNECTION_DETAILS	details[MAX_CONNECTIONS];

extern char	send_buffer[MAX_CONNECTIONS][2048];

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_GenerateRandom
 *  Description:  This function will generate the random number.
 *-------------------------------------------------------------------------------------*/
static void	tls_GenerateRandom(unsigned int connection, char* buffer)
{
	int count;

	/* TODO: Create a proper rand generator */
	for (count=0;count<32;count++)
	{
		buffer[count] = 0x45;
	}
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_GenerateSessionID
 *  Description:  This function will generate the session id.
 *-------------------------------------------------------------------------------------*/
static int tls_GenerateSessionID(char* buffer)
{
	int	count;

	/* TODO: make a proper session_id, if required.empty session id for now. */
	for (count=0;count<32;count++)
	{
		buffer[count] = 0x11;
	}

	return 32;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_ConnectionAlert
 *  Description:  This function will send a connection alert.
 *-------------------------------------------------------------------------------------*/
void	tls_SendConnectionAlert(unsigned int connection)
{
	int	offset = 0;
	
	send_buffer[connection][offset++] = CT_ALERT;
	send_buffer[connection][offset++] = details[connection].sec_details.client_version_major;
	send_buffer[connection][offset++] = details[connection].sec_details.client_version_minor;
	send_buffer[connection][offset++] = 2;
	send_buffer[connection][offset++] = 2;
	send_buffer[connection][offset++] = 40;

	/* send the start */
	send(details[connection].socket,send_buffer[connection],offset,0);
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_SendHello
 *  Description:  This function will build and send the ServerHello message back to
 *  			  the client.
 *-------------------------------------------------------------------------------------*/
void	tls_SendServerHello(unsigned int connection)
{
	int size;
	int result = 1;
	int	offset = 0;
	
	/* TLS header */
	send_buffer[connection][0] = CT_HANDSHAKE;	/* server hello */
	send_buffer[connection][1] = details[connection].sec_details.client_version_major;
	send_buffer[connection][2] = details[connection].sec_details.client_version_minor;

	/* Handshake header */
	send_buffer[connection][5] = HT_SERVER_HELLO;	/* server hello */
	offset = 9;

	/* set the header */
	send_buffer[connection][offset++] = details[connection].sec_details.client_version_major;
	send_buffer[connection][offset++] = details[connection].sec_details.client_version_minor;

	/* servers random number */
	tls_GenerateRandom(connection,details[connection].sec_details.server_random);
	memcpy(&send_buffer[connection][offset],details[connection].sec_details.server_random,32);
	offset += 32;

	/* session ID */
	send_buffer[connection][offset++] = 0;	// Session ID length 0
//	size = tls_GenerateSessionID(details[connection].sec_details.session_id);
//	memcpy(&send_buffer[connection][offset],details[connection].sec_details.session_id,size);
//	offset += size;

	/* cipher suit */
	tls_GetCipher(details[connection].sec_details.cipher,&send_buffer[connection][offset]);
	offset += 2;

	/* compression method */
	send_buffer[connection][offset++] = details[connection].sec_details.compression_method;

	printf("Size: %d\n",offset);

	/* now set the sizes */
	tls_PutWord(&send_buffer[connection][3],offset - 5);		/* put the TLS message size in */
	tls_Put24Bit(&send_buffer[connection][6],offset - 9);		/* put the HANDSHAKE size in */

	printf("about to send: %d\n",offset);

	/* send the hello */
	DumpHexMem(send_buffer[connection],offset);
	send(details[connection].socket,send_buffer[connection],offset,0);
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_Certificate
 *  Description:  This function will send the certificate message.
 *-------------------------------------------------------------------------------------*/
void	tls_SendCertificate(unsigned int connection, unsigned int number_of_certs, CERTIFICATE* cert_chain)
{
	int	count;
	int	offset = 0;
	int total_size = 0;

	/* calculate the size of the certificate chain */
	for (count = 0;count < number_of_certs;count++)
	{
		total_size = cert_chain[count].size + 3;
	}

	if (total_size > 0)
	{
		/* build the message */
		send_buffer[connection][0] = CT_HANDSHAKE;
		send_buffer[connection][1] = details[connection].sec_details.client_version_major;
		send_buffer[connection][2] = details[connection].sec_details.client_version_minor;
		tls_PutWord(&send_buffer[connection][3],total_size + 4 + 3);	/* put the HT message size */ 

		/* put the handsake message header in */
		send_buffer[connection][5] = HT_CERTIFICATE;					/* server hello */
		tls_Put24Bit(&send_buffer[connection][6],total_size + 3);		/* total cert chain size + the vector size bytes */

		/* not add the vector size for the total cert size */
		tls_Put24Bit(&send_buffer[connection][9],total_size);

		offset = 12;

		/* now add the certificates */
		for (count=0;count<number_of_certs;count++)
		{
			/* cert play load = vector size + certificate */
			tls_Put24Bit(&send_buffer[connection][offset],cert_chain[count].size);
			memcpy(&send_buffer[connection][offset+3],cert_chain[count].certificate,cert_chain[count].size);

			offset += cert_chain[count].size + 3;
		}
			
		/* send the start */
		DumpHexMem(send_buffer[connection],offset);
		send(details[connection].socket,send_buffer[connection],offset,0);
	}
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_ServerHelloDone
 *  Description:  This function will send a connection alert.
 *-------------------------------------------------------------------------------------*/
void	tls_SendServerHelloDone(unsigned int connection)
{
	int	offset = 0;
	
	send_buffer[connection][offset++] = CT_HANDSHAKE;	/* Handshake message */
	send_buffer[connection][offset++] = details[connection].sec_details.client_version_major;
	send_buffer[connection][offset++] = details[connection].sec_details.client_version_minor;
	send_buffer[connection][offset++] = 0;
	send_buffer[connection][offset++] = 4;
	
	send_buffer[connection][offset++] = HT_SERVER_HELLO_DONE;	/* server hello done */
	send_buffer[connection][offset++] = 0x00;
	send_buffer[connection][offset++] = 0x00;
	send_buffer[connection][offset++] = 0x00;

	DumpHexMem(send_buffer[connection],offset);
	send(details[connection].socket,send_buffer[connection],offset,0);
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_SendChangeCipher
 *  Description:  This function will send the Send change Cipher message.
 *-------------------------------------------------------------------------------------*/
void tls_SendChangeCipher (unsigned int connection)
{
	send_buffer[connection][TLS_CONTENT_TYPE	] = CT_CHANGE_CIPHER_SPEC;
	send_buffer[connection][TLS_CT_VERSION_MAJOR] = details[connection].sec_details.client_version_major;
	send_buffer[connection][TLS_CT_VERSION_MINOR] = details[connection].sec_details.client_version_minor;
	send_buffer[connection][TLS_CT_SIZE_MSB		] = 0;
	send_buffer[connection][TLS_CT_SIZE_LSB		] = 1;
	send_buffer[connection][TLS_CT_START		] = 1;	

	DumpHexMem(send_buffer[connection],TLS_CT_START+1);
	send(details[connection].socket,send_buffer[connection],TLS_CT_START+1,0);
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_SendFinished
 *  Description:  This function will handle the finish message. This message is encryped
 *                using the current selected cipher and the keys that have been exchanged.
 *-------------------------------------------------------------------------------------*/
void tls_SendFinished (unsigned int connection)
{
	unsigned int	size;

	send_buffer[connection][TLS_CONTENT_TYPE	] = CT_HANDSHAKE;
	send_buffer[connection][TLS_CT_VERSION_MAJOR] = details[connection].sec_details.client_version_major;
	send_buffer[connection][TLS_CT_VERSION_MINOR] = details[connection].sec_details.client_version_minor;

	send_buffer[connection][TLS_HT_TYPE] = HT_FINISHED;

	size =  tls_EncryptData(connection,&send_buffer[connection][TLS_HT_DATA_START],2048-TLS_HT_DATA_START,"server finished",sizeof("server finished") - 1);

	tls_PutWord(&send_buffer[connection][TLS_CT_SIZE_MSB],size + 4);
	tls_Put24Bit(&send_buffer[connection][TLS_HT_DATA_START],size);

	DumpHexMem(send_buffer[connection],size + 9);
	send(details[connection].socket,send_buffer[connection],size + 9,0);
}

