/***************************************************************************************
 *
 *       Filename:  tls_encryption
 *
 *    Description:  This file holds the functions 
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
extern 	CIPHER_LIST			ciphers[];
extern 	CONNECTION_DETAILS	details[MAX_CONNECTIONS];
extern char					send_buffer[MAX_CONNECTIONS][2048];


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_EncryptData
 *  Description:  This function will encrypt the data using the negotiated cipher
 *                suite and keys.
 *
 *                The function return the size of the data encrypted including the
 *                vector size.
 *-------------------------------------------------------------------------------------*/
int	tls_EncryptData (unsigned int conneciton, unsigned char* dest_buffer, unsigned int dest_size, unsigned char* source_buffer, unsigned char source_size )
{
	unsigned int	result = 0;

	if (source_size + 2 <= dest_size)
	{
		/* TODO: Obviously we need to implement the actual encryption stuffs */
		tls_PutWord(dest_buffer,source_size);
		memcpy(dest_buffer,source_buffer,source_size);

		result = 2 + source_size;
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_HMACHash
 *  Description:  This function will generate the HMAC for the given keys.
 *                This function is based on RFC 2104.
 *-------------------------------------------------------------------------------------*/
void	tls_HMACHash (unsigned int connection, unsigned char* text, unsigned int text_length,unsigned char* key, unsigned int key_length, unsigned char* hmac)
{
	unsigned int	count;
	unsigned int	B = 64; 	/* this may change with the hash function */
	unsigned char	k_opad[64];
	unsigned char	k_ipad[64];
	unsigned char	digest[16];

	if (key_length > 64)
	{
		/* hash the key */
		/* dont handle this at the moment */
	}
	else
	{
		/* make the munged keys */
		for (count=0;count<key_length;count++)
		{
			k_opad[count] = key[count] ^ 0x5c;
			k_ipad[count] = key[count] ^ 0x36;
		}
		for (;count<64;count++)
		{
			k_opad[count] = 0x5c;
			k_ipad[count] = 0x36;
		}
	}

	/* now do the Hashes */
	switch(ciphers[details[connection].sec_details.cipher].mac_type)
	{
		case MAC_MD5:	
					tls_MD5HMACHash(k_ipad,text,text_length,digest);
					tls_MD5HMACHash(k_opad,digest,16,hmac);
					break;
//
//		case MAC_SHA:
//					tls_SHA1HMACHash(k_ipad,text,text_length,digest);
//					tls_SHA1HMACHash(k_opad,digest,xx,hmac);
//					break;
//
//		case MAC_SHA256:
//					tls_SHA256HMACHash(k_ipad,text,text_length,digest);
//					tls_SHA256HMACHash(k_opad,digest,yy,hmac);
//					break;
//		default:

					/* only handles MD5 for now */
					/* TODO: you know you need to */
	}

	/* generate the hmac as a TLS vector */
	printf("MD5: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
			hmac[0],hmac[1],hmac[2],hmac[3],
			hmac[4],hmac[5],hmac[6],hmac[7],
			hmac[8],hmac[9],hmac[10],hmac[11],
			hmac[12],hmac[13],hmac[14],hmac[15]);
}

