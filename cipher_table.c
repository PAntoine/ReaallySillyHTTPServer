/***************************************************************************************
 *
 *       Filename:  cipher_table.c
 *
 *    Description:  This file holds the cipher tables and the support functions for
 *                  handling the TLS cipher detection and handshake selection.
 *
 *        Version:  1.0
 *        Created:  20/03/2009 10:12:03
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
#include "http_server.h"

/*-----------------------------------------------------------------------------*
 *  ciphers list
 *  This lists all the ciphers that we know about and has a weighting for
 *  each of them so we can best choose against the cipher that the client
 *  wants to use.
 *-----------------------------------------------------------------------------*/

CIPHER_LIST	ciphers[] ={{0,{ 0x00,0x00 },	KEA_NULL		,C_NULL			,MAC_NULL		},	/* TLS_NULL_WITH_NULL_NULL					*/
						{0,{ 0x00,0x01 },	KEA_RSA			,C_NULL			,MAC_MD5		},	/* TLS_RSA_WITH_NULL_MD5					*/
						{0,{ 0x00,0x02 },	KEA_RSA			,C_NULL			,MAC_SHA		},	/* TLS_RSA_WITH_NULL_SHA					*/
						{0,{ 0x00,0x3B },	KEA_RSA			,C_NULL			,MAC_SHA256		},	/* TLS_RSA_WITH_NULL_SHA256					*/
						{1,{ 0x00,0x04 },	KEA_RSA			,C_RC4_128		,MAC_MD5		},	/* TLS_RSA_WITH_RC4_128_MD5					*/
						{0,{ 0x00,0x05 },	KEA_RSA			,C_RC4_128		,MAC_SHA		},	/* TLS_RSA_WITH_RC4_128_SHA					*/
						{0,{ 0x00,0x0A },	KEA_RSA			,C_3DES_EDE_CBC	,MAC_SHA		},	/* TLS_RSA_WITH_3DES_EDE_CBC_SHA			*/
						{0,{ 0x00,0x2F },	KEA_RSA			,C_AES_128_CBC	,MAC_SHA		},	/* TLS_RSA_WITH_AES_128_CBC_SHA				*/
						{0,{ 0x00,0x35 },	KEA_RSA			,C_AES_256_CBC	,MAC_SHA		},	/* TLS_RSA_WITH_AES_256_CBC_SHA				*/
						{0,{ 0x00,0x3C },	KEA_RSA			,C_AES_128_CBC	,MAC_SHA256		},	/* TLS_RSA_WITH_AES_128_CBC_SHA256			*/
						{0,{ 0x00,0x3D },	KEA_RSA			,C_AES_256_CBC	,MAC_SHA256		},	/* TLS_RSA_WITH_AES_256_CBC_SHA256			*/
						{0,{ 0x00,0x0D },	KEA_DH_DSS		,C_3DES_EDE_CBC	,MAC_SHA		},	/* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA			*/
						{0,{ 0x00,0x10 },	KEA_DH_RSA		,C_3DES_EDE_CBC	,MAC_SHA		},	/* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA			*/
						{0,{ 0x00,0x13 },	KEA_DHE_DSS		,C_3DES_EDE_CBC	,MAC_SHA		},	/* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA		*/
						{0,{ 0x00,0x16 },	KEA_DHE_RSA		,C_3DES_EDE_CBC	,MAC_SHA		},	/* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA		*/
						{0,{ 0x00,0x18 },	KEA_DH_ANON		,C_RC4_128		,MAC_MD5		},	/* TLS_DH_anon_WITH_RC4_128_MD5				*/
						{0,{ 0x00,0x1B },	KEA_DH_ANON		,C_3DES_EDE_CBC	,MAC_SHA		},	/* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA		*/
						{0,{ 0x00,0x30 },	KEA_DH_DSS		,C_AES_128_CBC	,MAC_SHA		},	/* TLS_DH_DSS_WITH_AES_128_CBC_SHA			*/
						{0,{ 0x00,0x31 },	KEA_DH_RSA		,C_AES_128_CBC	,MAC_SHA		},	/* TLS_DH_RSA_WITH_AES_128_CBC_SHA			*/
						{0,{ 0x00,0x32 },	KEA_DHE_DSS		,C_AES_128_CBC	,MAC_SHA		},	/* TLS_DHE_DSS_WITH_AES_128_CBC_SHA			*/
						{0,{ 0x00,0x33 },	KEA_DHE_RSA		,C_AES_128_CBC	,MAC_SHA		},	/* TLS_DHE_RSA_WITH_AES_128_CBC_SHA			*/
						{0,{ 0x00,0x36 },	KEA_DH_DSS		,C_AES_256_CBC	,MAC_SHA		},	/* TLS_DH_DSS_WITH_AES_256_CBC_SHA			*/
						{0,{ 0x00,0x37 },	KEA_DH_RSA		,C_AES_256_CBC	,MAC_SHA		},	/* TLS_DH_RSA_WITH_AES_256_CBC_SHA			*/
						{0,{ 0x00,0x38 },	KEA_DHE_DSS		,C_AES_256_CBC	,MAC_SHA		},	/* TLS_DHE_DSS_WITH_AES_256_CBC_SHA			*/
						{0,{ 0x00,0x39 },	KEA_DHE_RSA		,C_AES_256_CBC	,MAC_SHA		},	/* TLS_DHE_RSA_WITH_AES_256_CBC_SHA			*/
						{0,{ 0x00,0x3E },	KEA_DH_DSS		,C_AES_128_CBC	,MAC_SHA256		},	/* TLS_DH_DSS_WITH_AES_128_CBC_SHA256		*/
						{0,{ 0x00,0x3F },	KEA_DH_RSA		,C_AES_128_CBC	,MAC_SHA256		},	/* TLS_DH_RSA_WITH_AES_128_CBC_SHA256		*/
						{0,{ 0x00,0x40 },	KEA_DHE_DSS		,C_AES_128_CBC	,MAC_SHA256		},	/* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256		*/
						{0,{ 0x00,0x67 },	KEA_DHE_RSA		,C_AES_128_CBC	,MAC_SHA256		},	/* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256		*/
						{0,{ 0x00,0x68 },	KEA_DH_DSS		,C_AES_256_CBC	,MAC_SHA256		},	/* TLS_DH_DSS_WITH_AES_256_CBC_SHA256		*/
						{0,{ 0x00,0x69 },	KEA_DH_RSA		,C_AES_256_CBC	,MAC_SHA256		},	/* TLS_DH_RSA_WITH_AES_256_CBC_SHA256		*/
						{0,{ 0x00,0x6A },	KEA_DHE_DSS		,C_AES_256_CBC	,MAC_SHA256		},	/* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256		*/
						{0,{ 0x00,0x6B },	KEA_DHE_RSA		,C_AES_256_CBC	,MAC_SHA256		},	/* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256		*/
						{0,{ 0x00,0x34 },	KEA_DH_ANON		,C_AES_128_CBC	,MAC_SHA		},	/* TLS_DH_anon_WITH_AES_128_CBC_SHA			*/
						{0,{ 0x00,0x3A },	KEA_DH_ANON		,C_AES_256_CBC	,MAC_SHA		},	/* TLS_DH_anon_WITH_AES_256_CBC_SHA			*/
						{0,{ 0x00,0x6C },	KEA_DH_ANON		,C_AES_128_CBC	,MAC_SHA256		},	/* TLS_DH_anon_WITH_AES_128_CBC_SHA256		*/
						{0,{ 0x00,0x6D },	KEA_DH_ANON		,C_AES_256_CBC	,MAC_SHA256		}};	/* TLS_DH_anon_WITH_AES_256_CBC_SHA256		*/ 

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_CipherLookup
 *  Description:  This function will look up the cipher and return its index.
 *-------------------------------------------------------------------------------------*/

int	tls_CipherLookup (char c1, char c2)
{
	int	count;
	int	result = 0;

	for (count=0;count<TLS_MAX_CIPHERS;count++)
	{
		if (ciphers[count].sig[0] == c1 && ciphers[count].sig[1] == c2)
		{
			printf("found: %02x %02x \n",c1,c2);

			result = count;
			break;
		}
	}
	
	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_SelectCipher
 *  Description:  This function will take the ciphers line from the TLS negotiation
 *                and decide which cipher is going to get used during the life-time
 *                of the session.
 *
 *       params: type		 - 0 = V2 else 1
 *       		 size        - The size in number of entries.
 *               cipher_line - The list of ciphers that the client requests.
 *-------------------------------------------------------------------------------------*/

unsigned int	tls_SelectCipher(unsigned int type, unsigned int size, char* cipher_line)
{
	char			*buffer;
	unsigned int	temp;
	unsigned int	index;
	unsigned int	entry_size;
	unsigned int	line_length;
	unsigned int	result = 0;
	unsigned int	weight = 0;

	if (type == VERSION_2_HEADER)
	{
		entry_size = 3;
		buffer = cipher_line + 1;
	}else{
		entry_size = 2;
		buffer = cipher_line;
	}

	/* Go thru all the items in the clients weighting function, and see if
	 * the item is one we support, and work out a weighting for the different
	 * ciphers that we support. We want to balance there needs vs ours.
	 */
	for (index=0; index < size/entry_size; index++, buffer += entry_size)
	{
		temp = tls_CipherLookup(buffer[0],buffer[1]);

		if (ciphers[temp].weight > weight)
		{
			result = temp;
			weight = ciphers[temp].weight;
		}
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  tls_GetCipher
 *  Description:  This function will look up the cipher and return its signature.
 *-------------------------------------------------------------------------------------*/

void tls_GetCipher(unsigned int cipher, char* buffer)
{
	buffer[0] = ciphers[cipher].sig[0];
	buffer[1] = ciphers[cipher].sig[1];
}

