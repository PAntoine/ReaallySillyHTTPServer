#include <openssl/ssl.h>

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  get_dh1024
 *  Description:  Open SSL generated code.
 *-------------------------------------------------------------------------------------*/
DH* get_dh1024()
{
	static unsigned char dh1024_p[]=
	{
		0xD9,0x80,0x9D,0xF9,0x04,0x4E,0xE2,0x87,0x38,0x25,0x9A,0x13,
		0xE5,0xBE,0x17,0x79,0x0C,0xFD,0xEE,0xF3,0xE4,0x0F,0x21,0x65,
		0xBE,0xCE,0xAB,0x01,0x8C,0x42,0xB5,0x0E,0x68,0x11,0x00,0xAF,
		0x80,0x56,0x79,0x90,0x67,0x1B,0xFF,0x3B,0x86,0x1C,0x19,0x80,
		0xD3,0xFA,0xF7,0xF2,0x94,0x72,0x19,0xBB,0xD7,0x8A,0x9D,0xFC,
		0xFA,0x4E,0xB2,0x90,0x9A,0x50,0x9D,0xB4,0xC7,0xA3,0xDC,0x98,
		0xAB,0xA3,0xA4,0x08,0x1C,0x6B,0xF7,0xF5,0xF4,0x71,0x8C,0x06,
		0x34,0x5A,0xC1,0x03,0x24,0x47,0xDA,0x1A,0x07,0x06,0xB3,0xB9,
		0x04,0xF4,0x97,0x4A,0xD3,0x4C,0xA9,0xAF,0xA4,0xC1,0x1C,0xAD,
		0x04,0x08,0x71,0x55,0xA2,0x8B,0x70,0x99,0x23,0x9E,0x88,0xE7,
		0xAA,0x2A,0x17,0xC6,0xE2,0x18,0xF0,0xFB,
	};

	static unsigned char dh1024_g[]={ 0x02 };

	DH *dh;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
	dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		{ DH_free(dh); return(NULL); }
	return(dh);
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  InitialiseCTX
 *  Description:  This function will initialise the SSL CTX.
 *-------------------------------------------------------------------------------------*/
SSL_CTX*	InitialiseCTX ( char* keyfile, char* certfile )
{
	SSL_METHOD		*meth;
	SSL_CTX			*ctx;
	unsigned int	worked = 0;

	/* we have the initialise the SSL library */
	SSL_library_init();

	/* create the context that will support a SSLv2 or SSLv3 client.  */
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

	/* Ok, now load the certificate and keys
	 * Note: there are memory versions of these so the certs can be
	 *       encoded within the app.
	 */
	if (SSL_CTX_use_certificate_chain_file(ctx,keyfile))
	{
		if (SSL_CTX_use_PrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM))
		{
			if (SSL_CTX_load_verify_locations(ctx,certfile,NULL))
			{
				if (SSL_CTX_set_tmp_dh(ctx,get_dh1024()) >= 0)
				{
					worked = 1;
				}
			}
		}
	}

	if (worked)
	{
		return ctx;
	}
	else
	{
		printf("failed somewhere\n");
		return NULL;
	}
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  SSLAccept
 *  Description:  This function will accept and create the SSL connection on-top of
 *                the standard socket.
 *-------------------------------------------------------------------------------------*/
SSL*	SSLAccept ( SSL_CTX* ctx, int socket )
{
	SSL*	ssl;
	
	/* create the SSL socket */
	ssl = SSL_new(ctx);

	/* add and accept the client's connection */
	SSL_set_fd(ssl, socket);

	if (SSL_accept(ssl) == 1)
	{
		return ssl;
	}
	else
	{
		SSL_free(ssl);
		return NULL;
	}
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  SSLRelease
 *  Description:  This function will release the SSL connection.
 *-------------------------------------------------------------------------------------*/
void SSLRelease ( SSL* ssl )
{
	SSL_free(ssl);              /* release SSL state */
}

#if 0
 /* now you can read/write */
bytes = SSL_read(ssl, buf, sizeof(buf)); /* get HTTP request */
/*...process request */
SSL_write(ssl, reply, strlen(reply));	     /* send reply */
#endif

/* $Id$ */

