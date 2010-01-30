/***************************************************************************************
 *
 *       Filename:  RSA_PublicCrypto.h
 *
 *    Description:  This file holds the structures for the RSA public key cryptography
 *                  functions.
 *
 *
 *        Version:  1.0
 *        Created:  21/01/2010 19:58:22
 *       Revision:  none
 *
 *         Author:  Peter Antoine
 *          Email:  me@peterantoine.me.uk
 *
 *------------------------------------------------------------------------------------- 
 *                         Copyright (c) 2010 : Peter Antoine
 *                        Released under the Artistic License.
 ***************************************************************************************/

#ifndef	__RSA_PUBLIC_KEY_H__
#define	__RSA_PUBLIC_KEY_H__

/*-----------------------------------------------------------------------------*
 *  RSA Public Key Functions
 *-----------------------------------------------------------------------------*/
typedef struct
{
	unsigned int	modulus_length;			/* representation 1 of the private key */
	unsigned int	primes_length;			/* representation 2 of the private key */
	unsigned long	version;
	unsigned long	public_exponent;		/* e */
	unsigned char	modulus[256];			/* n - same length as private exponent */
	unsigned char	private_exponent[256];	/* d */
	unsigned char	prime1[128];			/* p - all the following are the same length */
	unsigned char	prime2[128];			/* q */
	unsigned char	exponent1[128];			/* d mod (p - 1) */
	unsigned char	exponent2[128];			/* d mod (q -1 ) */
	unsigned char	coefficient[128];		/* (inverse of q) mod p */

} RSA_PRIVATE_KEY;


#endif

