/***************************************************************************************
 *
 *       Filename:  RSA_PublicCrypto.c
 *
 *    Description:  This file holds the functions that are used to handle the RSA 
 *                  public crypto stuff.
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

#include "ASN1_decoder.h"
#include "RSA_PublicCrypto.h"

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  RSA_LoadPublicKey
 *  Description:  This function with handle the decoding of the ASN.1 format 
 *-------------------------------------------------------------------------------------*/
int RSA_LoadPublicKey ( RSA_PRIVATE_KEY* key, unsigned char* data  )
{
	int	result = 0;

	ASN1_OBJECT		container;
	ASN1_OBJECT		element;

	if (ASN1_GetObject(data,&container))
	{
		/* version */
		if ((ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			key->version = ASN1_DecodeInteger(&element);
		}

		/* modulus */
		if ((ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			key->modulus_length = ASN1_DecodeLargeInteger(&element,key->modulus,256);
		}

		/* public exponent */
		if (key->modulus_length && (ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			key->public_exponent = ASN1_DecodeInteger(&element);
		}

		/* private exponent */
		if (key->public_exponent && (ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			result = ASN1_DecodeLargeInteger(&element,key->private_exponent,256);
		}

		/* TODO:
		 * I know if any of the ASN1 decodes below fail the it does not invalidate the key
		 * but I really don't care. Should only be using the three above. 
		 * 
		 * This is not to be used for real, just for working out the real stuff.
		 */

		/* prime 1 */
		if ((result && ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			key->primes_length = result && ASN1_DecodeLargeInteger(&element,key->prime1,128);
		}

		/* prime 2 */
		if ((key->primes_length && ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			result = result && ASN1_DecodeLargeInteger(&element,key->prime2,128);
		}

		/* exponent 1 */
		if ((result && ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			result = result && ASN1_DecodeLargeInteger(&element,key->exponent1,128);
		}

		/* exponent 2 */
		if ((result && ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			result = result && ASN1_DecodeLargeInteger(&element,key->exponent2,128);
		}

		/* coefficient */
		if ((result && ASN1_GetNextObject(&container,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE)) )
		{
			result = ASN1_DecodeLargeInteger(&element,key->coefficient,128);
		}
	}

	return result;
}


