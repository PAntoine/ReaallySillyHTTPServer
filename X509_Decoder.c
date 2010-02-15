/***************************************************************************************
 *
 *       Filename:  X509_Decoder.c
 *
 *    Description:  This file holds the functions that are used to decode an X509
 *                  certificate.
 *
 *                  Enjoy this XML inspired piece of utter w**k.
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

#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include "X509_encoding.h"
#include "ASN1_decoder.h"

/*-----------------------------------------------------------------------------*
 *  X509 Constant Strings
 *-----------------------------------------------------------------------------*/
static const unsigned char	id_pkix[] = {0x2b,0x06,0x01,0x05,0x05,0x07};
static const unsigned char	id_pkcs[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01};
static const unsigned char	id_ansi[] = {0x2a,0x86,0x48,0xce,0x3d};

static const unsigned char	id_ce[]	= {0x55,0x1d};

static const unsigned char id_holdInstruction[] = {0x52,0x86,0x48,0xce,0x38,0x02};
static const unsigned char id_domainComponent[] = {0x09,0x92,0x26,0x89,0x93,0xf2,0x2c,0x64,0x01,0x19};


static const unsigned char md2_with_rsa[]	= {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x02};
static const unsigned char md5_with_rsa[]	= {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x04};
static const unsigned char sha1_with_rsa[]	= {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05};
static const unsigned char sha1_with_dsa[]	= {0x2a,0x86,0x48,0xce,0x38,0x04,0x03};
static const unsigned char sha1_with_ecdsa[]= {0x2a,0x86,0x48,0xce,0x3d,0x04,0x01};

static const unsigned char md2[] =	{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x02};
static const unsigned char md5[] =	{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05};

/* public key IDs */
static const unsigned char rsa[]	= {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01};
static const unsigned char dsa[]	= {0x2a,0x86,0x48,0xce,0x38,0x04,0x01};
static const unsigned char dh[]		= {0x2a,0x86,0x48,0xce,0x3e,0x02,0x01};
static const unsigned char sha1[]	= {0x2b,0x0e,0x03,0x02,0x1a};
static const unsigned char kea[]	= {0x38,0x86,0x48,0x01,0x65,0x02,0x01,0x01};
static const unsigned char ecd[]	= {0x2a,0x86,0x48,0xce,0x3d,0x01};			// ECDSA and ECDH

/*-----------------------------------------------------------------------------*
 *  X509 Signature Matrix
 *-----------------------------------------------------------------------------*/
typedef struct
{
	unsigned const char*		sig_string;
	unsigned int				sig_length;
	X509_SIGNATURE_ALGORITHM	algorithm;
} SIG_MATRIX;

static	SIG_MATRIX	sig_matrix[]	= { { md2_with_rsa		,sizeof(md2_with_rsa)	, X509SA_RSA_MD2	},
										{ md5_with_rsa		,sizeof(md5_with_rsa)	, X509SA_RSA_MD5	},
										{ sha1_with_rsa		,sizeof(sha1_with_rsa)	, X509SA_RSA_SHA1	},
										{ sha1_with_dsa		,sizeof(sha1_with_dsa)	, X509SA_DSA_SHA1	},
										{ sha1_with_ecdsa	,sizeof(sha1_with_ecdsa), X509SA_ECDSA_SHA1	}};

#define	NUMBER_OF_SIGNATURE_ALGOS	((sizeof(sig_matrix)/sizeof(sig_matrix[0])))


/*-----------------------------------------------------------------------------*
 *  X509 Encryption Algorithm Matrix
 *-----------------------------------------------------------------------------*/
typedef struct
{
	unsigned const char*		alg_string;
	unsigned int				alg_length;
	X509_PUBLIC_KEY_ALGORITHM	algorithm;
} ENCRYPT_MATRIX;

static	ENCRYPT_MATRIX	encrypt_matrix[]	= { { rsa ,sizeof(rsa)	, X509PKA_RSA  },
												{ dsa ,sizeof(dsa)	, X509PKA_DSA  },
												{ dh  ,sizeof(dh)	, X509PKA_DH   },
												{ kea ,sizeof(kea)	, X509PKA_KEA  },
												{ ecd ,sizeof(ecd)	, X509PKA_ECDSA}};
#define	NUMBER_OF_ENCRYPTIONS	((sizeof(encrypt_matrix)/sizeof(encrypt_matrix[0])))


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  X509_DecodeSignatureAlgorithm
 *  Description:  This function will detect and decode the signature algorithm. It will
 *                also extract any parameters that are required for the algorithm.
 *-------------------------------------------------------------------------------------*/
static	unsigned int X509_DecodeSignatureAlgorithm ( ASN1_OBJECT* object, SIGNATURE* algorithm )
{
	unsigned int	count;
	unsigned int	result = 0;
	unsigned int	have_prameters;
	ASN1_OBJECT		sub_item;

	if (ASN1_GetNextObject(object,&sub_item) && ASN1_CHECK_OBJECT(sub_item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_OBJECT_IDENTIFIER_TYPE) )
	{
		for (count=0;count < NUMBER_OF_SIGNATURE_ALGOS;count++)
		{
			if (sub_item.length == sig_matrix[count].sig_length && memcmp(sub_item.data,sig_matrix[count].sig_string,sub_item.length) == 0)
			{
				/* found the signature */
				algorithm->algorithm = sig_matrix[count].algorithm;
				break;
			}
		}
	}

	have_prameters = ASN1_GetNextObject(object,&sub_item) && !ASN1_CHECK_OBJECT(sub_item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_NULL_TYPE);

	/* lets now check for any parameters that exist */
	switch (algorithm->algorithm)
	{
		case X509SA_RSA_MD2:
		case X509SA_RSA_MD5:
		case X509SA_RSA_SHA1:
			if (!have_prameters)
			{
				/* the RSA's don't have parameters */
				result = 1;
			}
			break;

		case X509SA_DSA_SHA1:
			/* find any parameters - this should depend on the type */
			while (ASN1_GetNextObject(object,&sub_item) && !ASN1_CHECK_OBJECT(sub_item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_NULL_TYPE))
			{
				printf("We have parameters: \n");
			}
			break;

		case X509SA_ECDSA_SHA1:
			break;
	}

	return result;
}


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  X509_DecodeValidity
 *  Description:  This function will decode the validity object and convert the two
 *                dates to the "struct tm" dates.
 *-------------------------------------------------------------------------------------*/
static unsigned int X509_DecodeValidity ( ASN1_OBJECT* object, X509_CERTIFICATE* certificate )
{
	unsigned int result	= 0;
	ASN1_OBJECT	sub_item;

	if (ASN1_GetNextObject(object,&sub_item))
	{
		if (ASN1_CHECK_OBJECT(sub_item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_UTC_TIME_TYPE))
		{
			/* time is UTC */
			result = ANS1_DecodeUTCTime(&sub_item,&certificate->start_time);

		}
		else if (ASN1_CHECK_OBJECT(sub_item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_GENERALIZED_TIME_TYPE))
		{
			/* time is generalised */
			printf("genralised time\n");
		}
	}

	if (result && ASN1_GetNextObject(object,&sub_item))
	{
		if (ASN1_CHECK_OBJECT(sub_item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_UTC_TIME_TYPE))
		{
			/* time is UTC */
			result = ANS1_DecodeUTCTime(&sub_item,&certificate->start_time);

		}
		else if (ASN1_CHECK_OBJECT(sub_item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_GENERALIZED_TIME_TYPE))
		{
			/* time is generalised */
			printf("generalised time\n");
		}
	}
	return result;
}


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  X509_DecodePublicKey
 *  Description:  This function will decode the public key structure.
 *-------------------------------------------------------------------------------------*/
static unsigned int X509_DecodePublicKey ( ASN1_OBJECT* object, X509_CERTIFICATE* certificate )
{
	unsigned int	count;
	unsigned int	result = 0;
	ASN1_OBJECT		item;
	ASN1_OBJECT		encryption;
	ASN1_OBJECT		sub_item;

	if (ASN1_GetNextObject(object,&item) && ASN1_CHECK_OBJECT(item,A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE))
	{
		if (ASN1_GetNextObject(&item,&sub_item) && ASN1_CHECK_OBJECT(sub_item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_OBJECT_IDENTIFIER_TYPE) )
		{
			for (count = 0; count < NUMBER_OF_ENCRYPTIONS; count++)
			{
				if (sub_item.length == encrypt_matrix[count].alg_length && memcmp(sub_item.data,encrypt_matrix[count].alg_string,sub_item.length) == 0)
				{
					/* found the signature */
					certificate->public_key.encryption = encrypt_matrix[count].algorithm;
					break;
				}
			}

			result = 1;
		}
	}

	if (result && ASN1_GetNextObject(object,&item) && ASN1_CHECK_OBJECT(item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_BITSTRING_TYPE) )
	{
		switch(certificate->public_key.encryption)
		{
			case X509PKA_RSA:
				if (ASN1_GetObject(&item.data[1],&encryption) && ASN1_CHECK_OBJECT(encryption,A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE))
				{
					/* RSA keys are modulus and publicExponent */
					if (ASN1_GetNextObject(&encryption,&item) && ASN1_CHECK_OBJECT(item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE))
					{
						if (item.data[0] == 0x00)
						{
							memcpy(certificate->public_key.key.rsa.modulus,&item.data[1],item.length-1);
							certificate->public_key.key.rsa.modulus_size = (item.length-1) * 8;
						}
						else
						{
							memcpy(certificate->public_key.key.rsa.modulus,item.data,item.length);
							certificate->public_key.key.rsa.modulus_size = item.length * 8;
						}

						if (ASN1_GetNextObject(&encryption,&item) && ASN1_CHECK_OBJECT(item,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE))
						{
							certificate->public_key.key.rsa.exponent = ASN1_DecodeInteger(&item);

							result = 1;
						}
					}
				}
				break;

			case X509PKA_DSA:	break;
			case X509PKA_DH:	break;
			case X509PKA_KEA:	break;
			case X509PKA_ECDSA:	break;
			default:
				result = 0;
		}
	} else {
		result = 0;
	}

	return result;
}


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  X509_DecodeExtensions
 *  Description:  This function will decode the extensions.
 *-------------------------------------------------------------------------------------*/
unsigned int	X509_DecodeExtensions ( ASN1_OBJECT* object, X509_CERTIFICATE* certificate )
{
	unsigned int	result = 1;
	unsigned int	count;
	unsigned int	critical = 0;
	ASN1_OBJECT		item;
	ASN1_OBJECT		sub_item;
	ASN1_OBJECT		element;
	ASN1_OBJECT		payload;
	ASN1_OBJECT		sub_element;
	ASN1_OBJECT		sub_sub_element;		/* f**king XMLers */



	if (ASN1_GetNextObject(object,&item) && ASN1_CHECK_OBJECT(item,A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE))
	{
		while (ASN1_GetNextObject(&item,&sub_item) && ASN1_CHECK_OBJECT(sub_item,A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE))
		{
			if (ASN1_GetNextObject(&sub_item,&element) && ASN1_CHECK_OBJECT(element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_OBJECT_IDENTIFIER_TYPE) )
			{
				if (ASN1_GetNextObject(&sub_item,&payload) && ASN1_CHECK_OBJECT(payload,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_BOOLEAN_TYPE) )
				{
					/* X509 are C**kMonkeys!!! Why not just make the critical boolean Mandatory!!! */
					critical = payload.data[0];
					ASN1_GetNextObject(&sub_item,&payload);
				}

				if (((unsigned short)element.data[0] == (unsigned short)id_ce[0]) && ASN1_CHECK_OBJECT(payload,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_OCTETSTRING_TYPE))
				{
					/* decode the elements and ignore the ones that we don't support */
					switch(element.data[2])
					{
						case X520_ID_CE_AUTHORITYKEYIDENTIFIER:			/* Does not need support, but should be supported  (except when is MUST be. Ahhhh!!!!! ) */
							if (ASN1_GetNextObject(&payload,&sub_element) && ASN1_CHECK_OBJECT(sub_element,A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE))
							{
								if (ASN1_GetNextObject(&sub_element,&sub_sub_element) && ASN1_CHECK_OBJECT(sub_sub_element,A1T_PRIMITIVE,A1C_CONTEXT_SPECIFIC,0))
								{
								}
								else if (ASN1_GetNextObject(&sub_element,&sub_sub_element) && ASN1_CHECK_OBJECT(sub_sub_element,A1T_PRIMITIVE,A1C_CONTEXT_SPECIFIC,1))
								{
									/* I can't be arsed decoding the rest, its pointless */
								}
								else if (ASN1_GetNextObject(&sub_element,&sub_sub_element) && ASN1_CHECK_OBJECT(sub_sub_element,A1T_PRIMITIVE,A1C_CONTEXT_SPECIFIC,2))
								{
									/* as above */
								}
							}
							break;

						case X520_ID_CE_SUBJECTKEYIDENTIFIER:			/* Does not need support, but should be supported */
							if (ASN1_GetNextObject(&payload,&sub_element) && ASN1_CHECK_OBJECT(sub_element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_OCTETSTRING_TYPE))
							{
								/* we havethe subject key ID */
								// hexDump(sub_element.data,sub_element.length);
							}
							break;

						case X520_ID_CE_BASICCONSTRAINTS:				/* must be supported */
							if (ASN1_GetObject(payload.data,&sub_element) && sub_element.length != 0)
							{
								if (ASN1_GetNextObject(&sub_element,&sub_sub_element) && ASN1_CHECK_OBJECT(sub_sub_element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_BOOLEAN_TYPE))
								{
									/* we have the CA flag */
									certificate->public_key.isCA = sub_sub_element.data[0];
								}
							}
							break;

						case X520_ID_CE_KEYUSAGE:						/* must be supported */
							if (ASN1_GetObject(payload.data,&sub_element) && ASN1_CHECK_OBJECT(sub_element,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_BITSTRING_TYPE) )
							{
								/* we have the key usage */
								certificate->public_key.cert_usage = (sub_element.data[1] | (sub_element.data[2] << 8));
							}
							break;

						case X520_ID_CE_CERTIFICATEPOLICIES:			/* must be supported */
								if (critical)
									result = 0;		/* fail is the cert requires this */
							break;

						case X520_ID_CE_SUBJECTALTNAME:					/* must be supported */
								if (critical)
									result = 0;		/* fail is the cert requires this */
							break;

						case X520_ID_CE_NAMECONSTRAINTS:				/* must be supported */
								if (critical)
									result = 0;		/* fail is the cert requires this */
							break;

						case X520_ID_CE_EXTKEYUSAGE:					/* must be supported */
								if (critical)
									result = 0;		/* fail is the cert requires this */
							break;

						case X520_ID_CE_POLICYCONSTRAINTS:				/* must be supported */
								if (critical)
									result = 0;		/* fail is the cert requires this */
							break;

						case X520_ID_CE_INHIBITANYPOLICY:				/* must be supported */		
								if (critical)
									result = 0;		/* fail is the cert requires this */
							break;

						/* none of the following need to be supported */	
						case X520_ID_CE_PRIVATEKEYUSAGEPERIOD:
						case X520_ID_CE_POLICYMAPPINGS:
						case X520_ID_CE_ISSUERALTNAME:
						case X520_ID_CE_SUBJECTDIRECTORYATTRIBUTES:
						case X520_ID_CE_CRLDISTRIBUTIONPOINTS:
						case X520_ID_CE_FRESHESTCRL:
						case X520_ID_CE_CRLNUMBER:
						case X520_ID_CE_ISSUINGDISTRIBUTIONPOINT:
						case X520_ID_CE_DELTACRLINDICATOR:
						case X520_ID_CE_CRLREASONS:
						case X520_ID_CE_CERTIFICATEISSUER:
						case X520_ID_CE_HOLDINSTRUCTIONCODE:
						case X520_ID_CE_INVALIDITYDATE:
							break;
					}
				}
			}
		}
	}
	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  X509_DecodeTBSCertificate
 *  Description:  This function will decode the TBS Certificate part of the certificate.
 *-------------------------------------------------------------------------------------*/
static	unsigned int X509_DecodeTBSCertificate ( ASN1_OBJECT* tbsCert, X509_CERTIFICATE* certificate )
{
	int			result = 1;
	ASN1_OBJECT	sub_object[5];

	if (ASN1_GetNextObject(tbsCert,&sub_object[0]) && ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_CONTEXT_SPECIFIC,0) )
	{
		/* this is a sub-object of CONSTRUCTED TYPE */
		if (ASN1_GetNextObject(&sub_object[0],&sub_object[1]) && ASN1_CHECK_OBJECT(sub_object[1],A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE) )
		{
			certificate->version = ASN1_DecodeInteger(&sub_object[1]);
		} else {
			result = 0;
		}

		/* the serial number */
		if (result && ASN1_GetNextObject(tbsCert,&sub_object[0]) && ASN1_CHECK_OBJECT(sub_object[0],A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_INTEGER_TYPE) )
		{
			certificate->serial_number = result && ASN1_DecodeInteger(&sub_object[0]);
		} else {
			result = 0;
		}

		/* the signature algorithm */
		if (result && ASN1_GetNextObject(tbsCert,&sub_object[0]) && ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE) )
		{
			result = X509_DecodeSignatureAlgorithm(&sub_object[0],&certificate->signature);
		} else {
			result = 0;
		}

		/* decode the issuer name */
		if (result && ASN1_GetNextObject(tbsCert,&sub_object[0]) && ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE) )
		{
			printf("have the subject name \n");
		} else {
			result = 0;
		}

		/* decode the validity */
		if (result && ASN1_GetNextObject(tbsCert,&sub_object[0]) && ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE) )
		{
			result = X509_DecodeValidity(&sub_object[0],certificate);
		} else {
			result = 0;
		}

		/* decode the name */
		if (result && ASN1_GetNextObject(tbsCert,&sub_object[0]) && ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE) )
		{
			printf("have the issuer name \n");
		} else {
			result = 0;
		}

		/* decode the public key information */
		if (result && ASN1_GetNextObject(tbsCert,&sub_object[0]) && ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_UNIVERSAL,A1UC_SEQUENCE_TYPE) )
		{
			result = X509_DecodePublicKey(&sub_object[0],certificate);

		} else {
			result = 0;
		}

		/* lets decode the optional elements */
		while (result && ASN1_GetNextObject(tbsCert,&sub_object[0]))
		{
			if (ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_CONTEXT_SPECIFIC,1) )
			{
				printf("issuer Unique ID\n");
			}
			else if (ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_CONTEXT_SPECIFIC,2))
			{
				printf("subject Unique ID\n");

			}
			else if (ASN1_CHECK_OBJECT(sub_object[0],A1T_CONSTRUCTED,A1C_CONTEXT_SPECIFIC,3))
			{
				result = X509_DecodeExtensions(&sub_object[0],certificate);
			}
			else
			{
				result = 0;
			}
		}
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  X509_DecodeCertificate
 *  Description:  This function will decode the X509 certificate.
 *-------------------------------------------------------------------------------------*/
int X509_DecodeCertificate ( X509_CERTIFICATE* certificate, unsigned char* data )
{
	int				result = 0;
	SIGNATURE		copy_algo;
	ASN1_OBJECT		tbsCert;
	ASN1_OBJECT		container;
	ASN1_OBJECT		signature;
	ASN1_OBJECT		signature_algo;
	
	/* set the defaults */
	memset(certificate,0,sizeof(X509_CERTIFICATE));

	/* lets decode the certificate */
	if (ASN1_GetObject(data,&container))
	{
		if (container.type == A1T_CONSTRUCTED && container.asn1_class == A1C_UNIVERSAL)
		{
			if (ASN1_GetNextObject(&container,&tbsCert))
			{
				result = X509_DecodeTBSCertificate(&tbsCert,certificate);
			}

			if (result && (result = ASN1_GetNextObject(&container,&signature_algo)))
			{
				if ((result = X509_DecodeSignatureAlgorithm(&signature_algo,&copy_algo)))
				{
					/* this one should match the one inside the cert object */
					if (copy_algo.algorithm == certificate->signature.algorithm)
					{
						/* now check the parameters */
						switch(copy_algo.algorithm)
						{
							case X509SA_RSA_MD2:
							case X509SA_RSA_MD5:
							case X509SA_RSA_SHA1:	result = 1;		/* no parameters to check */
													break;

							default:
													result = 0;		/* not supported yet */
													break;
						}
					} else {
						/* fail it if it does not match */
						result = 0;
					}
				}
			}

			if (result && (result = ASN1_GetNextObject(&container,&signature)))
			{
				if ( ASN1_CHECK_OBJECT(signature,A1T_PRIMITIVE,A1C_UNIVERSAL,A1UC_BITSTRING_TYPE) )
				{
					if (certificate->signature.signature_length = ASN1_DecodeBitString(&signature,certificate->signature.signature,256) > 0)
					{
						result = 1;
					}
				}
				else
				{
					result = 0;
				}
			}
		}
	}

	if (result)
	{
//		result = X509_ValidateCertificate(data,certificate);
	}

	return result;
}



