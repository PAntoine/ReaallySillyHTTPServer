/***************************************************************************************
 *
 *       Filename:  X509 encoding
 *
 *    Description:  This file holds the structures required for holding a X509 encoded
 *                  certificate file.
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

#include <time.h>

/*-----------------------------------------------------------------------------*
 *  X509 algorithm definitions.
 *-----------------------------------------------------------------------------*/
typedef enum
{
	X509SA_NONE,		/* not used - a total failure */
	X509SA_RSA_MD2,
	X509SA_RSA_MD5,
	X509SA_RSA_SHA1,
	X509SA_DSA_SHA1,
	X509SA_ECDSA_SHA1

} X509_SIGNATURE_ALGORITHM;

typedef enum
{
	X509PKA_NONE,			/* failed */
	X509PKA_RSA,
	X509PKA_DSA,
	X509PKA_DH,
	X509PKA_KEA,
	X509PKA_ECDSA,
	X509PKA_ECDH

} X509_PUBLIC_KEY_ALGORITHM;

/*-----------------------------------------------------------------------------*
 *  Basic Structures for the Decode.
 *-----------------------------------------------------------------------------*/

/* structures for the signature algorithm */
typedef struct
{
	unsigned long	not_used;

} RSA_PARAMETERS;

typedef union
{
	RSA_PARAMETERS	rsa_params;

} SIGNATURE_PARAMETERS;

typedef struct
{
	X509_SIGNATURE_ALGORITHM	algorithm;
	SIGNATURE_PARAMETERS		parameters;
	unsigned int				signature_length;	/* in bits */
	unsigned char				signature[256];

} SIGNATURE;

/* structures for the encryption algorithm */
typedef struct
{
	unsigned long	modulus_size;
	unsigned long	exponent;
	unsigned char	modulus[256];

} RSA_PUBLIC_KEY;

typedef union
{
	RSA_PUBLIC_KEY	rsa;

} PUBLIC_KEY_DATA;

typedef struct
{
	unsigned char				isCA;				/* is this certificate a CA cert */
	unsigned int				cert_usage;			/* the usafe flags for the certificate */
	X509_PUBLIC_KEY_ALGORITHM	encryption;			/* the encryption algorithm */
	PUBLIC_KEY_DATA				key;
} PUBLIC_KEY;


/* The certificate structure */
typedef struct
{
	unsigned int	version;
	unsigned int	serial_number;
	struct tm		start_time;
	struct tm		end_time;
	unsigned int	key_length;			/* in bits */
	SIGNATURE		signature;
	PUBLIC_KEY		public_key;

} X509_CERTIFICATE;

/*-----------------------------------------------------------------------------*
 *  X509 enum types
 *-----------------------------------------------------------------------------*/

typedef	enum
{
	X5CPT_VERSION			= 0,
	X5CPT_ISSUER_UNIQUE		= 1,
	X5CPT_SUBJECT_UNIQUE	= 2,
	X5CPT_EXTENSION			= 3

} X509_CONTEXT_SPECIFIC_TAG;


/*-----------------------------------------------------------------------------*
 *  X520 item types
 *  The fun of this committee designed name convention knowns no bounds.
 *-----------------------------------------------------------------------------*/

#define	X520_ID_SIG	(0x55)

/* one of these are thed next bytes after the sig */
typedef enum
{
	X520_ID_AT	= 4,
	X520_ID_CE	= 29		/* HEX 1D */

} X520_TYPES;

/* if the previous byte was a 0x04 */
typedef enum
{
	X520_ID_AT_NAME						= 41,
	X520_ID_AT_SURNAME					= 4,
	X520_ID_AT_GIVENNAME				= 42,
	X520_ID_AT_INITIALS					= 43,
	X520_ID_AT_GENERATIONQUALIFIER 		= 44,
	X520_ID_AT_COMMONNAME				= 3,
	X520_ID_AT_LOCALITYNAME				= 7,
	X520_ID_AT_STATEORPROVINCENAME 		= 8,
	X520_ID_AT_ORGANIZATIONNAME			= 10,
	X520_ID_AT_ORGANIZATIONALUNITNAME 	= 11,
	X520_ID_AT_TITLE					= 12,
	X520_ID_AT_DNQUALIFIER				= 46,
	X520_ID_AT_COUNTRYNAME				= 6,
	X520_ID_AT_SERIALNUMBER				= 5,
	X520_ID_AT_PSEUDONYM				= 65

} X520_ID_AT_FIELDS;

/* if the previous byte 0x1d (29) */
typedef enum
{
	X520_ID_CE_AUTHORITYKEYIDENTIFIER		= 35,
	X520_ID_CE_SUBJECTKEYIDENTIFIER			= 14,
	X520_ID_CE_KEYUSAGE						= 15,
	X520_ID_CE_PRIVATEKEYUSAGEPERIOD		= 16,
	X520_ID_CE_CERTIFICATEPOLICIES			= 32,
	X520_ID_CE_POLICYMAPPINGS				= 33,
	X520_ID_CE_SUBJECTALTNAME				= 17,
	X520_ID_CE_ISSUERALTNAME				= 18,
	X520_ID_CE_SUBJECTDIRECTORYATTRIBUTES 	= 9 ,
	X520_ID_CE_BASICCONSTRAINTS				= 19,
	X520_ID_CE_NAMECONSTRAINTS				= 30,
	X520_ID_CE_POLICYCONSTRAINTS			= 36,
	X520_ID_CE_CRLDISTRIBUTIONPOINTS     	= 31,
	X520_ID_CE_EXTKEYUSAGE 					= 37,
	X520_ID_CE_INHIBITANYPOLICY				= 54,
	X520_ID_CE_FRESHESTCRL					= 46,
	X520_ID_CE_CRLNUMBER					= 20,
	X520_ID_CE_ISSUINGDISTRIBUTIONPOINT		= 28,
	X520_ID_CE_DELTACRLINDICATOR			= 27,
	X520_ID_CE_CRLREASONS					= 21,
	X520_ID_CE_CERTIFICATEISSUER			= 29,
	X520_ID_CE_HOLDINSTRUCTIONCODE			= 23,
	X520_ID_CE_INVALIDITYDATE				= 24

} X520_ID_CE_FIELDS;

/*-----------------------------------------------------------------------------*
 *  PKIX definitions
 *  pubic key infrastructure extensions, more magic committee.
 *-----------------------------------------------------------------------------*/

typedef	enum
{
	PKIXCU_DIGITAL_SIGNATURE	= 0x01,
	PKIXCU_CONTENT_COMMITMENT	= 0x02,
	PKIXCU_KEY_ENCIPHERMENT		= 0x04,
	PKIXCU_DATA_ENCIPHERMENT	= 0x08,
	PKIXCU_KEY_AGREEMENT		= 0x10,
	PKIXCU_KEY_CERT_SIGN		= 0x20,
	PKIXCU_CRL_SIGN				= 0x40,
	PKIXCU_ENCIPHER_ONLY		= 0x80,
	PKIXCU_DECIPHER_ONLY		= 0x01		/* in byte 2 */

} PKIX_CERT_USAGE;

typedef	enum
{
	PKIX_ID_PE	= 1,
	PKIX_ID_QT	= 2,
	PKIX_ID_KP	= 3,
	PKIX_ID_AD	= 48	/* hex: 30 */
} PKIX_OBJECTS;

typedef enum
{
	PKIX_ID_AD_OCSP				= 1,
	PKIX_ID_AD_CAISSUERS		= 2,
	PKIX_ID_AD_TIMESTAMPING		= 3,
	PKIX_ID_AD_CAREPOSITORY		= 5
} PKIX_IS_AD_OBJECTS;

typedef enum
{
	PKIX_ID_KP_SERVERAUTH		= 1,
	PKIX_ID_KP_CLIENTAUTH		= 2,
	PKIX_ID_KP_CODESIGNING		= 3,
	PKIX_ID_KP_EMAILPROTECTION	= 4,
	PKIX_ID_KP_TIMESTAMPING		= 8,
	PKIX_ID_KP_OCSPSIGNING		= 9
} PKIX_IS_KP_OBJECTS;

typedef enum
{
	PKIX_ID_PE_AUTHORITYINFOACCESS	= 1,
	PKIX_ID_PE_SUBJECTINFOACCESS 	= 11
} PKIX_ID_PE_OBJECTS;

typedef enum
{
	PKIX_ID_QT_CPS		= 1,
	PKIX_ID_QT_UNOTICE	= 2
} PKIX_ID_QT_OBJECTS;


/*-----------------------------------------------------------------------------*
 *  PKCS definitions.
 *  RSA specific fields. pkcs-1 -> pkcs-9 The byte that following the id is
 *  the PKCS version. But, this is not consistent (at all).
 *-----------------------------------------------------------------------------*/

/* the following MUST follow a id_pkcs and a 0x01 */
typedef enum
{
	PKCS1_RSA_ENCRYPTION		= 1,
	PKCS1_RSA_MD2_SIGNATURE		= 2,
	PKCS1_RSA_MD5_SIGNATURE		= 4,
	PKCS1_RSA_SHA1_SIGNATURE	= 5

} PKCS_1_ID_OBJECTS;

/* X509 are a bunch of ****'s --- why would you do the following??? */
/* the following MUST follow a id_pkcs and a 0x09 */
typedef enum
{
	PKCS9_EMAIL_ADDRESS			= 1		/* Yes! The f**king email address is defined as an RSA specific type! */
										/* The above is true and not true, pkcs does not really mean RSA,
										 * but only RSA uses this prefix - so kind of stands :) */

} PKCS_1_ID_OBJECTS;


/*-----------------------------------------------------------------------------*
 *  Other random ones.
 *-----------------------------------------------------------------------------*/

typedef enum
{
	ID_HOLDINSTR_NONE		= 1,	/* not used */
	ID_HOLDINSTR_CALLUSER	= 2,
	ID_HOLDINSTR_REJECT		= 3
} ID_HOLDINSTR_OBJECTS;

/*-----------------------------------------------------------------------------*
 *  X509 Decode Functions.
 *-----------------------------------------------------------------------------*/
int	X509_LoadPem ( unsigned char* filename, unsigned char* buffer, unsigned int buffer_size );
int	X509_DecodeCertificate ( X509_CERTIFICATE* certificate, unsigned char* data );

