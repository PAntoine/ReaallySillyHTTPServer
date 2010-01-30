/*********************************************************************************
 * Name: Decode herders
 * Description:
 *
 * This function will decode the HTTP headers looking for the standard headers
 * that the sever should handle.
 *
 * Date  : 7th March 2009
 * Author: Peter Antoine.
 *
 *********************************************************************************/

#ifndef	__HTTP_SERVER_H__
#define	__HTTP_SERVER_H__

#include <winsock2.h>

/* server name and version */
#define	SERVER_NAME "ReaallyPoorServer/0.1"

#define	MAX_CONNECTIONS	(5)
#define	BUFFER_SIZE		(10 * 1024)

#define	DELIMITER_CRLF	'\n'
#define	DELIMITER_COLON	':'

#define MAX_CERT_SIZE	(2 * 1024)
#define MAX_KEY_SIZE	(1 * 1024)

#define VERSION_2_HEADER	(0x80)
#define TLS_HEADER			(0x16)	/* any random number not 0x80 - so use the first TLS byte */

#define	UINT16(x,y)		((((unsigned char)x) << 8) | (unsigned char)y)
#define	UINT24(x,y,z)	((((((unsigned char)x) << 16) | ((unsigned char)(y)) << 8)) | (unsigned char)z)


typedef enum	
{	
	SC_100_CONTINUE,
	SC_101_SWITCHING_PROTOCOLS,
	SC_200_OK,
	SC_201_CREATED,
	SC_202_ACCEPTED,
	SC_203_NON_AUTHORITATIVE_INFORMATION,
	SC_204_NO_CONTENT,
	SC_205_RESET_CONTENT,
	SC_206_PARTIAL_CONTENT,
	SC_300_MULTIPLE_CHOICES,
	SC_301_MOVED_PERMANENTLY,
	SC_302_FOUND,
	SC_303_SEE_OTHER,
	SC_304_NOT_MODIFIED,
	SC_305_USE_PROXY,
	SC_307_TEMPORARY_REDIRECT,
	SC_400_BAD_REQUEST,
	SC_401_UNAUTHORIZED,
	SC_402_PAYMENT_REQUIRED,
	SC_403_FORBIDDEN,
	SC_404_NOT_FOUND,
	SC_405_METHOD_NOT_ALLOWED,
	SC_406_NOT_ACCEPTABLE,
	SC_407_PROXY_AUTHENTICATION_REQUIRED,
	SC_408_REQUEST_TIME_OUT,
	SC_409_CONFLICT,
	SC_410_GONE,
	SC_411_LENGTH_REQUIRED,
	SC_412_PRECONDITION_FAILED,
	SC_413_REQUEST_ENTITY_TOO_LARGE,
	SC_414_REQUEST_URI_TOO_LARGE,
	SC_415_UNSUPPORTED_MEDIA_TYPE,
	SC_416_REQUESTED_RANGE_NOT_SATISFIABLE,
	SC_417_EXPECTATION_FAILED,
	SC_500_INTERNAL_SERVER_ERROR,
	SC_501_NOT_IMPLEMENTED,
	SC_502_BAD_GATEWAY,
	SC_503_SERVICE_UNAVAILABLE,
	SC_504_GATEWAY_TIME_OUT,
	SC_505_HTTP_VERSION_NOT_SUPPORTED,
	SC_MAX_CODES

} STATUS_CODE_ENUM;


typedef enum
{
	HTTP_COMMAND_BAD,
	HTTP_COMMAND_HEAD,
	HTTP_COMMAND_GET,
	HTTP_COMMAND_POST,
	HTTP_COMMAND_OPTION,
	HTTP_COMMAND_QUIT		// pseudo command - connection dropped

} HTTP_COMMANDS;

typedef enum
{
	STOP_BEING_SILLY,		// bug fix -- quite silly!!!
	GET_G,
	GET_E,
	POST_P,
	POST_O,
	POST_S,
	OPTION_O,
	OPTION_P,
	OPTION_T,
	OPTION_I,
	OPTION_O2,
	OPTION_N
} HTTP_COMMAND_LETTERS;

typedef enum
{
	HTH_CACHE_CONTROL,
	HTH_CONNECTION,
	HTH_DATE,
	HTH_PRAGMA,
	HTH_TRAILER,
	HTH_TRANSFER_ENCODING,
	HTH_UPGRADE,
	HTH_VIA,
	HTH_WARNING,
	HTH_ACCEPT,
	HTH_ACCEPT_CHARSET,
	HTH_ACCEPT_ENCODING,
	HTH_ACCEPT_LANGUAGE,
	HTH_AUTHORIZATION,
	HTH_EXPECT,
	HTH_FROM,
	HTH_HOST,
	HTH_IF_MATCH,
	HTH_IF_MODIFIED_SINCE,
	HTH_IF_NONE_MATCH,
	HTH_IF_RANGE,
	HTH_IF_UNMODIFIED_SINCE,
	HTH_MAX_FORWARDS,
	HTH_PROXY_AUTHORIZATION,
	HTH_RANGE,
	HTH_REFERER,
	HTH_TE,
	HTH_USER_AGENT,
	HTH_ACCEPT_RANGES,
	HTH_AGE,
	HTH_ETAG,
	HTH_LOCATION,
	HTH_PROXY_AUTHENTICATE,
	HTH_RETRY_AFTER,
	HTH_SERVER,
	HTH_VARY,
	HTH_WWW_AUTHENTICATE,
	HTH_ALLOW,
	HTH_CONTENT_ENCODING,
	HTH_CONTENT_LANGUAGE,
	HTH_CONTENT_LENGTH,
	HTH_CONTENT_LOCATION,
	HTH_CONTENT_MD5,
	HTH_CONTENT_RANGE,
	HTH_CONTENT_TYPE,
	HTH_EXPIRES,
	HTH_LAST_MODIFIED,
	HTH_EXTENSION_HEADER,
	HTH_MAX_CODES

} HTTP_HEADER;

typedef enum
{
		TLS_NULL_WITH_NULL_NULL,
		TLS_RSA_WITH_NULL_MD5,
		TLS_RSA_WITH_NULL_SHA,
		TLS_RSA_WITH_NULL_SHA256,
		TLS_RSA_WITH_RC4_128_MD5,
		TLS_RSA_WITH_RC4_128_SHA,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA256,
		TLS_RSA_WITH_AES_256_CBC_SHA256,
		TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
		TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
		TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_DH_DSS_WITH_AES_128_CBC_SHA,
		TLS_DH_RSA_WITH_AES_128_CBC_SHA,
		TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_DH_DSS_WITH_AES_256_CBC_SHA,
		TLS_DH_RSA_WITH_AES_256_CBC_SHA,
		TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
		TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
		TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
		TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
		TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
		TLS_DH_anon_WITH_RC4_128_MD5,
		TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
		TLS_DH_anon_WITH_AES_128_CBC_SHA,
		TLS_DH_anon_WITH_AES_256_CBC_SHA,
		TLS_DH_anon_WITH_AES_128_CBC_SHA256,
		TLS_DH_anon_WITH_AES_256_CBC_SHA256,
		TLS_MAX_CIPHERS
} TLS_CIPHER;

typedef	enum
{
	MT_HTML,
	MT_CSS,
	MT_JPEG,
	MT_PNG,
	MT_TIFFM,
	MT_TIFFI,
	MT_MPEG,
	MT_MAX_TYPES

} MIME_TYPE;

typedef enum
{
	CT_CHANGE_CIPHER_SPEC = 20,
	CT_ALERT,
	CT_HANDSHAKE,
	CT_APPLICATION_DATA
} CONTENT_TYPE;

typedef enum
{
	AD_CLOSE_NOTIFY					= 0,
	AD_UNEXPECTED_MESSAGE			= 10,
	AD_BAD_RECORD_MAC				= 20,
	AD_DECRYPTION_FAILED_RESERVED	= 21,
	AD_RECORD_OVERFLOW				= 22,
	AD_DECOMPRESSION_FAILURE		= 30,
	AD_HANDSHAKE_FAILURE			= 40,
	AD_NO_CERTIFICATE_RESERVED		= 41,
	AD_BAD_CERTIFICATE				= 42,
	AD_UNSUPPORTED_CERTIFICATE		= 43,
	AD_CERTIFICATE_REVOKED			= 44,
	AD_CERTIFICATE_EXPIRED			= 45,
	AD_CERTIFICATE_UNKNOWN			= 46,
	AD_ILLEGAL_PARAMETER			= 47,
	AD_UNKNOWN_CA					= 48,
	AD_ACCESS_DENIED				= 49,
	AD_DECODE_ERROR					= 50,
	AD_DECRYPT_ERROR				= 51,
	AD_EXPORT_RESTRICTION_RESERVED	= 60,
	AD_PROTOCOL_VERSION				= 70,
	AD_INSUFFICIENT_SECURITY		= 71,
	AD_INTERNAL_ERROR				= 80,
	AD_USER_CANCELED				= 90,
	AD_NO_RENEGOTIATION				= 100,
	AD_UNSUPPORTED_EXTENSION		= 110

} ALERT_DESCRIPTION;

typedef enum
{
	HT_HELLO_REQUEST		= 0,
	HT_CLIENT_HELLO			= 1,
	HT_SERVER_HELLO			= 2,
	HT_CERTIFICATE			= 11,
	HT_SERVER_KEY_EXCHANGE 	= 12,
	HT_CERTIFICATE_REQUEST	= 13,
	HT_SERVER_HELLO_DONE	= 14,
	HT_CERTIFICATE_VERIFY	= 15,
	HT_CLIENT_KEY_EXCHANGE	= 16,
	HT_FINISHED				= 20
} HANDSHAKE_TYPE;

typedef enum
{
	KEA_NULL,					/* EVIL!! never to be used */
	KEA_RSA,
	KEA_DH_DSS,
	KEA_DH_RSA,
	KEA_DHE_DSS,
	KEA_DHE_RSA,
	KEA_DH_ANON
} KEY_EXCHANGE_ALGORITHM;

typedef enum
{
	MAC_NULL,					/* EVIL!! must not be used */
	MAC_MD5,
	MAC_SHA,
	MAC_SHA256
} MAC_TYPES;

typedef enum
{
	C_NULL,						/* EVIL!!! as above */
	C_RC4_128,
	C_3DES_EDE_CBC,
	C_AES_128_CBC,
	C_AES_256_CBC
} CIPHER_TYPES;

typedef enum
{
	PEMFT_CERTIFICATE,
	PEMFT_RSA_PRIVATE_KEY

} PEM_FILE_TYPES;

/*-----------------------------------------------------------------------------*
 *  Structures required by the code.
 *-----------------------------------------------------------------------------*/

typedef struct
{
	unsigned char*	type_name;
	unsigned int	type_name_length;
} PEM_NAME_ENTRY;


typedef	struct
{
	MIME_TYPE		mime_type;
	unsigned char	magic_number[2];
	char			*mime_name;
	int				length;
	char			**file_extenstions;

} MIME_LOOK_UP;

typedef struct
{
	unsigned int	weight;
	char			sig[2];
	unsigned char	key_exchange_algorithm;
	unsigned char	cipher_type;
	unsigned char	mac_type;

} CIPHER_LIST;

typedef struct
{
	unsigned int	size;
	unsigned char*	certificate;

} CERTIFICATE;

typedef	struct
{
	unsigned char	client_version_major;
	unsigned char	client_version_minor;
	unsigned char	session_id[32];
	unsigned char	client_random[32];
	unsigned char	server_random[32];
	unsigned int	compression_method;
	unsigned int	cipher;				/* the cipher that we have chosen */
	unsigned char	compresson_method;
	unsigned int	client_key_size;	/* in bits */
	unsigned int	server_key_size;	/* in bits */
	unsigned char	client_key[512];	/* sent by the client */
	unsigned char	server_key[512];	/* we generate */

} TLS_SECURITY;

typedef struct
{
	unsigned int	connection;
	SOCKET			socket;
	char			in_use;
	char			is_secure;
	char			user[32];
	char			passwd[32];
	unsigned int	retry_count;
	TLS_SECURITY	sec_details;
} CONNECTION_DETAILS;

/*-----------------------------------------------------------------------------*
 *  TLS packet static offsets.
 *-----------------------------------------------------------------------------*/
#define TLS_CONTENT_TYPE		(0)
#define	TLS_CT_VERSION_MAJOR	(1)
#define	TLS_CT_VERSION_MINOR	(2)
#define TLS_CT_SIZE_MSB			(3)
#define TLS_CT_SIZE_LSB			(4)
#define TLS_CT_START			(5)

/*-----------------------------------------------------------------------------*
 *  TLS packet HANDSHAKE offsets.
 *-----------------------------------------------------------------------------*/
#define TLS_HT_TYPE				(TLS_CT_START + 0)
#define TLS_HT_SIZE_BYTE_1		(TLS_CT_START + 1)
#define TLS_HT_SIZE_BYTE_2		(TLS_CT_START + 2)
#define TLS_HT_SIZE_BYTE_3		(TLS_CT_START + 3)
#define TLS_HT_DATA_START		(TLS_CT_START + 4)

/*-----------------------------------------------------------------------------*
 *  ServerHello offsets
 *  These are from message start.
 *-----------------------------------------------------------------------------*/
#define	TLS_SHO_VERSION_MAJOR	(TLS_HT_DATA_START)
#define	TLS_SHO_VERSION_MINOR	(TLS_HT_DATA_START + 1)
#define	TLS_SHO_RANDOM			(TLS_HT_DATA_START + 2)
#define TLS_SHO_SESSION_ID		(TLS_HT_DATA_START + 34)

/*-----------------------------------------------------------------------------*
 *  The TLS message functions.
 *-----------------------------------------------------------------------------*/
void	tls_ConnectionAlert(unsigned int connection);
void	tls_SendServerHello(unsigned int connection);
void	tls_SendCertificate(unsigned int connection, unsigned int number_of_certs, CERTIFICATE* cert_chain);
void	tls_SendServerHelloDone(unsigned int connection);
void	tls_SendChangeCipher(unsigned int connection);
void	tls_SendFinished(unsigned int connection);

/*-----------------------------------------------------------------------------*
 *  The TLS encryption functions.
 *-----------------------------------------------------------------------------*/
int		tls_EncryptData (unsigned int conneciton, unsigned char* dest_buffer, unsigned int dest_size, unsigned char* source_buffer, unsigned char source_size );
void	tls_HMACHash (unsigned int connection, unsigned char* text, unsigned int text_length,unsigned char* key, unsigned int key_length, unsigned char* hmac);

/*-----------------------------------------------------------------------------*
 *  The MD5 Hash functions
 *-----------------------------------------------------------------------------*/
void 			tls_MD5Setup ( void );
void			tls_MD5Init ( unsigned int* md5_digest );
unsigned int	tls_MD5Hash ( unsigned char* input_buffer, unsigned int input_size_bits, unsigned int* md5_digest );
void			tls_MD5Finish ( unsigned char* input_buffer, unsigned int input_size_bits, unsigned int* md5_digest, unsigned int total_bits, unsigned char* md5_hash );
void 			tls_MD5HMACHash (unsigned char* kpad,unsigned char *text,unsigned int text_length,unsigned char* digest);

#endif
