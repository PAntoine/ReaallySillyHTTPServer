/*-------------------------------------------------------------------------------------*
 *
 * name:  sasl.h
 * proj:  Miniweb browser version 3
 *
 * desc:  stuff.
 *
 * auth:  Peter Antoine  
 * date:  02/09/10
 *
 *               Copyright (c) 2009 Miniweb Interactive.
 *                       All rights Reserved.
 *-------------------------------------------------------------------------------------*/

#ifndef  __SASL_H__
#define  __SASL_H__

typedef	struct
{
	unsigned int			digest_length;
	unsigned int			hmac_block_size;
	HNUT_SASL_HASH_FUNC		hash_function;
	HNUT_SASL_HMAC_FUNC		hmac_hash;
	HNUT_SASL_KEYED_FUNC	keyed_hash;

} HNUT_SASL_HASH;


typedef struct
{
	HNUT_SASL_SECRECT_TYPE	type;
	unsigned char			user_name[HNUT_MAX_USER_NAME_LENGTH];
	unsigned char
	unsigned char			secret;

static	HNUT_SASL_HASH	hmut_hash[] = { 
										{16,64,	HNMD5_Hash,	HNMD5_HMACHash,	HNMD5_MakeKeyedHash	}, 		/* MD5 definition */
										{20,64,	HNSHA1_Hash,HNSHA1_HMACHash,HNSHA1_MakeKeyedHash} 		/* SHA1 definition */
									};

/*
        realm             = "realm" "=" <"> realm-value <">
        realm-value       = qdstr-val
        nonce             = "nonce" "=" <"> nonce-value <">
        nonce-value       = qdstr-val
        qop-options       = "qop" "=" <"> qop-list <">
        qop-list          = 1#qop-value
        qop-value         = "auth" | "auth-int" | "auth-conf" | token
        stale             = "stale" "=" "true"
        maxbuf            = "maxbuf" "=" maxbuf-value
        maxbuf-value      = 1*DIGIT
        charset           = "charset" "=" "utf-8"
        algorithm         = "algorithm" "=" "md5-sess"
        cipher-opts       = "cipher" "=" <"> 1#cipher-value <">
        cipher-value      = "3des" | "des" | "rc4-40" | "rc4" | "rc4-56" | token
        auth-param        = token "=" ( token | quoted-string )
*/

/* DIGEST Challenge */
realm
nonce
qop
auth
stale
maxbuf
charset
algorithm
cipher

/* DIGEST response */
username
cnonce
nc
qop
digest-uri
response
cipher
authzid

/* DIGEST response-auth */
rspauth

/* IGNORED if received in step one */
opaque
domain
       
/* IGNORED in step three - not generated */
nextnonce
qop
cnonce
nc

/*
 * Step One:
 *  server ---->[challenge]----> Client
 * Step Two:    opaque
    domain

 *  server <----[response]<----- Client
 * Step Three:
 *  sever  -->[response-auth]--> client
 */
unsigned int	HNUT_SASL_Digest(HNUT_SASL_HASH_TYPE hash_type, HNUT_SASL* sasl, unsigned char* data, unsigned int data_size, unsigned char* output, unsigned int output_size)
{
	switch (sasl->state)
	{
		case HNUT_SASLDS_INITIALISE:
			/* need to generate the challenge */

			sasl->state = HNUT_SASLDS_WAIT_FOR_RESPONSE;
			break;

		case HNUT_SASLDS_WAIT_FOR_RESPONSE:
			/* OK, get the response from client */

			/* generate the response-auth string */

			sasl->state = HNUT_SASLDS_NEGOTIATION_COMPLETE;
			break;

		default:
			break;
	}

	return result;
}

unsigned int	HNUT_SASL_HMAC(HNUT_SASL_HASH_TYPE hash_type, unsigned char* text, unsigned int text_length,unsigned char* key, unsigned int key_length, unsigned char* hmac_digest)
{
	unsigned int	count;
	unsigned char	k_opad[HNUT_HMAC_MAX_BLOCK_SIZE];
	unsigned char	k_ipad[HNUT_HMAC_MAX_BLOCK_SIZE];
	unsigned char	digest[HNUT_HMAC_MAX_RESULT_SIZE];
	unsigned int	result = 0;

	unsigned char*	use_key = key;

	if (hash_type < HNUT_SASL_HFT_MAX_HASH)
	{
		if (key_length > hmut_hash[hash_type].hmac_block_size)
		{
			hmut_hash[hash_type].hash_function(key,key_length,internal_key);
			use_key = internal_key;
			key_length = hmut_hash[hash_type].digest_length;
		}

		/* make the munged keys */
		for (count=0;count<key_length;count++)
		{
			k_opad[count] = use_key[count] ^ 0x5c;
			k_ipad[count] = use_key[count] ^ 0x36;
		}
		for (;count<hmut_hash[hash_type].hmac_block_size;count++)
		{
			/* save a copy */
			k_opad[count] = 0x5c;
			k_ipad[count] = 0x36;
		}

		/* now produce the results */
		hmut_hash[hash_type].HMACHash(k_ipad,text,text_length,digest);
		hmut_hash[hash_type].HMACHash(k_opad,digest,hmut_hash[hash_type].digest_length,hmac_digest);

		/* we produced a HMAC */
		result = 1;
	}

	return result;
}

#endif 


/* $Id$ */

