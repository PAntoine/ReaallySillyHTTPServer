/*--------------------------------------------------------------------------------*
 * Name: Parser Look-up tree
 * Desc: function and data structures to speed up a specific string search
 *
 *         **** DO NOT AMEND THIS CODE - IT IS AUTO_GENERATED ****
 *
 * Code and table produced by:
 *            build_graph 
 *            version 0.1
 *
 *  written by Peter Antoine. 
 *--------------------------------------------------------------------------------*/

#ifndef	__HEADERS_H__
#define __HEADERS_H__

typedef	struct
{
	char*			name;
	unsigned int	length;
} HEADERS_STRING_TABLE;

typedef enum
{
	HST_CACHE_CONTROL,
	HST_CONNECTION,
	HST_DATE,
	HST_PRAGMA,
	HST_TRAILER,
	HST_TRANSFER_ENCODING,
	HST_UPGRADE,
	HST_VIA,
	HST_WARNING,
	HST_ACCEPT,
	HST_ACCEPT_CHARSET,
	HST_ACCEPT_ENCODING,
	HST_ACCEPT_LANGUAGE,
	HST_AUTHORIZATION,
	HST_EXPECT,
	HST_FROM,
	HST_HOST,
	HST_IF_MATCH,
	HST_IF_MODIFIED_SINCE,
	HST_IF_NONE_MATCH,
	HST_IF_RANGE,
	HST_IF_UNMODIFIED_SINCE,
	HST_MAX_FORWARDS,
	HST_PROXY_AUTHORIZATION,
	HST_RANGE,
	HST_REFERER,
	HST_TE,
	HST_USER_AGENT,
	HST_ACCEPT_RANGES,
	HST_AGE,
	HST_ETAG,
	HST_LOCATION,
	HST_PROXY_AUTHENTICATE,
	HST_RETRY_AFTER,
	HST_SERVER,
	HST_VARY,
	HST_WWW_AUTHENTICATE,
	HST_ALLOW,
	HST_CONTENT_ENCODING,
	HST_CONTENT_LANGUAGE,
	HST_CONTENT_LENGTH,
	HST_CONTENT_LOCATION,
	HST_CONTENT_MD5,
	HST_CONTENT_RANGE,
	HST_CONTENT_TYPE,
	HST_EXPIRES,
	HST_LAST_MODIFIED,
	HST_EXTENSION_HEADER,
	HST_KEEP_ALIVE
} HST_HEADERS;

int	headers_check_word(char* word);
HEADERS_STRING_TABLE	headers_table[49];
#endif
