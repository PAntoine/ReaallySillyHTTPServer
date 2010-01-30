/*********************************************************************************
 * Name: tables
 * Description:
 *
 * This file holds the text tables for the server.
 *
 * Date  : 15th February 2009
 * Author: Peter Antoine. 
 *
 *********************************************************************************/

#include "http_server.h"

/* define the mime type tables */
char	*htmls[] = {"htm","html",NULL};
char	*jpegs[] = {"jpg",NULL};
char	*pngs[] = {"png",NULL};
char	*csss[] = {"css",NULL};
char	*tiffs[] = {"tif",NULL};
char	*mpegs[] = {"mpg","mpeg",NULL};
char	*ukwns[] = {"unknown",NULL};

const	MIME_LOOK_UP	mime_lookup[MT_MAX_TYPES+1] = {	{MT_HTML,	{0,0},			"text/html",	sizeof("text/html")-1,	htmls},
														{MT_CSS,	{0,0},			"text/css",		sizeof( "text/css")-1,	csss},
														{MT_JPEG,	{0xff,0xd8},	"image/jpeg",	sizeof("image/jpeg")-1,	jpegs},
														{MT_PNG,	{0x89,0x50},	"image/png", 	sizeof("image/png")-1,	pngs},
														{MT_TIFFM,	{0x4d,0x4d},	"image/tiff",	sizeof("image/tiff")-1,	tiffs},
														{MT_TIFFI,	{0x49,0x49},	"image/tiff",	sizeof("image/tiff")-1,	tiffs},
														{MT_MPEG,	{0,0},			"image/mpeg",	sizeof("image/mpeg")-1,	mpegs},
														/* must be the last one */                            
														{MT_MAX_TYPES,{0,0},		"text/plain",	sizeof("text/plain")-1,	ukwns}};

const char message_start[]	= "HTTP/1.1 ";
const char error_start[]	= "<HTML><HEAD><TITLE>";
const char error_middle[]	= "</TITLE></HEAD><BODY>";
const char error_end[]		= "</BODY></HTML>"; 

int message_start_size	= sizeof(message_start) - 1;
int error_start_size	= sizeof(error_start) - 1;
int error_middle_size	= sizeof(error_middle) - 1;
int error_end_size		= sizeof(error_end) - 1;

unsigned int	status_code_size[SC_MAX_CODES];
const	char *status_code[] = {	{"100 Continue"},
								{"101 Switching Protocols"},
								{"200 OK"},
								{"201 Created"},
								{"202 Accepted"},
								{"203 Non-Authoritative Information"},
								{"204 No Content"},
								{"205 Reset Content"},
								{"206 Partial Content"},
								{"300 Multiple Choices"},
								{"301 Moved Permanently"},
								{"302 Found"},
								{"303 See Other"},
								{"304 Not Modified"},
								{"305 Use Proxy"},
								{"307 Temporary Redirect"},
								{"400 Bad Request"},
								{"401 Unauthorized"},
								{"402 Payment Required"},
								{"403 Forbidden"},
								{"404 Not Found"},
								{"405 Method Not Allowed"},
								{"406 Not Acceptable"},
								{"407 Proxy Authentication Required"},
								{"408 Request Time-out"},
								{"409 Conflict"},
								{"410 Gone"},
								{"411 Length Required"},
								{"412 Precondition Failed"},
								{"413 Request Entity Too Large"},
								{"414 Request-URI Too Large"},
								{"415 Unsupported Media Type"},
								{"416 Requested range not satisfiable"},
								{"417 Expectation Failed"},
								{"500 Internal Server Error"},
								{"501 Not Implemented"},
								{"502 Bad Gateway"},
								{"503 Service Unavailable"},
								{"504 Gateway Time-out"},
								{"505 HTTP Version not supported"}};

