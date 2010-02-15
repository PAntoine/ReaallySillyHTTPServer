/*********************************************************************************
 * Name: Decode decode headers
 * Description:
 *
 * This function will decode the HTTP headers looking for the standard headers
 * that the sever should handle.
 *
 * Date  : 7th March 2009
 * Author: Peter Antoine.
 *
 *********************************************************************************/

#include <stdio.h>
#include "headers.h"
#include "http_server.h"

/*------------------------------------------------------------*
 * buffer read functions
 *------------------------------------------------------------*/
extern	int		do_read(SOCKET handle);
extern	char	connection_buffer[MAX_CONNECTIONS][BUFFER_SIZE];
extern	int		buff_pos[MAX_CONNECTIONS];
extern	int		data_read[MAX_CONNECTIONS];
extern CONNECTION_DETAILS	details[MAX_CONNECTIONS];

/*------------------------------------------------------------*
 * external definitions for the header fields.
 *------------------------------------------------------------*/
extern const	char	*general_header[];
extern const	char	*request_header[];
extern const	char	*response_header[];
extern const	char	*entity_header[];
extern const	char	*status_code[][2];


/*-----------------------------------------------------------------------------*
 *  Authorise field names
 *-----------------------------------------------------------------------------*/

static const char*	auth_names[] =
{
	"username",
	"realm",
	"nonce",
	"uri",
	"response",
	"opaque",
	"qop",
	"nc",
	"cnonce",
	"algorithm"
};

enum
{
	AFN_USERNAME,
	AFN_REALM,
	AFN_NONCE,
	AFN_URI,
	AFN_RESPONSE,
	AFN_OPAQUE,
	AFN_QOP,
	AFN_NC,
	AFN_CNONCE,
	AFN_ALGORITHM,
	AFN_NUMBER_OF_AUTH_FIELDS
};

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  DecodeAuthentication
 *  Description:  THis function will decode the Authentication headers and pack them
 *                into the authentication structure for the connection.
 *
 *                It expects that the header buffer is valid and ends with a 0x0a 0x0d.
 *-------------------------------------------------------------------------------------*/
int DecodeAuthentication ( unsigned int connection , unsigned char* buffer, unsigned int buffer_size )
{
	int				count;
	int				index;
	int				result = 0;
	int				offset = 0;
	int				finished = 0;
	unsigned int	name_length;
	unsigned int	value_length;
	unsigned char	output[255];
	unsigned char	field_name[32];
	unsigned char	field_value[80];
	AUTHORISATION	*auth;

	name_length = GetField(field_name,32,&buffer[offset],buffer_size-offset,' ');
	offset += name_length;

	printf("Auth type = %s\n",field_name);

	if (strcmp(field_name,"Basic") == 0)
	{
		/* basic coding */
		decode_base64(output,255,&buffer[offset],buffer_size-offset);
		
		for(count=0;count<32;count++)
		{
			if (output[count] == ':')
			{
				details[connection].user[count] = '\0';
				break;
			}
				
			details[connection].user[count] = output[count];
		}

		for(count++;count<32;count++)
		{
			if (output[count] == ':')
			{
				details[connection].passwd[count] = '\0';
				break;
			}
				
			details[connection].passwd[count] = output[count];
		}
	}
	else if (strcmp(field_name,"Digest") == 0)
	{
		auth = &details[connection].authorisation;

		/* Digest authentication */
		while (offset < buffer_size && !finished)
		{
			name_length = GetField(field_name,32,&buffer[offset],buffer_size-offset,DELIMITER_EQUALS);
			value_length = GetField(field_value,80,&buffer[offset+name_length],buffer_size-name_length,DELIMITER_COMMA);

			offset += value_length + name_length;

			if (name_length > 0 && value_length > 0)
			{
				/* find the fields */
				for (count=0;count<AFN_NUMBER_OF_AUTH_FIELDS;count++)
				{
					if (strcmp(field_name,auth_names[count]) == 0)
					{
						switch(count)
						{
							case AFN_USERNAME:
								GetField(auth->user_name,32,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_REALM:
								GetField(auth->realm,64,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_NONCE:
								GetField(auth->nonce,64,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_URI:
//								GetField(auth->uri,32,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_RESPONSE:
								GetField(auth->response,64,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_OPAQUE:
								GetField(auth->opaque,64,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_QOP:
//								GetField(auth->qop,32,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_NC:
//								GetField(auth->user_name,32,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_CNONCE:
								GetField(auth->cnonce,64,field_value,value_length,DELIMITER_DOUBLE_QUOTE);
								break;
							case AFN_ALGORITHM:
//								GetField(auth->user_name,32,field_value,value_length,DELIMITER_COMMA);
								break;
						}

						break;
					}
				}
			}
			else
			{
				/* it failed */
				break;
			}
		}

		DumpHexMem(auth,sizeof(AUTHORISATION));

	}

	/* TODO: Work out the result here */

	return result;
}


/*------------------------------------------------------------*
 * This function will decode the request headers.
 *------------------------------------------------------------*/
unsigned int	decode_request_headers(unsigned int connection)
{
	unsigned int	count;
	unsigned int	size;
	unsigned int	token;
	unsigned int	offset;
	unsigned int	headers_found = 0;
	int				delimiter;
	char			header_name[32];
	char			header_field[255];
	char			output[255];

	do
	{
		size = GetToken(connection,details[connection].socket,header_name,32,&delimiter);

		printf("size: %d %s\n",size,header_name);

		if (size == 0)
		{
			/* finished finding all the headers */
			break;
		}
		else
		{
			size = GetToken(connection,details[connection].socket,header_field,255,&delimiter);
			token = headers_check_word(header_name);
			
			if (token != -1)
				headers_found = 1;

			if (token == HST_AUTHORIZATION)
			{
				DecodeAuthentication(connection,header_field,size);

			}
		}

		printf("Header:[%d] %s -- %s\n",token,header_name,header_field); 
	}
	while(1);


	return headers_found;
}

/*------------------------------------------------------------*
 * This function will decode the request body.
 *------------------------------------------------------------*/
unsigned int	decode_request_body(unsigned int connection)
{
	char			lf_found = 0;
	char			line_feed = 0;
	char			just_entered = 1;
	char			header_finished = 0;
	unsigned int	headers_found = 0;

	/* only enter if not at the end of the transfer */
	if (buff_pos[connection] != data_read[connection])
	{
		do
		{
			if (buff_pos[connection] == data_read[connection])
			{
				if (!do_read(details[connection].socket))
				{
					printf("Failed\n");
					break;
				}
			}

			switch(connection_buffer[connection][buff_pos[connection]])
			{
				case '\r':	lf_found = 1;	
						break;

				case '\n':	
						if (lf_found)
						{
							if (line_feed || just_entered)
								header_finished = 1;

							lf_found  = 0;
							line_feed = 1;
						}
						break;
				default:
						lf_found = 0;
						line_feed = 0;
						just_entered = 0;
						break;
			}

			buff_pos[connection]++;
		}
		while(!header_finished);
	}

	return headers_found;
}
