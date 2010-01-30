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

#include <winsock2.h>
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
				decode_base64(output,255,&header_field[7],size);
				
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

				printf("Auth: user-%s passwd: %s\n",details[connection].user,details[connection].passwd);
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
