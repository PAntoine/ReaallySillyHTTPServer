/*********************************************************************************
 * Name: Utilities
 * Description:
 *
 * This file holds the utility functions that are required by the server.
 *
 * Date  : 7th March 2009
 * Author: Peter Antoine.
 *
 *********************************************************************************/

#include <winsock2.h>
#include "http_server.h"

/*------------------------------------------------------------*
 * buffer read functions
 *------------------------------------------------------------*/
extern	int		do_read(SOCKET handle);
extern	char	connection_buffer[MAX_CONNECTIONS][BUFFER_SIZE];
extern	int		buff_pos[MAX_CONNECTIONS];
extern	int		data_read[MAX_CONNECTIONS];

/*------------------------------------------------------------*
 * Get Token
 *
 * This function will find and return a token from the data
 * input. It will return the length of the token and the
 * what type of token it fond.
 *------------------------------------------------------------*/
int	GetToken(unsigned int connection,SOCKET handle,char* buffer, unsigned int buffer_size, int *delimiter)
{
	int	token_size = 0;
	int lf_found = 0;
	int found = 0;

	do
	{
		if (buff_pos[connection] >= data_read[connection])
		{
			if (!do_read(handle))
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
						found = 1;
						*delimiter = DELIMITER_CRLF;

						buffer[token_size] = '\0';
					}
					break;

			case ':': /* token has finished */
					buffer[token_size] = '\0';
					found = 1;
					*delimiter = DELIMITER_COLON;
					break;

			default:

					buffer[token_size] = connection_buffer[connection][buff_pos[connection]];
					token_size++;

					lf_found = 0;
					break;
		}

		buff_pos[connection]++;

	}
	while (!found && token_size < buffer_size);

	return token_size;
}

