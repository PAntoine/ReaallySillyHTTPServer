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

#include <stdio.h>

#include "http_server.h"

/*------------------------------------------------------------*
 * buffer read functions
 *------------------------------------------------------------*/
extern	int		do_read(SOCKET handle);
extern	char	connection_buffer[MAX_CONNECTIONS][BUFFER_SIZE];
extern	int		buff_pos[MAX_CONNECTIONS];
extern	int		data_read[MAX_CONNECTIONS];


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  encode_hex
 *  Description:  This function will encode a value as hex.
 *-------------------------------------------------------------------------------------*/
void encode_hex ( char* buffer, int buffer_size, unsigned int value )
{
	int count = 0;
	char HexDigits[] = "0123456789ABCDEF";

	for (count=buffer_size; count > 0; count--)
	{
		buffer[count-1] = HexDigits[value & 0x0f];
		value >>= 4;
	}
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  GetField
 *  Description:  This function will return a field from a token. The fields are 
 *                delimited by either a CRLF or the delimeter passed in.
 *-------------------------------------------------------------------------------------*/
int GetField(unsigned char* buffer, unsigned int buffer_size, unsigned char* input_buffer, unsigned int input_size, char delimiter)
{
	int	bytes_used = 0;
	int lf_found = 0;
	int offset = 0;
	int found = 0;

	/* remove leading white space */
	while (input_buffer[bytes_used] == ' ')
		bytes_used++;

	if ((input_buffer[bytes_used] == DELIMITER_DOUBLE_QUOTE) && (delimiter == DELIMITER_DOUBLE_QUOTE))
	{
		bytes_used++;
	}

	do
	{
		switch(input_buffer[bytes_used])
		{
			case '\0':	found = 1;
						buffer[offset++] = '\0';
						break;

			default:
					if (input_buffer[bytes_used] == delimiter)
					{
						found = 1;
						buffer[offset++] = '\0';
					}
					else
					{
						buffer[offset++] = input_buffer[bytes_used];
						lf_found = 0;
					}
					break;
		}
		bytes_used++;
	}
	while(!found && offset < buffer_size && bytes_used < input_size);

	if (!found)
		return 0;
	else
		return bytes_used;
}


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

