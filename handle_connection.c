/*********************************************************************************
 * Name: handle_connection
 * Description:
 *
 * This thread function will handle the connection from the remote server.
 *
 * It will handle the basic commands that have to be handled by a basic HTTP
 * server.
 *
 * Date  : 15th February 2009
 * Author: Peter Antoine. 
 *
 *********************************************************************************/

#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <winsock2.h>

#include "headers.h"
#include "http_server.h"


extern unsigned int	decode_request_headers(unsigned int connection);
extern unsigned int	decode_request_body(unsigned int connection);

/*------------------------------------------------------------*
 * external definitions for the header fields.
 *------------------------------------------------------------*/
extern char			*status_code[];
extern const char	*http_header[];

extern const	MIME_LOOK_UP		mime_lookup[MT_MAX_TYPES+1];

extern unsigned int	status_code_size[SC_MAX_CODES];

extern const char	message_start[];
extern const char	error_start[];
extern const char	error_middle[];
extern const char	error_end[];

extern int message_start_size;
extern int message_start_size;
extern int error_start_size;
extern int error_middle_size;
extern int error_end_size;

extern int use_digest;

/*------------------------------------------------------------*
 * connection data connections
 *------------------------------------------------------------*/
extern CONNECTION_DETAILS	details[MAX_CONNECTIONS];

unsigned char	connection_buffer[MAX_CONNECTIONS][BUFFER_SIZE];
int		buff_pos[MAX_CONNECTIONS];
int		data_read[MAX_CONNECTIONS];
char	send_buffer[MAX_CONNECTIONS][2048];
int		socket_problem = 0;

#define MAX_URI_LENGTH	(255)

void	SendResponse(unsigned int connections,char* uri,MIME_TYPE type,int head_command);

/* forward references */
void	RetrieveHeaders(SOCKET handle);
void	RetrieveBody(SOCKET handle);

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  handle_connection
 *  Description:  This function is the basic connection handler. It will handle the
 *  			  various requests on the same socket.
 *-------------------------------------------------------------------------------------*/
void	handle_connection(unsigned int connection)
{
	int closed = 0;
	char			uri[MAX_URI_LENGTH + 1];
	HTTP_COMMANDS	command = HTTP_COMMAND_GET;

	// New connection - reset data read.
	if (do_read(connection) > 0)
	{
		while (command != HTTP_COMMAND_BAD)
		{
			// waiting for new connection
			command = DecodeCommand(connection,uri);

			switch(command)
			{
				case HTTP_COMMAND_HEAD:
						decode_request_headers(connection);
						decode_request_body(connection);
						SendResponse(connection,&uri[1],GetMimeType(&uri[1]),0);
						break;

				case HTTP_COMMAND_GET:		// We have a get command
						decode_request_headers(connection);
						decode_request_body(connection);
						SendResponse(connection,&uri[1],GetMimeType(&uri[1]),0);
						break;

				case HTTP_COMMAND_POST: 	// We have post command
						decode_request_headers(connection);
						decode_request_body(connection);
						SendResponse(connection,&uri[1],GetMimeType(&uri[1]),0);
						break; 

				case HTTP_COMMAND_OPTION:
						break;

				default: 
						command = HTTP_COMMAND_BAD;
						break;
			}
		}

		connection_buffer[connection][0] = '\0';
	}

	/* free the connection slot */
	details[connection].in_use = 0;
}

int	do_read(unsigned int connection)
{
	data_read[connection] = recv(details[connection].socket,connection_buffer[connection],BUFFER_SIZE,0);
	buff_pos[connection] = 0;

	if (data_read[connection] < 0)
	{
		printf("connection problem: %d\n",data_read[connection]);
		// connection problem - assume the connection has been dropped
		socket_problem = 1;

   		printf("recv failed: %d\n", WSAGetLastError());
	}
	else if (data_read[connection] == 0)
	{
		printf("connection closed.\n");
	}
	else
	{
		connection_buffer[connection][data_read[connection]] = '\0';
	}

	printf("hello\n");
	printf("do read returns: %d\n",data_read[connection]);

	return data_read[connection];
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  DecodeCommand
 *  Description:  This function will take the first line of an HTTP connection and
 *  			  work-out what has to be done with it. It will basically work out
 *  			  what to do.
 *-------------------------------------------------------------------------------------*/
HTTP_COMMANDS	DecodeCommand(unsigned int connection,char* uri)
{
	int	count = 0;
	int	found = HTTP_COMMAND_BAD;
	int	finished = 0;
	int	failed = 0;
	int found_cr = 0;
	int found_lf = 0;

	do
	{
		if (buff_pos[connection] == data_read[connection])
		{
			if (do_read(connection) <= 0)
			{
				failed = 1;
				finished = 1;
				printf("Failed: %d\n",failed);
			}

		}

		switch (connection_buffer[connection][buff_pos[connection]])
		{
			case 'G':
				if (found == 0)
					found = GET_G;
				else
					failed = 1;	// g can only be the first letter
				break;

			case 'P':
				if (found == 0)
					found = POST_P;
				else if (found == OPTION_O)
					found = OPTION_P;
				else
					failed = 1; // P must be the first letter
				break;

			case 'O':
				if (found == 0)
					found = OPTION_O;
				else if (found == OPTION_I)
					found = OPTION_O2;
				else if (found == POST_P)
					found = POST_O;
				else
					failed = 1;
				break;

			case 'E':
				if (found == GET_G)
					found = GET_E;
				else
					failed = 1;
				break;

			case 'I':
				if  (found == OPTION_T)
					found = OPTION_I;
				else
					failed = 1;
				break;

			case 'N':
				if (found == OPTION_O2)
					found = HTTP_COMMAND_OPTION;
				else
					failed = 1;
				break;
			
			case 'S':
				if (found == POST_O)
					found = POST_S;
				else
					failed = 1;
				break;

			case 'T':
				if (found == GET_E)
					found = HTTP_COMMAND_GET;
				else if (found == POST_S)
					found = HTTP_COMMAND_POST;
				else
					failed = 1;
				break;

			case ' ':
				if (found == HTTP_COMMAND_POST || found == HTTP_COMMAND_GET || found == HTTP_COMMAND_OPTION)
					finished = 1;
				else
					failed = 1;
				break;

			default:
				failed = 1;
		}

		buff_pos[connection]++;
	}
	while(!failed && !finished);

	/* now get the URL */
	while (count < MAX_URI_LENGTH && !failed)
	{
		if (buff_pos[connection] == data_read[connection])
		{
			failed = do_read(connection);
		}

		if (connection_buffer[connection][buff_pos[connection]] == ' ')
		{
			// found it
			uri[count] = 0;
			break;
		}
		else if (connection_buffer[connection][buff_pos[connection]] == '\r' || connection_buffer[connection][buff_pos[connection]] == '\n')
		{
			// these should not be in a URL
			failed = 1;
			break;
		}
		else
		{
			/* OK, there could be lots of bad chars here, but this is demo code
			 * not the full thing.
			 */
			uri[count] = connection_buffer[connection][buff_pos[connection]];
		}

		count++;
		buff_pos[connection]++;
	}

	/* Now get the version of the HTTP (dont really care) */
	while (!failed && !(found_cr && found_lf))
	{
		if (buff_pos[connection] == data_read[connection])
		{
			failed = do_read(connection);
		}

		// now just read the rest of the line until the crlf pair.
		if (connection_buffer[connection][buff_pos[connection]] == '\n')
			found_cr = 1;
		else if (connection_buffer[connection][buff_pos[connection]] == '\r')
			found_lf = 1;

		buff_pos[connection]++;
	}

	if (!failed)
		printf("URL is: \"%s\"  (%d)\n",uri,finished);

	if (!failed)
		return found;
	else
		return HTTP_COMMAND_BAD;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  GetMimeType
 *  Description:  This function will return the mime type of a url. It will work off 
 *  			  the file name, when it can. But, when it cant it will use the 
 *  			  magic number. I know this is the wrong way around (the other way is
 *  			  safer to the client) but the easy way works for this hack-fest.
 *-------------------------------------------------------------------------------------*/
MIME_TYPE	GetMimeType(char* uri)
{
	int			file;
	int 		count = 0;
	int			char_count;
	int			extension;
	char 		*last_point = NULL;
	char		bytes[2];
	MIME_TYPE	result = MT_MAX_TYPES;

	/* check the extension first */
	while (uri[count] != '\0')
	{
		if (uri[count] == '.')
			last_point = &uri[count];

		count++;
	}

	if (last_point != NULL)
	{
		last_point++;

		/* we have a extension so check that against the table */
		for (count=0;count<MT_MAX_TYPES && result == MT_MAX_TYPES;count++)
		{
			extension = 0;

			while(mime_lookup[count].file_extenstions[extension] != NULL)
			{
				for (char_count=0;	last_point[char_count] == mime_lookup[count].file_extenstions[extension][char_count] &&
									last_point[char_count] != '\0' &&
									mime_lookup[count].file_extenstions[extension][char_count] != '\0'; char_count++)
				{};

				if (last_point[char_count] == '\0' && mime_lookup[count].file_extenstions[extension][char_count] == '\0')
				{
					// we have found it 
					result = count;
					break;
				}

				extension++;
			}
		}

		/* only want to check the magic numbers if the we cant find the extensions */
		if (result == MT_MAX_TYPES)
		{
			// we have to check the magic number of the file.
			if ((file = open(uri,O_RDONLY)) != -1)
			{
				if (read(file,bytes,2) == 2)
				{
					for (count=0;count<MT_MAX_TYPES;count++)
					{
						if (mime_lookup[count].magic_number[0] == bytes[0] && mime_lookup[count].magic_number[1] == bytes[1] )
						{
							result = count;
							break;
						}
					}
				}

				close(file);
			}
		}
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  size_to_string
 *  Description:  This function will return int as a string (it needs to be 10 bytes).
 *  			  it will return an int of the size of the string that has been made.
 *-------------------------------------------------------------------------------------*/
int	size_to_string(char* string,int size)
{
	int digits = 0;

	while(size > 0)
	{
		string[8-digits] = '0' + (size % 10);
		digits++;
		size = size / 10;
	}

	return digits;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  AddHeader
 *  Description:  This function will add a header to the buffer.
 *-------------------------------------------------------------------------------------*/
unsigned int AddHeader(unsigned char *buffer,HTTP_HEADER header,unsigned char *data,unsigned int data_size)
{
	unsigned int total = 0;

	memcpy(buffer,headers_table[header].name,headers_table[header].length);
	total += headers_table[header].length;

	buffer[total++] = ':';
	buffer[total++] = ' ';
	memcpy(&buffer[total],data,data_size);
	total += data_size;

	buffer[total++] = 0x0d;
	buffer[total++] = 0x0a;

	return total;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  CheckRequestStatus
 *  Description:  This function will test the state of a uri request to see if the
 *                request is valid, and if any other action rather than just returning
 *                the file is required.
 *-------------------------------------------------------------------------------------*/
int		CheckRequestStatus(char* uri, unsigned int connection, int* file,char* data_length,int* digits,int* reported_file_size, char** redirect_uri)
{
	int	status = SC_200_OK;
	int		file_size;

	if (strncmp(uri,"secure",6) == 0)
	{
		/* we have a secure file */
		if (details[connection].user[0] == '\0')
		{
			/*need to ask for a user name and password */
			status = SC_401_UNAUTHORIZED;
		}
		else if (strcmp(details[connection].user,"valid_user") != 0)
		{
			printf("======= retry count:%d\n",details[connection].retry_count);

			if (details[connection].retry_count < 3)
			{
				status = SC_401_UNAUTHORIZED;
				details[connection].retry_count++;
			}
			else
			{
				status = SC_403_FORBIDDEN;
				details[connection].retry_count = 0;
			}

		}else{
			details[connection].retry_count = 0;
		}

		*digits = size_to_string(data_length, error_start_size + (status_code_size[status]*2) + error_middle_size + error_end_size);
	}	
	
	if (status == SC_200_OK)
	{
		if ((*file = open(uri,(O_RDONLY|O_BINARY))) != -1)
		{
			file_size = lseek(*file,0,SEEK_END);
			*reported_file_size = file_size;
			lseek(*file,0,SEEK_SET);

			*digits = size_to_string(data_length,file_size);

			/* we have found the file */
			status = SC_200_OK;
		}else{
			status = SC_404_NOT_FOUND;
			*digits = size_to_string(data_length,
									error_start_size + (status_code_size[status]*2) + error_middle_size + error_end_size);
		}
	}

	if (status != SC_200_OK)
	{

	}

	return status;
}


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  AddAuthenticationHeader
 *  Description:  This function will build a Digest Header.
 *-------------------------------------------------------------------------------------*/
int AddAuthenticationHeader ( unsigned char* buffer,unsigned char* realm_name, unsigned int length )
{
	int	result = 0;

	memcpy(buffer,headers_table[HST_WWW_AUTHENTICATE].name,headers_table[HST_WWW_AUTHENTICATE].length);
	result = headers_table[HST_WWW_AUTHENTICATE].length;

	memcpy(&buffer[result],": Digest ",sizeof(": Digest ") - 1);
	result += sizeof(": Digest ") - 1;


	/* realm */
	memcpy(&buffer[result],"realm=\"",sizeof("realm=\"") - 1);
	result += sizeof("realm=\"") - 1;

	memcpy(&buffer[result],realm_name,length);
	result += length;
	
	buffer[result++] = '\"';
	buffer[result++] = ',';

	/* qop */
	memcpy(&buffer[result],"qop=\"auth\",",sizeof("qop=\"auth\",") - 1);
	result += sizeof("qop=\"auth\",") - 1;

	/* nonce */
	memcpy(&buffer[result],"nonce=\"",sizeof("nonce=\"") - 1);
	result += sizeof("nonce=\"") - 1;

	memcpy(&buffer[result],realm_name,length);
	result += length;
	
	buffer[result++] = '\"';
	buffer[result++] = ',';

	/* opaque */
	memcpy(&buffer[result],"opaque=\"",sizeof("opaque=\"") - 1);
	result += sizeof("opaque=\"") - 1;

	memcpy(&buffer[result],realm_name,length);
	result += length;
	
	buffer[result++] = '\"';

	/* header end */
	buffer[result++] = 0x0d;
	buffer[result++] = 0x0a;

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  SendResponse
 *  Description:  The function handles the response to the uri request.
 *-------------------------------------------------------------------------------------*/
void	SendResponse(unsigned int connection,char* uri,MIME_TYPE type, int head_command)
{
	int		file;
	int		digits = 0;
	int		bytes_read = 0;
	int		total = 0;
	int		bytes_written = 0;
	int		status;
	int		reported_file_size;
	char	data_length[10];
	char	*redirect_uri;

	/* check to see what has to be done for the file */
	status = CheckRequestStatus(uri,connection,&file,data_length,&digits,&reported_file_size,&redirect_uri);

	if (status != SC_200_OK)
	{
		/* we are going to generate stuff */
		type = MT_HTML;
	}

	/* create the headers */
	memcpy(send_buffer[connection],message_start,message_start_size);
	total = message_start_size;

	memcpy(&send_buffer[connection][total],status_code[status],status_code_size[status]);
	total += status_code_size[status];

	send_buffer[connection][total++] = 0x0d;
	send_buffer[connection][total++] = 0x0a;


	/* add the server name!! reaally important!! */
	total += AddHeader(&send_buffer[connection][total],HST_SERVER,SERVER_NAME,sizeof(SERVER_NAME)-1);

	/* add the content type header */
	total += AddHeader(&send_buffer[connection][total],HST_CONTENT_TYPE,mime_lookup[type].mime_name,mime_lookup[type].length);

	/* add the content length */
	total += AddHeader(&send_buffer[connection][total],HST_CONTENT_LENGTH,&data_length[9-digits],digits);
	
	if (status == SC_401_UNAUTHORIZED)
	{
		if (use_digest)
		{
			total += AddAuthenticationHeader(&send_buffer[connection][total],"home",sizeof("home")-1);
		}
		else
		{
			total += AddHeader(&send_buffer[connection][total],HST_WWW_AUTHENTICATE,"Basic realm=home",sizeof("Basic realm=home"));
		}
	}
	else if (status >= SC_300_MULTIPLE_CHOICES && status <= SC_307_TEMPORARY_REDIRECT)
	{
		total += AddHeader(&send_buffer[connection][total],HST_LOCATION,redirect_uri,strlen(redirect_uri));
	}

	/* header end */
	send_buffer[connection][total++] = 0x0d;
	send_buffer[connection][total++] = 0x0a;

	DumpHexMem(send_buffer[connection],total);

	send(details[connection].socket,send_buffer[connection],total,0);

	if (status == SC_200_OK)
	{
		if (!head_command)
		{
			while ((bytes_read = read(file,send_buffer[connection],2048)) > 0)
			{
				do
				{
					bytes_written = send(details[connection].socket,send_buffer[connection],bytes_read,0);

					total += bytes_written;
				}
				while(total < bytes_read && bytes_written != -1);
			}

			if (reported_file_size > total)
			{
				// pad the send
				for (digits=total;digits<reported_file_size;digits += sizeof("\n"))
				{
					send(details[connection].socket,"\n",sizeof("\n"),0);
					printf("x");
				}
			}
		}

		close(file);
	}
	else
	{
		/* we have a file that cannot be transmitted */
		if (head_command)
		{
			/* body in a request */
			send_buffer[connection][0] = 0x0d;
			send_buffer[connection][1] = 0x0a;
			total = 2;
			
		}else{
			/* add the HTML for the error */
			memcpy(send_buffer[connection],error_start,error_start_size);
			total = error_start_size;

			memcpy(&send_buffer[connection][total],status_code[status],status_code_size[status]);
			total += status_code_size[status];
	
			memcpy(&send_buffer[connection][total],error_middle,error_middle_size);
			total += error_middle_size;

			memcpy(&send_buffer[connection][total],status_code[status],status_code_size[status]);
			total += status_code_size[status];
			
			memcpy(&send_buffer[connection][total],error_end,error_end_size);
			total += error_end_size;
		}

		/* send the special header/body */
		send(details[connection].socket,send_buffer[connection],total,0);
	}
}

