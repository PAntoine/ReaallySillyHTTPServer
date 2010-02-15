/*********************************************************************************
 * Name: cross_platform
 * Description:
 *
 * This file holds the cross platform functions.
 *
 * Date  : 7th March 2009
 * Author: Peter Antoine.
 *
 *********************************************************************************/

#include "http_server.h"

#ifdef _WIN32

void	StartNetworking(void)
{
	/* windows nonsense that is needed before you can talk to
	 * the windows 2 sockets.
	 */ 
	int			err;
	WORD		wVersionRequested;	
	WSADATA 	wsaData;

	wVersionRequested = MAKEWORD( 2, 2 ); 
	err = WSAStartup( wVersionRequested, &wsaData );
	
	if ( err != 0 ) 
	{	
		printf("Unable to find the WinSock DLL\n");
		exit(-1);
	}
}	

#else

#include <malloc.h>

/* empty function as there is not networking start code required on *nix */
void	StartNetworking(void)
{
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  CreateThread
 *  Description:  This is the posix version of CreateThread.
 *-------------------------------------------------------------------------------------*/
pthread_t*	CreateThread(	unsigned int* 			not_used,
							unsigned int			stack_size,
							LPTHREAD_START_ROUTINE 	function,
							void*					parameters,
							unsigned int			flags,
							unsigned int*			thread_id)
{
	pthread_t*	result = malloc(sizeof(pthread_t));

	if (result != NULL)
	{
		if (pthread_create(result,NULL,function,parameters) == 0)
		{
			return result;
		}
		else
		{
			free(result);
		}
	}

	return NULL;
} 

#endif


