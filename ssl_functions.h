SSL_CTX*	InitialiseCTX	( char* keyfile, char* certfile );
SSL*		SSLAccept 		( SSL_CTX* ctx, int socket );
void 		SSLRelease		( SSL* ssl );

