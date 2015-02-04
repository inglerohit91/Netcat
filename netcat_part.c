#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> 
#define BUF_LEN 30720 
#define SHA_HASHLEN 20

static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

/**************************************
 * Structure to hold all relevant state
 *************************************/
typedef struct nc_args{
  struct sockaddr_in destaddr;		 //destination/server address
  unsigned short port; 			 //destination/listen port
  unsigned short listen; 		 //listen flag
  int n_bytes; 				 //number of bytes to send
  int offset; 				 //file offset
  int verbose; 				 //verbose output info
  int message_mode; 			 //retrieve input to send via command line
  int mm_with_port;                      //message mode is activated and client provides port number
  int server_port;                       //to check if port is given on server. 
  char * message; 			 //if message_mode is activated, this will store the message
  char * filename; 			 //input/output file
}nc_args_t;

/*******************************************
 * Global Variables and function declarations
 *******************************************/
static const int MAXPENDING = 5;					/* Max Queue length of pending connections */
unsigned char receivedBuffer[BUF_LEN+20];				/* Buffer storing Message+Digest on server */
unsigned char final_message[BUF_LEN];					/* Buffer storing extracted message only   */
void send_message(nc_args_t * nc_args, int argc, char * argv[]);	/* Prototype for function sending message  */
void send_file(nc_args_t * nc_args, int argc, char * argv[]);		/* Prototype for function sending file     */
void listen_message(nc_args_t * nc_args, int argc, char * argv[]);     	/* Prototype for server funnction  	   */

/***************************************************************
 * usage(FILE * file) -> void
 *
 * Write the usage info for netcat_part to the give file pointer.
 ***************************************************************/
void usage(FILE * file){
  fprintf(file,
         "netcat_part [OPTIONS]  dest_ip [file] \n"
         "\t -h           \t\t Print this help screen\n"
         "\t -v           \t\t Verbose output\n"
	 "\t -m \"MSG\"   \t\t Send the message specified on the command line. \n"
	 "                \t\t Warning: if you specify this option, you do not specify a file. \n"
         "\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
         "\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
         "\t -o offset    \t\t Offset into file to start sending\n"
         "\t -l           \t\t Listen on port instead of connecting and write output to file\n"
         "                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n"
         );
}
/*******************************************************************
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function using getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return results
 *******************************************************************/
void parse_args(nc_args_t * nc_args, int argc, char * argv[]) {
  int ch=0;
  struct hostent * hostinfo = NULL;
  nc_args->n_bytes = -1;
  nc_args->offset = 0;
  nc_args->listen = 0;
  nc_args->port = 6767;
  nc_args->verbose = 0;
  nc_args->message_mode = 0;
  nc_args->mm_with_port = 0;
  nc_args->server_port = 0;
  nc_args->destaddr.sin_family = AF_INET;
  nc_args->destaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  nc_args->destaddr.sin_port = htons(nc_args->port);
 
  while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1) {  	/* While loop parsing command line arguments */
    switch (ch) {
    	case 'h':	 		//help
      		usage(stdout);
      		exit(0);
      		break;
    	case 'l':			 //listen
      		nc_args->listen = 1;
      		break;
    	case 'p':			 //port
      		nc_args->port = atoi(optarg);
      		nc_args->mm_with_port = 1;
     		 break;
    	case 'o':			//offset
      		nc_args->offset = atoi(optarg);
      		break;
    	case 'n':			//bytes
      		nc_args->n_bytes = atoi(optarg);
      		break;
    	case 'v':
      		nc_args->verbose = 1;	//verbose 
      		break;
    	case 'm':			//message mode
      		nc_args->message_mode = 1;
      		nc_args->message = malloc(strlen(optarg)+1);
      		strncpy(nc_args->message, optarg, strlen(optarg)+1);
		break;
    	default:
      		fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
      		usage(stdout);
      		exit(1);

    }		/*End of switch case */
  }	/* End of While loop */


  if (nc_args->mm_with_port == 1 && nc_args->listen == 1) {  /* Means we are on server */
	nc_args->server_port = 1;
	nc_args->mm_with_port = 0;
  }
 
  if (argc < 2 && nc_args->message_mode == 0){   /* no command line arguments */
    	fprintf(stderr, "ERROR: No command line arguments passed\n");
    	usage(stderr);
    	exit(1);
  }
  else if (argc - optind > 2 || (argc - optind >1 && nc_args->message_mode ==1) || (argc - optind == 0 && argc >2 )
	|| (nc_args->message_mode ==1 && nc_args->listen ==1))  { 	/* Invalid arguments */
    	fprintf(stderr, "ERROR: Invalid Inputs. Please check arguments passed.\n");
    	usage(stderr);
    	exit(1);
  }
  else if (argc < 3 && nc_args->listen == 1)  { 		/* less arguments given on server command line*/
    	fprintf(stderr, "ERROR: Missing arguments\n");
    	usage(stderr);
    	exit(1);
  }
  else if (argc < 3 && nc_args->message_mode == 0 && nc_args->listen == 0){   /* Missing arguments */
    	fprintf(stderr, "ERROR: Invalid command.\n");
    	usage(stderr);
    	exit(1);
  } 
  else if (argc == 3 && nc_args->message_mode == 1){		/* Check for missing port/ip/message */
 	fprintf(stderr, "ERROR: Missing destination port/destination ip/message to be sent/or other inputs\n");
  	usage(stderr);
  	exit(1);
  }
  else if (argc == 4 && nc_args->mm_with_port == 1){		/* Check for missing destination port/filename */
 	fprintf(stderr, "ERROR: Missing destination port/destination ip/filename/or other inputs\n");
  	usage(stderr);
  	exit(1);
  }
  else if ((argc > 5 && nc_args->message_mode == 1 && nc_args->mm_with_port == 0) || 
        	(argc > 10 && nc_args->mm_with_port == 1 ) ||
		 (argc > 10 && nc_args->message_mode ==0 && nc_args->listen == 0)){	/* Excess command line arguments passed */ 
        fprintf(stderr, "ERROR: Excess no. of command line arguments passed1\n");
        usage(stderr);
        exit(1);
  }
  else if ((argc > 7 && nc_args->listen == 1 )){   		/* Excess command line arguments passed */
	fprintf(stderr, "ERROR: Excess no. of command line arguments passed2\n");
	usage(stderr);
    	exit(1);
  }
  else if (!(hostinfo = gethostbyname(argv[optind])) && (argc - optind == 2) && 
	  ((nc_args->message_mode ==1 ) || (nc_args->listen ==1 && argc!=3 && argc == 5 && nc_args->verbose ==1) 
	  || (nc_args->listen == 1 && argc!=3 && argc!=5))){ 
	fprintf(stderr,"ERROR: Invalid host name/IP '%s'\n", argv[optind]); 	/* Check for valid IP */
	usage(stderr);
    	exit(1);
  }
  else if (!(hostinfo = gethostbyname(argv[optind])) && (argc - optind ==1) && (nc_args->message_mode == 1)) { 
    	fprintf(stderr,"ERROR: Invalid host name/IP '%s'\n", argv[optind]);	/* Check for valid IP */
	usage(stderr);
    	exit(1);
  }
  else if (!(hostinfo = gethostbyname(argv[optind])) && (nc_args->listen == 0) && (nc_args->message_mode == 0)) { 
    	fprintf(stderr,"ERROR: Invalid host name/IP '%s'\n", argv[optind]);	/* Check for valid IP */
	usage(stderr);
    	exit(1);
  }
	/* Populating IP address variables */

if(((nc_args->listen == 1 && argc - optind ==2) && (argc==4 || argc==6 || argc==7))|| (nc_args->message_mode == 1)) {
  
  memset(&nc_args->destaddr, 0, sizeof(nc_args->destaddr)); /* Initialize server IP with zero */
  nc_args->destaddr.sin_family = hostinfo->h_addrtype;
  nc_args->destaddr.sin_family = AF_INET;
  bcopy((char *) hostinfo->h_addr,
        (char *) &(nc_args->destaddr.sin_addr.s_addr),
         hostinfo->h_length);
  nc_args->destaddr.sin_port = htons(nc_args->port);
}
  
  nc_args->destaddr.sin_port = htons(nc_args->port);

if((nc_args->listen == 0) && (nc_args->message_mode == 0)) {	/* Check for client sending file case */
  
  memset(&nc_args->destaddr, 0, sizeof(nc_args->destaddr)); /* Initialize server IP with zero */
  nc_args->destaddr.sin_family = hostinfo->h_addrtype;
  nc_args->destaddr.sin_family = AF_INET;
  bcopy((char *) hostinfo->h_addr,
        (char *) &(nc_args->destaddr.sin_addr.s_addr),
         hostinfo->h_length);
  nc_args->destaddr.sin_port = htons(nc_args->port);
}

/* Save file name if not in message mode */
 
    if (((nc_args->message_mode == 0)||(nc_args->listen ==1)) && argc-optind ==2) { /* Case checking for both IP and Filename provided in Command Line */
    	nc_args->filename = malloc(strlen(argv[optind+1])+1);
    	strncpy(nc_args->filename,argv[optind+1],strlen(argv[optind+1])+1);
    }
    else if (( nc_args->listen == 1) && (argc-optind == 1)) {	/* We are on server and only filename is provided. By default IP = localhost */
    	nc_args->filename = malloc(strlen(argv[optind])+1);
    	strncpy(nc_args->filename,argv[optind],strlen(argv[optind])+1);
    }
  return;
}

/*********************************
 * Main Function
 * ******************************/

int main(int argc, char * argv[]){

	nc_args_t nc_args;

	/* initializes the arguments struct for  use */
	parse_args(&nc_args, argc, argv);

		if (nc_args.listen  == 1) {		/* We are on server instance      */
			listen_message(&nc_args, argc, argv);
		}		
		else if (nc_args.message_mode == 1) {   /* Message sending mode on client */
			send_message(&nc_args, argc, argv);
		}
		else { 					/* File sending case on client 	  */
			send_file(&nc_args, argc, argv);
		}
	return 0;
}


/***********************************************************
 *	Function name : send_message()
 *
 *	Sends message from client to server
 *	in while in message mode securely
 *
 **********************************************************/

void send_message(nc_args_t * nc_args, int argc, char * argv[])
{
int 	i = 0;
int 	sockfd = 0;
int 	returnVal = 0;
size_t 	messageLen = strlen(nc_args->message); 	/* Length of message to be sent */
size_t 	bytesSent;				/* Stores bytes returned by write()  */

	if (messageLen == 0) {
		printf("\nERROR : No valid message entered to be sent\n");
		exit(1);
	}
	
	/* Reliable socket creation */
	
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( sockfd < 0) {
		printf("\nERROR : Socket() creation failed\n");
		exit(1);
	}

	/* Connect to netcat_part server */
	
	if (connect(sockfd, (struct sockaddr *)&(nc_args->destaddr), sizeof(nc_args->destaddr)) < 0) {
		printf("\nERROR : Connect() failed\n");
		exit(1);
	}


/* Message digest variables */
size_t 		re_alloc = 0;	/* Variable to hold size to increase message to include digest */
unsigned char*	digest = (unsigned char*)malloc(sizeof(EVP_MAX_MD_SIZE)); /* Stores the digest */
unsigned int*	ptr_len = (unsigned int *)malloc(sizeof(int));		 /* Length of digest  */

	if (nc_args->verbose ==1)	{
		printf("\nMessage			 = %s\n", nc_args->message);
		printf("Message Length		 = %d\n", (int)messageLen);
	}

	digest = HMAC(EVP_sha1(), key,sizeof(key), (unsigned char*)nc_args->message, 
		(int)messageLen,NULL, ptr_len);	/* Calling HMAC to calculate digest for message */

	re_alloc = strlen(nc_args->message) + (size_t)*ptr_len + 1;	/* Message+digest size   	   */
	nc_args->message = (char*)realloc(nc_args->message,re_alloc);  	/* Realloc message to hold digest  */
	strcat(nc_args->message,(char*) digest);			/* Concatenating digest to message */
	
	if (nc_args->verbose ==1)	{
		printf("Message + Digest length  = %d\n", (int)strlen(nc_args->message));
		printf("\nMessage Digest:\n");
		printf("===============\n");
		for (i = 0; i < *ptr_len; i++) 
                	printf("%02x ", digest[i]);
		printf("\n");
	}

	/* Send the message to netcat_part server */

	bytesSent = write(sockfd, nc_args->message, (int)strlen(nc_args->message));	/* Writing to socket */
	
	if (nc_args->verbose ==1)	{
		printf("\nBytes written to socket  = %d\n", (int)bytesSent);
		printf("Server IP Address        = %s\n", inet_ntoa(nc_args->destaddr.sin_addr));
		printf("Server Port     	 = %d\n", ntohs(nc_args->destaddr.sin_port));
	}

	if (bytesSent < 0) {
		printf("\nERROR : Write() to socket failed\n");
		exit(1);
	}

	printf("\n!!!!Message sent to Server!!!!\n\n");
	
	/* Close the socket now */
	
	returnVal = close(sockfd);
	if (returnVal == -1) {
		printf("\nERROR : Close() for socket failed\n");
		exit(1);
	}
return;
}	/* End of function send_message() */

/***********************************************************
 *	Function name : send_file()
 *
 *	Sends partial/full file from client to server
 * 	securely.	
 *
 **********************************************************/
void send_file(nc_args_t * nc_args, int argc, char * argv[])
{
int 	i = 0;
int	sockfd = 0;
int 	returnVal = 0;
int 	bytesRead = 0;
int 	filesize= 0;
FILE 	*fp = NULL;
char 	*fileBuf = NULL;
			
	fp = fopen(nc_args->filename, "r");	/* Open file on client to send */
	if (fp == NULL) {
		printf("\nERROR: Unable to open file..Please check file name.\n");
		exit(1);
	}
	/* Fseek operations to find file size to be sent */	
	
	fseek(fp,0,SEEK_END);
	filesize = ftell(fp);
	fseek(fp,0,SEEK_SET);     		
	
	if (nc_args->verbose ==1)	{
		printf("\nFilename		 = %s\n", nc_args->filename);
		printf("Filesize		 = %d\n", filesize);
	}
	
	if(filesize == 0)		{
		printf("\nERROR: Source file is empty. No bytes sent.\n");
		exit(1);
	}
	
	/* Now we check for nc_args->offset */
		
	if (nc_args->offset != 0) {
		if (nc_args->offset >= filesize-1 || nc_args->offset <0) {   /* Offset negative and greater than filesize check */
			printf("\nERROR: Invalid offset. Offset Range (0-%d)\n",filesize-2);
			exit(1);
		}
		else {
			fseek(fp,nc_args->offset,SEEK_SET);     		/* Traverse to the offset in the file */
			filesize = filesize - nc_args->offset ;
		}		
	}	/* End of IF */
	
	if (nc_args->n_bytes != -1) {
		if(nc_args->n_bytes == 0)		{
			printf("\nERROR: Cannot send 0 Bytes. No bytes sent\n");
			exit(1);
		}
		else if (nc_args->n_bytes >= filesize) {   /* Check for bytes available to write */
			printf("\nERROR: %d bytes not available in file to write. Writing till EOF\n",nc_args->n_bytes);
		}
		else if (nc_args->n_bytes <0){
			printf("\nERROR: Negative Input Encountered. Enter Positive number\n");
			exit(1);
		}
		else if (nc_args->offset == 0){
			fseek(fp,nc_args->n_bytes,SEEK_SET);     		/* Traverse to the offset in the file */
			filesize = ftell(fp) + 1;				/* Plus 1 for '/0' */
			fseek(fp,0,SEEK_SET);     				/* Traverse to file beginning */
		}		
		else {
			fseek(fp,nc_args->n_bytes,SEEK_CUR);     		/* Traverse to the offset in the file */
			filesize = ftell(fp) + 1 - nc_args->offset;		/* Plus 1 for '/0' */
			fseek(fp,-nc_args->n_bytes,SEEK_CUR);     		/* Traverse to the offset in the file */
		}

	}	/* End of IF */
	
	if (nc_args->verbose ==1 && (nc_args->offset)>0)	
		printf("File Offset		 = %d\n", nc_args->offset);
	if (nc_args->verbose ==1 && (nc_args->n_bytes)>0)	
		printf("Bytes to send		 = %d\n", filesize-1);
	
		
	/* Reliable socket creation */
	
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( sockfd < 0) {
		printf("\n Socket() creation failed.\n");
		exit(1);
	}

	/* Connect to netcat_part server */
	
	if (connect(sockfd, (struct sockaddr *)&(nc_args->destaddr), sizeof(nc_args->destaddr)) < 0) {
		printf("\nERROR : connect() failed\n");
		exit(1);
	}
	
	fileBuf = malloc(filesize);	/* Dynamic allocation to read from from file and store prior sending */
	bytesRead = fread(fileBuf,1,filesize,fp);	/* Reading from file */
	fileBuf[filesize-1] = '\0';
		//printf("\nFile read contents :\n\n%s\n", fileBuf);	
		//printf("\nLast character is : %c\n",fileBuf[filesize-2]);
	fclose(fp);			/* Cloing file after completing reading */

size_t bytesSent;			/* Stores bytes sent through socket */

	/* Message digest Variables*/

size_t		re_alloc = 0;				/* Variable to hold size to increase filesize to include digest */
unsigned char*	digest = (unsigned char*)malloc(sizeof(EVP_MAX_MD_SIZE)); /* Stores the digest */
unsigned int*	ptr_len = (unsigned int *)malloc(sizeof(int));		 /* Length of digest  */


	digest = HMAC(EVP_sha1(), key,sizeof(key), (unsigned char*)fileBuf, 
		(int)strlen(fileBuf), NULL, ptr_len);	/* Calling HMAC to calculate digest for file */

	re_alloc = strlen(fileBuf) + (size_t)*ptr_len + 1;	/* File+digest size            	   */
	fileBuf = (char*)realloc(fileBuf,re_alloc);		/* Realloc message to hold digest  */
	strcat(fileBuf,(char*) digest);				/* Concatenating digest to file    */


	if (nc_args->verbose ==1)	{
		printf("File + Digest length     = %d\n", (int)strlen(fileBuf));
		printf("\nMessage Digest:\n");
		printf("===============\n");
		for (i = 0; i < *ptr_len; i++) 
                	printf("%02x ", digest[i]);
		printf("\n");
	}

	/* Send the file to server */

	bytesSent = write(sockfd, fileBuf, strlen(fileBuf));
	if (bytesSent < 0) {
		printf("\nERROR : write() failed\n");
		exit(1);
	}

	if (nc_args->verbose ==1)	{
		printf("\nBytes written to socket  = %d\n", (int)bytesSent);
		printf("Server IP Address        = %s\n", inet_ntoa(nc_args->destaddr.sin_addr));
		printf("Server Port     	 = %d\n", ntohs(nc_args->destaddr.sin_port));
	}
	/* Close the socket now */
	
	printf("\n!!!!File sent to Server!!!!\n\n");
	
	returnVal = close(sockfd);
	if (returnVal == -1) {
		printf("\nERROR : close() failed\n");
		exit(1);
	}
free(fileBuf);
return;
}	/* End of function send_file() */
/***********************************************************
 *	Function Name : listen_message()
 *
 * 	Function for listening to incoming connections on
 * 	server and writing the data reveived to a file	
 *
 * **********************************************************/

void listen_message(nc_args_t * nc_args, int argc, char * argv[])
{
int 	sockfd = 0;		

	/* Create socket for incoming connection */

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( sockfd < 0) {
		printf("\nERROR: Socket() creation failed\n");
		exit(1);
	}

	/* Bind to local address */

	if (bind(sockfd, (struct sockaddr*) &(nc_args->destaddr), sizeof(nc_args->destaddr)) < 0 ) {
		printf("\nERROR: Bind() operation failed\n");
		exit(1);
	}

	/* Make socket listen to incoming connections */
	
	if (listen(sockfd, MAXPENDING) < 0) {
		printf("\nERROR: Listen() operation failed\n");
		exit(1);
	}
FILE *fp;
	if (nc_args->verbose ==1)	{
		printf("\nServer IP Address        = %s\n", inet_ntoa(nc_args->destaddr.sin_addr));
		printf("Server Port     	 = %d\n", ntohs(nc_args->destaddr.sin_port));
	}
	printf("\n.......Waiting for client to connect\n");	
	printf("\t\t\t\t\t Press Control+C to exit\n");	
	
	/* Infinite loop for server */

while(1)
{
struct sockaddr_in clientIP;			/* Client IP Adress */
socklen_t 	clientLen = sizeof(clientIP);	/* Length of client address*/

	/* Accept client connection */	

	int clientSock = accept(sockfd, (struct sockaddr *) &clientIP, &clientLen);
	if (clientSock < 0) {
		printf("\nERROR: Accept() operation failed\n");
		exit(1);
	}

	/* Now clientSock is connected to a client */
int 	i = 0;
int 	check =0;
int 	md_index = 0;
size_t 	bytesReceived = 0;			/* Stores bytes sent through socket */

	memset(receivedBuffer, 0, BUF_LEN+20); 
	memset(final_message, 0, BUF_LEN); 
	receivedBuffer[0]='\0';
	final_message[0]='\0';
	
	/* Reading from socket */
	
	bytesReceived = read(clientSock, receivedBuffer, BUF_LEN);
	receivedBuffer[bytesReceived]='\0';	
	final_message[bytesReceived]='\0';	
	
	if (bytesReceived < 0) {
		printf("\nERROR : Read() operation failed\n");
		exit(1);
	}

	/* Calculating Index till last message byte before digest */
	
	md_index = (int)(strlen((char*)receivedBuffer) - SHA_HASHLEN);	/* sha1() produces 20 byte has */

unsigned char*	digest =  (unsigned char*)malloc(sizeof(EVP_MAX_MD_SIZE));      /* to store received digest 	*/
unsigned char*	digest_own =  (unsigned char*)malloc(sizeof(EVP_MAX_MD_SIZE));  /* to store calculated digest 	*/
unsigned int*	ptr_len = (unsigned int *)malloc(sizeof(int));			/* digest length 		*/
char* 	md_index1 = (char*)receivedBuffer;

	md_index1+=md_index;
	strcpy((char*)digest,md_index1);	/* Copying digest from received Buffer */

	strncpy((char*)final_message,(char*)receivedBuffer,md_index);	/* Extract message from received Buffer */

		
		/* Calculating digest on message using shared key */

	digest_own = HMAC(EVP_sha1(), key,sizeof(key), (unsigned char*)final_message, 
		(int)strlen((char*)final_message), NULL, ptr_len);

		printf("\n!!!!Data Received from Client!!!!\n");
	
	if (nc_args->verbose ==1)	{
		printf("\nBytes received = %d\n", (int)bytesReceived);
		printf("\nMessage Digest Received:\n");
		printf("========================\n");
		for (i = 0; i < *ptr_len; i++) 
                	printf("%02x ", digest[i]);
		printf("\n");
		printf("\nMessage Digest Calculated at server:\n");
		printf("====================================\n");
		for (i = 0; i < *ptr_len; i++) 
                	printf("%02x ", digest_own[i]);
		printf("\n");
	}

fflush(stdout);

	/* Compare the received digest and the calculated digest */
	for (i = 0; i< 20; i++)
	{
		if(digest[i] != digest_own[i]) {
			printf("\nERROR : HMAC integrity not maintained. Digests are not equal\n");
			check = 1;
			break;
			
		}
	}	/* End of for loop */

	if (check == 0)	/* If both the digests are equal */
		printf("\nIntegrity maintained. HMAC Digests are equal\n");

	if(receivedBuffer[0] != '\0') { 
		fp = fopen(nc_args->filename, "w");	/* Open file to dump received data */
		
		if (fp == NULL) {
			printf("\nUnable to open file..ERRROR\n");
			exit(1);
		}
		fwrite(receivedBuffer,1,md_index,fp);	/* Write to file */
		printf("\nData Written to file : %s\n", nc_args->filename);
		fclose(fp);
	printf("\n\n\n\n.......Waiting for client to connect\n");	
	printf("\t\t\t\t\t Press Control+C to exit\n");	
	}	/* End of IF */
}
 	
	close(sockfd);
return;
}	/* End of Function listen_message() */
