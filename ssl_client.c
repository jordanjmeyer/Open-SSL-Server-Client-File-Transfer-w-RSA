#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/dh.h>	


//RESOURCES

//File transfer using char array, since SSL accomodates char arrays
//http://www.codecodex.com/wiki/Read_a_file_into_a_byte_array 

//SSL
//https://www.openssl.org/docs/apps/openssl.html
//http://wiki.openssl.org/index.php/Main_Page     *** and various pages

//More on SSL
//http://www.cs.miami.edu/~burt/learning/Csc524.102/notes/ssl-tutorial.html

//prints str as hex, for keys/hashes
void print_hex(unsigned char * str, int size)
{
  int i;
  for (i = 0; i < size; i++)
    printf("%02X", str[i] & 0xFF);
  printf("\n\n");
}

//strip "--"/'=' from port param
int remove_eq(char * new_array, char * arg)
{
	char * tok;
	tok = strtok(arg, "-=");
	strcpy(new_array, tok);
	return 0;
}

//split command line arguments
int parse_argv(char* argv[], char* server, char* port, char * cmd, char * path)
{
	char parser[64];
	remove_eq(parser, argv[1]);
	remove_eq(server, NULL);
	remove_eq(parser, argv[2]);
	remove_eq(port, NULL);
	remove_eq(cmd, argv[3]);
	strcpy(path, argv[4]);
	return atoi(port);
}

int check_server_response(int dec_resp_size, 
						unsigned char decrypted_server_response [dec_resp_size],
						unsigned char hash[dec_resp_size])
{
	//loop compares client-side hash and the decrypted server's response
	int i; //C99 error if declared inside for-loop
	for(i = 0; i < dec_resp_size; i++)
	{
	  if(decrypted_server_response[i] != hash[i])//check every element
	  {
	    printf("Hashed values do not match, quitting\n");
	    return 1;
	  }
	}
	return 0;
}

//main, SSL workings not divided into functions, due to time and variable control
int main(int argc, char * argv[])
{	
	//client uses strictly 5 params
	if(argc < 5 || argc > 5)
	{
		printf("Use: client --serverAddress --port send/receive filepath");
		return 1;
	}
	
	//client parameters
	char server[64];
	char port[64];
	char cmd[64];
	char path[64];
	char address[128];	
	parse_argv(argv, server, port, cmd, path);
	
	//for output msg
	strcpy(address, server);
	strcat(address, ":");
	strcat(address, port);
	
	//ensure correct params parsed from argv
	printf("\nServer:     %s\n", server);
	printf("Port #:     %s\n", port);
	printf("Address:    %s\n", address);
	printf("Command:    %s\n", cmd);
	printf("File(Path): %s\n", path);


	printf("-----------------------\n");
	printf("BEGIN CONNECTION SETUP\n");
	printf("-----------------------\n");

	//Client setup
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	
	BIO * bio;
	SSL * ssl;
	SSL_CTX * ctx;
	
	if(!SSL_library_init())
	{
		printf("Error initializing OpenSSL\n");
		return 1;
	}

	ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx)
	{
	  printf("Error setting up client SSL context\n");
	  ERR_print_errors_fp(stderr);
	  return 1;
	}
	printf("\nClient context setup done.\n");
	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	
	if(SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA") != 1)
	{
	  printf("Error setting client cipher list\n");
	  return 1;
	}
	
	bio = BIO_new_connect(address);
	if(bio == NULL) 
	{
	  printf("There was a problem creating the BIO object\n");
	  return 1;
	}
	
	if(BIO_do_connect(bio) <= 0)
	{
	  printf("BIO connection failed, quitting\n");
	  return 1;
	}
	
	ssl = SSL_new(ctx);
	
	if(!ssl)
	{
	  printf("Error creating client SSL, quitting\n");
	  return 1;
	}
	
	SSL_set_bio(ssl, bio, bio);
	printf("Attempting to connect to the server specified\n");
	
	if(SSL_connect(ssl) <= 0)
	{
	  printf("Error connecting to server, quitting\n");
	  return 1;
	}
	
	//client context setup done
	printf("Connection successful\n\n");
	printf("-----------------------\n");
	printf("BEGIN CHALLENGE\n");
	printf("-----------------------\n");
	
	//challenge for server /  authentication
	unsigned char challenge[64];
	
	//cryptographically acceptable PRNG
	if(RAND_bytes(challenge, 64) != 1)
	{
	  printf("Error generating random challenge, quitting\n");
	  ERR_print_errors_fp(stderr);
	  return 1;
	}
	//challenge made

	printf("Unencrypted Challenge: ");
	print_hex(challenge, 64);
	    
	//hash challenge for auth. check from server
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(challenge, 64, hash);
	printf("Challenge Hash: ");
	print_hex(hash, SHA_DIGEST_LENGTH);

	//encrypt challenge using public RSA key from rsapub.pem
	BIO * pub_key = BIO_new_file("rsapub.pem", "r");
	if(pub_key == NULL)
	{
	  printf("Error reading in public key, quitting\n");
	  return 1;
	}
	
	//client uses public key
	RSA * public_key =  PEM_read_bio_RSA_PUBKEY(pub_key, NULL, 0, NULL);
	
	int rsa_size = RSA_size(public_key);
	unsigned char encrypted_challenge[rsa_size - 11];
	int enc_size = RSA_public_encrypt(64, challenge, encrypted_challenge, public_key, RSA_PKCS1_PADDING);
	
	if( enc_size == -1)
	{
	  printf("Error encrypting challenge, quitting\n");
	  return 1;
	}
	
	printf("RSA encrypted size: %d\n\n", enc_size);
	printf("Encrypted Challenge: \n");
	print_hex(encrypted_challenge, enc_size);
	//encryption done

	//send server the challenge just made
	int r = SSL_write(ssl, encrypted_challenge, enc_size);
	if(r < 0)
	{
	  printf("Error writing to server, quitting\n");
	  return 1;
	}

	//read signed server response 
	unsigned char in_buff[enc_size];
	r = SSL_read(ssl, in_buff, enc_size);
	if(r < 0)
	{
	  printf("Error reading from server\n");
	  return 1;
	}
	
	printf("Server returned: \n");
	print_hex(in_buff, sizeof in_buff);

	//begin decryption of server response
	unsigned char decrypted_server_response[SHA_DIGEST_LENGTH];
	int dec_resp_size = RSA_public_decrypt(r, in_buff, decrypted_server_response, public_key, RSA_PKCS1_PADDING);
	printf("Decrypted Response: ");
	print_hex(decrypted_server_response, dec_resp_size);
	//end decryption
	
	if(check_server_response(dec_resp_size, decrypted_server_response, hash))
	{
		//printf("Hashed values do not match, quitting\n");
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    SSL_CTX_free(ctx);
	    return 1;
	}
	
	printf("Decrypted server response and challenge hash match. SUCCESS\n\n");
	//SUCCESS
	printf("-----------------------\n");
	printf("BEGIN FILE TRANSFER \n");
	printf("-----------------------\n");

    //File work
	printf("File work can begin.\n");
    if(!strcmp(cmd, "send"))
    {
    	SSL_write(ssl, cmd, 64);
    	SSL_write(ssl, path, 64);
    
    		printf("Will send server: %s\n", path);
    		//printf("From client: %s\n", cmd);
	  		//SSL_read(ssl, path, 64);
	  		//printf("Will send file: %s\n", path);
	  	
	  		FILE * send_file = fopen(path, "r");
	  		if(send_file == NULL)
	  		{
	  			//if file does not exist, close client
	  			printf("File does not exist locally, closing client\n");
	  			SSL_shutdown(ssl);
				SSL_free(ssl);
				printf("SSL connection closed\n");
				SSL_CTX_free(ctx);
				printf("SSL context freed\n");
				printf("Client finished\n");
				return 1;
		  	}
		  	else
	  		{
	  			printf("Sending File: %s\n", path);
	  			
	  			fseek(send_file, 0, SEEK_END);
	  			long len = ftell(send_file);		
	  			
	  			char file_size[32];
	  			
	  			sprintf(file_size, "%ld", len);
	  			printf("File size: %s\n", file_size);
	  			SSL_write(ssl, file_size, 32);
	  			
	  			char * ret = malloc(len);
                char * ret_ptr = ret;
	  			fseek(send_file, 0, SEEK_SET);
	  			fread(ret, 1, len, send_file);
	  			fclose(send_file);
	  			
                int i;
                for(i = 0; i < (len/16384) +1; ++i)//attempted fix for large files
                {
                    SSL_write(ssl, ret_ptr, len);
                    ret_ptr += 16384;
	  			}
                
	  			//Used to debug
	  			//int bytes_written = SSL_write(ssl, ret, len); 
	  			//printf("Bytes Written: %d\n", bytes_written);
	  		}
     
    }
    else if(!strcmp(cmd, "receive"))
    {
    	printf("Writing: %s\n", cmd);
    	printf("File: %s\n", path);
    	SSL_write(ssl, cmd, 64);
    	SSL_write(ssl, path, 64);
    
    	//printf("Will receive from server: ", path);
    	
    	char file_size [32];
    	SSL_read(ssl, file_size, 32);
    	
    	//if file doesn't exist on server-side, quit
    	if(file_size[0] == 'x')
    	{
    		printf("File does not exist on server, closing connection.\n");
    		SSL_shutdown(ssl);
			SSL_free(ssl);
			printf("SSL connection closed\n");
			SSL_CTX_free(ctx);
			printf("SSL context freed\n");
			printf("Client finished\n");
			return 1;
    	}
    	
    	printf("File size: %s\n", file_size);
    	long len = atol(file_size);
    	
    	char file_buf[len];
        char * ptr = file_buf;
        int i;
        for(i = 0; i < (len/16384) +1; ++i)
        {
            SSL_read(ssl, ptr, len);
            ptr += 16384;
    	}
    	FILE * receive_file = fopen(path, "w");
    	fwrite(file_buf, 1, len, receive_file);
	    fclose(receive_file);
	    
	    //printf("File received: ", receive_file);
    
    }
    
    printf("-----------------------\n");
	printf("FILE TRANSFER COMPLETE, CLIENT CLOSING\n");
	printf("-----------------------\n");

	//Freedom
	SSL_shutdown(ssl);
	SSL_free(ssl);
	printf("SSL connection closed\n");
	SSL_CTX_free(ctx);
	printf("SSL context freed\n");
	printf("Client finished\n");
	return 0;
}
