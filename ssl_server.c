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
#include <openssl/sha.h>

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

int main(int argc, char * argv[])
{
	BIO * bio;
	SSL * ssl;
	SSL_CTX * ctx;

//grab port from command line
	if(argc < 2 || argc > 2)
	{
		printf("Use: server --port=portnumber \n");
		return 1;
	}
	
	//parse port
	char port[64];
	char * pch;
	pch = strtok(argv[1], "=");
	strcpy(port, pch);
	pch = strtok(NULL, "=");
	strcpy(port, pch);
	printf("Port: %s\n", port);

	printf("-----------------------\n");
	printf("BEGIN CONNECTION SETUP\n");
	printf("-----------------------\n");

	//server setup
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	if(!SSL_library_init())
	{
		printf("Error initializing OpenSSL, quitting\n");
		return 1;
	}

	
	ctx = SSL_CTX_new(SSLv23_server_method());
	if(!ctx)
	{
	  printf("Error creating client SSL context, quitting\n");
	  return 1;
	}
	printf("Client context created.\n");
	
	//SETUP FOR DIFFIE-HELLMAN, to avoid standard auth settings
	DH* dh = DH_new();
	if(!dh)
	{
	  printf("Error at DH_new(), quitting\n");
	  return 1;
	}

	if(!DH_generate_parameters_ex(dh, 64, 2, 0))
	{
	  printf("Error at DH_generate_parameters_ex, quitting\n");
	  return 1;
	}

	int dh_codes;
	if(!DH_check(dh, &dh_codes))
	{
	  printf("Error at DH_check(), quitting\n");
	  return 1;
	}
	
	if(!DH_generate_key(dh))
	{
	  printf("Error at DH_generate_key(), quitting\n");
	  return 1;
	}

	SSL_CTX_set_tmp_dh(ctx, dh);   
	
	//DO NOT SEND CERTIFICATE TO CLIENT, AUTH DONE VIA RSA/SHA-1
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	
	if(SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA") != 1)
	{
	    printf("Error at SSL_CTX_set_cipher_list(), quitting\n");
	    return 1;
	}
	//server setup complete, for D-H, so the challenge for RSA will follow
	
	//set address based on port and current addr
	char serv_address[64];
	char * s = "*:";
	strcpy(serv_address, s);
	strcat(serv_address, port);
	printf("BIO Port: %s\n", serv_address);
	
	bio = BIO_new_accept(serv_address);
    
	if(!bio)
	{
	  printf("Error creating server BIO, quitting\n");
	  return 1;
	}
    
	if(BIO_do_accept(bio) <= 0)
	{
	  printf("Error accepting BIO object, quitting\n");
	  return 1;
	}

	BIO * client;
	
	//server runs continuously, so more than one client can connect
	//and the server will constantly wait for connections
	while(1)
	{
	  if(BIO_do_accept(bio) <= 0)
	  {
	    printf("Error accepting BIO object, quitting\n");
	  }
	  //client connected
	  else
	  {
	    printf("Connection accepted\n");
	    client = BIO_pop(bio);
	    if (!(ssl = SSL_new(ctx)))
	    {
	      printf("Error creating SSL, quitting\n");
	      return 1;
	    }
	    SSL_set_bio(ssl, client, client);
	    if (SSL_accept(ssl) <= 0)
	    {
	      printf("Error accepting SSL, quitting\n");
	      return 1;
	    }
	    printf("Connection successful!\n");
	    
	    printf("-----------------------\n");
		printf("BEGIN CHALLENGE\n");
		printf("-----------------------\n");
	    
	    unsigned char buf[1024];
	    int r = SSL_read(ssl, buf, sizeof buf);
	    printf("Bytes read: %d\n\n", r);
	    printf("Received challenge: \n");
	    print_hex(buf, r);

    	//decrypt client's challenge using the private key
	    BIO * private_key = BIO_new_file("rsapriv.pem", "r");
	    if(private_key == NULL)
	    {
	      printf("Error reading in private key, quitting\n");
	      return 1;
	    }
	    
	    //server uses private key
	    RSA * priv_key =  PEM_read_bio_RSAPrivateKey(private_key, NULL, 0, NULL);
	    
	    int rsa_size = RSA_size(priv_key);
	    unsigned char decrypted_challenge[rsa_size];
	    int dec_size = RSA_private_decrypt(r, buf, decrypted_challenge, priv_key, RSA_PKCS1_PADDING);
	    if( dec_size == -1)
	    {
	      printf("Error decrypting challenge, quitting\n");
	      return 1;
	    }
	    printf("RSA decrypted size: %d\n\n", dec_size);
	    printf("Decrypted issued challenge: ");
	    
	    print_hex(decrypted_challenge, dec_size);
    	//decryption of challenge done
    	
    	//hash the decrypted challenge
	    unsigned char hash[SHA_DIGEST_LENGTH];
	    SHA1(decrypted_challenge, dec_size, hash);
	    
	    printf("Hash value of decrypted_challenge: ");
	    print_hex(hash, SHA_DIGEST_LENGTH);
	    //hashing done
	    
	    //sign the hash from above
	    unsigned char signed_challenge[rsa_size - 11];
	    int signed_size = RSA_private_encrypt(SHA_DIGEST_LENGTH, hash, signed_challenge, priv_key, RSA_PKCS1_PADDING);
	    if( signed_size == -1)
	    {
	      printf("Error decrypting the challenge, quitting\n");
	      return 1;
	    }
	    printf("RSA signed size: %d\n\n", signed_size);
	    printf("Signed challenge: \n");
	    
    // Sending signed hashed challenge to client
	    print_hex(signed_challenge, signed_size);
	    r = SSL_write(ssl, signed_challenge, signed_size);
	    printf("Bytes sent: %d\n", r);
    // End sending signed hashed challenge to client
    
	    printf("-----------------------\n");
		printf("BEGIN FILE WORK IF CHALLENGE RESPONSE SUCCESSFUL\n");
		printf("-----------------------\n");

		char cmd [64];
		char path [64];
    	SSL_read(ssl, cmd, 64);
    	//printf("From client: %s\n", cmd);
    	
	    if(!strcmp(cmd, "receive"))
	  	{
	  		printf("From client: %s\n", cmd);
	  		SSL_read(ssl, path, 64);
	  		//printf("Will send file: %s\n", path);
	  	
	  		FILE * send_file = fopen(path, "r");
	  		if(send_file == NULL)
	  		{
	  			printf("File not found\n");
	  			char file_size[32];
	  			file_size[0] = 'x';
	  			SSL_write(ssl, file_size, 32);
	  			printf("Sent file-not-found message\n");
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
	  			fseek(send_file, 0, SEEK_SET);
	  			fread(ret, 1, len, send_file);
	  			fclose(send_file);
	  			
                char * ret_ptr = ret;
                int i;
                for(i = 0; i < (len/16384) +1; ++i)
                {
                    SSL_write(ssl, ret_ptr, len);
                    ret_ptr += 16384;
	  			}
	  			
	  			//Used to debug
	  			//int bytes_written = SSL_write(ssl, ret, len); 
	  			//printf("Bytes Written: %d\n", bytes_written);
	  		}
	  }
	  else if(!strcmp(cmd, "send"))
	  {
	  	//***MATCHES CLIENT-SIDE RECEIVE
	  	SSL_read(ssl, path, 64);

	  	printf("Will store file: %s\n", path);
    	printf("Receiving File: %s\n", path);
    	
    	char file_size [32];
    	SSL_read(ssl, file_size, 32);
    	
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
	    
	    printf("File received: %s\n", path);
	  }
	  else
	  {
	  	printf("INVALID COMMAND\n");
	  }
	    printf("-----------------------\n");
		printf("FILE TRANSFER COMPLETE, WILL AWAIT NEW CONNECTION\n");
		printf("-----------------------\n");
	 }
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	
	}
	return 0;
}
