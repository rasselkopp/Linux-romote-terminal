#define _GNU_SOURCE
#define _POSIX_C_SOURCE >= 199309L
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <termios.h>
#include <termio.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <poll.h>


#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/param_build.h>
#include "crypt_data.h"

#define Eingabe 1024
//#define _DEBUG_KEYS

static void make_iv(const struct dir_iv *s, unsigned char iv[12])
{
    memcpy(iv, s->base_iv, 12);
    for (int i = 0; i < 8; i++)
        iv[11 - i] ^= (unsigned char)(s->counter >> (8 * i));
}

/* out muss inlen + 16 Byte groß sein; Rückgabe: Bytes auf der Leitung oder -1 */
int gcm_encrypt(EVP_CIPHER_CTX *ctx, const unsigned char *key, struct dir_iv *s,
                const unsigned char *in, int inlen, unsigned char *out)
{
    unsigned char iv[12];
    int len, total;

    make_iv(s, iv);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) return -1;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) return -1;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) return -1;
    if (EVP_EncryptUpdate(ctx, out, &len, in, inlen) != 1) return -1;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) return -1;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + total) != 1) return -1;

    s->counter++;
    return total + 16;
}

/* inlen enthält den Tag; out braucht inlen - 16 Byte; Rückgabe: Klartextlänge oder -1 */
int gcm_decrypt(EVP_CIPHER_CTX *ctx, const unsigned char *key, struct dir_iv *s,
                const unsigned char *in, int inlen, unsigned char *out)
{
    unsigned char iv[12];
    int len, total, ctlen = inlen - 16;

    if (ctlen < 0) return -1;
    make_iv(s, iv);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) return -1;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) return -1;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) return -1;
    if (EVP_DecryptUpdate(ctx, out, &len, in, ctlen) != 1) return -1;
    total = len;
    /* Tag VOR Final setzen (const-Cast nötig, OpenSSL ändert ihn nicht) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(in + ctlen)) != 1) return -1;
    if (EVP_DecryptFinal_ex(ctx, out + total, &len) <= 0) return -1;   /* Tag falsch */
    total += len;

    s->counter++;
    return total;
}

/* Fingerprint = SHA-256( len(n) | n | len(e) | e ), Längen als 4 Byte Big-Endian */
int rsa_fingerprint(const BIGNUM *n, const BIGNUM *e, unsigned char fp[32])
{
    unsigned char buf[4 + 1024 + 4 + 16];   /* reicht bis RSA-8192 */
    int nl = BN_num_bytes(n), el = BN_num_bytes(e);
    if (nl <= 0 || el <= 0 || nl > 1024 || el > 16) return -1;

    unsigned char *p = buf;
    p[0] = nl >> 24; p[1] = nl >> 16; p[2] = nl >> 8; p[3] = nl; p += 4;
    BN_bn2bin(n, p); p += nl;
    p[0] = el >> 24; p[1] = el >> 16; p[2] = el >> 8; p[3] = el; p += 4;
    BN_bn2bin(e, p); p += el;

    unsigned int fl = 0;
    if (EVP_Digest(buf, p - buf, fp, &fl, EVP_sha256(), NULL) != 1) return -1;
    return 0;
}

static void digest_to_hex(const unsigned char d[32], char out[65])
{
    static const char hx[] = "0123456789ABCDEF";
    for (int i = 0; i < 32; i++) {
        out[2*i]     = hx[d[i] >> 4];
        out[2*i + 1] = hx[d[i] & 0x0f];
    }
    out[64] = '\0';
}

int aes_encrypt(EVP_CIPHER_CTX * ctx,const unsigned char * key,const unsigned char * iv,const unsigned char * inb,int inl,unsigned char * out){
	unsigned int outl = 0, hilf = 0;
	EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,NULL,NULL);
	EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv);
	EVP_EncryptUpdate(ctx,out,&outl,inb,inl);
	hilf = outl;
	EVP_EncryptFinal_ex(ctx,(out + hilf),&outl);
	return hilf + outl;	
	}

int aes_decrypt(EVP_CIPHER_CTX * ctx,const unsigned char * key,const unsigned char * iv,const unsigned char * inb,int inl,unsigned char * out){
	unsigned int outl = 0, hilf = 0;
	EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,NULL,NULL);
	EVP_DecryptInit_ex(ctx,NULL,NULL,key,iv);
	EVP_DecryptUpdate(ctx,out,&outl,inb,inl);
	hilf = outl;
	EVP_DecryptFinal_ex(ctx,(out + hilf),&outl);
	return hilf + outl;
	}

int s_write(int fd, const unsigned char *buf, int bytes)
{
    const unsigned char *p = buf;
    while (bytes > 0) {
        ssize_t b = send(fd, p, bytes, MSG_NOSIGNAL);
        if (b > 0) { p += b; bytes -= b; continue; }
        if (b < 0 && errno == EINTR) continue;
        if (b < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pf = { .fd = fd, .events = POLLOUT };
            poll(&pf, 1, -1);
            continue;
        }
        return -1;
    }
    return 0;
}

int t_write(int fd,unsigned char * buffer,int bytes){
	unsigned char * p = buffer;

	while(bytes > 0){
		errno = 0;
		int b = 0;
		b = write(fd,p,bytes);
		if(b > 0){ p = p + b; bytes = bytes - b; continue;}
		if(b < 0 && errno == EINTR){ continue;}
		if(b < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)){
			struct pollfd pf = { .fd = fd, .events = POLLOUT };
			poll(&pf,1,-1);
			continue;
		}
		return -1;	
	}
	return 0;
}

static struct termios e_settings;

void ex_func(void){
	tcgetattr(0,&e_settings);
	e_settings.c_lflag = e_settings.c_lflag | ECHO | ICANON;
	tcsetattr(0,TCSANOW,&e_settings);	
	}

int main( int argc, char ** argv){
	BIGNUM * bn_e = 0, * bn_n = 0, * bn_d = 0;	
	EVP_CIPHER_CTX * ctx = 0;
	int mein_socket = 0,y = 1,ret = 0, fd_flags = 0, zahl = 0, lauf = 0, ch_zahl = 0, PORT = 0, fd_known = 0, fd_file = 0;
	unsigned int hilf = 0, total_length = 0, packet_number = 0; 
	size_t outlen = 0;
	struct sockaddr_in addr, client;
	size_t client_len;
	char buffer[2049] = {0}, sec_buffer[2048 + 16] = {0}, nachricht[256] = {0}, go = 1;
	struct termios b_settings,n_settings;
	sigset_t mask;
	struct f_owner_ex owner;
	struct winsize ws;
	siginfo_t info;	
	long m_mode = 0;
	//const unsigned char iv[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	unsigned char gcm_iv[12] = {0};
	unsigned char sec_key[256] = {0}, sec2_key[256] = {0}, IP[16] = {0}, digest[33] = {0}, digest_flag = 0, pre_digest[65] = {0}, server_row[50] = {0}, hex_digest[65]={0};
	unsigned char r_key[32] = {0}, r2_key[32] = {0}, sec_iv[512] = {0}, err = 0, * known_buff = 0, * result = 0, * result2 = 0, * result_source = 0, frage = 0;
	struct c_data pk_data;
        struct ak_data akk_data;
	struct stat st;

	struct dir_iv state_iv;
	struct dir_iv state2_iv;	

	akk_data.a_hdr = 0;
	akk_data.a_bytes = 0;
	memset(akk_data.a_buffer,0,2048);

	// openssl 3.0
	EVP_PKEY_CTX * ppctx = NULL;
	EVP_PKEY * ppkey = NULL;
	OSSL_PARAM * bparams = 0;	
	OSSL_PARAM_BLD * bld = OSSL_PARAM_BLD_new();

	SSL_load_error_strings();
	// openssl 3.0
	
	// get IP and PORT for connection
	if(argc != 2){	printf("Bitte geben Sie die Adresse an. Format: IP:Port\n"); exit(1);}
	else{		
		char * zeichen = argv[1], *endptr = 0;
		int i = 0;
		struct in_addr ip;
		while( *zeichen && *zeichen != ':' ){
			//printf("%c ",*zeichen);
			IP[i++] = *zeichen;	
			zeichen++;
		}
		zeichen++;
		
		if( inet_pton(AF_INET,IP,&ip) != 1){	printf("ungültige IP\n"); exit(1);}
		PORT = (int)strtol(zeichen,&endptr,10);
		if( PORT < 1024 || PORT > 65535){	printf("PORT out of Range exit\nm"); exit(1);}
		

		printf("IP: %s PORT: %i\n",IP,PORT);
		}

	// exit function
	atexit(ex_func);
	// exit function
	
#ifdef _DEBUG_KEYS
	if( (fd_file = open("test_client", O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0 ){
		printf("Fehler bei open() logfile\n"); exit(1);	
		}
#endif

	// get the digest if one is there	
	if( (fd_known = open("known_connection",O_RDWR | O_APPEND)) < 0){
		printf("Fehler bei open() known_connections\n"); exit(1);
		}
	
	if( fstat(fd_known,&st) == -1){
		printf("Fehler bei fstat()\n");
		exit(1);
	}
	else{ known_buff = (unsigned char*)malloc(st.st_size + 256);
		if(known_buff == NULL){
			printf("Fehler bei mallo()\n");
			exit(1);
		}
		ret = 0;
		hilf = 0;
		while( (ret = read(fd_known,known_buff + hilf, st.st_size - hilf)) != st.st_size - hilf ){
			if(ret > 0) hilf += ret;
			ret = 0;
		}
	known_buff[st.st_size] = 0;
	}
	
	if( (result = strstr(known_buff,IP)) != 0){
		while( *result != ' '){ result++;}
		result++;
		memcpy(pre_digest,result,64);
	}
	else{	printf("IP nicht gefunden keine Digest\n");}
	
	if( ( bn_n = BN_secure_new() ) == NULL){
                printf("Fehler bei new BN n mein RSA\n");
                return -1;      
                }
        if( ( bn_e = BN_secure_new() ) == NULL ){
                printf("Fehler bei new BN e mein RSA\n");
                return -1;
                }
	if( (bn_d = BN_new()) == NULL){
		printf("Fehler bei new BN d\n");
		return -1;
		}	
		
		
	
	// random key
	if( RAND_bytes(r_key,32) != 1){
		printf("Fehler bei random bytes\n");
		}
#ifdef _DEBUG_KEYS
	else{	printf("r_key:");
		for(lauf=0;lauf<32;lauf++){
			printf(" %02x ",r_key[lauf]);
			}
		printf("\n");
		}
#endif
	if( RAND_bytes(r2_key,32) != 1){
		printf("Fehler bei random bytes\n");
		}
#ifdef _DEBUG_KEYS
	else{	printf("r2_key:");
		for(lauf=0;lauf<32;lauf++){
			printf(" %02x ",r2_key[lauf]);
			}
		printf("\n");
		}
#endif
	//random key
	//random IV
	
	if( RAND_bytes(state_iv.base_iv,12) != 1){
		printf("Fehler bei random IV\n");
		}
#ifdef _DEBUG_KEYS
	else{	printf("IV:");
		for(lauf=0;lauf<12;lauf++){
			printf(" %02x ",state_iv.base_iv[lauf]);
			}
		printf("\n");
		}
#endif
	if( RAND_bytes(state2_iv.base_iv,12) != 1){
		printf("Fehler bei random IV\n");
		}
#ifdef _DEBUG_KEYS
	else{	printf("IV 2:");
		for(lauf=0;lauf<12;lauf++){
			printf(" %02x ",state2_iv.base_iv[lauf]);
			}
		printf("\n");
		}
#endif
	//random IV
	
	// AES Cipher_CTX
	if( (ctx = EVP_CIPHER_CTX_new()) == NULL ){
		printf("Fehler bei EVP_CIPHER_CTX_ne() \n");
		exit(-1);
		}

	//open socket	
	if( (mein_socket = socket(AF_INET,SOCK_STREAM,0)) < 0){
		printf("Fehler bei socket()\n");
		return -1;
		}
	
	if( (setsockopt(mein_socket,SOL_SOCKET,SO_REUSEADDR,&y,sizeof(int))) < 0){
	printf("Fehler bei set sock options\n");
	return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	inet_aton(IP,&addr.sin_addr);

	// set Terminal
	tcgetattr(0,&n_settings);
	n_settings.c_lflag = n_settings.c_lflag & ~(ICANON | ECHO );
	tcsetattr(0,TCSANOW,&n_settings);	
	
	if( connect(mein_socket,(struct sockaddr *)&addr,sizeof(struct sockaddr_in)) < 0){
		printf("Verbindung konnte nicht hergestellt werden\n");
		return -1;
		}

	//send winsize to server
	ioctl(0,TIOCGWINSZ,&ws);
	//printf("client ws: %i \n",ws.ws_col);
	printf("write winsize: %i\n",(int)write(mein_socket,&ws,sizeof(struct winsize)));
	//neu winsize 	
	
	// get RSA modulus
	if( (ret = read(mein_socket,buffer,512)) != 512 ){
                printf("Fehler bei read() modulo\n");
                return -1;
                }

        //printf("Modulus Empfang erfolreich: %d, sizeof string: %d\n",ret,(int)strlen(buffer) );

        BN_hex2bn( &bn_n,buffer);
#ifdef _DEBUG_KEYS
	printf("Modulus: ");
        BN_print_fp(stdout,bn_n);
	printf("\n");
#endif

	for(int i=0;i<1025;i++){		// clear buffer
		buffer[i] = 0;
		}

	if( (ret = read(mein_socket,buffer,6)) != 6 ){
		printf("Fehler bei read() exponent: %i\n",ret);
		return -1;
		}
	
	//printf("Exponent Empfang erfolgreich: %d,sizeof string: %d\n",ret,(int)strlen(buffer));
	
	BN_hex2bn( &bn_e,buffer);
#ifdef _DEBUG_KEYS
	printf("Exponent: ");
	BN_print_fp(stdout,bn_e);
	printf("\n");	
#endif
	// get server digest	
	if( rsa_fingerprint(bn_n,bn_e,digest) < 0){	printf("rsa_fingerprint() FAILED");exit(1);}
	else{	digest_to_hex(digest,hex_digest);
		printf("Server digest: %s\n",hex_digest);}	


	//compare digest
	if(*pre_digest){	
		printf("pre_Digest: %s\n",pre_digest);
		if( CRYPTO_memcmp(hex_digest,pre_digest,64) ){
			printf("ACHTUNG!!!!!!! Digest's stimmen NICHT überein\n");
			printf("Wurde der ServerKey geändert ? Soll die Digest angepasst werden ? (y/n)");
			fflush(stdout);
			read(0,&frage,1);
			printf("\n");
			if(frage == 'y'){					// if yes remove row
				result2 = result;
				while( *result != '\n'){result--;}
				result++;
				while(*result2 != '\n'){result2++;}
				result2++;
				result_source = result2;
				ret = 0;
				while(*result2 && *result2 != '\n'){ ret++; result2++; }
				ret++;
				memmove(result,result_source, (known_buff+st.st_size) - result_source);
				result[ (known_buff+st.st_size) - result_source  ] = 0;
				printf("Ergebnis Buffer:\n%sRET: %i\n",known_buff,ret);
				if( ftruncate(fd_known,0) ){
					printf("truncate kown_connection file to 0 not possible\n"); exit(1);
				}
				else{	if( (write(fd_known,known_buff,strlen(known_buff))) != strlen(known_buff) )
					{	printf("Write known_connection FAILED\n");}
					exit(1);
				}	
			}
			else{	printf("\n");exit(1);}
		}
		else{	printf("Digest sind GLEICH\n");}
	}
	else{
		frage = 0;
		printf("Keine Serverdaten vorhanden, soll der Server aufgenommen werden (y/n):");
		fflush(stdout);
		read(0,&frage,1);
		printf("\n");
		if(frage == 'y'){
			write(fd_known,argv[1],strlen(argv[1]));			// fd opened with truncate flag
			write(fd_known," ",1);
			write(fd_known,hex_digest,strlen(hex_digest));
			write(fd_known,"\n",1);	
		}
		else{ exit(0);}
	}	

	//	openssl 3.0 bild RSA-Key, encrypt 2 Keys and 2 IVs and send them to server

	if( OSSL_PARAM_BLD_push_BN(bld,"n",bn_n) <= 0){	printf("param build FAILED\n");exit(1);}

	if( OSSL_PARAM_BLD_push_BN(bld,"e",bn_e) <= 0){	printf("param build FAILED\n");exit(1);}

	if( ( bparams = OSSL_PARAM_BLD_to_param(bld)) == NULL){	printf("param build FAILED\n");exit(1);}

	for(int i=0;bparams[i].key != NULL;i++){
		//printf("params-key: %s\n",(char*)(bparams[i].key));
	}

	if( (ppctx = EVP_PKEY_CTX_new_from_name(NULL,"RSA",NULL)) == NULL ){	printf("pkey ctx new from name FAILED\n");exit(1);}
	//else{	printf("pkey ctx new from name successfull\n");}

	if( EVP_PKEY_fromdata_init(ppctx) <= 0){	printf("fromdata init FAILED\n");exit(1);}
	//else{	printf("keygen init successfull\n");}

	if( EVP_PKEY_fromdata(ppctx,&ppkey, EVP_PKEY_PUBLIC_KEY, bparams) <= 0){	printf("ppkey generate fromdata FAILED\n");exit(1);}
	//else{	printf("ppkey generate fromdata successfull\n");}

	EVP_PKEY_CTX_free(ppctx);

	if( (ppctx = EVP_PKEY_CTX_new(ppkey,NULL)) == NULL ){	printf("CTX generation FAILED\n"); exit(1);}
	//else{	printf("CTX generated!\n");}

	if( EVP_PKEY_public_check(ppctx) != 1){printf("pkey is not OK!\n");exit(1);}

	if( EVP_PKEY_encrypt_init(ppctx) <= 0){	printf("pkey encrypt_init FAILED\n");exit(1);}
	//else{	printf("pkey encrypt_init successfull\n");}

	if( EVP_PKEY_CTX_set_rsa_padding(ppctx,RSA_PKCS1_OAEP_PADDING) <= 0){	printf("CTX set rsa padding FAILED\n");exit(1);}
	//else{	printf("CTX set rsa padding successfull\n");}

	if( EVP_PKEY_CTX_set_rsa_oaep_md(ppctx, EVP_sha256()) <= 0){	printf("CTX set md 256 FAILED\n");exit(1);}
	//else{	printf("CTX set sha256 successfull\n");}	

	if( EVP_PKEY_encrypt(ppctx, NULL, &outlen, r_key, 32) <= 0){	printf("encypt for outlen FAILED!\n");exit(1);}
	//else{	printf("outlen: %ld\n",outlen);}

	if( EVP_PKEY_encrypt(ppctx, sec_key, &outlen, r_key, 32) <= 0){	printf("encrypt FAILED!\n");exit(1);}
	//else{	printf("encrypted buffer: %ld\n",outlen);}

	if( EVP_PKEY_encrypt(ppctx, NULL, &outlen, r2_key, 32) <= 0){	printf("encypt key2 for outlen FAILED!\n");exit(1);}
	//else{	printf("2. outlen: %ld\n",outlen);}

	if( EVP_PKEY_encrypt(ppctx, sec2_key, &outlen, r2_key, 32) <= 0){	printf("encrypt key2 FAILED!\n");exit(1);}
	//else{	printf("2. encrypted buffer: %ld\n",outlen);}

	outlen = 0;

	if( EVP_PKEY_encrypt(ppctx, NULL, &outlen, state_iv.base_iv, 12) <= 0){	printf("encypt IV for outlen FAILED!\n");exit(1);}
	//else{	printf("IV outlen: %ld\n",outlen);}

	if( EVP_PKEY_encrypt(ppctx, sec_iv, &outlen, state_iv.base_iv, 12) <= 0){	printf("encrypt IV FAILED!\n");exit(1);}
	//else{	printf("IV encrypted buffer: %ld\n",outlen);}

	if( EVP_PKEY_encrypt(ppctx, NULL, &outlen, state2_iv.base_iv, 12) <= 0){	printf("encrypt IV FAILED!\n");exit(1);}
	//else{	printf("IV 2 outlen: %ld\n",outlen);}

	if( EVP_PKEY_encrypt(ppctx, sec_iv + 256, &outlen, state2_iv.base_iv, 12) <= 0){	printf("encrypt IV FAILED!\n");exit(1);}
	//else{	printf("IV 2 encrypted buffer: %ld\n",outlen);}

	EVP_PKEY_CTX_free(ppctx);
	EVP_PKEY_free(ppkey);
	BN_clear_free(bn_n);BN_clear_free(bn_e);	

	//	openssl 3.0
	 
	if(write(mein_socket,sec_key,256) != 256){
		printf("key-sendung nicht erfolgreich\n");
		exit(-1);
		}
	
	/*if(write(mein_socket,iv,16) != 16){
		printf("IV-Sendung fehlerhaft\n");
		exit(-1);	
		}*/

	
	if(write(mein_socket,sec2_key,256) != 256){
		printf("key-sendung nicht erfolgreich\n");
		exit(-1);
		}
	if(write(mein_socket,sec_iv,512) != 512){
		printf("IV-Sendung fehlerhaft\n");
		exit(-1);	
		}

	// new code for terminal
		
	
	fd_flags = fcntl(0,F_GETFL);
	fd_flags = fd_flags | O_ASYNC | O_NONBLOCK;
	fcntl(0,F_SETFL,fd_flags);

	fcntl(0,F_SETSIG,SIGRTMIN);
	owner.type = F_OWNER_PID; 
	owner.pid = getpid();
	fcntl(0,F_SETOWN_EX,&owner);
	fcntl(0,F_GETOWN,&owner);
	//printf("IO-SIG OwNER: %i\n",(int)owner.pid);
	
	sigemptyset(&mask);
	sigaddset(&mask,SIGRTMIN);
	//sigfillset(&mask); // test block all signals
	sigprocmask(SIG_SETMASK,&mask,NULL);

		
	// neu fd mein_socket
	fd_flags = fcntl(mein_socket,F_GETFL);
	fd_flags = fd_flags | O_ASYNC | O_NONBLOCK;
	fcntl(mein_socket,F_SETFL,fd_flags);

	fcntl(mein_socket,F_SETSIG,SIGRTMIN);
	owner.type = F_OWNER_PID;
	owner.pid = getpid();
	fcntl(mein_socket,F_SETOWN_EX,&owner);

	// neu fd mein_socket
	
	// loop until lost connection or exit	
	go = 1;
	while(go == 1){ 
		if( sigwaitinfo(&mask,&info) == SIGRTMIN ){ if(info.si_code == POLL_ERR)exit(1);
			errno = 0;
			if(info.si_fd == 0 && info.si_code == POLL_IN ){
				memset(sec_buffer,0,1040);
				while( (ch_zahl = read(0,buffer,Eingabe)) == Eingabe){
					pk_data.p_length = ch_zahl + 16; pk_data.p_number = packet_number++;
					pk_data.p_length = htonl(pk_data.p_length); pk_data.p_number = htonl(pk_data.p_number);	//+++++
					gcm_encrypt(ctx,r2_key,&state2_iv,(unsigned char*)&pk_data,8,sec_buffer);
					hilf = gcm_encrypt(ctx,r2_key,&state2_iv,buffer,ch_zahl,sec_buffer + 24);
					//write(mein_socket,sec_buffer,hilf+24);
					if( s_write(mein_socket,sec_buffer,hilf + 24) < 0){ go = 0;}
					}
				if( ch_zahl > 0){
					pk_data.p_length = ch_zahl + 16; pk_data.p_number = packet_number++;
					pk_data.p_length = htonl(pk_data.p_length); pk_data.p_number = htonl(pk_data.p_number);	//+++++
					gcm_encrypt(ctx,r2_key,&state2_iv,(unsigned char*)&pk_data,8,sec_buffer);
					hilf = gcm_encrypt(ctx,r2_key,&state2_iv,buffer,ch_zahl,sec_buffer + 24);
					//write(mein_socket,sec_buffer,hilf + 24);
					if( s_write(mein_socket,sec_buffer,hilf + 24) < 0){ go = 0;}	
				}
				else if( ch_zahl == -1 ){  if( errno == EAGAIN || errno == EWOULDBLOCK)  continue;
                                                                else if( errno == EIO) go = 0;
                                                                else{ go = 0;
                                                                        //sprintf(nachricht,"Fehler bei read() Masterside: %i errno: %i\n",ch_zahl,errno);
                                                                        //write(fd_file,nachricht,strlen(nachricht));
									}
                                }
                                else if( ch_zahl == 0){    	//sprintf(nachricht,"Sonderfall read() Terminalside 0 Bytes gelesen\n");
                                                                //write(fd_file,nachricht,strlen(nachricht));
                                                                go = 0;
                                }
                                else{                   	//sprintf(nachricht,"Fehler bei read() Terminalside %i errno: %i\n",zahl,errno);
                                                                //write(fd_file,nachricht,strlen(nachricht));
                                                                go = 0;
                               }	
			}
			else if(info.si_fd == mein_socket && info.si_code == POLL_IN){
				
				while(1){
					errno = 0;
					ch_zahl = read(mein_socket,akk_data.a_buffer + akk_data.a_bytes, sizeof(akk_data.a_buffer) - akk_data.a_bytes);
					if( ch_zahl > 0){
						//sprintf(nachricht,"READ size: %i rest: %i \n",ch_zahl,akk_data.a_bytes);
						//write(fd_file,nachricht,strlen(nachricht));
						akk_data.a_bytes += ch_zahl;
						zahl = 0; err = 0;
						while(1){
							if( akk_data.a_hdr == 0){
								if(akk_data.a_bytes - zahl < 24){ break;}					// Header unvollständig	
								gcm_decrypt(ctx,r_key,&state_iv,akk_data.a_buffer + zahl,24,(unsigned char*)&pk_data);
								pk_data.p_length = ntohl(pk_data.p_length);pk_data.p_number = ntohl(pk_data.p_number);	//++++
								if( pk_data.p_length > 1040 ){	err = 1; break;}
								zahl = zahl + 24;
								akk_data.a_hdr = 1;
								//sprintf(nachricht,"header p_length: %i \n",pk_data.p_length);
								//write(fd_file,nachricht,strlen(nachricht));
							}
							if( pk_data.p_length > akk_data.a_bytes - zahl){ break; }				// payload unvollständig
							hilf = gcm_decrypt(ctx,r_key,&state_iv,akk_data.a_buffer + zahl,pk_data.p_length,buffer);
							//sprintf(nachricht,"nach entschlüsselung: %i pos: %i\n",akk_data.a_bytes,zahl);
							//write(fd_file,nachricht,strlen(nachricht));
							if( t_write(0,buffer,hilf) < 0){	
								//sprintf(nachricht,"Fehler bei t_write()\n");
								//write(fd_file,nachricht,strlen(nachricht));
								err=1;break;
							}
							zahl = zahl + pk_data.p_length;
							akk_data.a_hdr = 0;
						}
						if(err == 1){	go = 0; break;}
						memmove(akk_data.a_buffer,akk_data.a_buffer + zahl,akk_data.a_bytes - zahl);
						akk_data.a_bytes = akk_data.a_bytes - zahl;
						//sprintf(nachricht,"Verlasse Akk Schleife pos: %i bytes: %i\n",zahl,akk_data.a_bytes);
						//write(fd_file,nachricht,strlen(nachricht));		
					}
					else if( ch_zahl == 0){
						go = 0; break;
					}
					else if( ch_zahl < 0){
						if(errno == EINTR){ continue;}
						else if( errno == EAGAIN || errno == EWOULDBLOCK){ break;}	
					}
					else{	perror("read"); go=0; break;}

					} //while	
				}
				else if( info.si_code == POLL_OUT){}						//only catch do nothing
			}
			else{printf("FREMDES SIGNAL\n");}

		}			//while(go)
	// neu fd 0
	
	
	printf("Hier close exit()!!\n");
	close(mein_socket);
	EVP_CIPHER_CTX_free(ctx); 
	OPENSSL_cleanse(r_key,16);OPENSSL_cleanse(r2_key,16);OPENSSL_cleanse(state_iv.base_iv,12);OPENSSL_cleanse(state2_iv.base_iv,12);
	OPENSSL_cleanse(&state_iv.counter,sizeof(uint64_t));OPENSSL_cleanse(&state2_iv.counter,sizeof(uint64_t));
	return 0;
	}
