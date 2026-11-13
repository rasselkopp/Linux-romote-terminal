#define _GNU_SOURCE
#define _POSIX_C_SOURCE >= 199309L
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>
#include <termio.h>
#include <termios.h>
#include <string.h>
#include <stdbool.h>
#include <poll.h>
//#include <syslog.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <signal.h>
#include "crypt_data.h"
#include "netdb.h"

//#define _DEBUG_KEYS

char go = 0;


typedef void (*signalhandler_t) (int);

static signalhandler_t handle_signal(int signur, signalhandler_t signalhandler){
	struct sigaction neu_sig, alt_sig;
	neu_sig.sa_handler = signalhandler;
	sigemptyset(&neu_sig.sa_mask);
	neu_sig.sa_flags = SA_RESTART;
	if(sigaction(signur,&neu_sig,&alt_sig) < 0 ){
		return SIG_ERR;
		}
	return alt_sig.sa_handler;
	}

static void mein_handler(int signur){
	int status;
	wait(&status);
	go = 0;
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

static void make_iv(const struct dir_iv *s, unsigned char iv[12])
{
    memcpy(iv, s->base_iv, 12);
    for (int i = 0; i < 8; i++)
        iv[11 - i] ^= (unsigned char)(s->counter >> (8 * i));
}

/* out muss inlen + 16 Byte groß sein; Rückgabe: Bytes auf der Leitung oder -1 */
int gcm_encrypt(EVP_CIPHER_CTX *ctx, const unsigned char *key, struct dir_iv *s,
                const unsigned char *in, int inlen, unsigned char *out,unsigned char *print_iv)
{
    unsigned char iv[12];
    int len, total;

    make_iv(s, iv);
    memcpy(print_iv,iv,12);
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
                const unsigned char *in, int inlen, unsigned char *out,unsigned char *print_iv)
{
    unsigned char iv[12];
    int len, total, ctlen = inlen - 16;

    if (ctlen < 0) return -1;
    make_iv(s, iv);
    memcpy(print_iv,iv,12);
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

int open_pts(int *fd_m,char *slave_name,int *testfd,char *test_buffer, unsigned char *logexec_path){
	pid_t pid = 0;
	int fd_flags = 0;
	struct f_owner_ex owner;
	sigset_t mask;
	
	
	if( (*fd_m = open("/dev/ptmx",O_RDWR | O_NOCTTY )) < 0 ){
        return -1;
        	}
	else{   sprintf(test_buffer,"fd_m: %i\n",*fd_m);
		//test_buffer[8] = 0;
		write(*testfd,test_buffer,8);
        	}

	if( ptsname_r(*fd_m,slave_name,50) == 0){
        	sprintf(test_buffer,"Slave device: %s\n",slave_name);
		//test_buffer[30] = 0;
		write(*testfd,test_buffer,strlen(test_buffer));
        	}
	else{   return -1;
        	}

	//printf("ptsname: %s\n",ptsname(fd_m));

	if( grantpt(*fd_m) != 0){
        	return -1;
        	}
	if( unlockpt(*fd_m) != 0){
        	return -1;
        	}
	
	// fork	
	
	if( (pid = fork()) == 0){
		//Child-process
		int fd_s = 0, err = 0, flags = 0, log = 0;
		struct winsize c_ws;
		char string[100] = {0},p_string[100] = {0};
		struct termios b_settings;
		struct termios tio;
		
		close(*fd_m);
		close(*testfd); 
		setsid();
	

		if( ((fd_s = open(slave_name,O_RDWR)) < 0) ){	// should be the first fd open, dont need to be close
			return -1;
			}
		if( ioctl(fd_s,TIOCSCTTY,NULL) < 0){exit(-1);}
		if( fd_s == 0 ){
			dup2(fd_s,STDIN_FILENO);
			dup2(STDIN_FILENO,STDOUT_FILENO);
			dup2(STDIN_FILENO,STDERR_FILENO);
			}
		else{	dup2(fd_s,STDIN_FILENO);
			close(fd_s);
			dup2(STDIN_FILENO,STDOUT_FILENO);
			dup2(STDIN_FILENO,STDERR_FILENO);
			}

		log = open(logexec_path,O_RDWR | O_CREAT | O_TRUNC,0666);
		sprintf(string,"fd_s: %i \n",fd_s);
		write(log,string,strlen(string));
		//sleep(3);
		//flags = fcntl(fd_s,F_GETFL);
		//flags = flags & ~(O_NONBLOCK);
		//fcntl(fd_s,F_SETFL,flags);
		write(log,"PTS vor read() \n",16);
		//ioctl(fd_s,TCFLSH,TCIOFLUSH);		
		if( (err = read(0,&c_ws,sizeof(struct winsize))) != sizeof(struct winsize)){
			sprintf(string,"winsize error: %i\n",err);
			write(log,string,strlen(string));
			}
		if( (err = read(0,p_string,1)) < 1 ){
			sprintf(string,"problem: %i \n",err);
			write(log,string,strlen(string));
			}

				
		sprintf(string,"Pts: ws: %i err: %i \n",c_ws.ws_col,err);
		write(log,string,strlen(string));

		if (tcgetattr(0, &tio) < 0) {
    			sprintf(string, "tcgetattr Fehler errno=%d %s\n",errno, strerror(errno));
    			write(log, string, strlen(string));
		}
		else {
    			sprintf(string,"termios: ICANON=%d ECHO=%d ISIG=%d IEXTEN=%d ""VMIN=%d VTIME=%d\n",!!(tio.c_lflag & ICANON),!!(tio.c_lflag & ECHO),!!(tio.c_lflag & ISIG),\
            		!!(tio.c_lflag & IEXTEN),tio.c_cc[VMIN],tio.c_cc[VTIME]);
			write(log, string, strlen(string));
		}

		ioctl(fd_s,TIOCSWINSZ,&c_ws);					//ioctl(fd_s,TIOCSWINSZ,&c_ws);
		//while(1){}
		err = 0;
		memset(string,0,100);

		while( err < 4){
			int hilf = 0;
			hilf = read(0,string,1);
			err = err + hilf;
			sprintf(string,"read(string): %i\n",err);
			write(log,string,strlen(string));
			}
		sprintf(string,"read Endstring done: %i\n",err);
		write(log,string,strlen(string));
		

		sprintf(string,"starte login \n");
		write(log,string,strlen(string));
		//sleep(1);

		//new tcsetattr
		if( tcgetattr(0,&b_settings) < 0 ){
			sprintf(string,"Fehler bei tcgetattr()\n");
			write(log,string,strlen(string));
			}
		b_settings.c_lflag &= ~ICANON;
		
		if( tcsetattr(0,TCSANOW,&b_settings) < 0 ){
			sprintf(string,"Fehler bei tcsetattr()\n");
			write(log,string,strlen(string));
			}

		close(log);
			
		//new tcsetattr
		execl("/bin/login","login",NULL);
		//sprintf(string,"NIEMALS\n");
		//write(log,string,strlen(string));
		exit(0);
		}
	else if(pid == -1){
		exit(-1);
		}
	else{
		return 0;
		}
	
	}

int set_paths(int fd_conf, unsigned char * key_path, unsigned char * log_path, unsigned char * logexec_path){
	
	int z = 0, fd_error = 0, m_read = 0;
	unsigned char * res = 0;
	unsigned char * key_words[] = {"key\0","server_log\0","exec_log\0"};			// use same keyword's like in server.conf
	unsigned char test_path[3073] = {0};

	if( (m_read = read(fd_conf,test_path,3072)) < 0){	
		fd_error = open("ERROR",O_RDWR | O_CREAT); write(fd_error,"server.conf not readable\n",25);
		close(fd_error); exit(1);
		
	}
	else{
		for(int i=0;i<3;i++){
			if( (res = strstr(test_path,key_words[i])) != 0){
				
				while(*res != '='){
					res++;
				}
				res = res + 2;
				z = 0;
				switch(i){
				case 0: while( *res != '\n'){
						key_path[z++] = *res; res++;}
						break;
				case 1: while( *res != '\n'){
				       		log_path[z++] = *res; res++;}
						break;
				case 2: while( *res != '\n'){
						logexec_path[z++] = *res; res++;}
						break;
				default:
				}
			}
		}
	}
}

void log_crypt(int fd, struct dir_iv * state_iv,unsigned char *print_iv){
	unsigned char buffer[256] = {0};
	unsigned char * p = buffer;

	sprintf(buffer,"counter: %li ",state_iv->counter);
	write(fd,buffer,strlen(buffer));
	write(fd,"IV: ",4);
	for(int i=0;i<12;i++){
		sprintf(p,"%02x",print_iv[i]);
		p += 2;
	}
	buffer[24] = '\n';
	write(fd,buffer,strlen(buffer));
	//write(fd,"\n",1);
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

int aes_decrypt(EVP_CIPHER_CTX * ctx,const unsigned char * key,const unsigned char * iv,const unsigned char * inb,int inl, unsigned char * out){
	unsigned int outl = 0, hilf = 0;
	EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,NULL,NULL);
	EVP_DecryptInit_ex(ctx,NULL,NULL,key,iv);
	EVP_DecryptUpdate(ctx,out,&outl,inb,inl);
	hilf = outl;
	EVP_DecryptFinal_ex(ctx,(out + hilf),&outl);
	return hilf + outl;
	}


int ssocket(int fd_conf){
	BIGNUM * bn_e = 0, * bn_n = 0, * bn_d = 0;	
	EVP_CIPHER_CTX * ctx;
	unsigned int ret = 0, packet_number = 0, hilf = 0;
	struct sockaddr_in addr, client;
	size_t client_len, len_s = 0;
	int y = 1,file = 0, lauf = 0, signal = 0;
	char buffer[4096 +1] = {0}, nachricht[2048] = {0}, test_buffer[2048] = {0}, /*go = 1,*/ sec_buffer[2048 + 32] = {0};	
	pid_t pid = 0;
	int fd_m = 0, len = 0, fd_flags = 0, ch_zahl = 0, error = 0, m_write = 0, m_read = 0, sig_number = 0, sec_len = 0, zahl = 0, fd_error = 0;
	int fd_key = 0, testfd = 0, mein_socket = 0, acc_socket = 0;
	char slave_name [256] = {0};
	struct f_owner_ex owner;
	sigset_t mask;
	siginfo_t info;
	struct winsize ws;
	long m_mode = 0;
	unsigned char sec_key[256] = {0}, key[1024] = {0}, key2[1024] = {0}, sec_iv[512] = {0}, sec2_key[256] = {0}, digest[32] = {0};
	unsigned char log_path[1024] = {0}, key_path[1024] = {0}, logexec_path[1024] = {0}, print_iv[12] = {0};
	struct c_data pk_data;
	struct protoent * pro_struc = 0;
	bool ext = false;
	BIO * fd_bio = 0;

	struct dir_iv state_iv;
	struct dir_iv state2_iv;

	state_iv.counter = 0;
	state2_iv.counter = 0;

	struct ak_data akk_data;

	akk_data.a_bytes = 0;
	akk_data.a_hdr = 0;
	memset(akk_data.a_buffer,0,sizeof(akk_data.a_buffer));

	// neu openssl 3.0
	EVP_PKEY * pkey = NULL;
	EVP_PKEY_CTX * pctx = NULL;
	OSSL_PARAM * param = NULL;
	BIGNUM * exponent = NULL, * modulu = NULL;
	//EVP_PKEY_CTX * pctx = NULL;
	
	handle_signal(SIGCHLD,mein_handler);
	//printf("Hallo hier ist secure socket\n");

	// get path's by key and log files
	set_paths(fd_conf,key_path,log_path,logexec_path);	

	close(fd_conf);

	errno = 0;
	if( (testfd = open(log_path,O_CREAT| O_TRUNC | O_RDWR,0666)) < 0){
		fd_error = open("ERROR",O_CREAT | O_RDWR,0666); write(fd_error,"open log file ERROR\n",20); exit(1);
	}

	//sprintf(buffer,"log path's:\n%s %s %s",key_path,log_path,logexec_path);
	//write(testfd,buffer,strlen(buffer));	
	
	// rsa openssl 3.0
	 
	errno = 0;
	if( (fd_key = open(key_path,O_RDONLY)) < 0 ){	sprintf(buffer,"RSA Key_file open FAILED: %s\n",strerror(errno));
								write(testfd,buffer,strlen(buffer));exit(1);}

	// read RSA Key
	fd_bio = BIO_new(BIO_s_fd());

	BIO_set_fd(fd_bio,fd_key,BIO_CLOSE);
	
	if( (pkey = PEM_read_bio_PrivateKey(fd_bio,NULL,NULL,NULL)) == NULL ){	sprintf(buffer,"PEM_read_PrivateKey() FAILED\n");
										write(testfd,buffer,strlen(buffer)); exit(1);}	
	BIO_free(fd_bio);
	close(fd_key);

	// get modulus and public exponent to send to client
	if( EVP_PKEY_get_bn_param(pkey,"n",&bn_n) != 1 ){	sprintf(buffer,"param get modulu FAILED\n");
								write(testfd,buffer,strlen(buffer));
								exit(1);}
	else{	sprintf(buffer,"param get modulu successfull\n");
		write(testfd,buffer,strlen(buffer));}

	if( EVP_PKEY_get_bn_param(pkey,"e",&bn_e) != 1 ){	sprintf(buffer,"param get exponent FAILED\n");
								write(testfd,buffer,strlen(buffer));
								exit(1);}
	else{	sprintf(buffer,"param get exponent successfull\n");
		write(testfd,buffer,strlen(buffer));}

	// get digest and print in log file
	if( rsa_fingerprint(bn_n,bn_e,digest) < 0){	sprintf(buffer,"rsa_fingerprint() FAILED\n");
							write(testfd,buffer,strlen(buffer));
							exit(1);
	}

	if( ( bn_d = BN_new()) == NULL){		sprintf(buffer,"BN_new() FAILED\n");
							write(testfd,buffer,strlen(buffer)); exit(1);}	
	BN_bin2bn(digest,32,bn_d);
	sprintf(buffer,"Digest: %s\n",BN_bn2hex(bn_d));
	write(testfd,buffer,strlen(buffer));	

	// rsa openssl 3.0

	// AES Chipher CTX
	if( (ctx = EVP_CIPHER_CTX_new()) == 0){
		sprintf(test_buffer,"Fehler bei EVP_CIPHER_CTX_new()\n");
		write(testfd,test_buffer,strlen(buffer));
		exit(-1);
		}
	
	// ctx generation

	//rsa out	
	//sprintf(test_buffer,"n.dmax: %d n.top: %d rsa size: %d\n",(*(*mein_rsa).n).dmax,(*(*mein_rsa).n).top,RSA_size(mein_rsa));
	//write(testfd,test_buffer,strlen(test_buffer));	
	
	// set socket
	if ( (mein_socket = socket(AF_INET,SOCK_STREAM,0)) < 0 ){
		sprintf(nachricht,"Fehler bei mein socket(): %d\n",mein_socket);
		write(testfd,nachricht,strlen(nachricht));
		return -1;
		}
	if( (setsockopt(mein_socket,SOL_SOCKET,SO_REUSEADDR,&y,sizeof(int))) < 0){
	//printf("Fehler bei set sock options\n");
	return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(15000);
	addr.sin_addr.s_addr = INADDR_ANY;

	if( bind(mein_socket,(struct sockaddr*)&addr,sizeof(addr)) < 0){
		//printf("Ferhler bei bind\n");
		return -1;
		}
	

	if( listen(mein_socket,5) < 0){
		//printf("FErhler bei listen()\n");
		}

	//accept loop, new connection is handled by child	
	while(1){
		if( (acc_socket = accept(mein_socket,(struct sockaddr*)&client,&len)) < 0){
			//printf("Fehler bei accept()\n");
			return -1;
			}

		//test keepalive
		
		/*if( ( pro_struc = getprotobyname("tcp")) == NULL ){ 
			sprintf(nachricht,"Fehler bei getprotobyname()!!!\n");
			write(testfd,nachricht,strlen(nachricht));
			}
		else{	sprintf(nachricht,"protocol: %d %s !!!!!\n",(*pro_struc).p_proto,(*pro_struc).p_name);
			write(testfd,nachricht,strlen(nachricht));
			}

		if( (setsockopt(acc_socket,6,SO_KEEPALIVE,&y,sizeof(int))) < 0 ){
			sprintf(nachricht,"Fehler bei KEEPALIVE!!!!!!! \n");
			write(testfd,nachricht,strlen(nachricht));
			}*/
		//test keepalive

		if( (pid = fork()) == 0){
			
		read(acc_socket,&ws, sizeof(struct winsize));

		// test open pts
		
		if(open_pts(&fd_m,slave_name,&testfd,test_buffer, logexec_path) < 0){
		sprintf(test_buffer,"Fehler bei open pts\n");
		write(testfd,test_buffer,20);
		exit(-1);
		}

		// test open pts

		while( (error = write(fd_m,&ws,sizeof(struct winsize))) != sizeof(struct winsize)){
			sprintf(buffer,"Fehler bei write winsize: %i \n",error);
			write(testfd,buffer,strlen(buffer));
			}
		write(fd_m,"\n",1);
		//ioctl(fd_m,TCFLSH,TCIOFLUSH);
		sprintf(buffer,"ACC_socket: ws: %i error: %i \n",ws.ws_col,error);
		write(testfd,buffer,strlen(buffer));

		error = read(fd_m,buffer,2 * sizeof(struct winsize) + 2);
		sprintf(buffer,"read winsize bytes: %i, fd_m: %i \n",error,fd_m);
		write(testfd,buffer,strlen(buffer));

		//neu winsize
		
		// rsa out
		if( ( error = write(acc_socket,BN_bn2hex( bn_n ),strlen( BN_bn2hex( bn_n )))) < strlen(BN_bn2hex( bn_n ))){
                        printf("Fehler bei write BIGNUM");
                        return -1;
                        }
                sprintf(buffer,"Modulus erfolgreich versendet: %d strlen modulus: %d \n",error,(int)strlen(BN_bn2hex( bn_n )));
		write(testfd,buffer,strlen(buffer));
	
		if( (ret = write(acc_socket,BN_bn2hex( bn_e ),strlen( BN_bn2hex( bn_e )))) < strlen(BN_bn2hex( bn_e ))){
                        printf("Fehler bei write() exponent\n");
                        exit(1);
                        }
                sprintf(buffer,"Exponent erfolreich versandt: %d\n",ret);
		write(testfd,buffer,strlen(buffer));
		
		if( (sec_len = read(acc_socket,sec_key,256)) != 256 ){
			sprintf(buffer,"sec_key fehler\n");
			write(testfd,buffer,strlen(buffer));
			exit(1);
			}

		if( read(acc_socket,sec2_key,256) != 256){
			sprintf(buffer,"sec2_key Sednung fehlerhat\n");
			write(testfd,buffer,strlen(buffer));
			exit(1);	
			}

		if( read(acc_socket,sec_iv,512) != 512){
			sprintf(buffer,"sec_iv Sendung fehlerhaft\n");
			write(testfd,buffer,strlen(buffer));
			exit(1);
			}

		// rsa openssl 3.0 encrypt 2 Key's and IV's
		   
		if( (pctx = EVP_PKEY_CTX_new(pkey,NULL)) == NULL){	sprintf(buffer,"pctx pkey new FAILED\n");
									write(testfd,buffer,strlen(buffer));
									exit(1);}

		if( EVP_PKEY_decrypt_init(pctx) != 1){	sprintf(buffer,"evp decrypt init FAILED\n");
							write(testfd,buffer,strlen(buffer));
							exit(1);}
		  
		if( EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_OAEP_PADDING) != 1){	sprintf(buffer,"ctx set rsa padding FAILED\n");
											write(testfd,buffer,strlen(buffer));
											exit(1);}

		if( EVP_PKEY_CTX_set_rsa_oaep_md(pctx,EVP_sha256()) != 1 ){		sprintf(buffer,"ctx set sha256 FAILE\n");
											write(testfd,buffer,strlen(buffer));
											exit(1);}

		if( EVP_PKEY_decrypt(pctx, NULL,&len_s,sec_key,sec_len) != 1){	sprintf(buffer,"evp decrypt laenge FAILED: %zu\n",len_s);
												write(testfd,buffer,strlen(buffer));
												exit(1);}	
		
		if( EVP_PKEY_decrypt(pctx,key,&len_s,sec_key,sec_len) != 1){	sprintf(buffer,"evp decrypt wert FAILED: %zu\n",len_s);
												write(testfd,buffer,strlen(buffer));
												exit(1);}	

		if( EVP_PKEY_decrypt(pctx, NULL,&len_s,sec2_key,sec_len) != 1){	sprintf(buffer,"evp decrypt key2 laenge FAILED: %zu\n",len_s);
												write(testfd,buffer,strlen(buffer));
												exit(1);}	
		
		if( EVP_PKEY_decrypt(pctx,key2,&len_s,sec2_key,sec_len) != 1){	sprintf(buffer,"evp decrypt key2 wert FAILED: %zu\n",len_s);
												write(testfd,buffer,strlen(buffer));
												exit(1);}

		if( EVP_PKEY_decrypt(pctx, NULL,&len_s,sec_iv,sec_len) != 1){	sprintf(buffer,"evp decrypt iv laenge FAILED: %zu\n",len_s);
												write(testfd,buffer,strlen(buffer));
												exit(1);}	
		
		if( EVP_PKEY_decrypt(pctx,state_iv.base_iv,&len_s,sec_iv,sec_len) != 1){	sprintf(buffer,"evp decrypt iv wert FAILED: %zu\n",len_s);
												write(testfd,buffer,strlen(buffer));
												exit(1);}

		if( EVP_PKEY_decrypt(pctx, NULL,&len_s,sec_iv + 256,sec_len) != 1){	sprintf(buffer,"evp decrypt iv2 laenge FAILED: %zu\n",len_s);
												write(testfd,buffer,strlen(buffer));
												exit(1);}	
		
		if( EVP_PKEY_decrypt(pctx,state2_iv.base_iv,&len_s,sec_iv + 256,sec_len) != 1){	sprintf(buffer,"evp decrypt iv2 wert FAILED: %zu\n",len_s);
												write(testfd,buffer,strlen(buffer));
												exit(1);}

		EVP_PKEY_free(pkey);
		EVP_PKEY_CTX_free(pctx);
		BN_clear_free(bn_n); BN_clear_free(bn_e);



		 //  rsa openssl 3.0
		 
#ifdef _DEBUG_KEYS
		sprintf(buffer,"random_key: ");
		write(testfd,buffer,strlen(buffer));
		for(lauf=0;lauf<32;lauf++){
			sprintf(buffer," %02x",key[lauf]);
			write(testfd,buffer,strlen(buffer));
			}
		
		sprintf(buffer,"\nrandom_key 2: ");
		write(testfd,buffer,strlen(buffer));
		for(lauf=0;lauf<32;lauf++){
			sprintf(buffer," %02x",key2[lauf]);
			write(testfd,buffer,strlen(buffer));
			}

		sprintf(buffer,"\nrandom IV: ");
		write(testfd,buffer,strlen(buffer));
		for(lauf=0;lauf<12;lauf++){
			sprintf(buffer," %02x",state_iv.base_iv[lauf]);
			write(testfd,buffer,strlen(buffer));
			}

		sprintf(buffer,"\nrandom 2 IV: ");
		write(testfd,buffer,strlen(buffer));
		for(lauf=0;lauf<12;lauf++){
			sprintf(buffer," %02x",state2_iv.base_iv[lauf]);
			write(testfd,buffer,strlen(buffer));
			}

		write(testfd,"\n",1);
#endif

		//fd_m assync
		fd_flags = fcntl(fd_m,F_GETFL);
		fd_flags = fd_flags | O_ASYNC | O_NONBLOCK;
		fcntl(fd_m,F_SETFL,fd_flags);
	
		fcntl(fd_m,F_SETSIG,SIGRTMIN);
		owner.type = F_OWNER_PID;
		owner.pid = getpid();
		fcntl(fd_m,F_SETOWN_EX,&owner);
	
		sigemptyset(&mask);
		sigaddset(&mask,SIGRTMIN);
		sigprocmask(SIG_SETMASK,&mask,NULL);
		//fd_m assync			
		
		//new acc_socket
		fd_flags = fcntl(acc_socket,F_GETFL);
		fd_flags = fd_flags | O_ASYNC | O_NONBLOCK;
		fcntl(acc_socket,F_SETFL,fd_flags);

		fcntl(acc_socket,F_SETSIG,SIGRTMIN);
		owner.type = F_OWNER_PID;
		owner.pid = getpid();
		fcntl(acc_socket,F_SETOWN_EX,&owner);
		//new acc_socket
	
		// new sigwaitinfo
		while(write(fd_m,"\n\n\n\n",4) != 4){
							sprintf(buffer,"Sendung 4 return werte negativ\n");
							write(testfd,buffer,strlen(buffer));
			}

		errno = 0;
		memset(buffer,0,2048);
		while( read(fd_m,buffer,4) > 0 && errno == 11 ){
			sprintf(buffer,"\nReturn can-ENDE: %d errno: %d fd_m: %i  %s\n",error,errno,fd_m,strerror(errno));
			write(testfd,buffer,strlen(buffer));
			errno = 0;
		}

		// loop until error or connection lost,exit
		go = 1;
		while(go == 1){
			if( (sig_number = sigwaitinfo(&mask,&info)) == SIGRTMIN){ //write(testfd,"SIGRTMIN\n",9);
			
				if(info.si_fd == fd_m && info.si_code == POLL_IN){
				errno = 0;
				memset(sec_buffer,0,1040);
				memset(buffer,0,1040);
					while( (zahl = read(fd_m,buffer,1024)) == 1024){	
						pk_data.p_length = zahl + 16, pk_data.p_number = packet_number++;
						pk_data.p_length = htonl(pk_data.p_length);pk_data.p_number = htonl(pk_data.p_number);	// +++++
						gcm_encrypt(ctx,key,&state_iv,(unsigned char*)&pk_data,8,sec_buffer, print_iv);
#ifdef _DEBUG_KEYS				
						log_crypt(testfd,&state_iv,print_iv);	
#endif
						hilf = gcm_encrypt(ctx,key,&state_iv,buffer,zahl,sec_buffer + 24, print_iv);
						//write(acc_socket,sec_buffer,hilf + 24);
						if( s_write(acc_socket,sec_buffer,hilf + 24) < 0){ go = 0; break; }
#ifdef _DEBUG_KEYS				
						log_crypt(testfd,&state_iv,print_iv);	
#endif	
						//sprintf(nachricht,"zahl: %i enchzahl: %i \n",zahl,hilf);
						//write(testfd,nachricht,strlen(nachricht));
						}
					if( zahl > 0){
						pk_data.p_length = zahl + 16, pk_data.p_number = packet_number++;
						pk_data.p_length = htonl(pk_data.p_length);pk_data.p_number = htonl(pk_data.p_number); 	// +++++
						gcm_encrypt(ctx,key,&state_iv,(unsigned char*)&pk_data,8,sec_buffer,print_iv);
#ifdef _DEBUG_KEYS				
						log_crypt(testfd,&state_iv,print_iv);	
#endif
						hilf = gcm_encrypt(ctx,key,&state_iv,buffer,zahl,sec_buffer + 24,print_iv);
						//m_write = write(acc_socket,sec_buffer,hilf + 24);
						if( s_write(acc_socket,sec_buffer,hilf + 24) < 0){ go = 0;}
#ifdef _DEBUG_KEYS				
						log_crypt(testfd,&state_iv,print_iv);	
#endif
						//sprintf(nachricht,"nach fd write: %i enchzahl: %i\n",m_write,hilf);
						//write(testfd,nachricht,strlen(nachricht));
					}
					else if( zahl == -1 ){	if( errno == EAGAIN || errno == EWOULDBLOCK)  continue;
								else if( errno == EIO) go = 0;
								else{ go = 0;
									sprintf(nachricht,"Fehler bei read() Masterside: %i errno: %i\n",zahl,errno);
									write(testfd,nachricht,strlen(nachricht));}
					}
					else if( zahl == 0){ 	sprintf(nachricht,"Sonderfall read() Masterside 0 Bytes gelesen\n");
								write(testfd,nachricht,strlen(nachricht));
								go = 0;
					}							
					else{			sprintf(nachricht,"Fehler bei read() Masterside %i errno: %i\n",zahl,errno);
								write(testfd,nachricht,strlen(nachricht));
								go = 0;
					}
					//}
				}
			else if(info.si_fd == acc_socket && info.si_code == POLL_IN){
			
			while(1){	
				errno = 0;
				zahl = 0;
				if( (ch_zahl = read(acc_socket,akk_data.a_buffer + akk_data.a_bytes, sizeof(akk_data.a_buffer) - akk_data.a_bytes)) > 0 ){ 
					//sprintf(nachricht,"M READ: %i rest: %i\n",ch_zahl,akk_data.a_bytes);
					//write(testfd,nachricht,strlen(nachricht));
					akk_data.a_bytes = akk_data.a_bytes + ch_zahl;
					error = 0;
					while(1){
						if(akk_data.a_hdr == 0){
							if(akk_data.a_bytes - zahl < 24){ break;}				// Header unvollständig
							gcm_decrypt(ctx,key2,&state2_iv,akk_data.a_buffer + zahl, 24,(unsigned char*)&pk_data,print_iv);
							pk_data.p_length = ntohl(pk_data.p_length);pk_data.p_number = ntohl(pk_data.p_number);	//++++++
#ifdef _DEBUG_KEYS					
							log_crypt(testfd,&state2_iv,print_iv);	
#endif
							zahl = zahl + 24;
							akk_data.a_hdr = 1;
						}
						if( pk_data.p_length > 1048){	error = 1; break;}
						if( pk_data.p_length > akk_data.a_bytes - zahl){	break;} // Payload unvollständig
						hilf = gcm_decrypt(ctx,key2,&state2_iv,akk_data.a_buffer + zahl,pk_data.p_length,buffer,print_iv);
						if( t_write(fd_m,buffer,hilf) < 0){
							sprintf(nachricht,"Fehler bei t_write() fd_m\n");
							write(testfd,nachricht,strlen(nachricht));
							error = 1; break;
						}
#ifdef _DEBUG_KEYS				
						log_crypt(testfd,&state2_iv,print_iv);	
#endif
						zahl = zahl + pk_data.p_length;
						akk_data.a_hdr = 0;
						//sprintf(nachricht,"M READ Schleife: %i bytes verarb:%i bytes:%i\n",pk_data.p_length,zahl,akk_data.a_bytes);
						//write(testfd,nachricht,strlen(nachricht));
					}
					if( error == 1){	go = 0; break;}
					memmove(akk_data.a_buffer, akk_data.a_buffer + zahl, akk_data.a_bytes - zahl);
					akk_data.a_bytes = akk_data.a_bytes - zahl;

				}
				else if( ch_zahl == -1){
					if( errno == EAGAIN || errno == EWOULDBLOCK) break;
					else{	sprintf(nachricht,"Fehler read() socket\n");
						write(testfd,nachricht,strlen(nachricht));
						go = 0; break;
						}
				}
				else if( ch_zahl == 0){
					write(acc_socket,sec_buffer,0);
					read(acc_socket,sec_buffer,0);
					sprintf(nachricht,"read() 0 Programm beendet\n");
					write(testfd,nachricht,strlen(nachricht));
					go = 0; break;
				}
				else{	sprintf(nachricht,"Fehler unbekannt bei read() socket: %i\n",ch_zahl);
					write(testfd,nachricht,strlen(nachricht));
					go = 0; break;
					}

				} //while

				}
			else{	sprintf(nachricht,"Anderes info.si_code!!!!\n"); // new test
				write(testfd,nachricht,strlen(nachricht));	 // new test
				}						 // new test
			}
			else{	sprintf(nachricht,"Anderes Signal:%i SIG_HUP:%i !!!\n",sig_number,SIGHUP);	//new test
				write(testfd,nachricht,strlen(nachricht));	//new test
				//exit(0);
				go = 0;
				}			
			
		}							// while(go==1)
		
		close(fd_m);
		close(acc_socket);
		EVP_CIPHER_CTX_free(ctx);
		close(testfd);
		OPENSSL_cleanse(key,16); OPENSSL_cleanse(key2,16); OPENSSL_cleanse(state_iv.base_iv,12);OPENSSL_cleanse(state2_iv.base_iv,12);
		OPENSSL_cleanse(&state_iv.counter,sizeof(uint64_t));OPENSSL_cleanse(&state2_iv.counter,sizeof(uint64_t));
		exit(0);
		}							// fork()
		else if( pid == -1){exit(1);}
		close(acc_socket);
	}								// accept() loop

	EVP_CIPHER_CTX_free(ctx);
	close(testfd);
	close(mein_socket);
	return 0;
	}

int main(int argc,char ** argv){
	int fd_conf = 0;
	if( fork() != 0){
		printf("Eltern/Fehler Prozess Ende\n");
		exit(0);
		}
	printf("hier ist kind\n");
	if( setsid() < 0){
		printf("Prozess kann nicht session-führer werden\n");
		exit(EXIT_FAILURE);
		}
	//handle_signal(SIGHUP,SIG_IGN);
	if( argc < 2){	printf("Please give the working directory path as argument\n"); exit(0);}
	else{	
		if ( chdir(argv[1]) < 0 ){	printf("Working directory not possible: %s\n",argv[1]), exit(1);}
	}
	if( (fd_conf = open("server.conf",O_RDWR)) < 0){	printf("Server.conf is not available\n"), exit(1);
	}

	umask(0);
	close(0);
	close(1);
	close(2);
	
	if( fork() != 0){
		exit(0);
		}
	return ssocket(fd_conf);
	}

