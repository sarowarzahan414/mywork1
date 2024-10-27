#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

void* recvMsg(void*);       /* for receiving messages */

#define max(a, b)         \
    ({ typeof(a) _a = a;    \
     typeof(b) _b = b;    \
     _a > _b ? _a : _b; })

RSA *Prikey;
RSA *Pubkey;

RSA* loadRSAPrivateKey(const char* privateKeyPath) {
    FILE* fp = fopen(privateKeyPath, "r");
    if (!fp) {
        perror("Failed to open private key file");
        return NULL;
    }

    RSA* key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!key) {
        ERR_print_errors_fp(stderr);
    }

    return key;
}

RSA* loadRSAPublicKey(const char* publicKeyPath) {
    FILE* fp = fopen(publicKeyPath, "r");
    if (!fp) {
        perror("Failed to open public key file");
        return NULL;
    }

    RSA* key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!key) {
        ERR_print_errors_fp(stderr);
    }

    return key;
}

/* network stuff... */

static int listensock, sockfd;

static void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int initServerNet(int port) {
    int reuse = 1;
    struct sockaddr_in serv_addr;

    // Create the socket
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    if (listensock < 0)
        error("ERROR opening socket");

    // Set socket options to allow address reuse
    if (setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        error("ERROR setting socket options");
    }

    // Initialize the server address structure
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to any available interface
    serv_addr.sin_port = htons(port);        // Set the port number

    // Bind the socket to the port
    if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");

    fprintf(stderr, "listening on port %i...\n", port);

    // Listen for incoming connections (max queue of 1 connection)
    listen(listensock, 1);

    // Accept an incoming connection
    socklen_t clilen = sizeof(struct sockaddr_in);
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");

    // Close the listening socket after accepting the connection
    close(listensock);

    fprintf(stderr, "connection made, starting session...\n");
    return 0;
}

int initClientNet(char* hostname, int port) {
    struct sockaddr_in serv_addr;
    struct hostent *server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");

    return 0;
}

void authenticateuser()
{
    Prikey = loadRSAPrivateKey("clientprivate.pem");
    Pubkey = loadRSAPublicKey("approvedclient.pem");

    char* message = "My name is Ozymandias, King of Kings; Look on my Works, ye Mighty, and despair!";
    size_t len = strlen(message);
    unsigned char* ct = malloc(RSA_size(Pubkey));
    int ctlen = RSA_public_encrypt(len+1, (unsigned char*)message, ct, Pubkey, RSA_PKCS1_OAEP_PADDING);
    if (ctlen == -1) exit(1);
    char* pt = malloc(ctlen);
    RSA_private_decrypt(ctlen, ct, (unsigned char*)pt, Prikey, RSA_PKCS1_OAEP_PADDING);

    if (strcmp(pt, message) == 0)
        printf("Authenticated the client with the server\n");
    else
        printf("Authentication failed, user not confirmed!\n");

    free(ct);
    free(pt);
}

unsigned char key[32];
unsigned char iv[16];
unsigned char receiveMac[64];
unsigned char hmackey[24];

void AESinit()
{
    unsigned char x[32];
    unsigned char y[16];
    size_t i;
    for (i = 0; i < 32; i++) 
        x[i] = (rand() % 100);
    for (i = 0; i < 16; i++) 
        y[i] = (rand() % 100);
    strncpy((char*)key, (char*)x, 32); 
    strncpy((char*)iv, (char*)y, 16);
    strncpy((char*)hmackey, (char*)y, 16);
}

void AESenc(char * message, char * output)
{
    unsigned char mac[64];
    unsigned int maclen;
    size_t message_len = strlen(message);

    HMAC(EVP_sha512(), hmackey, strlen((char*)hmackey), (unsigned char*)message, message_len, mac, &maclen);

    char newmessage[1024];
    strcpy(newmessage, message);
    strcat(newmessage, "-");
    strcat(newmessage, (char*)mac);

    unsigned char ct[10024];
    memset(ct, 0, 10024);
    size_t len = strlen(newmessage);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, key, iv))
        ERR_print_errors_fp(stderr);
    int nWritten;
    if (1 != EVP_EncryptUpdate(ctx, ct, &nWritten, (unsigned char*)newmessage, len))
        ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    size_t ctlen = nWritten;

    memcpy(output, ct, ctlen);
}

void AESdec(char * message, char * output, ssize_t nbytes)
{
    unsigned char pt[10024];
    memset(pt, 0, 10024);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), 0, key, iv))
        ERR_print_errors_fp(stderr);
    int nWritten;
    for (size_t i = 0; i < strlen(message); i++) {
        if (1 != EVP_DecryptUpdate(ctx, pt+i, &nWritten, (unsigned char*)message+i, 1))
            ERR_print_errors_fp(stderr);
    }
    EVP_CIPHER_CTX_free(ctx);
    memcpy(output, pt, nbytes);
}

void VerifyHmac(char * message, unsigned char * sentMac)
{
    unsigned char mac[64];
    unsigned int maclen;
    HMAC(EVP_sha512(), hmackey, strlen((char*)hmackey), (unsigned char*)message, strlen(message), mac, &maclen);

    if (memcmp(sentMac, mac, 64) == 0)
        printf("HMAC verified.\nMessage is authentic and comes from a trusted user with the key.\n");
    else
        printf("HMAC not verified.\nMessage may be tampered or comes from a user without the key.\n");
}

void* recvMsg(void *param)
{
    size_t maxlen = 10024;
    char msg[maxlen+2];
    ssize_t nbytes;

    char pt[512];
    memset(pt, 0, 512);

    while (1) {
        if ((nbytes = recv(sockfd, msg, maxlen, 0)) == -1)
            error("recv failed");
        if (nbytes == 0) {
            return 0;
        }

        AESdec(msg, pt, nbytes);

        char delim[] = "-";
        char *ptr = strtok(pt, delim);
        unsigned char *ptr2 = (unsigned char*)strtok(NULL, delim);

        VerifyHmac(ptr, ptr2);

        char* m = malloc(maxlen+2);
        memcpy(m, pt, nbytes);
        if (m[nbytes-1] != '\n')
            m[nbytes++] = '\n';
        m[nbytes] = 0;
    }
    return 0;
}

// Adding the main function
int main(int argc, char *argv[]) {
    int port = 1337;             // Default port
    int is_server = 0;           // Flag for server mode
    char hostname[256] = "localhost"; // Default hostname for client mode

    // Initialize GTK
    gtk_init(&argc, &argv);

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            is_server = 1;  // Set server mode
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            strcpy(hostname, argv[++i]); // Set hostname for client mode
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);  // Set port
        }
    }

    // Perform authentication and AES initialization
    authenticateuser();
    AESinit();

    // Run as server
    if (is_server) {
        printf("Starting server on port %d...\n", port);
        initServerNet(port);  // Initialize server and wait for a connection
        pthread_t receiver_thread;
        pthread_create(&receiver_thread, NULL, recvMsg, NULL);
        pthread_join(receiver_thread, NULL);  // Wait for the receiver thread
    }
    // Run as client
    else {
        printf("Connecting to server %s on port %d...\n", hostname, port);
        initClientNet(hostname, port);  // Connect to the server
        pthread_t receiver_thread;
        pthread_create(&receiver_thread, NULL, recvMsg, NULL);
        pthread_join(receiver_thread, NULL);  // Wait for the receiver thread
    }

    return 0;
}

