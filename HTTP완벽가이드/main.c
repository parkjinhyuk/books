#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    // 0. 변수 선언
    SSL *ssl;
    SSL_CTX *ctx;
    const SSL_METHOD *client_method;
    X509 *server_cert;
    int sd;
    int err;
    char *str;
    char *hostname;
    char outbuf[4096];
    char inbuf[4096];
    char host_header[512];
    struct hostent *host_entry;
    struct sockaddr_in server_socket_address;
    struct in_addr ip;

    // 1. 라이브러리 초기화
    OPENSSL_init_ssl(0, NULL);
    client_method = TLS_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(client_method);
    printf("(1) SSL 콘텍스트가 초기화되었습니다\n\n");

    // 2. 서버의 호스트명을 IP 주소로 변환
    hostname = argv[1];
    host_entry = gethostbyname(hostname);
    bcopy(host_entry->h_addr, &(ip.s_addr), host_entry->h_length);
    printf("(2) '%s'의 IP주소: '%s'\n\n", hostname, inet_ntoa(ip));

    // 3. 서버의 443 포트로 TCP 커넥션을 연다
    sd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_socket_address, '\0', sizeof(server_socket_address));
    server_socket_address.sin_family = AF_INET;
    server_socket_address.sin_port = htons(443);
    memcpy(&(server_socket_address.sin_addr.s_addr), host_entry->h_addr, host_entry->h_length);
    err = connect(sd, (struct sockaddr*)&server_socket_address, sizeof(server_socket_address));
    if (err < 0) { perror("서버 포트와 연결할 수 없습니다"); exit(1); }
    printf("(3) 호스트 '%s', 포트 %d로 TCP커넥션을 열었습니다\n\n", hostname, server_socket_address.sin_port);

    // 4. TCP 커넥션을 통해 SSL 핸드셰이크 개시
    ssl = SSL_new(ctx);     // SSL 스택 종점을 만든다
    SSL_set_fd(ssl, sd);    // SSL 스택을 소켓에 붙인다
    err = SSL_connect(ssl); // SSL 핸드셰이크를 시작한다
    printf("(4) SSL 종점이 생성되었으며 핸드셰이크가 완료되었습니다\n\n");

    // 5. 협상을 통해 선택된 암호를 출력한다
    printf("(5) 다음의 암호로 SSL 연결이 되었습니다: %s\n\n", SSL_get_cipher(ssl));
    
    // 6. 서버 인증서를 출력한다
    server_cert = SSL_get_peer_certificate(ssl);
    printf("(6) 서버 인증서를 받았습니다:\n\n");
    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    printf("    대상: %s\n", str);
    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    printf("    발급자: %s\n\n", str);
    /* 인증서 검사 로직이 여기에*/
    X509_free(server_cert);

    // 7. 핸드셰이크 완료 - SSL을 통해 HTTP 요청을 보낸다
    sprintf(host_header, "Host: %s:443\r\n", hostname);
    strcpy(outbuf, "GET / HTTP/1.1\r\n");
    strcat(outbuf, host_header);
    strcat(outbuf, "Connection: close\r\n");
    strcat(outbuf, "\r\n");
    err = SSL_write(ssl, outbuf, strlen(outbuf));
    shutdown(sd, 1); // 서버에 EOF를 보낸다
    printf("(7) 암호화된 채널을 통해 HTTP 요청을 보냈습니다:\n\n%s\n", outbuf);

    // 8. SSL 스택으로부터 HTTP 응답을 읽어들인다
    err = SSL_read(ssl, inbuf, sizeof(inbuf)-1);
    inbuf[err] = '\0';
    printf("(8) HTTP 응답에서 %d 바이트를 가져왔습니다:\n\n%s\n", err, inbuf);

    // 9. 모두 끝났으므로 커넥션을 닫고 정리한다
    SSL_shutdown(ssl);
    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf("(9) 모두 끝났으므로 커넥션을 닫고 정리합니다\n\n");

    return 0;
}