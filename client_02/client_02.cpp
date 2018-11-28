#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <chrono>
#include <iostream>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <applink.c>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment (lib, "libssl.lib")
#pragma comment (lib, "libcrypto.lib")

//SSL_read() works based on the SSL/TLS records. The data are received in records (with a maximum record size of 16kB for SSLv3/TLSv1).
#define DEFAULT_BUFLEN 16*1024
#define DEFAULT_PORT "4433"

#if 0
int __cdecl main(int argc, char **argv)
{
    SSL_CTX * ctx = SSL_CTX_new(TLS_client_method());
    BIO * bio = BIO_new_ssl_connect(ctx);
    SSL * ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, "192.168.2.182:4433");
    if (BIO_do_connect(bio) <= 0) {
        printf("NOK: BIO_do_connect\n");
        return 1;
    }

}
#else
int __cdecl main(int argc, char **argv)
{
    SSL_CTX * ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    printf("OK: SSL_CTX_new\n");

    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
        *ptr = NULL,
        hints;
    char sendbuf[] = "this is a test";
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    // Validate the parameters
    if (argc != 2) {
        printf("usage: %s server-name\n", argv[0]);
        return 1;
    }

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %d\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }
        // Receive timeout.
#if 0
        DWORD timeout = 5000;
        iResult = setsockopt(ConnectSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
        if (iResult == SOCKET_ERROR) {
            printf("setsockopt failed with error: %d\n", WSAGetLastError());
        }
#endif

        // Non blocking mode.
#if 0
        unsigned long iMode = 1;
        iResult = ioctlsocket(ConnectSocket, FIONBIO, &iMode);
        if (iResult == SOCKET_ERROR) {
            printf("ioctlsocket failed with error: %d\n", WSAGetLastError());
        }
#endif

        // Not needed for nonblocking connect().
#if 0
        fd_set write_fd_set;
        FD_ZERO(&write_fd_set);
        FD_SET(ConnectSocket, &write_fd_set);
        TIMEVAL timeout = { 0, 0 };
        iResult = select(0, nullptr, &write_fd_set, nullptr, &timeout);
        if (iResult == SOCKET_ERROR) {
            printf("select failed with error: %d\n", WSAGetLastError());
        }
        else {
            printf("writable sockets: %d\n", iResult);
        }
#endif

    try_connect:
        // Connect to server.
        auto connect_start = std::chrono::system_clock::now();
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        auto connect_end = std::chrono::system_clock::now();
        std::chrono::duration<double> connect_diff = connect_end - connect_start;
        std::cout << connect_diff.count() << std::endl;
        if (iResult == SOCKET_ERROR) {
            printf("connect failed with error: %d\n", WSAGetLastError());
            int error = WSAGetLastError();
            if (WSAEWOULDBLOCK == error || WSAEALREADY == error) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                goto try_connect;
            }
            else if (WSAEISCONN == error) {
                break;
            }
            else {
                closesocket(ConnectSocket);
                ConnectSocket = INVALID_SOCKET;
                continue;
            }
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }
    SSL_library_init();
    SSL * ssl = SSL_new(ctx);
    if (!ssl) {
        perror("Unable to create SSL");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("OK: SSL_new\n");
    SSL_set_connect_state(ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    if (0 == SSL_set_fd(ssl, (int)ConnectSocket)) {
        perror("SSL_set_fd failed.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("OK: SSL_set_fd\n");
#if 0
    if (SSL_do_handshake(ssl) <= 0) {
        perror("SSL_do_handshake failed.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("OK: SSL_connect\n");
#endif
    if (SSL_connect(ssl) <= 0) {
        perror("SSL_connect failed.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("OK: SSL_connect\n");

    int n;
    n = SSL_write(ssl, sendbuf, sizeof(sendbuf));
    if (n < 0) {
        perror("SSL_write failed.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("OK: SSL_write\n");

    n = SSL_read(ssl, recvbuf, recvbuflen);
    if (n < 0) {
        perror("SSL_read failed.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("OK: SSL_read: %s\n", recvbuf);

#if 0
    // Send an initial buffer
    iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    printf("Bytes Sent: %ld\n", iResult);
#endif

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }
#if 0
    // Receive until the peer closes the connection
    do {

        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0)
            printf("Bytes received: %d\n", iResult);
        else if (iResult == 0)
            printf("Connection closed\n");
        else
            printf("recv failed with error: %d\n", WSAGetLastError());

    } while (iResult > 0);
#endif
    // cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}
#endif