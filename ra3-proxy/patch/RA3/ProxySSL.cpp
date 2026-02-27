// ProxySSL.cpp : Implements the ProxySSL class and I/O abstractions for proxy operations.
#include "ProxySSL.h"
#include "ProxyCert.hpp"
#include "../../Config.hpp"
#include <boost/exception/diagnostic_information.hpp>
#include "../../util.h"

using namespace boost::asio;
using namespace boost::asio::ssl;

// ============================================================================
// SSLSocketIO Implementation
// ============================================================================

SSLSocketIO::SSLSocketIO(SSL* ssl, bool ownsSocket)
    : ssl_(ssl), ownsSocket_(ownsSocket) {}

SSLSocketIO::~SSLSocketIO() {
    if (!closed_) {
        close();
    }
}

int SSLSocketIO::read(char* buffer, size_t len) {
    return SSL_read(ssl_, buffer, static_cast<int>(len));
}

int SSLSocketIO::write(const char* buffer, size_t len) {
    return SSL_write(ssl_, buffer, static_cast<int>(len));
}

void SSLSocketIO::close() {
    if (closed_) return;
    closed_ = true;

    if (ssl_ && ownsSocket_) {
        // Attempt graceful SSL shutdown
        int ret = SSL_shutdown(ssl_);
        if (ret == 0) {
            // Bidirectional shutdown not yet complete, call again
            SSL_shutdown(ssl_);
        }
        int fd = SSL_get_fd(ssl_);
        SSL_free(ssl_);
        if (fd >= 0) {
            shutdown(fd, SD_BOTH);
            closesocket(fd);
        }
    }
    ssl_ = nullptr;
}

int SSLSocketIO::getFd() const {
    return ssl_ ? SSL_get_fd(ssl_) : -1;
}

int SSLSocketIO::getSSLError(int ret) const {
    return ssl_ ? SSL_get_error(ssl_, ret) : SSL_ERROR_SSL;
}

// ============================================================================
// PlainSocketIO Implementation
// ============================================================================

PlainSocketIO::PlainSocketIO(int sockfd, bool ownsSocket)
    : sockfd_(sockfd), ownsSocket_(ownsSocket) {}

PlainSocketIO::~PlainSocketIO() {
    if (!closed_) {
        close();
    }
}

int PlainSocketIO::read(char* buffer, size_t len) {
    return recv(sockfd_, buffer, static_cast<int>(len), 0);
}

int PlainSocketIO::write(const char* buffer, size_t len) {
    return send(sockfd_, buffer, static_cast<int>(len), 0);
}

void PlainSocketIO::close() {
    if (closed_) return;
    closed_ = true;

    if (sockfd_ >= 0 && ownsSocket_) {
        shutdown(sockfd_, SD_BOTH);
        closesocket(sockfd_);
    }
    sockfd_ = -1;
}

// ============================================================================
// ProxySSL Implementation
// ============================================================================

ProxySSL::ProxySSL() {
    // Read configured proxy listen port
    proxyPort_ = Config::GetInstance().proxyListenPort;

    // Initialize OpenSSL
    initOpenSSL();
}

ProxySSL::~ProxySSL() {
    stop();

    // Stop and join the cleanup thread
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }

    // Wait for all client threads to finish
    {
        std::lock_guard<std::mutex> lock(threadsMutex_);
        for (auto& threadInfo : clientThreads_) {
            if (threadInfo->thread.joinable()) {
                threadInfo->thread.join();
            }
        }
        clientThreads_.clear();
    }

    // Clean up SSL context
    if (ctx_) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }

    // Note: EVP_cleanup() is deprecated in OpenSSL 1.1.0+ and can cause
    // issues during static destruction. Modern OpenSSL handles cleanup automatically.
    // cleanupOpenSSL();
}

bool ProxySSL::run() {
    BOOST_LOG_NAMED_SCOPE("FESL_proxy");

    // Create SSL context if not already created
    if (!ctx_) {
        ctx_ = createServerContext();
        if (!ctx_) {
            BOOST_LOG_TRIVIAL(error) << "Error creating SSL context";
            return false;
        }

        // Configure SSL context with certificate, key, and ciphers
        configureContext(ctx_);
    }

    // Create server socket
    serverFd_ = createServerSocket();
    if (serverFd_ == INVALID_SOCKET) {
        BOOST_LOG_TRIVIAL(error) << "Error creating server socket";
        return false;
    }

    BOOST_LOG_TRIVIAL(info) << "Server started on port " << proxyPort_;
    BOOST_LOG_TRIVIAL(info) << "Using cipher list: " << CIPHER_LIST;

    // Start the cleanup thread for finished client threads
    startCleanupThread();

    // Main server loop
    while (running_) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);

        BOOST_LOG_TRIVIAL(info) << "Waiting for connection...";

        // Accept client connection
        SOCKET clientFd = accept(serverFd_, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientFd == INVALID_SOCKET) {
            if (running_) {
                BOOST_LOG_TRIVIAL(error) << "Error accepting connection: " << WSAGetLastError();
            }
            continue;
        }

        // Get client IP address for logging
        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
        BOOST_LOG_TRIVIAL(info) << "Client connected: " << clientIp << ":" << ntohs(clientAddr.sin_port);

        // Create thread tracking structure and spawn handler thread
        {
            std::lock_guard<std::mutex> lock(threadsMutex_);
            auto threadInfo = std::make_unique<ClientThread>();
            ClientThread* rawPtr = threadInfo.get();
            threadInfo->thread = std::thread(&ProxySSL::handleClient, this, ctx_, static_cast<int>(clientFd), rawPtr);
            clientThreads_.push_back(std::move(threadInfo));
        }
    }

    // Stop cleanup thread
    stopCleanupThread();

    // Wait for all client threads to finish
    {
        std::lock_guard<std::mutex> lock(threadsMutex_);
        for (auto& threadInfo : clientThreads_) {
            if (threadInfo->thread.joinable()) {
                threadInfo->thread.join();
            }
        }
        clientThreads_.clear();
    }

    // Clean up server socket
    if (serverFd_ != INVALID_SOCKET) {
        closesocket(serverFd_);
        serverFd_ = INVALID_SOCKET;
    }

    return true;
}

void ProxySSL::stop() {
    running_ = false;
    // Close server socket to interrupt blocking accept()
    if (serverFd_ != INVALID_SOCKET) {
        closesocket(serverFd_);
        serverFd_ = INVALID_SOCKET;
    }
}

// ============================================================================
// Thread Management
// ============================================================================

void ProxySSL::startCleanupThread() {
    cleanupThread_ = std::thread(&ProxySSL::cleanupFinishedThreads, this);
}

void ProxySSL::stopCleanupThread() {
    running_ = false;
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
}

void ProxySSL::cleanupFinishedThreads() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        std::lock_guard<std::mutex> lock(threadsMutex_);
        clientThreads_.remove_if([](std::unique_ptr<ClientThread>& threadInfo) {
            if (threadInfo->finished.load()) {
                if (threadInfo->thread.joinable()) {
                    threadInfo->thread.join();
                }
                BOOST_LOG_TRIVIAL(debug) << "Cleaned up finished client thread";
                return true;
            }
            return false;
        });
    }
}

// ============================================================================
// OpenSSL Management
// ============================================================================

void ProxySSL::initOpenSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void ProxySSL::cleanupOpenSSL() {
    EVP_cleanup();
}

SSL_CTX* ProxySSL::createServerContext() {
    // Using SSLv3 for legacy Red Alert 3 client support (intentionally insecure)
    const SSL_METHOD* method = SSLv3_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
    }

    return ctx;
}

SSL_CTX* ProxySSL::createClientContext() {
    // Using SSLv3 for legacy server compatibility
    const SSL_METHOD* method = SSLv3_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
    }

    return ctx;
}

void ProxySSL::configureContext(SSL_CTX* ctx) {
    // Load embedded certificate and private key
    if (SSL_CTX_use_certificate_ASN1(ctx, sizeof(SSL_CERT_X509), SSL_CERT_X509) != 1) {
        BOOST_LOG_TRIVIAL(error) << "Failed to load SSL certificate";
        logSSLErrors();
    }

    if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, SSL_CERT_RSA, sizeof(SSL_CERT_RSA)) != 1) {
        BOOST_LOG_TRIVIAL(error) << "Failed to load SSL private key";
        logSSLErrors();
    }

    SSL_CTX_set_verify_depth(ctx, 1);

    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        BOOST_LOG_TRIVIAL(error) << "Private key does not match the certificate public key";
        logSSLErrors();
    }

    // Set cipher list for legacy support (RC4 ciphers required for old game)
    if (!SSL_CTX_set_cipher_list(ctx, CIPHER_LIST)) {
        BOOST_LOG_TRIVIAL(error) << "Error setting cipher list";
        ERR_print_errors_fp(stderr);
    }

    // Additional options for legacy compatibility
    SSL_CTX_set_options(ctx, SSL_OP_ALL);  // All bug workarounds

    // Disable modern TLS versions to force SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
}

// ============================================================================
// Socket Operations
// ============================================================================

void ProxySSL::setSocketTimeouts(SOCKET s, int timeoutMs) {
    DWORD timeout = static_cast<DWORD>(timeoutMs);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
}

SOCKET ProxySSL::createServerSocket() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        BOOST_LOG_TRIVIAL(error) << "Unable to create socket: " << WSAGetLastError();
        return INVALID_SOCKET;
    }

    // Set socket options for address reuse
    int opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        BOOST_LOG_TRIVIAL(error) << "setsockopt failed: " << WSAGetLastError();
        closesocket(s);
        return INVALID_SOCKET;
    }

    // Bind to port
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(proxyPort_);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        BOOST_LOG_TRIVIAL(error) << "Unable to bind: " << WSAGetLastError();
        closesocket(s);
        return INVALID_SOCKET;
    }

    // Start listening (backlog of 10 for better connection handling)
    if (listen(s, 10) == SOCKET_ERROR) {
        BOOST_LOG_TRIVIAL(error) << "Unable to listen: " << WSAGetLastError();
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

int ProxySSL::createConnectedSocket(const std::string& hostname, int port) {
    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        BOOST_LOG_TRIVIAL(error) << "Error creating socket: " << WSAGetLastError();
        return -1;
    }

    // Resolve hostname (supports both IP addresses and hostnames)
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(port);
    int gaiResult = getaddrinfo(hostname.c_str(), portStr.c_str(), &hints, &result);
    if (gaiResult != 0) {
        BOOST_LOG_TRIVIAL(error) << "Failed to resolve hostname '" << hostname << "': " << gai_strerror(gaiResult);
        closesocket(sockfd);
        return -1;
    }

    // Connect to server
    int connectResult = connect(sockfd, result->ai_addr, static_cast<int>(result->ai_addrlen));
    freeaddrinfo(result);

    if (connectResult == SOCKET_ERROR) {
        BOOST_LOG_TRIVIAL(error) << "Connection failed to " << hostname << ":" << port << " error: " << WSAGetLastError();
        closesocket(sockfd);
        return -1;
    }

    // TODO: add keep alive support for FESL server connections
    // Set socket timeouts (30 seconds)
    //setSocketTimeouts(sockfd, SOCKET_TIMEOUT_MS);

    BOOST_LOG_TRIVIAL(info) << "TCP connection established to " << hostname << ":" << port;
    return static_cast<int>(sockfd);
}

// ============================================================================
// Forwarder Initialization
// ============================================================================

std::unique_ptr<ISocketIO> ProxySSL::initForwarder() {
    const auto config = &Config::GetInstance();
    if (config->proxySSL) {
        return initSSLForwarder();
    } else {
        return initPlainForwarder();
    }
}

std::unique_ptr<ISocketIO> ProxySSL::initPlainForwarder() {
    BOOST_LOG_FUNCTION();

    const auto config = &Config::GetInstance();
    int sockfd = createConnectedSocket(config->getHostname("login"), config->proxyDestinationPort);

    if (sockfd < 0) {
        return nullptr;
    }

    return std::make_unique<PlainSocketIO>(sockfd);
}

std::unique_ptr<ISocketIO> ProxySSL::initSSLForwarder() {
    BOOST_LOG_FUNCTION();

    const auto config = &Config::GetInstance();

    // Create connected TCP socket
    int sockfd = createConnectedSocket(config->getHostname("login"), config->proxyDestinationPort);
    if (sockfd < 0) {
        return nullptr;
    }

    // Create SSL client context
    SSL_CTX* ctx = createClientContext();
    if (!ctx) {
        BOOST_LOG_TRIVIAL(error) << "Error creating SSL context";
        closesocket(sockfd);
        return nullptr;
    }

    // Configure context with same legacy settings
    configureContext(ctx);

    // Create SSL object
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        BOOST_LOG_TRIVIAL(error) << "Error creating SSL object";
        SSL_CTX_free(ctx);
        closesocket(sockfd);
        return nullptr;
    }

    // Associate socket with SSL
    if (SSL_set_fd(ssl, sockfd) != 1) {
        BOOST_LOG_TRIVIAL(error) << "Error associating socket with SSL";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(sockfd);
        return nullptr;
    }

    // Perform SSL handshake
    if (SSL_connect(ssl) != 1) {
        BOOST_LOG_TRIVIAL(error) << "SSL_connect failed";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(sockfd);
        return nullptr;
    }

    BOOST_LOG_TRIVIAL(info) << "SSL connection using " << SSL_get_cipher(ssl);
    BOOST_LOG_TRIVIAL(info) << "SSL version: " << SSL_get_version(ssl);

    // Log server certificate info
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char* line = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        BOOST_LOG_TRIVIAL(debug) << "Server certificate subject: " << line;
        OPENSSL_free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        BOOST_LOG_TRIVIAL(debug) << "Server certificate issuer: " << line;
        OPENSSL_free(line);

        X509_free(cert);
    }

    // Free the context - SSL object has incremented its reference count
    SSL_CTX_free(ctx);

    return std::make_unique<SSLSocketIO>(ssl);
}

// ============================================================================
// Data Forwarding
// ============================================================================

void ProxySSL::forwardData(ISocketIO* from, ISocketIO* to, const std::string& direction,
                           std::atomic<bool>& stopFlag) {
    char buffer[BUFFER_SIZE];

    while (!stopFlag.load()) {
        int bytesReceived = from->read(buffer, sizeof(buffer) - 1);

        if (bytesReceived > 0) {
            BOOST_LOG_TRIVIAL(info) << "Received data: " << direction;
            print_hex(buffer, bytesReceived);

            if (!writeAll(to, buffer, bytesReceived, direction)) {
                BOOST_LOG_TRIVIAL(error) << "Write failed, closing connection (" << direction << ")";
                stopFlag.store(true);
                return;
            }

            BOOST_LOG_TRIVIAL(info) << "Forwarded " << bytesReceived << " bytes (" << direction << ")";
            continue;
        }

        if (bytesReceived == 0) {
            BOOST_LOG_TRIVIAL(info) << "Connection closed by peer (" << direction << ")";
            stopFlag.store(true);
            return;
        }

        // bytesReceived < 0: handle error
        if (from->isSSL()) {
            SSLReadResult result = handleSSLReadResult(
                static_cast<SSLSocketIO*>(from)->getSSL(), bytesReceived);

            switch (result) {
                case SSLReadResult::WantRetry:
                    // Non-blocking: wait briefly and retry
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                case SSLReadResult::Closed:
                    BOOST_LOG_TRIVIAL(info) << "SSL connection closed (" << direction << ")";
                    stopFlag.store(true);
                    return;
                case SSLReadResult::Error:
                    BOOST_LOG_TRIVIAL(error) << "SSL read error (" << direction << ")";
                    stopFlag.store(true);
                    return;
                default:
                    stopFlag.store(true);
                    return;
            }
        } else {
            int wsaError = WSAGetLastError();
            if (wsaError == WSAEWOULDBLOCK) {
                // Non-blocking socket, retry
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            BOOST_LOG_TRIVIAL(error) << "Failed to receive data (" << direction
                << "): error " << wsaError;
            stopFlag.store(true);
            return;
        }
    }
}

bool ProxySSL::writeAll(ISocketIO* socket, const char* buffer, int len, const std::string& direction) {
    int totalSent = 0;

    while (totalSent < len) {
        int bytesSent = socket->write(buffer + totalSent, len - totalSent);

        if (bytesSent < 0) {
            if (socket->isSSL()) {
                int sslError = socket->getSSLError(bytesSent);
                if (sslError == SSL_ERROR_WANT_WRITE || sslError == SSL_ERROR_WANT_READ) {
                    // Non-blocking, retry
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                BOOST_LOG_TRIVIAL(error) << "SSL write failed (" << direction << ")";
                logSSLErrors();
            } else {
                BOOST_LOG_TRIVIAL(error) << "Socket write failed (" << direction
                    << "): error " << WSAGetLastError();
            }
            return false;
        }

        if (bytesSent == 0) {
            BOOST_LOG_TRIVIAL(error) << "Connection closed during write (" << direction << ")";
            return false;
        }

        totalSent += bytesSent;
    }

    return true;
}

// ============================================================================
// Error Handling
// ============================================================================

SSLReadResult ProxySSL::handleSSLReadResult(SSL* ssl, int bytes) {
    if (bytes > 0) {
        return SSLReadResult::Success;
    }

    if (bytes == 0) {
        return SSLReadResult::Closed;
    }

    int errorCode = SSL_get_error(ssl, bytes);
    switch (errorCode) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return SSLReadResult::WantRetry;

        case SSL_ERROR_ZERO_RETURN:
            return SSLReadResult::Closed;

        case SSL_ERROR_SYSCALL:
            if (ERR_peek_error() == 0) {
                if (bytes == 0) {
                    // EOF without proper SSL shutdown
                    return SSLReadResult::Closed;
                }
                // System error
                //BOOST_LOG_TRIVIAL(error) << "SSL_ERROR_SYSCALL: " << strerror_s(errno);
            } else {
                logSSLErrors();
            }
            return SSLReadResult::Error;

        case SSL_ERROR_SSL:
            BOOST_LOG_TRIVIAL(error) << "SSL protocol error";
            logSSLErrors();
            return SSLReadResult::Error;

        default:
            BOOST_LOG_TRIVIAL(error) << "Unknown SSL error: " << errorCode;
            logSSLErrors();
            return SSLReadResult::Error;
    }
}

void ProxySSL::logSSLErrors() {
    unsigned long err;
    char errBuf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, errBuf, sizeof(errBuf));
        BOOST_LOG_TRIVIAL(error) << "SSL error: " << errBuf;
    }
}

// ============================================================================
// Connection Shutdown
// ============================================================================

void ProxySSL::gracefulShutdown(SSL* ssl) {
    if (!ssl) return;

    // Attempt bidirectional SSL shutdown
    int ret = SSL_shutdown(ssl);
    if (ret == 0) {
        // Shutdown not yet complete, call again
        SSL_shutdown(ssl);
    }

    int fd = SSL_get_fd(ssl);
    SSL_free(ssl);

    if (fd >= 0) {
        shutdown(fd, SD_BOTH);
        closesocket(fd);
    }
}

void ProxySSL::gracefulShutdown(int sockfd) {
    if (sockfd < 0) return;

    // Send FIN to peer
    shutdown(sockfd, SD_BOTH);
    closesocket(sockfd);
}

// ============================================================================
// Client Handling
// ============================================================================

void ProxySSL::handleClient(SSL_CTX* ctx, int clientFd, ClientThread* threadInfo) {
    BOOST_LOG_FUNCTION();

    // Ensure thread is marked as finished when we exit
    struct ThreadFinisher {
        ClientThread* info;
        ~ThreadFinisher() { if (info) info->finished.store(true); }
    } finisher{threadInfo};

    const auto config = &Config::GetInstance();

    // Note: No socket timeout for the game client connection - this connection
    // remains open for the entire game session and should not time out
    //setSocketTimeouts(clientFd, SOCKET_TIMEOUT_MS);

    // Create SSL connection with game client
    SSL* gameSsl = SSL_new(ctx);
    if (!gameSsl) {
        BOOST_LOG_TRIVIAL(error) << "Failed to create SSL object";
        closesocket(clientFd);
        return;
    }

    if (SSL_set_fd(gameSsl, clientFd) != 1) {
        BOOST_LOG_TRIVIAL(error) << "Error associating client socket with SSL";
        logSSLErrors();
        SSL_free(gameSsl);
        closesocket(clientFd);
        return;
    }

    // Perform SSL handshake with game client
    if (SSL_accept(gameSsl) <= 0) {
        char errBuf[256];
        unsigned long err = ERR_get_error();
        ERR_error_string_n(err, errBuf, sizeof(errBuf));
        BOOST_LOG_TRIVIAL(error) << "SSL handshake failed: " << errBuf;
        logSSLErrors();
        SSL_free(gameSsl);
        closesocket(clientFd);
        return;
    }

    BOOST_LOG_TRIVIAL(debug) << "SSL handshake successful with cipher: " << SSL_get_cipher(gameSsl);

    // Create I/O wrapper for game connection
    auto gameIO = std::make_unique<SSLSocketIO>(gameSsl);

    // Initialize forwarder connection
    auto forwarderIO = initForwarder();
    if (!forwarderIO) {
        BOOST_LOG_TRIVIAL(error) << "Failed to connect to forwarder target";
        return;  // gameIO will cleanup gameSsl
    }

    // Create bidirectional forwarding threads
    // We need raw pointers for the threads since unique_ptr can't be copied
    ISocketIO* gamePtr = gameIO.get();
    ISocketIO* forwarderPtr = forwarderIO.get();

    // Shared stop flag for both directions
    std::atomic<bool> stopFlag{false};

    std::thread clientToTarget([this, gamePtr, forwarderPtr, &stopFlag]() {
        forwardData(gamePtr, forwarderPtr, "Game->Proxy", stopFlag);
    });

    std::thread targetToClient([this, forwarderPtr, gamePtr, &stopFlag]() {
        forwardData(forwarderPtr, gamePtr, "Proxy->Game", stopFlag);
    });

    // Wait for both threads to finish
    clientToTarget.join();
    targetToClient.join();

    // Close both connections to ensure clean shutdown
    // (unique_ptr destructors will handle the actual cleanup)
    gameIO->close();
    forwarderIO->close();

    BOOST_LOG_TRIVIAL(info) << "Client session ended";
}
