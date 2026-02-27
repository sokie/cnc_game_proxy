// ProxySSL.hpp : Defines the ProxySSL class and I/O abstractions for proxy operations.
#pragma once
#include "../../Framework.h"
#include <memory>
#include <list>
#include <mutex>
#include <atomic>
#include <condition_variable>

// ============================================================================
// I/O Abstraction Layer
// ============================================================================

/**
 * Abstract interface for socket I/O operations.
 * Allows unified handling of SSL and plain TCP sockets.
 */
class ISocketIO {
public:
    virtual ~ISocketIO() = default;

    /**
     * Read data from the socket.
     * @param buffer Destination buffer
     * @param len Maximum bytes to read
     * @return Bytes read, 0 on close, negative on error
     */
    virtual int read(char* buffer, size_t len) = 0;

    /**
     * Write data to the socket.
     * @param buffer Source buffer
     * @param len Bytes to write
     * @return Bytes written, negative on error
     */
    virtual int write(const char* buffer, size_t len) = 0;

    /**
     * Gracefully close the socket.
     */
    virtual void close() = 0;

    /**
     * Get the underlying file descriptor.
     */
    virtual int getFd() const = 0;

    /**
     * Check if this is an SSL socket.
     */
    virtual bool isSSL() const = 0;

    /**
     * Get SSL error code (only valid for SSL sockets).
     * @param ret The return value from the last read/write operation
     */
    virtual int getSSLError(int ret) const { return 0; }
};

/**
 * SSL socket I/O wrapper.
 */
class SSLSocketIO : public ISocketIO {
public:
    explicit SSLSocketIO(SSL* ssl, bool ownsSocket = true);
    ~SSLSocketIO() override;

    int read(char* buffer, size_t len) override;
    int write(const char* buffer, size_t len) override;
    void close() override;
    int getFd() const override;
    bool isSSL() const override { return true; }
    int getSSLError(int ret) const override;

    SSL* getSSL() const { return ssl_; }

private:
    SSL* ssl_;
    bool ownsSocket_;
    bool closed_ = false;
};

/**
 * Plain TCP socket I/O wrapper.
 */
class PlainSocketIO : public ISocketIO {
public:
    explicit PlainSocketIO(int sockfd, bool ownsSocket = true);
    ~PlainSocketIO() override;

    int read(char* buffer, size_t len) override;
    int write(const char* buffer, size_t len) override;
    void close() override;
    int getFd() const override { return sockfd_; }
    bool isSSL() const override { return false; }

private:
    int sockfd_;
    bool ownsSocket_;
    bool closed_ = false;
};

// ============================================================================
// SSL Error Handling
// ============================================================================

enum class SSLReadResult {
    Success,      // Data was read successfully
    WantRetry,    // Non-blocking: retry later
    Closed,       // Connection closed cleanly
    Error         // Fatal error occurred
};

// ============================================================================
// ProxySSL Class
// ============================================================================

class ProxySSL
{
public:
    // Configuration constants
    static constexpr const char* CIPHER_LIST = "TLS_RSA_WITH_RC4_128_SHA:TLS_RSA_WITH_RC4_128_MD5:RC4-SHA:RC4-MD5";
    static constexpr size_t BUFFER_SIZE = 4096;
    static constexpr int SOCKET_TIMEOUT_MS = 30000;  // 30 second socket timeout

    ~ProxySSL();

    // Delete copy constructor and assignment operator
    ProxySSL(const ProxySSL&) = delete;
    ProxySSL& operator=(const ProxySSL&) = delete;

    /**
     * Get the singleton instance (Meyer's singleton - thread-safe, no memory leak).
     */
    static ProxySSL& GetInstance()
    {
        static ProxySSL instance;
        return instance;
    }

    /**
     * Get the configured proxy listen port.
     */
    USHORT getProxyPort() const { return proxyPort_; }

    /**
     * Initialize and run the proxy server.
     * This method blocks until stop() is called.
     * @return true if server ran successfully, false on initialization error
     */
    bool run();

    /**
     * Signal the proxy to stop accepting connections.
     */
    void stop();

private:
    ProxySSL();

    // ========================================================================
    // Thread Management
    // ========================================================================

    struct ClientThread {
        std::thread thread;
        std::atomic<bool> finished{false};
    };

    std::list<std::unique_ptr<ClientThread>> clientThreads_;
    std::mutex threadsMutex_;
    std::atomic<bool> running_{true};
    std::thread cleanupThread_;
    SOCKET serverFd_{INVALID_SOCKET};
    SSL_CTX* ctx_{nullptr};
    USHORT proxyPort_;

    void cleanupFinishedThreads();
    void startCleanupThread();
    void stopCleanupThread();

    // ========================================================================
    // OpenSSL Management
    // ========================================================================

    void initOpenSSL();
    void cleanupOpenSSL();
    SSL_CTX* createServerContext();
    SSL_CTX* createClientContext();
    void configureContext(SSL_CTX* ctx);

    // ========================================================================
    // Socket Operations
    // ========================================================================

    /**
     * Set read/write timeouts on a socket.
     * @param s Socket to configure
     * @param timeoutMs Timeout in milliseconds
     */
    void setSocketTimeouts(SOCKET s, int timeoutMs);

    /**
     * Create a listening server socket.
     * @return Socket handle, or INVALID_SOCKET on error
     */
    SOCKET createServerSocket();

    /**
     * Create a connected TCP socket to the specified host.
     * @param hostname IP address or hostname
     * @param port Port number
     * @return Socket file descriptor, or -1 on error
     */
    int createConnectedSocket(const std::string& hostname, int port);

    // ========================================================================
    // Forwarder Initialization
    // ========================================================================

    /**
     * Initialize a connection to the proxy target.
     * Automatically handles SSL or plain TCP based on configuration.
     * @return Unique pointer to socket I/O wrapper, or nullptr on error
     */
    std::unique_ptr<ISocketIO> initForwarder();

    /**
     * Initialize a plain TCP forwarder connection.
     * @return Unique pointer to PlainSocketIO, or nullptr on error
     */
    std::unique_ptr<ISocketIO> initPlainForwarder();

    /**
     * Initialize an SSL forwarder connection.
     * @return Unique pointer to SSLSocketIO, or nullptr on error
     */
    std::unique_ptr<ISocketIO> initSSLForwarder();

    // ========================================================================
    // Data Forwarding
    // ========================================================================

    /**
     * Forward data between two sockets bidirectionally.
     * Reads from 'from' socket and writes to 'to' socket.
     * @param from Source socket
     * @param to Destination socket
     * @param direction Description for logging (e.g., "Game->Proxy")
     * @param stopFlag Atomic flag to signal when to stop forwarding
     */
    void forwardData(ISocketIO* from, ISocketIO* to, const std::string& direction,
                     std::atomic<bool>& stopFlag);

    /**
     * Write all bytes to a socket, handling partial writes.
     * @param socket Destination socket
     * @param buffer Data to write
     * @param len Number of bytes to write
     * @param direction Description for logging
     * @return true if all bytes written, false on error
     */
    bool writeAll(ISocketIO* socket, const char* buffer, int len, const std::string& direction);

    // ========================================================================
    // Error Handling
    // ========================================================================

    /**
     * Handle SSL read result and determine action.
     * @param ssl SSL connection
     * @param bytes Return value from SSL_read
     * @return SSLReadResult indicating what action to take
     */
    SSLReadResult handleSSLReadResult(SSL* ssl, int bytes);

    /**
     * Log SSL errors to the error log.
     */
    void logSSLErrors();

    // ========================================================================
    // Connection Shutdown
    // ========================================================================

    /**
     * Gracefully shutdown an SSL connection.
     * Performs bidirectional SSL shutdown before freeing resources.
     */
    void gracefulShutdown(SSL* ssl);

    /**
     * Gracefully shutdown a plain socket.
     * Sends FIN to peer before closing.
     */
    void gracefulShutdown(int sockfd);

    // ========================================================================
    // Client Handling
    // ========================================================================

    /**
     * Handle a client connection.
     * @param ctx SSL context for accepting connections
     * @param clientFd Client socket file descriptor
     * @param threadInfo Pointer to thread tracking structure
     */
    void handleClient(SSL_CTX* ctx, int clientFd, ClientThread* threadInfo);
};
