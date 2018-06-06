/*
 *   Example of a MQTT TLS client with 2-way auth  
 *
 */

#ifndef _TLSClient_H_
#define _TLSClient_H_

#include "TCPSocket.h"

#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include <stdint.h>

/**
 * Change to a number between 1 and 4 to debug the TLS connection
 */
#define DEBUG_LEVEL  0

/**
 * Length (in bytes) for generic buffers used to hold debug or HTTP
 * request/response strings
 */
#define GENERAL_PURPOSE_BUFFER_LENGTH   1024

/**
 * This class implements the logic for fetching a file from a webserver using
 * a TCP socket and parsing the result.
 */
class TLSClient
{
public:
    /**
     * Construct an TLSClient instance
     *
     * \param[in]   in_server_name
     *              The server domain/IP address
     * \param[in]   in_server_port
     *              The server port
     */
    TLSClient(const char *in_server_name,
                     const uint16_t in_server_port,
                     mbedtls_platform_context* in_platform_ctx);

    /**
     * Free any allocated resources
     */
    ~TLSClient();

    /**
     * Start the connection to the server and request to read the file at
     * HTTP_REQUEST_FILE_PATH
     *
     * \return  0 if successful
     */
    int run();
    NetworkInterface* network;

private:
    /**
     * Create a TCPSocket object that can be used to communicate with the server
     */
    int configureTCPSocket();

    /**
     * Configure the Mbed TLS structures required to establish a TLS connection
     * with the server
     */
    int configureTlsContexts();

    /**
     * Wrapper function around TCPSocket that gets called by Mbed TLS whenever
     * we call mbedtls_ssl_read()
     *
     * \param[in]   ctx
     *              The TCPSocket object
     * \param[in]   buf
     *              Buffer where data received will be stored
     * \param[in]   len
     *              The length (in bytes) of the buffer
     *
     * \return  If successful, the number of bytes received, a negative value
     *          otherwise.
     */
    static int sslRecv(void *ctx, unsigned char *buf, size_t len);

    /**
     * Wrapper function around TCPSocket that gets called by Mbed TLS whenever
     * we call mbedtls_ssl_write()
     *
     * \param[in]   ctx
     *              The TCPSocket object
     * \param[in]   buf
     *              Buffer containing the data to be sent
     * \param[in]   len
     *              The number of bytes to send
     *
     * \return  If successful, the number of bytes sent, a negative value
     *          otherwise
     */
    static int sslSend(void *ctx, const unsigned char *buf, size_t len);

    /**
     * Callback to handle debug prints to serial
     *
     * \param[in]   ctx
     *              The context (unused in this case)
     * \param[in]   level
     *              The current debug level
     * \param[in]   file
     *              The C file that is logging this message
     * \param[in]   line
     *              The line number in the file
     * \param[in]   str
     *              The string to log to serial
     */
    static void sslDebug(void *ctx, int level, const char *file, int line,
                         const char *str);

    /**
     * Callback to handle certificate verification
     *
     * /param[in]       data
     *                  (unused)
     * /param[in]       crt
     *                  The crt in the chain that we are verifying
     * /param[in]       depth
     *                  The depth of the current certificate in the chain
     * /param[in/out]   flags
     *                  The flags resulting from the verification
     *
     * /return  0 if successful
     */
    static int sslVerify(void *ctx, mbedtls_x509_crt *crt, int depth,
                         uint32_t *flags);

private:
    /**
     * Personalization string for the drbg
     */
    static const char *DRBG_PERSONALIZED_STR;

    /**
     *  Length of error string buffer for logging failures related to Mbed TLS
     */
    static const size_t ERROR_LOG_BUFFER_LENGTH;

    /**
     * Chain of trusted CAs in PEM format
     */
    static const char *TLS_PEM_CA;

    /**
     * Path to the file that will be requested from the server
     */
    //static const char *HTTP_REQUEST_FILE_PATH;

    /**
     * Expected strings in the HTTP response from the server
     */
    //static const char *HTTP_OK_STR;

    /**
     * Expected strings in the HTTP response from the server
     */
    //static const char *HTTP_HELLO_STR;

    /**
     * Instance of TCPSocket used to communicate with the server
     */
    TCPSocket socket;
    
    

    /**
     * The domain/IP address of the server to contact
     */
    const char *server_name;
    /**
     * The port number to use in the connection
     */
    const uint16_t server_port;

    /**
     * A generic buffer used to hold debug or HTTP request/response strings
     */
    char gp_buf[GENERAL_PURPOSE_BUFFER_LENGTH];

    /**
     * Entropy context used to seed the DRBG to use in the TLS connection
     */
    mbedtls_entropy_context entropy;
    /**
     * The DRBG used throughout the TLS connection
     */
    mbedtls_ctr_drbg_context ctr_drbg;
    /**
     * The parsed chain of trusted CAs
     */
    mbedtls_x509_crt cacert;
    /**
     * THe TLS context
     */
    mbedtls_ssl_context ssl;
    /**
     * The TLS configuration in use
     */
    mbedtls_ssl_config ssl_conf;

    mbedtls_platform_context* platform_ctx;
};

#endif /* _TLSClient_H_ */
