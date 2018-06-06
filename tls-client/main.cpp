/**
 * \file main.cpp
 *
 * \brief An example TLS MQTT Client  with 2-way auth
 *
 *
 * This example is implemented as a logic class (MQTTClient) wrapping a
 * TCP socket. The logic class handles all events, leaving the main loop to just
 * check if the process  has finished.
 */

#include "mbed.h"

Serial pc(USBTX, USBRX);
#define PRINT pc.printf   //to see output in serial port

#include "mbedtls/platform.h"

#include "TLSClient.h"

/* Domain/IP address of the MQTT broker  */
const char SERVER_NAME[] = "c02wg14lhtdd.sjc.arm.com";    //this is my MacBook with Moquitto broker

/* Port used to connect to the MQTT broker */
const int SERVER_PORT = 8883;  //1833 without TLS

/**
 * The main function 
 */
int main()
{
    pc.baud(115200);   //to see output in serial port
    PRINT("Hello from tls_client_my_copy \r\n");

    mbedtls_platform_context platform_ctx;
    int exit_code = MBEDTLS_EXIT_FAILURE;

    if((exit_code = mbedtls_platform_setup(&platform_ctx)) != 0) {
        printf("Platform initialization failed with error %d\r\n", exit_code);
        return MBEDTLS_EXIT_FAILURE;
    }
    /*
     * The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out.
     */

    TLSClient *client;

    mbedtls_printf("Starting mbed-os-example-tls/tls-client\n");

#if defined(MBED_MAJOR_VERSION)
    mbedtls_printf("Using Mbed OS %d.%d.%d\n",
                   MBED_MAJOR_VERSION, MBED_MINOR_VERSION, MBED_PATCH_VERSION);
#else
    printf("Using Mbed OS from master.\n");
#endif /* MBEDTLS_MAJOR_VERSION */

    /* Allocate a TLS client */
    client = new (std::nothrow) TLSClient(SERVER_NAME, SERVER_PORT,
                                                 &platform_ctx);
    if (client == NULL) {
        mbedtls_printf("Failed to allocate TLSClient object\n"
                       "\nFAIL\n");
        mbedtls_platform_teardown(&platform_ctx);
        return exit_code;
    }

    /* Run the client */
    if (client->run() != 0) {
        mbedtls_printf("\nFAIL in client->run()\n");
    } else {
        exit_code = MBEDTLS_EXIT_SUCCESS;
        mbedtls_printf("\nSUCCESS with client->run()\n");
    }

    delete client;

    mbedtls_platform_teardown(&platform_ctx);
    return exit_code;
}
