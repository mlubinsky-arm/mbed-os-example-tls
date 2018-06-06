/**
 * \file main.cpp
 *
 * \brief An example  MQTT Client  with TLS 2-way auth
 *
 *
 */

#include "mbed.h"

//Serial pc(USBTX, USBRX);
//#define PRINT pc.printf   //to see output in serial port

#include "mbedtls/platform.h"

#include "TLSClient.h"

#include "HelloHttpsClient.h"

/* Domain/IP address of the server to contact */
const char H_SERVER_NAME[] = "os.mbed.com";

/* Port used to connect to the server */
const int H_SERVER_PORT = 443;

const char SERVER_NAME[] = "10.72.153.40";    //this is my MacBook with Mosquitto broker

 
const int SERVER_PORT = 8883;  //1833 without TLS

/*
DigitalOut led1(LED1);
*/

/**
 * The main function 
 */
int main()
{
   // pc.baud(115200);   //to see output in serial port
   // PRINT("Hello from tls_client_my_copy \r\n");

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
    HelloHttpsClient *hclient;


    mbedtls_printf("Starting mbed-os-example-tls/tls-client\n");

#if defined(MBED_MAJOR_VERSION)
    mbedtls_printf("Using Mbed OS %d.%d.%d\n",
                   MBED_MAJOR_VERSION, MBED_MINOR_VERSION, MBED_PATCH_VERSION);
#else
    printf("Using Mbed OS from master.\n");
#endif /* MBEDTLS_MAJOR_VERSION */

    //hclient = new (std::nothrow) HelloHttpsClient(H_SERVER_NAME, H_SERVER_PORT,
    //                                             &platform_ctx);

    /* Allocate a TLS client */
    client = new (std::nothrow) TLSClient(SERVER_NAME, SERVER_PORT,
                                                 &platform_ctx);
    if (client == NULL) {
        mbedtls_printf("Failed to allocate TLSClient object\n"
                       "\nFAIL\n");
        mbedtls_platform_teardown(&platform_ctx);
        return exit_code;
    }

    /* Run the HelloHTTPsclient */
    /*
    if (hclient->run() != 0) {
        mbedtls_printf("\nFAIL in HTTPSclient->run()\n");
    } else {
        exit_code = MBEDTLS_EXIT_SUCCESS;
        mbedtls_printf("\nSUCCESS with HTTPSclient->run()\n");
    }
    */

    /* Run the TLSclient */
    if (client->run() != 0) {
        mbedtls_printf("\nFAIL in TLSclient->run()\n");
    } else {
        exit_code = MBEDTLS_EXIT_SUCCESS;
        mbedtls_printf("\nSUCCESS with TLSclient->run()\n");
    }


    delete client;

    mbedtls_platform_teardown(&platform_ctx);
    return exit_code;
}
