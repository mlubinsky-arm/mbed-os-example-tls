/*
 *  Example of a MQTT  client with 2-way TLS auth 
 *  Forked from https://github.com/ARMmbed/mbed-os-example-tls/blob/master/tls-client/HelloHttpsClient.cpp
 */

#include "TLSClient.h"

#include "easy-connect.h"



#include "mbedtls/platform.h"
#include "mbedtls/config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include <stdint.h>
#include <string.h>


#include "MQTTNetwork.h"
#include "MQTTmbed.h"
#include "MQTTClient.h"

Serial pc(USBTX, USBRX);
#define PRINT pc.printf   //to see output in serial port


//const char SERVER_NAME[] = "c02wg14lhtdd.sjc.arm.com";    //this is my MacBook with Mosquitto broker
//const int SERVER_PORT = 8883;  //1833 without TLS

const char *TLSClient::DRBG_PERSONALIZED_STR = "Mbed TLS  client";
const size_t TLSClient::ERROR_LOG_BUFFER_LENGTH = 128;

const char *TLSClient::TLS_PEM_CA =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\n"
    "A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\n"
    "b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\n"
    "MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\n"
    "YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\n"
    "aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\n"
    "jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\n"
    "xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\n"
    "1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\n"
    "snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\n"
    "U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\n"
    "9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\n"
    "BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\n"
    "AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\n"
    "yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\n"
    "38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\n"
    "AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\n"
    "DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\n"
    "HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n"
    "-----END CERTIFICATE-----\n";

const char *TLSClient::TLS_CLIENT_CERT = "abdc12 FakeCert";   //TODO which openssl command generates this file ?
const char *TLSClient::TLS_CLIENT_PKEY = "xyz FakePkey";      //TODO which openssl command generates this file ?

TLSClient::TLSClient(const char *in_server_name,
                                   const uint16_t in_server_port,
                                   mbedtls_platform_context* in_platform_ctx) :
    socket(),
    server_name(in_server_name),
    server_port(in_server_port),
    /* The platform context is passed just in case any crypto calls need it.
     * Please refer to https://github.com/ARMmbed/mbedtls/issues/1200 for more
     * information. */
    platform_ctx(in_platform_ctx)
{
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);    //  TODO compilation error here  client cert
    mbedtls_pk_init( &pkey );           //  TODO compilation error here private key 
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
}

TLSClient::~TLSClient()
{
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&clicert);
    mbedtls_ssl_free(&ssl);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_config_free(&ssl_conf);


    socket.close();
}


void TLSClient::publishMQTT(){
    MQTTNetwork mqttNetwork(network, &socket);
    MQTT::Client<MQTTNetwork, Countdown> mqtt_client(mqttNetwork);

    int rc_mqtt_network_connect = mqttNetwork.connect(server_name, server_port);
    if (rc_mqtt_network_connect != 0) {
        PRINT("MQTT ERROR rc from TCP connect is %d\r\n", rc_mqtt_network_connect);
    }

    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    data.MQTTVersion = 3;
    
    data.clientID.cstring = (char*)"mbed-sample";
    data.username.cstring = (char*)"testuser";
    data.password.cstring = (char*)"testpassword";
    int arrivedcount=0;

    int rc_mqtt_connect =  mqtt_client.connect(data);
    if (rc_mqtt_connect  != 0) {
        PRINT("ERROR --- rc from MQTT connect is %d\r\n", rc_mqtt_connect);
    }

    //int rc_mqtt_subscribe;
    //if ((rc_mqtt_subscribe = client.subscribe(topic, MQTT::QOS2, messageArrived)) != 0)
    //    PRINT("ERROR --- rc from MQTT subscribe is %d\r\n", rc_mqtt_subscribe);

    MQTT::Message message;
    int rc_pub;  
    char buf[100];
        
    const char* ip =  (network) ? network->get_ip_address()  : "IP address error";
    const char* mac = (network) ? network->get_mac_address() : "Mac address error";
    const char* topic = "mbed-sample";
    int i=0; 
    int N_MESSAGES=16;   

    while(i < N_MESSAGES){  
    
        i=i+1;
        //led1 = !led1;
        //wait(1.0);
        PRINT("Before publishing QoC_0 message # %d : rc_mqtt_network_connect=%d rc_mqtt_connect=%d   IP=%s MAC=%s \r\n", i, rc_mqtt_network_connect, rc_mqtt_connect,  ip, mac );
         
        // QoS 0
        
        sprintf(buf, "Hello World!  QoS 0 message number=%d \r\n", i);
        message.qos = MQTT::QOS0;
        message.retained = false;
        message.dup = false;
        message.payload = (void*)buf;
        message.payloadlen = strlen(buf)+1;
        rc_pub = mqtt_client.publish(topic, message);
        PRINT("After publishing QoC_0 message # %d rc_pub=%d   arrivedcount=%d  \r\n  \r\n", i, rc_pub, arrivedcount);
      
        //while (arrivedcount < 1)
        //    client.yield(100);
          
     } //end while (i <  N_MESSAGE)

    int rc;
    if ((rc = mqtt_client.unsubscribe(topic)) != 0)
        PRINT("rc from unsubscribe = %d\r\n", rc);

    if ((rc = mqtt_client.disconnect()) != 0)
        PRINT("rc from disconnect was %d\r\n", rc);

    mqttNetwork.disconnect();
}

int TLSClient::run()
{
    pc.baud(115200);   //to see output in serial port
    int ret;
    uint32_t flags;
    
    /* Configure the TCPSocket */
    if ((ret = configureTCPSocket()) != 0)
        return ret;

    /* Configure already initialized Mbed TLS structures */
    if ((ret = configureTlsContexts()) != 0)
        return ret;

    /* Start a connection to the server */
    if ((ret = socket.connect(server_name, server_port)) != NSAPI_ERROR_OK) {
        mbedtls_printf("socket.connect() returned %d\n", ret);
        return ret;
    }
    mbedtls_printf("Successfully connected to %s at port %u\n",
                   server_name, server_port);

    /* Start the TLS handshake */
    mbedtls_printf("Starting the TLS handshake...\n");
    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while(ret != 0 &&
            (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        mbedtls_printf("mbedtls_ssl_handshake() returned -0x%04X\n", -ret);
        return ret;
    }
    mbedtls_printf("Successfully completed the TLS handshake\n");

    /* Print information about the TLS connection */
    ret = mbedtls_x509_crt_info(gp_buf, sizeof(gp_buf),
                                "\r  ", mbedtls_ssl_get_peer_cert(&ssl));
    if (ret < 0) {
        mbedtls_printf("mbedtls_x509_crt_info() returned -0x%04X\n", -ret);
        return ret;
    }
    mbedtls_printf("Server certificate:\n%s\n", gp_buf);

    /* Ensure certificate verification was successful */
    flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        ret = mbedtls_x509_crt_verify_info(gp_buf, sizeof(gp_buf),
                                           "\r  ! ", flags);
        if (ret < 0) {
            mbedtls_printf("mbedtls_x509_crt_verify_info() returned "
                           "-0x%04X\n", -ret);
            return ret;
        } else {
            mbedtls_printf("Certificate verification failed (flags %lu):"
                           "\n%s\n", flags, gp_buf);
            return -1;
        }
    } else {
        mbedtls_printf("Certificate verification passed\n");
    }

    mbedtls_printf("Established TLS connection to %s\n", server_name);
    
    publishMQTT();

    return 0;
}

int TLSClient::configureTCPSocket()
{
    int ret;

    /*
     * Use easy-connect lib to support multiple network bearers. See
     * https://github.com/ARMmbed/easy-connect README.md for more information.
     */
#if DEBUG_LEVEL > 0
    //NetworkInterface *network = easy_connect(true);
    network = easy_connect(true);
#else
    //NetworkInterface *network = easy_connect(false);
    network = easy_connect(false);
#endif /* DEBUG_LEVEL > 0 */
    if(network == NULL) {
        mbedtls_printf("easy_connect() returned NULL\n"
                       "Failed to connect to the network\n");
        return -1;
    }

    if ((ret = socket.open(network)) != NSAPI_ERROR_OK) {
        mbedtls_printf("socket.open() returned %d\n", ret);
        return ret;
    }

    socket.set_blocking(false);

    return 0;
}

int TLSClient::configureTlsContexts()
{
    int ret;

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            reinterpret_cast<const unsigned char *>(DRBG_PERSONALIZED_STR),
            strlen(DRBG_PERSONALIZED_STR) + 1);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed() returned -0x%04X\n", -ret);
        return ret;
    }
    //TODO: another option is to parse the file: mbedtls_x509_crt_parse_file( &clicert, opt.crt_file )
    //example: https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_client2.c#L1207
    ret = mbedtls_x509_crt_parse(&cacert,
                        reinterpret_cast<const unsigned char *>(TLS_PEM_CA),
                        strlen(TLS_PEM_CA) + 1);
    if (ret != 0) {
        mbedtls_printf("mbedtls_x509_crt_parse() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ssl_config_defaults() returned -0x%04X\n",
                       -ret);
        return ret;
    }


    //   2-way auth  https://tls.mbed.org/api/ssl_8h.html#a4e54e9ace21beb608bae36ddb81a4fb0
 
    // TODO: initialize clicert and pkey - currently it is an compilation error here
    
    ret = mbedtls_x509_crt_parse(&clicert,
                        reinterpret_cast<const unsigned char *>(TLS_CLIENT_CERT),
                        strlen(TLS_CLIENT_CERT) + 1);
    if (ret != 0) {
        mbedtls_printf("mbedtls_x509_crt_parse() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_pk_parse_key(&pkey,
                        reinterpret_cast<const unsigned char *>(TLS_CLIENT_PKEY),
                        strlen(TLS_CLIENT_PKEY) + 1, NULL, 0);
    if (ret != 0) {
        mbedtls_printf("mbedtls_x509_crt_parse() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_ssl_conf_own_cert( 
       &ssl_conf,   //SSL conf
       &clicert,    //own public cert chain
       &pkey        //own private key
    );


    if (ret != 0) {
        mbedtls_printf("mbedtls_ssl_config_defaults() returned -0x%04X\n",
                       -ret);
        return ret;
    }
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    /*
     * It is possible to disable authentication by passing
     * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
     */
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if DEBUG_LEVEL > 0
    mbedtls_ssl_conf_verify(&ssl_conf, sslVerify, this);
    mbedtls_ssl_conf_dbg(&ssl_conf, sslDebug, NULL);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif /* DEBUG_LEVEL > 0 */

    if ((ret = mbedtls_ssl_setup( &ssl, &ssl_conf)) != 0) {
        mbedtls_printf("mbedtls_ssl_setup() returned -0x%04X\n", -ret);
        return ret;
    }

    if ((ret = mbedtls_ssl_set_hostname( &ssl, server_name )) != 0) {
        mbedtls_printf("mbedtls_ssl_set_hostname() returned -0x%04X\n",
                       -ret);
        return ret;
    }
// TODO - investigate if mbedtls_ssl_set_bio call is required
// https://tls.mbed.org/api/ssl_8h.html#a8b7442420aef7f1a76fa8c5336362f9e
// mbedtls_ssl_set_bio(&ssl, static_cast<void *>(&socket), sslSend, sslRecv, NULL);

    return 0;
}

/* Not in use because we just publishing
int TLSClient::sslRecv(void *ctx, unsigned char *buf, size_t len)
{
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    int ret = socket->recv(buf, len);

    if (ret == NSAPI_ERROR_WOULD_BLOCK)
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    else if (ret < 0)
        mbedtls_printf("socket.recv() returned %d\n", ret);

    return ret;
}*/

// This method needs to be modified to send MQTT messages
int TLSClient::sslSend(void *ctx, const unsigned char *buf, size_t len)
{
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    int ret = socket->send(buf, len);

    if (ret == NSAPI_ERROR_WOULD_BLOCK)
        ret = MBEDTLS_ERR_SSL_WANT_WRITE;
    else if (ret < 0)
        mbedtls_printf("socket.send() returned %d\n", ret);

    return ret;
}
/*
void TLSClient::sslDebug(void *ctx, int level, const char *file,
                                int line, const char *str)
{
    (void)ctx;

    const char *p, *basename;

     
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\')
            basename = p + 1;
    }

    mbedtls_printf("%s:%d: |%d| %s\r", basename, line, level, str);
}
*/
int TLSClient::sslVerify(void *ctx, mbedtls_x509_crt *crt, int depth,
                                uint32_t *flags)
{
    TLSClient *client = static_cast<TLSClient *>(ctx);

    int ret = -1;

    ret = mbedtls_x509_crt_info(client->gp_buf, sizeof(gp_buf), "\r  ", crt);
    if (ret < 0) {
        mbedtls_printf("mbedtls_x509_crt_info() returned -0x%04X\n", -ret);
    } else {
        ret = 0;
        mbedtls_printf("Verifying certificate at depth %d:\n%s\n",
                       depth, client->gp_buf);
    }

    return ret;
}

