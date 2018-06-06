/**
 * \file main.cpp
 *
 * \brief An example  MQTT Client  with TLS 2-way auth
 *
 *
 */

#include "mbed.h"

Serial pc(USBTX, USBRX);
#define PRINT pc.printf   //to see output in serial port

#include "mbedtls/platform.h"

#include "TLSClient.h"

#include "MQTTNetwork.h"
#include "MQTTmbed.h"
#include "MQTTClient.h"

/* Domain/IP address of the MQTT broker  */
const char SERVER_NAME[] = "c02wg14lhtdd.sjc.arm.com";    //this is my MacBook with Mosquitto broker

/* Port used to connect to the MQTT broker */
const int SERVER_PORT = 8883;  //1833 without TLS

DigitalOut led1(LED1);
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


/******  MQTT start *******/


    MQTTNetwork mqttNetwork(client->network);
    MQTT::Client<MQTTNetwork, Countdown> mqtt_client(mqttNetwork);

    int rc_mqtt_network_connect = mqttNetwork.connect(SERVER_NAME, SERVER_PORT);
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
        
    const char* ip =  (client->network) ? client->network->get_ip_address()  : "IP address error";
    const char* mac = (client->network) ? client->network->get_mac_address() : "Mac address error";
    const char* topic = "mbed-sample";
    int i=0; 
    int N_MESSAGES=16;   

    while(i < N_MESSAGES){  
    
        i=i+1;
        led1 = !led1;
        wait(1.0);
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

/****  MQTT end ******/

    delete client;

    mbedtls_platform_teardown(&platform_ctx);
    return exit_code;
}
