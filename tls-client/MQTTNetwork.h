#ifndef _MQTTNETWORK_H_
#define _MQTTNETWORK_H_

#include "NetworkInterface.h"
#include "TLSClient.h"

class MQTTNetwork {
public:
    MQTTNetwork(TLSClient* aTlc, NetworkInterface* aNetwork, TCPSocket* aSocket) : tlc(aTlc), network(aNetwork) , socket(aSocket) {
        //socket = new TCPSocket();
    }

    ~MQTTNetwork() {
        //delete socket;  
    }

    int read(unsigned char* buffer, int len, int timeout) {
        return tlc->sslRecvPub(buffer, len);
        // return socket->recv(buffer, len);
    }

    int write(unsigned char* buffer, int len, int timeout) {
        return tlc->sslSendPub(buffer, len);
        // return socket->send(buffer, len);
    }

    int connect(const char* hostname, int port) {
        // socket->open(network);
        // return socket->connect(hostname, port);
        return 0;
    }

    int disconnect() {
        //return socket->close();  // not required because there is call socket.close() in TLSClient destructor
        return 0;  
    }

private:
    TLSClient* tlc;
    NetworkInterface* network;
    TCPSocket* socket;
};

#endif // _MQTTNETWORK_H_
