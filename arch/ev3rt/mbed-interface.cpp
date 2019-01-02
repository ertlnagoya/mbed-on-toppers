#include "EthernetInterface.h"
#include "TCPSocket.h"
#include "DhcpServer.h"
#include "lwip/apps/httpd.h"

osMutexId httpd_post_mutex_id;
EthernetInterface *eth;
TCPSocket *sock;

extern "C"
void toppers_mbed_start_lwip(const char *ipv4addr) {	
    httpd_post_mutex_id = osMutexCreate(NULL);
    assert(httpd_post_mutex_id > 0);
//    debug("connect eth.\r\n");
	eth = new EthernetInterface();
	eth->set_network(ipv4addr, "255.255.255.0", ipv4addr);
    eth->connect();
//    debug("start dhcp\r\n");
	DhcpServer *dhcp_server = new DhcpServer("HostName", ipv4addr/*eth->get_ip_address()*/);
    httpd_init();
}

extern "C"
char* toppers_mbed_network_getmacaddress(void)
{
	return (eth->get_mac_address());
}

extern "C"
char* toppers_mbed_network_getipaddress(void)
{
	return (eth->get_ip_address());
}

extern "C"
char* toppers_mbed_network_getnetworkmask(void)
{
	return (eth->get_netmask());
}

extern "C"
char* toppers_mbed_network_getgateway(void)
{
	return (eth->get_gateway());
}

extern "C"
int toppers_mbed_socket_connect(const char *server, uint16_t port){
	sock = new TCPSocket(eth);
	return (sock->connect(server, port));
}

extern "C"
int toppers_mbed_socket_send(const void *http_req){
	return (sock->send((void *)http_req, (unsigned)strlen(http_req)));
}

extern "C"
int toppers_mbed_socket_receive(const void *rcvBuff){
    return (sock->recv(rcvBuff, (unsigned)sizeof(rcvBuff)-1));
}

extern "C"
void toppers_mbed_socket_disconnect(void){
	sock->close();
}

// FIXME: this is a workaround for compiler
void *__dso_handle=0;
