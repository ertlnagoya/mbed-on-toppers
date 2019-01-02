#pragma once

#ifdef __cplusplus
extern "C" {
#endif
	
/**
 * Provided interface
 */

void toppers_mbed_initialize(); // Must be called once before using toppers_mbed_start_xxx functions

void toppers_mbed_start_lwip(const char *ipv4addr); // Start lwIP and DHCP server with a static IP address

void httpd_receive_file_start(void *buffer, uint32_t size); // Start to receive a file over HTTP, any HTTP request before this call will be dropped. (buffer=NULL means cancel & disable)
int  http_receive_file_poll(const char **filename, uint32_t *size); // File name ("" means a firmware i.e. uImage received) and size will be filled if a file has been received. Return 0 means not yet.

/**
 * Required interface
 */

/* network library*/
char* toppers_mbed_network_getmacaddress(void);
char* toppers_mbed_network_getipaddress(void);
char* toppers_mbed_network_getnetworkmask(void);
char* toppers_mbed_network_getgateway(void);

/* socket library*/
int toppers_mbed_socket_connect(const char *server, uint16_t port);
int toppers_mbed_socket_send(const void *http_req);
int toppers_mbed_socket_receive(const void *rcvbuff);
void toppers_mbed_socket_disconnect(void);

#ifdef __cplusplus
}
#endif

