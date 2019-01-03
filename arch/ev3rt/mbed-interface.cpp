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

/*mbed TLS library*/
#include "ssl.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "debug.h"
#include "net.h"

mbedtls_ssl_context         ssl;
mbedtls_ssl_config          conf;
mbedtls_x509_crt            cacert;
mbedtls_ctr_drbg_context    ctr_drbg;   
mbedtls_entropy_context     entropy;
const char *pers = "mbedClient";
const char SSL_CA_PEM[] = "-----BEGIN CERTIFICATE-----\n"
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

extern "C"
int TlsReceive(void *sock, unsigned char *buf, size_t sz)
{

    return ((TCPSocket *)sock)->recv((char *) buf, (int)sz) ;
}

extern "C"
int TlsSend(void *sock, const unsigned char *buf, size_t sz)
{
    return ((TCPSocket *)sock)->send((char *) buf, (int)sz);
}

extern "C"
int toppers_mbed_ssl_init(const void *server){

    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );

	int ret=0;
	
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg,
									   mbedtls_entropy_func,
									   &entropy,
									   (const unsigned char *) pers,
									   strlen( pers ) ) ) != 0 ) {
		syslog(LOG_NOTICE, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
		return ret;
	}

    if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) SSL_CA_PEM, sizeof (SSL_CA_PEM))) != 0) {
		syslog(LOG_NOTICE, "mbedtls_x509_crt_parse", ret);
		return ret;
	}
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    //mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE );
    if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT,
											 MBEDTLS_SSL_TRANSPORT_STREAM,
											 MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
    	syslog(LOG_NOTICE, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        return ret;
    }

#if DEBUG_LEVEL > 0
    mbedtls_ssl_conf_verify(&conf, my_verify, NULL);
    mbedtls_ssl_conf_dbg( &conf, my_debug, NULL);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );   
	
    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 ){
    	syslog(LOG_NOTICE, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return ret;
    }
	
    if( ( ret = mbedtls_ssl_set_hostname( &ssl, server ) ) != 0 ){
    	syslog(LOG_NOTICE, " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        return ret;
    }

    mbedtls_ssl_set_bio( &ssl, (void *)sock, TlsSend, TlsReceive, NULL );

    while(( ret = mbedtls_ssl_handshake( &ssl )) != 0 ){
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
        	syslog(LOG_NOTICE, " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            return ret;
        }
    }	
}

extern "C"
int toppers_mbed_socket_ssl_send(const void *http_req){
	int ret=0;

    while((ret = (mbedtls_ssl_write(&ssl , (unsigned char*)http_req, strlen(http_req) ))) <= 0){
		if(ret != MBEDTLS_ERR_SSL_WANT_READ &&
		   ret != MBEDTLS_ERR_SSL_WANT_WRITE){
            syslog(LOG_NOTICE, "Write error! returned %d\n", ret);
            return EXIT_FAILURE;
        }
    }
	return (1);
}

extern "C"
int toppers_mbed_socket_ssl_receive(const void *rcvBuff){
	return (mbedtls_ssl_read(&ssl, rcvBuff, sizeof(rcvBuff)-1));
}

extern "C"
int toppers_mbed_ssl_free(void) {
	/* frees all data before client termination */
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_x509_crt_free( &cacert );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}

// FIXME: this is a workaround for compiler
void *__dso_handle=0;
