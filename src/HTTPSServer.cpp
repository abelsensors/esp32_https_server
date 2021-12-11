#include "HTTPSServer.hpp"
#ifdef HTTPS_USE_MBEDTLS
#include <WiFi.h>
#endif

namespace httpsserver {


HTTPSServer::HTTPSServer(SSLCert * cert, const uint16_t port, const uint8_t maxConnections, const in_addr_t bindAddress):
#ifndef HTTPS_USE_MBEDTLS
  HTTPServer(port, maxConnections, bindAddress),
  _cert(cert) {

  // Configure runtime data
  _sslctx = NULL;
#else
  HTTPServer(port, maxConnections, bindAddress) {
    int err = setupCert( cert->getCertData(), cert->getCertLength() );
    if ( err != 0 ) mbedtls_x509_crt_free( &_Cert );
    else {
      err = setupPK( cert->getPKData(), cert->getPKLength() );
      if ( err != 0 ) {
        mbedtls_pk_free( &_PK );
        mbedtls_x509_crt_free( &_Cert );
      }
    }

  if( err != 0 ) {
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror( err, error_buf, 100 );
    HTTPS_LOGE("Last error was: -0x%04X - %s", -1*err, error_buf );
#endif // MBEDTLS_ERROR_C
  } else {
    _CertOK = true;
  }
#endif // MBEDTLS
}

HTTPSServer::~HTTPSServer() {
#ifdef HTTPS_USE_MBEDTLS
  FreeSSL();
}

void HTTPSServer::FreeSSL(int err) {
  _CertOK = false;
  mbedtls_net_free( &server_fd );
  mbedtls_x509_crt_free( &_Cert );
  mbedtls_pk_free( &_PK );
  mbedtls_ssl_config_free( &_conf);

#ifdef HTTPS_USE_MBEDTLS_SSL_CACHE
  mbedtls_ssl_cache_free( &_cache );
#endif // SSL_CACHE

  mbedtls_ctr_drbg_free( &_ctr_drbg );

  mbedtls_entropy_free( &_entropy );

#ifdef MBEDTLS_ERROR_C
  if( err != 0 ) {
    char error_buf[100];
    mbedtls_strerror( err, error_buf, 100 );
    HTTPS_LOGE("Last error was: -0x%04X - %s", -1*err, error_buf );
  }
#endif // MBEDTLS_ERROR_C

#endif // MBEDTLS
}


/**
 * This method starts the server and begins to listen on the port
 */
uint8_t HTTPSServer::setupSocket(int SocketID) {
  if (!isRunning()) {
    int ret;
    if ( !(ret = setupSSLCTX()) ) {
      HTTPS_LOGE("setupSSLCTX failed");
#ifdef HTTPS_USE_MBEDTLS
      FreeSSL(ret);
#endif // MBEDTLS
      return 0;
    }

#ifndef HTTPS_USE_MBEDTLS
    if (!setupCert()) {
      HTTPS_LOGE("setupCert failed");
      SSL_CTX_free(_sslctx);
      _sslctx = NULL;
      return 0;
    }
#else
    if ( !_CertOK ) {
      HTTPS_LOGE("No valid Certificate");
      FreeSSL();
      return 0;
    }
#endif // MBEDTLS does this in setupSSLCTX()

#ifndef HTTPS_USE_MBEDTLS
    if ( !HTTPServer::setupSocket()) {
      HTTPS_LOGE("setupSockets failed");
      SSL_CTX_free(_sslctx);
      _sslctx = NULL;
      return 0;
    }
  }
#else
    mbedtls_net_init( &server_fd );
    if( ( ret = mbedtls_net_bind( &server_fd, NULL, String(_port).c_str(), MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
      HTTPS_LOGE( "mbedtls_net_bind returned %d", ret );
      FreeSSL(ret);
      return 0;
    }
    if ( !HTTPServer::setupSocket(server_fd.fd)) {
      HTTPS_LOGE("Adding Secure Socket failed");
      FreeSSL();
      return 0;
    }
  }
#endif // MBEDTLS
  return 1;
}

void HTTPSServer::teardownSocket() {
  HTTPServer::teardownSocket();

#ifndef HTTPS_USE_MBEDTLS
  // Tear down the SSL context
  SSL_CTX_free(_sslctx);
  _sslctx = NULL;
#else
  FreeSSL();
#endif // MBEDTLS
}

int HTTPSServer::createConnection(int idx) {
  HTTPSConnection * newConnection = new HTTPSConnection(this);
  _connections[idx] = newConnection;
#ifndef HTTPS_USE_MBEDTLS
  return newConnection->initialize(_socket, _sslctx, &_defaultHeaders);
#else
  return newConnection->initialize(&server_fd, &_conf, &_defaultHeaders);
#endif // MBEDTLS
}

/**
 * This method configures the ssl context that is used for the server
 */
#ifndef HTTPS_USE_MBEDTLS
uint8_t HTTPSServer::setupSSLCTX() {
  _sslctx = SSL_CTX_new(TLSv1_2_server_method());
  if (_sslctx) {
    // Set SSL Timeout to 5 minutes
    SSL_CTX_set_timeout(_sslctx, 300);
    return 1;
  } else {
    _sslctx = NULL;
    return 0;
  }
}
#else
int HTTPSServer::setupSSLCTX() {
  int ret;
  mbedtls_ssl_config_init( &_conf );
  mbedtls_entropy_init( &_entropy );
  mbedtls_ctr_drbg_init( &_ctr_drbg );

  if ( (ret = mbedtls_ssl_config_defaults( &_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0 ) {
    HTTPS_LOGE( "mbedtls_ssl_config_defaults returned %d", ret );
    return ret;
  }
  mbedtls_ssl_conf_read_timeout( &_conf, HTTPS_SHUTDOWN_TIMEOUT);	// from HTTPSServerConstants

  String pers = "HTTPSServer" + WiFi.macAddress();	// Use MAC address as additional entropy 
  if( ( ret = mbedtls_ctr_drbg_seed( &_ctr_drbg, mbedtls_entropy_func, &_entropy, (const unsigned char *)pers.c_str(), strlen( pers.c_str() ) ) ) != 0 ) {
    HTTPS_LOGE( "mbedtls_ctr_drbg_seed returned %d", ret );
    return ret;
  }
  mbedtls_ssl_conf_rng( &_conf, mbedtls_ctr_drbg_random, &_ctr_drbg );

  if ( ( ret = mbedtls_ssl_conf_own_cert( &_conf, &_Cert, &_PK ) ) != 0 ) {
    HTTPS_LOGE( "mbedtls_ctr_drbg_seed returned %d", ret );
    return ret;
  }
#ifdef HTTPS_USE_MBEDTLS_SSL_CACHE
  mbedtls_ssl_cache_init( &_cache );
  mbedtls_ssl_conf_session_cache( &_conf, &_cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set );
#endif // SSL_CACHE
}
#endif // MBEDTLS

#ifndef HTTPS_USE_MBEDTLS
/**
 * This method configures the certificate and private key for the given
 * ssl context
 */
uint8_t HTTPSServer::setupCert() {
  if ( !_cert ) return 0;
  // Configure the certificate first
  uint8_t ret = SSL_CTX_use_certificate_ASN1(
    _sslctx,
    _cert->getCertLength(),
    _cert->getCertData()
  );

  // Then set the private key accordingly
  if (ret) {
    ret = SSL_CTX_use_RSAPrivateKey_ASN1(
      _sslctx,
      _cert->getPKData(),
      _cert->getPKLength()
    );
  }

  return ret;
}
#else
int HTTPSServer::setupCert(const unsigned char *cert, size_t cert_len) {
  int ret;
  mbedtls_x509_crt_init( &_Cert );
  ret = mbedtls_x509_crt_parse( &_Cert, cert, cert_len+1 );
  if( ret != 0 ) {
    HTTPS_LOGE( "mbedtls_x509_crt_parse returned %d", ret );
  }

  return ret;
}

int HTTPSServer::setupPK(const unsigned char *private_key, size_t pk_len) {
  int ret;
  mbedtls_pk_init( &_PK );
  ret =  mbedtls_pk_parse_key( &_PK, private_key, pk_len+1, NULL, 0 );
  if( ret != 0 ) {
      HTTPS_LOGE( "mbedtls_pk_parse_key returned %d", ret );
  }

  return ret;
}
#endif // MBEDTLS

} /* namespace httpsserver */
