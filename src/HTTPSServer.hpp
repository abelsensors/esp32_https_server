#ifndef SRC_HTTPSSERVER_HPP_
#define SRC_HTTPSSERVER_HPP_

// Standard library
#include <string>

// Arduino stuff
#include <Arduino.h>

// Required for SSL
#ifndef HTTPS_USE_MBEDTLS	// From ServerConstats
  #include <openssl/ssl.h>
#else
  #include <mbedtls/ssl.h>
  #include <mbedtls/entropy.h>
  #include <mbedtls/ctr_drbg.h>
  #include <mbedtls/error.h>
#ifdef HTTPS_USE_MBEDTLS_SSL_CACHE
  #include <mbedtls/ssl_cache.h>
#endif // SSL_CACHE
#endif // MBEDTLS


// Internal includes
#include "HTTPServer.hpp"
#include "HTTPSServerConstants.hpp"
#include "HTTPHeaders.hpp"
#include "HTTPHeader.hpp"
#include "ResourceNode.hpp"
#include "ResourceResolver.hpp"
#include "ResolvedResource.hpp"
#include "HTTPSConnection.hpp"
#include "SSLCert.hpp"

namespace httpsserver {

/**
 * \brief Main implementation of the HTTP Server with TLS support. Use HTTPServer for plain HTTP
 */
class HTTPSServer : public HTTPServer {
public:
  HTTPSServer(SSLCert * cert, const uint16_t portHTTPS = 443, const uint8_t maxConnections = 4, const in_addr_t bindAddress = 0);
  virtual ~HTTPSServer();

private:
#ifndef HTTPS_USE_MBEDTLS
  // Static configuration. Port, keys, etc. ====================
  // Certificate that should be used (includes private key)
  SSLCert * _cert;

  //// Runtime data ============================================
  SSL_CTX * _sslctx;
#else
  bool _CertOK = false;
  mbedtls_net_context server_fd;
  mbedtls_x509_crt _Cert;
  mbedtls_pk_context _PK;
  mbedtls_ssl_config _conf;
  mbedtls_entropy_context _entropy;
  mbedtls_ctr_drbg_context _ctr_drbg;
#ifdef HTTPS_USE_MBEDTLS_SSL_CACHE
  mbedtls_ssl_cache_context _cache;
#endif // SSL_CACHE
#endif // MBEDTLS
  // Status of the server: Are we running, or not?

  // Setup functions
  virtual uint8_t setupSocket(int SocketID = -1);
  virtual void teardownSocket();
#ifndef HTTPS_USE_MBEDTLS
  uint8_t setupSSLCTX();
  uint8_t setupCert();
#else
  void FreeSSL(int err = 0);
  int setupSSLCTX();
  int setupCert(const unsigned char *cert, size_t cert_len);
  int setupPK(const unsigned char *private_key, size_t pk_len);
#endif // MBEDTLS

  // Helper functions
  virtual int createConnection(int idx);
};

} /* namespace httpsserver */

#endif /* SRC_HTTPSSERVER_HPP_ */
