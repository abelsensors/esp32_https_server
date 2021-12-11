#ifndef SRC_CONNECTIONCONTEXT_HPP_
#define SRC_CONNECTIONCONTEXT_HPP_

#include <Arduino.h>
#include <IPAddress.h>
#ifndef HTTPS_USE_MBEDTLS	// From ServerConstats
  #include <openssl/ssl.h>
#else
  #include <mbedtls/ssl.h>
  #include <mbedtls/entropy.h>
  #include <mbedtls/ctr_drbg.h>
  #include <mbedtls/net_sockets.h>
  #include <mbedtls/error.h>

#ifdef HTTPS_USE_MBEDTLS_SSL_CACHE
  #include <mbedtls/ssl_cache.h>
#endif // SSL_CACHE

#endif // MBEDTLS


namespace httpsserver {

class WebsocketHandler;

/**
 * \brief Internal class to handle the state of a connection
 */
class ConnectionContext {
public:
  ConnectionContext();
  virtual ~ConnectionContext();

  virtual void signalRequestError() = 0;
  virtual void signalClientClose() = 0;
  virtual size_t getCacheSize() = 0;

  virtual size_t readBuffer(byte* buffer, size_t length) = 0;
  virtual size_t pendingBufferSize() = 0;

  virtual size_t writeBuffer(byte* buffer, size_t length) = 0;

  virtual bool isSecure() = 0;
  virtual void setWebsocketHandler(WebsocketHandler *wsHandler);
  virtual IPAddress getClientIP() = 0;

  WebsocketHandler * _wsHandler;
};

} /* namespace httpsserver */

#endif /* SRC_CONNECTIONCONTEXT_HPP_ */
