#ifndef SRC_HTTPSCONNECTION_HPP_
#define SRC_HTTPSCONNECTION_HPP_

#include <Arduino.h>

#include <string>

// Required for SSL
#ifndef HTTPS_USE_MBEDTLS
  #include <openssl/ssl.h>
#else
  #include <mbedtls/ssl.h>
  #include <mbedtls/net_sockets.h>
  #include <mbedtls/error.h>
#endif // MBEDTLS


// Required for sockets
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include "HTTPSServerConstants.hpp"
#include "HTTPConnection.hpp"
#include "HTTPHeaders.hpp"
#include "HTTPHeader.hpp"
#include "ResourceResolver.hpp"
#include "ResolvedResource.hpp"
#include "ResourceNode.hpp"
#include "HTTPRequest.hpp"
#include "HTTPResponse.hpp"

namespace httpsserver {

/**
 * \brief Connection class for an open TLS-enabled connection to an HTTPSServer
 */
class HTTPSConnection : public HTTPConnection {
public:
  HTTPSConnection(ResourceResolver * resResolver);
  virtual ~HTTPSConnection();

#ifndef HTTPS_USE_MBEDTLS
  virtual int initialize(int SocketID, SSL_CTX * sslCtx, HTTPHeaders *defaultHeaders);
#else
  virtual int initialize(mbedtls_net_context * server_fd, mbedtls_ssl_config * sslCnf, HTTPHeaders *defaultHeaders);
#endif
  virtual void closeConnection();
  virtual bool isSecure();

protected:
  friend class HTTPRequest;
  friend class HTTPResponse;

  virtual size_t readBytesToBuffer(byte* buffer, size_t length);
  virtual size_t pendingByteCount();
  virtual bool canReadData();
  virtual size_t writeBuffer(byte* buffer, size_t length);

private:
  // SSL context for this connection
#ifndef HTTPS_USE_MBEDTLS
  SSL * _ssl;
#else
  mbedtls_ssl_context _ssl;
  mbedtls_net_context _client_fd;
#endif

};

} /* namespace httpsserver */

#endif /* SRC_HTTPSCONNECTION_HPP_ */
