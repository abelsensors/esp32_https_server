#include "HTTPSConnection.hpp"

namespace httpsserver {


HTTPSConnection::HTTPSConnection(ResourceResolver * resResolver):
  HTTPConnection(resResolver) {
#ifndef HTTPS_USE_MBEDTLS
  _ssl = NULL;
#endif 
}

HTTPSConnection::~HTTPSConnection() {
  // Close the socket
  closeConnection();
#ifdef HTTPS_USE_MBEDTLS
  freeSSL();
}

void HTTPSConnection::freeSSL() {
  mbedtls_ssl_free( &_ssl );
  mbedtls_net_free( &_client_fd );
#endif
}

bool HTTPSConnection::isSecure() {
  return true;
}

#ifndef HTTPS_USE_MBEDTLS
int HTTPSConnection::initialize(int SocketID, SSL_CTX * sslCtx, HTTPHeaders *defaultHeaders) {
  if (_connectionState == STATE_UNDEFINED) {
    // Let the base class connect the plain tcp socket
    int resSocket = HTTPConnection::initialize(SocketID, defaultHeaders);

    // Build up SSL Connection context if the socket has been created successfully
    if (resSocket >= 0) {

      _ssl = SSL_new(sslCtx);

      if (_ssl) {
        // Bind SSL to the socket
        int success = SSL_set_fd(_ssl, resSocket);
        if (success) {

          // Perform the handshake
          success = SSL_accept(_ssl);
          if (success) {
            return resSocket;
          } else {
            HTTPS_LOGE("SSL_accept failed. Aborting handshake. FID=%d", resSocket);
          }
        } else {
          HTTPS_LOGE("SSL_set_fd failed. Aborting handshake. FID=%d", resSocket);
        }
      } else {
        HTTPS_LOGE("SSL_new failed. Aborting handshake. FID=%d", resSocket);
      }

    } else {
      HTTPS_LOGE("Could not accept() new connection. FID=%d", resSocket);
    }
#else
int HTTPSConnection::initialize(mbedtls_net_context * server_fd, mbedtls_ssl_config * sslCnf, HTTPHeaders *defaultHeaders) {
  if (_connectionState == STATE_UNDEFINED) {
    int err;
    mbedtls_ssl_init( &_ssl );
    if( ( err = mbedtls_ssl_setup( &_ssl, sslCnf ) ) != 0 ) {
      HTTPS_LOGE( "mbedtls_ssl_setup returned %d", err );
    } else {
      mbedtls_net_init( &_client_fd );
      mbedtls_ssl_session_reset( &_ssl );
      if( ( err = mbedtls_net_accept( server_fd, &_client_fd, NULL, 0, NULL ) ) != 0 ) {
        HTTPS_LOGE( "mbedtls_net_accept returned %d", err );
      } else {
        int resSocket = HTTPConnection::initialize(_client_fd.fd, defaultHeaders);
        mbedtls_ssl_set_bio( &_ssl, &_client_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
        if( ( err = mbedtls_ssl_handshake_step( &_ssl ) ) != 0 ) {
          if( err != MBEDTLS_ERR_SSL_WANT_READ && err != MBEDTLS_ERR_SSL_WANT_WRITE ) {
            HTTPS_LOGE( "mbedtls_ssl_handshake_step returned %d", err );
          }
        } else {	// The next call to mbedtls_ssl_read will complete the handshake AND read the data
          HTTPS_LOGD( "mbedtls_ssl_handshake started");
          return resSocket;
        }

        mbedtls_ssl_session_reset( &_ssl );
      }
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror( err, error_buf, 100 );
    HTTPS_LOGE("Last error was: -0x%04X - %s", -1*err, error_buf );
#endif // MBEDTLS_ERROR_C
#endif // MBEDTLS
    _connectionState = STATE_ERROR;
    _clientState = CSTATE_ACTIVE;

    // This will only be called if the connection could not be established and cleanup
    // variables like _ssl etc.
    closeConnection();
  }
  // Error: The connection has already been established or could not be established
  return -1;
}


void HTTPSConnection::closeConnection() {
  // FIXME: Copy from HTTPConnection, could be done better probably
  if (_connectionState != STATE_ERROR && _connectionState != STATE_CLOSED) {

    // First call to closeConnection - set the timestamp to calculate the timeout later on
    if (_connectionState != STATE_CLOSING) {
      _shutdownTS = millis();
    }

    // Set the connection state to closing. We stay in closing as long as SSL has not been shutdown
    // correctly
    _connectionState = STATE_CLOSING;
  }

#ifndef HTTPS_USE_MBEDTLS
  // Try to tear down SSL while we are in the _shutdownTS timeout period or if an error occurred
  if (_ssl) {
    if(_connectionState == STATE_ERROR || SSL_shutdown(_ssl) == 0) {
      // SSL_shutdown will return 1 as soon as the client answered with close notify
      // This means we are safe to close the socket
      SSL_free(_ssl);
      _ssl = NULL;
    } else if (_shutdownTS + HTTPS_SHUTDOWN_TIMEOUT < millis()) {
      // The timeout has been hit, we force SSL shutdown now by freeing the context
      SSL_free(_ssl);
      _ssl = NULL;
      HTTPS_LOGW("SSL shutdown did not receive close notification from the client");
      _connectionState = STATE_ERROR;
    }
  }

  // If SSL has been brought down, close the socket
  if (!_ssl) {
    HTTPConnection::closeConnection();
  }
#else
  if ( _connectionState != STATE_ERROR ) {
    if (_shutdownTS + HTTPS_SHUTDOWN_TIMEOUT < millis()) {
      // The timeout has been hit, we force SSL shutdown now by freeing the context
      HTTPS_LOGW("SSL shutdown did not receive close notification from the client");
      _connectionState = STATE_ERROR;
    } else {
      int err = mbedtls_ssl_close_notify( &_ssl );
      /* mbedtls_ssl_close_notify will return 0 on success or a specific SSL error code.
         If this function returns something other than 0 or MBEDTLS_ERR_SSL_WANT_READ/WRITE,
         we must stop using the SSL context and free it.
         If MBEDTLS_ERR_SSL_WANT_READ/WRITE we should wait
      */
      if ( err == MBEDTLS_ERR_SSL_WANT_READ || err == MBEDTLS_ERR_SSL_WANT_WRITE ) {
        HTTPS_LOGD("Connection waiting for Read or Write. Socket FID=%d", _client_fd.fd);
        return;
      }
    }
  }

  HTTPConnection::closeConnection();
#endif // MBEDTLS
}

size_t HTTPSConnection::writeBuffer(byte* buffer, size_t length) {
#ifndef HTTPS_USE_MBEDTLS
  return SSL_write(_ssl, buffer, length);
#else
  return mbedtls_ssl_write( &_ssl, buffer, length);
#endif // MBEDTLS
}

size_t HTTPSConnection::readBytesToBuffer(byte* buffer, size_t length) {
#ifndef HTTPS_USE_MBEDTLS
  int ret = SSL_read(_ssl, buffer, length);
  if (ret < 0) {
    HTTPS_LOGE("SSL_read error: %d",  SSL_get_error(_ssl, ret));
  }
#else
  int ret = mbedtls_ssl_read( &_ssl, buffer, length);
  if ( ret < 0 ) {
    if ( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE
      || ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS || ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS
      || ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT ) return 0;
    else {
      HTTPS_LOGE("mbedtls_ssl_read returned: %d", ret);
#ifdef MBEDTLS_ERROR_C
      char error_buf[100];
      mbedtls_strerror( ret, error_buf, 100 );
      HTTPS_LOGE("Last error was: -0x%04X - %s", -1*ret, error_buf );
#endif // MBEDTLS_ERROR_C
	}
  }
#endif // MBEDTLS
  return ret;
}

size_t HTTPSConnection::pendingByteCount() {
#ifndef HTTPS_USE_MBEDTLS
  return SSL_pending(_ssl);
#else
  return mbedtls_ssl_get_bytes_avail( &_ssl );
#endif
}

bool HTTPSConnection::canReadData() {
#ifndef HTTPS_USE_MBEDTLS
  return HTTPConnection::canReadData() || (SSL_pending(_ssl) > 0);
#else
  return HTTPConnection::canReadData() || (mbedtls_ssl_check_pending( &_ssl ) > 0);
#endif // MBEDTLS
}

} /* namespace httpsserver */
