#ifndef SSL_CLIENT_H
#define SSL_CLIENT_H

#include "ssl.h"

#include <sys/types.h>

#include <string>
#include <vector>

class SslClient: public SSL {
 public:
  SslClient();
  virtual ~SslClient();

  virtual int connect(const std::string &ip, int port, uint16_t cxntype);

  virtual int close();

 private:
  // for DHE
  CryptoPP::Integer dh_p_;
  CryptoPP::Integer dh_q_;
  CryptoPP::Integer dh_g_;

  // for RSA
  CryptoPP::RSA::PrivateKey private_key_;
  CryptoPP::RSA::PublicKey public_key_;
  
};

#endif // SSL_CLIENT_H