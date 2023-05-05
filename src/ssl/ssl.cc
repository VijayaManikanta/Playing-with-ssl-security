#include "ssl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <iostream> // todo: remove this

#include "tcp.h"
#include "crypto_adaptor.h"
#include <sstream>
#include <base64.h>
#include <hex.h>
#include <osrng.h>
#include <rsa.h>
#include <files.h>

using namespace std;

SSL::SSL()
{
  this->tcp_ = new TCP();
  shared_key_ = NULL;
  shared_key_len_ = 0;
  CryptoPP::RSA::PrivateKey privateKey;
  CryptoPP::RSA::PublicKey publickey;
  pub_key_ = publickey;
  priv_key_ = privateKey;
}

SSL::SSL(TCP *tcp)
{
  this->tcp_ = tcp;
  shared_key_ = NULL;
  shared_key_len_ = 0;
}

SSL::~SSL()
{
  if (shared_key_ != NULL)
  {
    free(shared_key_);
  }
  if (this->tcp_)
  {
    this->tcp_->socket_close();
    delete this->tcp_;
  }
}

// hostname and port

string SSL::get_hostname() const
{
  string hostname;
  if (this->tcp_->get_hostname(&hostname) != 0)
  {
    printf("Can't get hostname.\n");
    exit(1);
  }
  return hostname;
}

int SSL::get_port() const
{
  int port;
  if (this->tcp_->get_port(&port) != 0)
  {
    printf("Can't get port.\n");
    exit(1);
  }
  return port;
}

// set key
int SSL::set_shared_key(const unsigned char *const shared_key, size_t key_len, const unsigned char *const iv, size_t ivlength)
{
  this->shared_key_len_ = key_len;
  this->ivlength = ivlength;
  this->shared_key_ = (unsigned char *)malloc(key_len * sizeof(unsigned char));
  memcpy(this->shared_key_, shared_key, key_len);
  this->iv = (unsigned char *)malloc(ivlength * sizeof(unsigned char));
  memcpy(this->iv, iv, ivlength);
  return 0;
}
int SSL::set_rsa_publickey(CryptoPP::RSA::PublicKey rsakey)
{
  this->pub_key_ = rsakey;
  return 0;
}
int SSL::set_rsa_privatekey(CryptoPP::RSA::PrivateKey clientkey)
{
  this->priv_key_ = clientkey;
  return 0;
}

std::string SSL::encode_struct(SSL::SSLRecord *data)
{
  std::ostringstream oss;
  oss << (int)data->requesttype << "," << data->cipherSuites << "," << data->cipherkey << "," << data->randomSeq << "," << data->data;
  std::string str = oss.str();
  std::string encoded;
  CryptoPP::StringSource ss(str, true,
                            new CryptoPP::Base64Encoder(
                                new CryptoPP::StringSink(encoded)));
  return encoded;
}

SSL::SSLRecord SSL::decode_struct(const std::string *encoded)
{
  string decoded;
  CryptoPP::StringSource ss(*encoded, true,
                            new CryptoPP::Base64Decoder(
                                new CryptoPP::StringSink(decoded)));
  std::istringstream iss(decoded);

  size_t pos = 0;
  std::string delimiter = ",";
  SSL::SSLRecord decdata;
  int i = 0;
  while ((pos = decoded.find(",")) != std::string::npos)
  {
    if (i == 0)
    {
      // 0 index stores requesttype
      decdata.requesttype = stoi(decoded.substr(0, pos));
    }
    if (i == 1)
    {
      // index 1 for cipher suites
      decdata.cipherSuites = stoi(decoded.substr(0, pos));
    }
    if (i == 2)
    {
      // Index 2 for key information

      decdata.cipherkey = decoded.substr(0, pos);
    }
    if (i == 3)
    {
      // Index 2 for key information

      decdata.randomSeq = decoded.substr(0, pos);
    }
    decoded.erase(0, pos + delimiter.length());
    i++;
  }
  decdata.data = (string)decoded;

  return decdata;
}
// strings: send, recv
// returns 0 on success, -1 otherwise

int SSL::send(const std::string &send_str)
{
  // make a record
  Record send_record;
  send_record.hdr.type = REC_APP_DATA;
  send_record.hdr.version = VER_99;

  // encrypt
  string cipher_text;
  if (aes_encrypt(this->shared_key_, this->shared_key_len_, this->iv, this->ivlength,
                  &cipher_text, send_str) != 0)
  {
    cerr << "Couldn't encrypt." << endl;
    return -1;
  }

  char *data = (char *)malloc(cipher_text.length() * sizeof(char));
  memcpy(data, cipher_text.c_str(), cipher_text.length());
  send_record.data = data;

  // add length to record
  send_record.hdr.length = cipher_text.length();

  // send
  int ret_code;
  ret_code = send(send_record);
  free(send_record.data);

  return ret_code;
}

int SSL::recv(std::string *recv_str)
{
  // receive record
  Record recv_record;
  if (recv(&recv_record) == -1)
  {
    cerr << "Couldn't receive." << endl;
    return -1;
  }

  // check
  if (recv_record.hdr.type != REC_APP_DATA)
  {
    cerr << "Not app data." << endl;
    return -1;
  }

  // extract
  string cipher_text(recv_record.data, recv_record.hdr.length);
  free(recv_record.data);

  // decrypt

  if (aes_decrypt(this->shared_key_, this->shared_key_len_, this->iv, this->ivlength,
                  recv_str, cipher_text) != 0)
  {
    cerr << "Couldn't decrypt." << endl;
    return -1;
  }

  return 0;
}

// records: send, recv
// returns 0 on success, -1 otherwise

int SSL::send(const Record &send_record)
{
  if (this->tcp_ == NULL)
  {
    cerr << "SSL::send: tcp not set." << endl;
    return -1;
  }

  // create new char array
  ssize_t send_len = 1 + 2 + 2 + send_record.hdr.length;
  char *send_str = (char *)malloc(send_len * sizeof(char));

  // fill it
  unsigned int index = 0;
  memcpy(&(send_str[index]), &send_record.hdr.type, 1);
  index += 1;
  memcpy(&(send_str[index]), &send_record.hdr.version, 2);
  index += 2;
  memcpy(&(send_str[index]), &send_record.hdr.length, 2);
  index += 2;
  memcpy(&(send_str[index]), send_record.data, send_record.hdr.length);

  // send it
  if (this->tcp_->socket_send(send_str, send_len) != send_len)
  {
    cerr << "SSL::send: couldn't send all data." << endl;
    return -1;
  }

  // clean up
  free(send_str);

  return 0;
}

int SSL::recv(Record *recv_record)
{
  if (this->tcp_ == NULL)
  {
    cerr << "SSL::recv: tcp not set." << endl;
    return -1;
  }

  // receive the header
  char *header = (char *)malloc(5 * sizeof(char));
  if (this->tcp_->socket_recv(header, 5) != 5)
  {
    cerr << "SSL::recv: Couldn't receive header." << endl;
    return -1;
  }

  char *type = header;
  char *version = &(header[1]);
  char *length = &(header[1 + 2]);

  uint16_t recv_len;
  memcpy(&recv_len, length, 2);
  char *recv_str = (char *)malloc(recv_len * sizeof(char));
  if (this->tcp_->socket_recv(recv_str, recv_len) != recv_len)
  {
    cerr << "SSL::recv: couldn't receive all data." << endl;
    return -1;
  }

  // set values to record
  memcpy(&(recv_record->hdr.type), type, 1);
  memcpy(&(recv_record->hdr.version), version, 2);
  recv_record->hdr.length = recv_len;
  recv_record->data = recv_str;

  // clean up
  free(header);

  return 0;
}

int SSL::rsasend(const std::string &send_str)
{
  // make a record
  Record send_record;
  send_record.hdr.type = REC_APP_DATA;
  send_record.hdr.version = VER_99;

  // encrypt
  string cipher_text;

  if (rsa_encrypt(this->pub_key_,
                  &cipher_text, send_str) != 0)
  {
    cerr << "Couldn't encrypt." << endl;
    return -1;
  }

  char *data = (char *)malloc(cipher_text.length() * sizeof(char));
  memcpy(data, cipher_text.c_str(), cipher_text.length());
  send_record.data = data;

  // add length to record
  send_record.hdr.length = cipher_text.length();

  // send
  int ret_code;
  ret_code = send(send_record);
  free(send_record.data);

  return ret_code;
}

int SSL::rsarecv(std::string *recv_str)
{
  // receive record
  Record recv_record;
  if (recv(&recv_record) == -1)
  {
    cerr << "Couldn't receive." << endl;
    return -1;
  }

  // check
  /*if ( recv_record.hdr.type != REC_APP_DATA) {
    cerr << "Not app data." << endl;
    return -1;
  }*/

  // extract
  string cipher_text(recv_record.data, recv_record.hdr.length);
  free(recv_record.data);

  // decrypt

  if (rsa_decrypt(this->priv_key_,
                  recv_str, cipher_text) != 0)
  {
    cerr << "Couldn't decrypt." << endl;
    return -1;
  }
  return 0;
}
