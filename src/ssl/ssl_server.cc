#include "ssl_server.h"

#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>

#include "dh.h"
#include "integer.h"
#include "osrng.h"

#include "crypto_adaptor.h"
#include "tcp.h"
#include "logger.h"
#include "utils.h"
#include <base64.h>
#include <cmath>
#include <hex.h>

#include <stdexcept>
#include <vector>

#include <aes.h>
#include <base64.h>
#include <cryptlib.h>
#include <dh.h>
#include <filters.h>
#include <hex.h>
#include <modes.h>
#include <osrng.h>
#include <rsa.h>
#include <secblock.h>
#include <sha.h>
#include <boost/asio.hpp>
#include <modes.h>
#include <aes.h>
#include <dh.h>
#include <iomanip>
#include <hkdf.h>
#include <files.h>
#include <integer.h>
#include <algebra.h>
#include <algparam.h>
#include <nbtheory.h>
#include <dsa.h>

using CryptoPP::HKDF;
using CryptoPP::HMAC;
using CryptoPP::SecByteBlock;
using CryptoPP::SHA256;

using namespace std;

SslServer::SslServer()
{
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0)
  {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_server_" + datetime + ".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Server Log at " + datetime);

  this->closed_ = false;

  // init dhe
  generate_pqg(this->dh_p_, this->dh_q_, this->dh_g_);

  // init rsa
  generate_rsa_keys(this->private_key_, this->public_key_);
  ////////cout<<"The RSA Keys are....................."<<endl;
}

SslServer::~SslServer()
{
  if (!this->closed_)
  {
    this->shutdown();
  }
  delete this->logger_;
}

int SslServer::start(int num_clients)
{
  if (this->closed_)
  {
    return -1;
  }

  return this->tcp_->socket_listen(num_clients);
}

SSL *SslServer::accept()
{
  if (this->closed_)
  {
    return NULL;
  }

  TCP *cxn = this->tcp_->socket_accept();
  if (cxn == NULL)
  {
    cerr << "error when accepting" << endl;
    return NULL;
  }

  cxn->set_logger(this->logger_);

  SSL *new_ssl_cxn = new SSL(cxn);
  this->clients_.push_back(new_ssl_cxn);

  // IMPLEMENT HANDSHAKE HERE

  //*********************Receive Client Hello******************************************************************

  Record recv_record;
  new_ssl_cxn->recv(&recv_record);
  string enc = (string)recv_record.data;
  SSLRecord decoded_data = this->decode_struct(&enc);

  if (decoded_data.cipherSuites == KE_RSA)
  {

    // RSA Transfer Mode Found

    // Fetching Client Random from hello and Generating Server Random

    CryptoPP::SecByteBlock client_random(32);
    CryptoPP::SecByteBlock server_random(32);

    if (decoded_data.requesttype == (int)HS_CLIENT_HELLO)
    {

      // Receive Client Random
      CryptoPP::StringSource tsss(decoded_data.randomSeq, true, new CryptoPP::HexDecoder);
      tsss.Get(client_random, client_random.size());

      // std::cout << std::endl;

      // Need to send Server Random

      CryptoPP::AutoSeededRandomPool rng;
      // Generate a random 32-byte block

      rng.GenerateBlock(server_random, server_random.size());

      // This is not Secured. More Details will be added in report
      /*// Insert the current timestamp into the first 4 bytes
      std::time_t now = std::time(nullptr);
      uint32_t timestamp = static_cast<uint32_t>(now);
      std::memcpy(randomBlock.data(), &timestamp, sizeof(timestamp));
      */

      // Output the random block with timestamp
      // std::cout << "Server: Random block with timestamp: ";
      // for (size_t i = 0; i < server_random.size(); i++) {
      //    std::cout << std::hex << static_cast<int>(server_random[i]) << " ";
      //}
      // std::cout << std::endl;
      // Serialize the random block into a byte array

      std::string serverRandomStr;
      CryptoPP::StringSource dss(server_random, server_random.size(), true,
                                 new CryptoPP::HexEncoder(
                                     new CryptoPP::StringSink(serverRandomStr),
                                     false));

      // Server Random and Client Random are now ready. Now need to send Server Random to client using Server Hello

      // Need to Send Server Hello Request

      //*********************************************************Send SERVER HELLO*********************************************

      SSLRecord ssldata;
      ssldata.requesttype = this->HS_SERVER_HELLO;
      ssldata.cipherSuites = decoded_data.cipherSuites;
      ssldata.data = "Server Hello request being sent";
      ssldata.randomSeq = serverRandomStr;
      string encdata = this->encode_struct(&ssldata);

      Record send_record;
      send_record.hdr.type = REC_HANDSHAKE;
      send_record.hdr.version = VER_99;
      string body = encdata;
      char *data = (char *)malloc(body.length() * sizeof(char));
      memcpy(data, body.c_str(), body.length());
      send_record.data = data;
      send_record.hdr.length = body.length();
      int ret_code = new_ssl_cxn->send(send_record);
    }

    //***************************************Send HS_CERTIFICATE**************************************************************************
    // Server Hello Done. Now need to send Certificate but as its local sending public key

    SSLRecord ssldata;
    ssldata.requesttype = this->HS_CERTIFICATE;
    ssldata.cipherSuites = decoded_data.cipherSuites;
    ssldata.data = "HS_CERTIFICATE is Being Sent";
    CryptoPP::ByteQueue queue;
    public_key_.Save(queue);

    // We get Bytes of format CryptoPP::ByteQueue. So converting into string
    std::string encoded_key;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded_key), false);
    this->public_key_.Save(encoder);
    encoder.MessageEnd();
    ssldata.cipherkey = encoded_key;
    string encdata = this->encode_struct(&ssldata);

    Record send_record;
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    string body = encdata;
    char *data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = body.length();
    int ret_code = new_ssl_cxn->send(send_record);

    // Sent Server Certificate(Public Key in this case)

    //***************************************Send HS_SERVER_HELLO_DONE**************************************************************************

    // Now Need to Send Server Hello Done

    ssldata.requesttype = this->HS_SERVER_HELLO_DONE;
    ssldata.cipherSuites = decoded_data.cipherSuites;
    ssldata.data = "HS_SERVER_HELLO_DONE is Being Sent";
    encdata = this->encode_struct(&ssldata);
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    body = encdata;

    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = body.length();
    ret_code = new_ssl_cxn->send(send_record);

    // Server Hello Completed

    // Waiting for Key Exchange Request

    //***************************************Receive Key Exchange Request**************************************************************************
    string preMasterkey;
    new_ssl_cxn->set_rsa_privatekey(this->private_key_);
    new_ssl_cxn->rsarecv(&preMasterkey);

    // Extract Pre master key and generate master and AES key
    CryptoPP::SecByteBlock preMasterSecret(48);
    CryptoPP::StringSource aes(preMasterkey, true, new CryptoPP::Base64Decoder(new CryptoPP::ArraySink(preMasterSecret, preMasterSecret.size())));

    // Derive master secret using TLS 1.2 PRF

    CryptoPP::SecByteBlock masterSecret(48);
    unsigned char label[] = "master secret";
    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    hmac.SetKey(preMasterSecret, preMasterSecret.size());
    unsigned char seed[64];

    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);

    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(masterSecret, 48, label, sizeof(label) - 1, seed, sizeof(seed), preMasterSecret.BytePtr(), preMasterSecret.size());

    //////cout<<"Server: The master key is"<<endl;
    // Master key is

    //////cout<<endl;

    // Generate Aes kEY
    SecByteBlock keyMaterial(64); // 32 bytes for AES key and 16 bytes for IV
    unsigned char keyLabel[] = "key expansion";
    unsigned char keySeed[64];

    memcpy(keySeed, server_random, 32);
    memcpy(keySeed + 32, client_random, 32);

    HKDF<CryptoPP::SHA256> keyHkdf;
    keyHkdf.DeriveKey(keyMaterial, 64, keyLabel, sizeof(keyLabel) - 1, keySeed, sizeof(keySeed), masterSecret.BytePtr(), masterSecret.size());

    // Extract AES key and IV from keyMaterial
    SecByteBlock aesKey(keyMaterial.BytePtr(), 32);
    SecByteBlock aesIV(keyMaterial.BytePtr() + 32, 16);

    // Waiting for Change Cipher Spec
    //***************************************Receive Change Cipher Spec**************************************************************************

    Record recv_record2;
    new_ssl_cxn->recv(&recv_record2);
    enc = (string)recv_record2.data;
    decoded_data = this->decode_struct(&enc);

    if (recv_record2.hdr.type == REC_CHANGE_CIPHER_SPEC)
    {
      //////cout<<"Server: Received REC_CHANGE_CIPHER_SPEC "<<endl;
      new_ssl_cxn->set_shared_key(aesKey.BytePtr(), aesKey.size(), aesIV.BytePtr(), aesIV.size());
    }

    // Wait for Client Finish
    //***************************************Receive Client Finish**************************************************************************
    new_ssl_cxn->recv(&recv_record2);
    enc = (string)recv_record2.data;
    decoded_data = this->decode_struct(&enc);
    //////cout<<"Server: Received Client Finish "<<endl;

    //******************************************Send REC_CHANGE_CIPHER_SPEC*****************************************************
    // Need to send REC_CHANGE_CIPHER_SPEC

    ssldata.cipherSuites = KE_RSA;
    ssldata.data = "Server: REC_CHANGE_CIPHER_SPEC";
    encdata = this->encode_struct(&ssldata);

    decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_CHANGE_CIPHER_SPEC;
    send_record.hdr.version = VER_99;
    body = encdata;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = strlen(data);
    ret_code = new_ssl_cxn->send(send_record);

    // Change Cipher Request sent

    // Send Server Finish
    //******************************************Send Server Finish*****************************************************

    // Need to Send Server Finish

    ssldata.requesttype = this->HS_FINISHED;
    ssldata.cipherSuites = KE_RSA;
    ssldata.data = "Server: HS Finish";
    encdata = this->encode_struct(&ssldata);

    decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    body = encdata;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = strlen(data);
    ret_code = new_ssl_cxn->send(send_record);

    // sent Server Finish.
    return new_ssl_cxn;
  }
  else if (decoded_data.cipherSuites == KE_DHE)
  {
    // As client requested for DHE cipher server is establishing all required values for DHE

    // DHE Transfer Mode Found

    // Fetching Client Random from hello and Generating Server Random

    CryptoPP::SecByteBlock client_random(32);
    CryptoPP::SecByteBlock server_random(32);

    // Receive Client Random
    CryptoPP::StringSource tsss(decoded_data.randomSeq, true, new CryptoPP::HexDecoder);
    tsss.Get(client_random, client_random.size());
    /*std::cout << "Server: Received Client Random ";
       for (size_t i = 0; i < client_random.size(); i++) {
        std::cout << std::hex << static_cast<int>(client_random[i]) << " ";
    }

    std::cout << std::endl;
    */

    // Need to send Server Random

    CryptoPP::AutoSeededRandomPool rng;
    // Generate a random 32-byte block

    rng.GenerateBlock(server_random, server_random.size());

    // This is not Secured. More Details will be added in report
    /*// Insert the current timestamp into the first 4 bytes
    std::time_t now = std::time(nullptr);
    uint32_t timestamp = static_cast<uint32_t>(now);
    std::memcpy(randomBlock.data(), &timestamp, sizeof(timestamp));
    */

    // Serialize the random block into a byte array

    std::string serverRandomStr;
    CryptoPP::StringSource dss(server_random, server_random.size(), true,
                               new CryptoPP::HexEncoder(
                                   new CryptoPP::StringSink(serverRandomStr),
                                   false));

    // Server Random and Client Random are now ready. Now need to send Server Random to client using Server Hello

    // Need to Send Server Hello Request

    //*********************************************************Send SERVER HELLO*********************************************

    SSLRecord ssldata;
    ssldata.requesttype = this->HS_SERVER_HELLO;
    ssldata.cipherSuites = decoded_data.cipherSuites;
    ssldata.data = "Server Hello request being sent";
    ssldata.randomSeq = serverRandomStr;
    string encdata = this->encode_struct(&ssldata);

    Record send_record;
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    string body = encdata;
    char *data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = body.length();
    int ret_code = new_ssl_cxn->send(send_record);

    //***********************************************Server Hello Done***************************************************************
    // Currently Ignore Certificate Verification as its local host

    // ServerKeyExchange Need to be sent with below data
    /*
    The server's DH public key (i.e., the value g^x mod p, where g is the generator, p is the prime modulus, and x is the server's private key).
    The chosen Diffie-Hellman parameters (i.e., the values of g and p).
    */

    //*********************************************ServerKeyExchange*******************************************************************
    CryptoPP::AutoSeededRandomPool rnd;
    // Generate the DH parameters (p, g)
    CryptoPP::DH dh;
    dh.AccessGroupParameters().GenerateRandomWithKeySize(rnd, 512);

    // Generate server's DH key pair (private key x and public key g^x mod p)
    CryptoPP::SecByteBlock serverPrivate(dh.PrivateKeyLength());
    CryptoPP::SecByteBlock serverPublic(dh.PublicKeyLength());
    dh.GenerateKeyPair(rnd, serverPrivate, serverPublic);

    // Create the message: concatenation of p, g, and serverPublicKey
    CryptoPP::Integer p = dh.GetGroupParameters().GetModulus();
    CryptoPP::Integer g = dh.GetGroupParameters().GetSubgroupGenerator();
    // Convert SecByteBlock to Integer
    CryptoPP::Integer y;
    y.Decode(serverPublic.BytePtr(), serverPublic.SizeInBytes());

    //-----------------------Process P------------------------------

    // Get the encoded size of the integer
    size_t encodedSize = p.MinEncodedSize();

    // Allocate a byte buffer with the required size
    std::vector<unsigned char> encodedInteger(encodedSize);

    // Encode the integer into the byte buffer
    p.Encode(encodedInteger.data(), encodedSize);

    // Copy the byte buffer to a SecByteBlock
    CryptoPP::SecByteBlock secByteBlockP(encodedInteger.data(), encodedInteger.size());

    // Serialize the random block into a byte array

    std::string secByteBlockPStr;
    CryptoPP::StringSource pdss(secByteBlockP, secByteBlockP.size(), true,
                                new CryptoPP::HexEncoder(
                                    new CryptoPP::StringSink(secByteBlockPStr),
                                    false));

    //--------------------Process G------------------------------------------------//

    // Get the encoded size of the integer
    encodedSize = g.MinEncodedSize();

    // Allocate a byte buffer with the required size
    std::vector<unsigned char> encodedIntegerG(encodedSize);

    // Encode the integer into the byte buffer
    g.Encode(encodedIntegerG.data(), encodedSize);

    // Copy the byte buffer to a SecByteBlock
    CryptoPP::SecByteBlock secByteBlockG(encodedIntegerG.data(), encodedIntegerG.size());
    // Serialize the random block into a byte array

    std::string secByteBlockGStr;
    CryptoPP::StringSource gdss(secByteBlockG, secByteBlockG.size(), true,
                                new CryptoPP::HexEncoder(
                                    new CryptoPP::StringSink(secByteBlockGStr),
                                    false));

    //********************Process y*******************************************

    // Get the encoded size of the integer
    encodedSize = y.MinEncodedSize();

    // Allocate a byte buffer with the required size
    std::vector<unsigned char> encodedIntegerY(encodedSize);

    // Encode the integer into the byte buffer
    y.Encode(encodedIntegerY.data(), encodedSize);

    // Copy the byte buffer to a SecByteBlock
    CryptoPP::SecByteBlock secByteBlockY(encodedIntegerY.data(), encodedIntegerY.size());

    // Serialize the random block into a byte array

    std::string secByteBlockYStr;
    CryptoPP::StringSource ydss(secByteBlockY, secByteBlockY.size(), true,
                                new CryptoPP::HexEncoder(
                                    new CryptoPP::StringSink(secByteBlockYStr),
                                    false));

    ssldata.requesttype = this->HS_SERVER_KEY_EXCHANGE;
    ssldata.data = "S: ServerKeyExchange with G,P,Y";
    ssldata.cipherkey = secByteBlockPStr + ":" + secByteBlockGStr + ":" + secByteBlockYStr;
    encdata = this->encode_struct(&ssldata);

    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    body = encdata;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = body.length();
    ret_code = new_ssl_cxn->send(send_record);

    // CertificateRequest: This message is sent only if the server requests client authentication. It requests that the client send its own certificate, and can also specify a set of acceptable CAs.
    // This is ignored

    //********************************************Sending Server Hello Done****************************************************************

    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = body.length();
    ret_code = new_ssl_cxn->send(send_record);

    //********************************************Sent Server Hello Done****************************************************************

    //***************************************Receive Client  Key Exchange Reques ****************************************************

    Record recv_record2;
    new_ssl_cxn->recv(&recv_record2);
    //////cout<<"S: Received server exch"<<endl;
    enc = (string)recv_record2.data;
    decoded_data = this->decode_struct(&enc);
    //////cout<<"S: The ciper is"<<endl<<decoded_data.cipherkey<<endl;

    CryptoPP::StringSource cplb(decoded_data.cipherkey, true, new CryptoPP::HexDecoder);
    CryptoPP::SecByteBlock clientPublic(64);
    cplb.Get(clientPublic, 64);

    //////cout<<"Server: Client Public Received Successfully...........................";

    CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
    dh.Agree(sharedSecret, serverPrivate, clientPublic);
    const unsigned char *sharedSecretPtr = sharedSecret.BytePtr();

    CryptoPP::SecByteBlock preMasterSecret(dh.AgreedValueLength());
    preMasterSecret = sharedSecret;

    // Derive master secret using TLS 1.2 PRF

    CryptoPP::SecByteBlock masterSecret(48);
    unsigned char label[] = "master secret";
    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    hmac.SetKey(preMasterSecret, preMasterSecret.size());
    unsigned char seed[64];

    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);

    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(masterSecret, 48, label, sizeof(label) - 1, seed, sizeof(seed), preMasterSecret.BytePtr(), preMasterSecret.size());

    //////cout<<"Server: The master key is"<<endl;
    // Master key is

    //////cout<<endl;

    // Generate Aes kEY
    SecByteBlock keyMaterial(64); // 32 bytes for AES key and 16 bytes for IV
    unsigned char keyLabel[] = "key expansion";
    unsigned char keySeed[64];

    memcpy(keySeed, server_random, 32);
    memcpy(keySeed + 32, client_random, 32);

    HKDF<CryptoPP::SHA256> keyHkdf;
    keyHkdf.DeriveKey(keyMaterial, 64, keyLabel, sizeof(keyLabel) - 1, keySeed, sizeof(keySeed), masterSecret.BytePtr(), masterSecret.size());

    // Extract AES key and IV from keyMaterial
    SecByteBlock aesKey(keyMaterial.BytePtr(), 32);
    SecByteBlock aesIV(keyMaterial.BytePtr() + 32, 16);

    // new_ssl_cxn->set_shared_key(aesKey.BytePtr(), aesKey.size(),aesIV.BytePtr(), aesIV.size());

    // Waiting for Change Cipher Spec
    //***************************************Receive Change Cipher Spec**************************************************************************

    new_ssl_cxn->recv(&recv_record2);
    enc = (string)recv_record2.data;
    decoded_data = this->decode_struct(&enc);

    if (recv_record2.hdr.type == REC_CHANGE_CIPHER_SPEC)
    {
      //////cout<<"Server: Received REC_CHANGE_CIPHER_SPEC "<<endl;
      new_ssl_cxn->set_shared_key(aesKey.BytePtr(), aesKey.size(), aesIV.BytePtr(), aesIV.size());
    }

    // Wait for Client Finish
    //***************************************Receive Client Finish**************************************************************************
    new_ssl_cxn->recv(&recv_record2);
    enc = (string)recv_record2.data;
    decoded_data = this->decode_struct(&enc);
    //////cout<<"Server: Received Client Finish "<<endl;

    //******************************************Send REC_CHANGE_CIPHER_SPEC*****************************************************
    // Need to send REC_CHANGE_CIPHER_SPEC

    ssldata.cipherSuites = KE_DHE;
    ssldata.data = "Server: REC_CHANGE_CIPHER_SPEC";
    encdata = this->encode_struct(&ssldata);

    decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_CHANGE_CIPHER_SPEC;
    send_record.hdr.version = VER_99;
    body = encdata;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = strlen(data);
    ret_code = new_ssl_cxn->send(send_record);

    // Change Cipher Request sent

    // Send Server Finish
    //******************************************Send Server Finish*****************************************************

    // Need to Send Server Finish

    ssldata.requesttype = this->HS_FINISHED;
    ssldata.cipherSuites = KE_DHE;
    ssldata.data = "Server: HS Finish";
    encdata = this->encode_struct(&ssldata);

    decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    body = encdata;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = strlen(data);
    ret_code = new_ssl_cxn->send(send_record);

    return new_ssl_cxn;
  }
  return NULL;
}

int SslServer::shutdown()
{
  if (this->closed_)
  {
    return -1;
  }

  // pop all clients
  while (!this->clients_.empty())
  {
    SSL *cxn = this->clients_.back();
    this->clients_.pop_back();
    if (cxn != NULL)
    {
      delete cxn;
    }
  }
  return 0;
}

vector<SSL *> SslServer::get_clients() const
{
  return vector<SSL *>(this->clients_);
}

int SslServer::broadcast(const string &msg)
{
  if (this->closed_)
  {
    return -1;
  }

  int num_sent = 0;

  // this->logger_->log("broadcast:");
  // this->logger_->log_raw(msg);

  for (vector<SSL *>::iterator it = this->clients_.begin();
       it != this->clients_.end(); ++it)
  {
    ssize_t send_len;
    send_len = (*it)->send(msg);
    if (send_len == (unsigned int)msg.length())
    {
      num_sent += 1;
    }
  }

  return num_sent;
}
