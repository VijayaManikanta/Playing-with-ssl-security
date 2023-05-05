
#include <dll.h>
#include "ssl_client.h"
#include "stdlib.h"
#include "string.h"
#include <iostream>
#include "dh.h"
#include "integer.h"
#include "osrng.h"

#include "tcp.h"
#include "crypto_adaptor.h"
#include "logger.h"
#include "utils.h"
#include <base64.h>
#include <hex.h>
#include <vector>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <integer.h>

#include <hex.h>
#include <filters.h>
#include <asn.h>
#include <string>
#include <vector>
#include <cryptlib.h>
#include <integer.h>
#include <dh.h>
#include <osrng.h>
#include <hex.h>
#include <secblock.h>

#include <rsa.h>
#include <base64.h>
#include <files.h>
#include <modes.h>
#include <aes.h>
#include <dh.h>
#include <iomanip>
#include <hkdf.h>
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

SslClient::SslClient()
{
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0)
  {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_client_" + datetime + ".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Client Log at " + datetime);

  // init rsa
  generate_rsa_keys(this->private_key_, this->public_key_);
  ////cout<<"The RSA Keys are....................."<<endl;
}

SslClient::~SslClient()
{
  if (this->logger_)
  {
    delete this->logger_;
    this->logger_ = NULL;
    this->tcp_->set_logger(NULL);
  }
}

int SslClient::connect(const std::string &ip, int port, uint16_t cxntype)
{

  // connect
  if (this->tcp_->socket_connect(ip, port) != 0)
  {
    cerr << "Couldn't connect" << endl;
    return -1;
  }

  // IMPLEMENT HANDSHAKE HERE
  if (cxntype == SSL::KE_RSA)
  {

    //************************CLIENT HELLO****************************************************//
    // Creating Record for Hello Request to Server
    // Generating Client Random

    CryptoPP::AutoSeededRandomPool rng;
    // Generate a random 32-byte block
    CryptoPP::SecByteBlock client_random(32);
    rng.GenerateBlock(client_random, client_random.size());

    // This is not a secured approach. More details in report
    /*  // Insert the current timestamp into the first 4 bytes
      std::time_t now = std::time(nullptr);
      uint32_t timestamp = static_cast<uint32_t>(now);
      std::memcpy(randomBlock.data(), &timestamp, sizeof(timestamp));
      */

    // Serialize the random block into a byte array

    std::string clientRandomStr;
    CryptoPP::StringSource dss(client_random, client_random.size(), true,
                               new CryptoPP::HexEncoder(
                                   new CryptoPP::StringSink(clientRandomStr),
                                   false));

    SSLRecord ssldata;
    ssldata.requesttype = this->HS_CLIENT_HELLO;
    ssldata.cipherSuites = this->KE_RSA;
    ssldata.data = "Hello request from client";
    ssldata.randomSeq = clientRandomStr;
    string encdata = this->encode_struct(&ssldata);
    Record send_record;
    SSLRecord decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    string body = encdata;
    char *data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = body.length();
    int ret_code = this->send(send_record);

    // Client Hello Sent Successfully. Waiting for Server Hello
    //**************************Waiting for Server Hello *************************************************************//

    Record recv_record;
    this->recv(&recv_record);
    string enc = (string)recv_record.data;
    decoded_data = this->decode_struct(&enc);
    if (decoded_data.requesttype == (int)HS_SERVER_HELLO)
    {

      // Received Server Hello Now fetch server random

      CryptoPP::StringSource tsss(decoded_data.randomSeq, true, new CryptoPP::HexDecoder);
      CryptoPP::SecByteBlock server_random(32);
      tsss.Get(server_random, server_random.size());

      /*std::cout << "Client Received Server Ramdom: ";

         for (size_t i = 0; i < server_random.size(); i++) {
          std::cout << std::hex << static_cast<int>(server_random[i]) << " ";
      }

      std::cout << std::endl;
   */

      //*************************Waiting for Server Certificate/Public Key**********************************************//
      // Need to wait for Server Cert/Public Key
      recv_record;
      this->recv(&recv_record);
      enc = (string)recv_record.data;
      decoded_data = this->decode_struct(&enc);
      std::string decoded_key;
      CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(decoded_key));
      decoder.Put((unsigned char *)decoded_data.cipherkey.data(), decoded_data.cipherkey.size());
      decoder.MessageEnd();
      CryptoPP::RSA::PublicKey loaded_public_key;
      loaded_public_key.Load(CryptoPP::StringSource(decoded_key, true).Ref());
      this->set_rsa_publickey(loaded_public_key);

      //**************************Waiting for Server Hello Done*****************************************************
      // Need to receive Server Hello Done
      recv_record;
      this->recv(&recv_record);
      enc = (string)recv_record.data;
      decoded_data = this->decode_struct(&enc);

      //************************Initiate Key Exchange Process**********************************************************
      // Need to sent Request for HS_CLIENT_KEY_EXCHANGE
      // Here we will share encrypted pre master key.

      //*************************************Compute Pre master Key*******************************************************//
      // Compute pre master key, master key and AES Key
      CryptoPP::AutoSeededRandomPool prng;
      CryptoPP::SecByteBlock preMasterSecret(48);

      // Write the TLS version (0x0303 for TLS 1.2) to the first two bytes
      preMasterSecret[0] = 0x03;
      preMasterSecret[1] = 0x03;

      // Fill the remaining 46 bytes with random data
      prng.GenerateBlock(preMasterSecret + 2, 46);

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

      std::string preMasterSecretBase64;
      CryptoPP::StringSource aess(preMasterSecret, preMasterSecret.size(), true,
                                  new CryptoPP::Base64Encoder(
                                      new CryptoPP::StringSink(preMasterSecretBase64),
                                      false)); // set padding to false

      // Try RSA SEND
      this->rsasend(preMasterSecretBase64);

      //******************************************Send REC_CHANGE_CIPHER_SPEC*****************************************************
      // Need to send REC_CHANGE_CIPHER_SPEC

      SSLRecord ssldata;
      ssldata.cipherSuites = KE_RSA;
      ssldata.data = "Client: REC_CHANGE_CIPHER_SPEC";
      string encdata = this->encode_struct(&ssldata);

      Record send_record;
      SSLRecord decoded_data = this->decode_struct(&encdata);
      send_record.hdr.type = REC_CHANGE_CIPHER_SPEC;
      send_record.hdr.version = VER_99;
      body = encdata;
      data = (char *)malloc(body.length() * sizeof(char));
      memcpy(data, body.c_str(), body.length());
      send_record.data = data;
      send_record.hdr.length = strlen(data);
      int ret_code = this->send(send_record);

      //******************************************Send Client Finish*****************************************************

      // Need to Send Client Finish

      ssldata.requesttype = this->HS_FINISHED;
      ssldata.cipherSuites = KE_RSA;
      ssldata.data = "Client: HS Finish";
      encdata = this->encode_struct(&ssldata);

      decoded_data = this->decode_struct(&encdata);
      send_record.hdr.type = REC_HANDSHAKE;
      send_record.hdr.version = VER_99;
      body = encdata;
      data = (char *)malloc(body.length() * sizeof(char));
      memcpy(data, body.c_str(), body.length());
      send_record.data = data;
      send_record.hdr.length = strlen(data);
      ret_code = this->send(send_record);

      // sent Client Finish. Now wait for Server Response

      //***************************************Receive Change Cipher Spec**************************************************************************
      // Wait for Server Change Cipher Request
      this->recv(&recv_record);
      if (recv_record.hdr.type == REC_CHANGE_CIPHER_SPEC)
      {
        // cout<<"Client: Received REC_CHANGE_CIPHER_SPEC "<<endl;
        this->set_shared_key(aesKey.BytePtr(), aesKey.size(), aesIV.BytePtr(), aesIV.size());
      }

      //***************************************Receive Server Finishc**************************************************************************
      // Wait for Server Change Cipher Request
      this->recv(&recv_record);
      // cout<<"Client: Received Server Finish "<<endl;
      return 0;
    }
  }

  if (cxntype == SSL::KE_DHE)
  {

    //************************CLIENT HELLO****************************************************//
    // Creating Record for Hello Request to Server
    // Generating Client Random

    CryptoPP::AutoSeededRandomPool rng;
    // Generate a random 32-byte block
    CryptoPP::SecByteBlock client_random(32);
    rng.GenerateBlock(client_random, client_random.size());

    // This is not a secured approach. More details in report
    /*  // Insert the current timestamp into the first 4 bytes
      std::time_t now = std::time(nullptr);
      uint32_t timestamp = static_cast<uint32_t>(now);
      std::memcpy(randomBlock.data(), &timestamp, sizeof(timestamp));
      */

    // Serialize the random block into a byte array

    std::string clientRandomStr;
    CryptoPP::StringSource dss(client_random, client_random.size(), true,
                               new CryptoPP::HexEncoder(
                                   new CryptoPP::StringSink(clientRandomStr),
                                   false));

    SSLRecord ssldata;
    ssldata.requesttype = this->HS_CLIENT_HELLO;
    ssldata.cipherSuites = this->KE_DHE;
    ssldata.data = "Hello request from client";
    ssldata.randomSeq = clientRandomStr;
    string encdata = this->encode_struct(&ssldata);
    Record send_record;
    SSLRecord decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    string body = encdata;
    char *data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = body.length();
    int ret_code = this->send(send_record);

    // Client Hello Sent Successfully. Waiting for Server Hello
    //**************************Waiting for Server Hello *************************************************************//

    // Waiting for Server Hello
    Record recv_record;
    this->recv(&recv_record);
    string enc = (string)recv_record.data;
    decoded_data = this->decode_struct(&enc);

    // Received Server Hello Now fetch server random

    CryptoPP::StringSource tran(decoded_data.randomSeq, true, new CryptoPP::HexDecoder);
    CryptoPP::SecByteBlock server_random(32);
    tran.Get(server_random, server_random.size());

    //************************************Server Key Exchange Request******************************************

    // Waiting for Server key exchange
    this->recv(&recv_record);
    enc = (string)recv_record.data;
    decoded_data = this->decode_struct(&enc);
    // cout<<"Client: Received Server Key Exchange"<<decoded_data.cipherkey<<endl;

    char delimiter = ':';

    std::vector<std::string> tokens;
    std::istringstream iss(decoded_data.cipherkey);
    std::string token;

    while (std::getline(iss, token, delimiter))
    {
      tokens.push_back(token);
    }

    // cout<<"Client: Token Print Completed"<<endl;
    CryptoPP::StringSource qseq(tokens[0], true, new CryptoPP::HexDecoder);
    CryptoPP::SecByteBlock secByteBlockP(64);
    qseq.Get(secByteBlockP, secByteBlockP.size());

    for (size_t i = 0; i < secByteBlockP.size(); i++)
    {
      // std::cout << std::hex << static_cast<int>(secByteBlockP[i]) << " ";
    }

    CryptoPP::Integer p;
    p.Decode(secByteBlockP.BytePtr(), secByteBlockP.SizeInBytes());
    // cout << "p: " << p << endl;

    //*************************************G*****************************************

    // cout<<"The token for g is"<<tokens[1]<<endl;
    CryptoPP::StringSource gseq(tokens[1], true, new CryptoPP::HexDecoder);
    CryptoPP::SecByteBlock secByteBlockQ(1);
    gseq.Get(secByteBlockQ, secByteBlockQ.size());
    // std::cout << "Client Received G: ";
    CryptoPP::Integer g;
    g.Decode(secByteBlockQ.BytePtr(), secByteBlockQ.SizeInBytes());

    //******************************y**************************************

    CryptoPP::StringSource yseq(tokens[2], true, new CryptoPP::HexDecoder);
    CryptoPP::SecByteBlock secByteBlockY(64);
    yseq.Get(secByteBlockY, secByteBlockY.size());
    CryptoPP::Integer y;
    y.Decode(secByteBlockY.BytePtr(), secByteBlockY.SizeInBytes());

    // Starting Pre master process

    CryptoPP::DH dh;
    CryptoPP::AutoSeededRandomPool rnd;
    dh.AccessGroupParameters().Initialize(p, g);
    CryptoPP::SecByteBlock clientPrivate(dh.PrivateKeyLength());
    CryptoPP::SecByteBlock clientPublic(dh.PublicKeyLength());
    dh.GenerateKeyPair(rnd, clientPrivate, clientPublic);

    CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
    dh.Agree(sharedSecret, clientPrivate, secByteBlockY);

    //************************************Receive: Server Hello Done******************************************

    // Waiting for Server key exchange
    this->recv(&recv_record);
    enc = (string)recv_record.data;
    decoded_data = this->decode_struct(&enc);
    // cout<<"Client: Received Server Hello Done"<<decoded_data.cipherkey<<endl;

    //************************************Receive: Server Hello Done******************************************

    //*************************Client  Key Exchange Request**************************************************//

    // cout<<"Client: Public being sent: ";

    std::string clientPublicStr;
    CryptoPP::StringSource dhss(clientPublic, clientPublic.size(), true,
                                new CryptoPP::HexEncoder(
                                    new CryptoPP::StringSink(clientPublicStr),
                                    false));

    ssldata.requesttype = this->HS_CLIENT_KEY_EXCHANGE;
    ssldata.cipherSuites = this->KE_DHE;
    ssldata.cipherkey = clientPublicStr;
    ssldata.data = "Key INFO Request from client";
    encdata = this->encode_struct(&ssldata);
    decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    body = encdata;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = body.length();
    ret_code = this->send(send_record);

    //*************************Client  Key Exchange Request**************************************************//

    // Compute the shared secret key

    dh.Agree(sharedSecret, clientPrivate, secByteBlockY);
    const unsigned char *sharedSecretPtr = sharedSecret.BytePtr();
    size_t sharedSecretLen = sharedSecret.SizeInBytes();

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

    this->set_shared_key(aesKey.BytePtr(), aesKey.size(), aesIV.BytePtr(), aesIV.size());

    //******************************************Send REC_CHANGE_CIPHER_SPEC*****************************************************
    // Need to send REC_CHANGE_CIPHER_SPEC

    ssldata.cipherSuites = KE_DHE;
    ssldata.data = "Client: REC_CHANGE_CIPHER_SPEC";
    encdata = this->encode_struct(&ssldata);

    decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_CHANGE_CIPHER_SPEC;
    send_record.hdr.version = VER_99;
    body = encdata;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = strlen(data);
    ret_code = this->send(send_record);

    //******************************************Send Client Finish*****************************************************

    // Need to Send Client Finish

    ssldata.requesttype = this->HS_FINISHED;
    ssldata.cipherSuites = KE_DHE;
    ssldata.data = "Client: HS Finish";
    encdata = this->encode_struct(&ssldata);

    decoded_data = this->decode_struct(&encdata);
    send_record.hdr.type = REC_HANDSHAKE;
    send_record.hdr.version = VER_99;
    body = encdata;
    data = (char *)malloc(body.length() * sizeof(char));
    memcpy(data, body.c_str(), body.length());
    send_record.data = data;
    send_record.hdr.length = strlen(data);
    ret_code = this->send(send_record);

    // sent Client Finish. Now wait for Server Response

    //***************************************Receive Change Cipher Spec**************************************************************************
    // Wait for Server Change Cipher Request
    this->recv(&recv_record);
    if (recv_record.hdr.type == REC_CHANGE_CIPHER_SPEC)
    {
      // cout<<"Client: Received REC_CHANGE_CIPHER_SPEC "<<endl;
      this->set_shared_key(aesKey.BytePtr(), aesKey.size(), aesIV.BytePtr(), aesIV.size());
    }

    //***************************************Receive Server Finishc**************************************************************************
    // Wait for Server Change Cipher Request
    this->recv(&recv_record);
    // cout<<"Client: Received Server Finish "<<endl;

    return 0;
  }

  return -1;
}

int SslClient::close()
{
  int ret_code;
  ret_code = this->tcp_->socket_close();
  return ret_code;
}
