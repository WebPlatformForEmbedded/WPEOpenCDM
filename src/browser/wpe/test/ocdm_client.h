#pragma once
#define OCDMCLIENT_H_

#include <common/cdm_logging.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>

class ocdmClient {
public :
  ocdmClient(){};
  ~ocdmClient(){}
  int clientCreateSession(void**, unsigned char*, int);
  int clientSelectSession(std::string);
  int streamGetLicenseChallenge(void*, std::string, int*, unsigned char*, int*);
  int streamUpdate(void*, unsigned char*, int);
  int streamDecrypt(void*, unsigned char*, uint32_t, unsigned char*, uint32_t);
  int streamCloseStream(void*);
};
