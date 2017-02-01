#ifndef OCDMCLIENT_H_
#define OCDMCLIENT_H_

#include <string.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <map>
#include <string>
#include <vector>
#include <stdlib.h>
#include <common/cdm_logging.h>

class ocdmClient {
public :
    ocdmClient(){};
    ~ocdmClient(){}
    int clientCreateSession(void  **, unsigned char *, int);
    int clientSelectSession(std::string);
    int streamGetLicenseChallenge(void *, std::string, int *, unsigned char *, int *);
    int streamUpdate(void *, unsigned char *, int);
    int streamDecrypt(void *, unsigned char *, uint32_t, unsigned char *, uint32_t);
    int streamCloseStream(void *);
};

#endif
