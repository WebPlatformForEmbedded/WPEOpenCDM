#include "ocdm_client.h"

#include <open_cdm.h>

using namespace std;
using namespace media;

static OpenCdm* g_pOpenCdm = NULL;
const std::string open_cdm_key_system = "com.widevine.alpha";

int ocdmClient::clientSelectSession(std::string session_id)
{
  if (!g_pOpenCdm) {
    g_pOpenCdm = new OpenCdm();
    g_pOpenCdm->SelectSession(session_id);
  }

  return 0;
}

int ocdmClient::streamDecrypt(void* ocdmDrmStream, unsigned char* encryptedData, uint32_t encryptedDataLength,
    unsigned char* ivData, uint32_t ivDataLength)
{
  int ret = 1;

  if (!g_pOpenCdm) {
	return ret;
  }

  g_pOpenCdm->Decrypt(encryptedData, encryptedDataLength, ivData, ivDataLength);
  CDM_DLOG() << "ocdmStream_Decrypt() returned! ";

  return 0;
}

int main(int argc, char* argv[])
{
  void* test_drm = NULL;

  unsigned char iv[16] =  {0}; // 16B - 128b
  unsigned char encryptedData[] = {0x87, 0x77, 0x7f, 0xc3, 0x1b, 0x2d, 0xca, 0x0d,
    0x2d, 0x54, 0x74, 0x60, 0x32, 0x4f, 0x05, 0xfd}; // 16B - 128b

  std::string key_req =  "{ \
			      \"kids\": \
				[,\
				\"LwVHf8JLtPrv2GUXFW2v_A\",\
				],\
			      \"type\":\"temporary\"\
			    }";

  std::string lic_response = "{ \
				  \"keys\":\
				    [{\
				      \"kty\":\"oct\",\
				      \"k\":\"ASNFZ4mrze8BI0VniavN7w==\",\
				      \"kid\":\"LwVHf8JLtPrv2GUXFW2v_A\"\
				    }],\
				  \"type\":\"temporary\"\
				}";

  ocdmClient* client =  new ocdmClient();
  std::cout << "argv : " << argv[1] << std::endl;
  client->clientSelectSession(argv[1]);
  client->streamDecrypt(test_drm, encryptedData, 16, iv, 16);

  return 0;
}
