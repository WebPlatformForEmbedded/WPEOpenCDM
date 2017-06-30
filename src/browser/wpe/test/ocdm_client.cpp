
#include "ocdm_client.h"

#include <open_cdm.h>

using namespace std;
using namespace media;

static OpenCdm* g_pOpenCdm = NULL;
const std::string open_cdm_key_system = "com.widevine.alpha";

int ocdmClient::clientCreateSession(void** ocdmDrmStream, unsigned char* pbInitData, int cbInitData)
{
  int ret  = 1;
  std::string s_id;
  const std::string mimeType = "video/mp4";
  if (!g_pOpenCdm) {
    g_pOpenCdm = new OpenCdm();
    g_pOpenCdm->SelectKeySystem(open_cdm_key_system);
  }

  if (g_pOpenCdm)
    CDM_DLOG() << "ocdmClientOpenDrmStream() called #1. ";
  else {
    CDM_DLOG() << "FAIL in DrmClient_OpenDrmStream() #1";
    return ret;
  }
  CDM_DLOG() << "IsTypeSupported #1#";
  g_pOpenCdm->IsTypeSupported(open_cdm_key_system,"");
  CDM_DLOG() << "IsTypeSupported #2#";
  g_pOpenCdm->IsTypeSupported("",mimeType);
  ret = g_pOpenCdm->CreateSession(mimeType,pbInitData, cbInitData, s_id, 0);
  CDM_DLOG() << "s_id received from OpenCdm->CreateSession : " << s_id;
  *ocdmDrmStream = (void*) g_pOpenCdm;
  return ret;
}

int ocdmClient::streamGetLicenseChallenge(void* ocdmDrmStream, std::string challenge,
    int* challengeLength, unsigned char* licenseURL, int* urlLength)
{
  int ret = 1;

  if (!g_pOpenCdm) {
	return ret;
  }

  ret = g_pOpenCdm->GetKeyMessage(challenge, challengeLength, licenseURL, urlLength);

  if ((!ret) && (!(*urlLength)) && (!(*challengeLength)))
    cout << "key ready, no need to generate a new license request!" << endl;
  else {
    cout << "license challenge received! length: " << *challengeLength << endl;
    cout << "license challenge url: " << licenseURL << " length: " << *urlLength << endl;
  }

  return ret;
}

int ocdmClient::streamUpdate(void* ocdmDrmStream, unsigned char* pbResponse, int  cbResponse)
{
  int ret = 1;
  std::string responseMsg;
  cout << "ocdmStream_ProcessLicenseResponse() response length:" << cbResponse << endl;
  if (!g_pOpenCdm) {
    cout << "mediakeysession is null" << endl;
    return ret;
  }

  ret = g_pOpenCdm->Update(pbResponse, cbResponse, responseMsg);
  cout << "ProcessLicenseResponse returned: " << std::hex << ret << std::dec << endl;

  return ret;
}

int ocdmClient::streamDecrypt(void* ocdmDrmStream, unsigned char* encryptedData, uint32_t encryptedDataLength,
    unsigned char* ivData, uint32_t ivDataLength)
{
  int ret = 1;

  if (!g_pOpenCdm) {
	return ret;
  }

  return 0;
}

int ocdmClient::streamCloseStream(void* ocdmDrmStream)
{
  int ret = 1;

  cout << "ocdmStream_CloseStream()" << endl;
  if (g_pOpenCdm)
  {
    delete(g_pOpenCdm);
    ret = 0;
  }

  return ret;
}

static void printBytes(std::ostream& out, const char* title, const unsigned char* data, size_t dataLen, bool format = true)
{
  out << title << std::endl;
  out << std::setfill('0');

  for (size_t i = 0; i < dataLen; ++i) {
    out << std::hex << std::setw(2) << (int)data[i];
    if (format) {
      out << (((i + 1) % 16 == 0) ? "\n" : " ");
    }
  }
  out << std::endl;
}

int main()
{
  void* test_drm = NULL;
  unsigned char initial_value[] = {"00000042"
    "70737368"
    "00000000"
    "edef8ba979d64acea3c827dcd51d21ed"
    "00000022"
    "08011a0d7769646576696e655f746573"
    "74220f73747265616d696e675f636c69"
    "7031" };

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
  unsigned char* puc_lic_response = (unsigned char*)lic_response.c_str();
  int cb_lic_response = lic_response.length();

  const char test_challenge[3096] = {0xde, 0xad, 0xf0, 0x01};
  int challenge_len = 0;
  unsigned char test_url[100];
  int url_length = 0;
  ocdmClient* client =  new ocdmClient();
  client->clientCreateSession(&test_drm, initial_value, 4);
  client->streamGetLicenseChallenge(test_drm, test_challenge, &challenge_len, test_url, &url_length);
  if (url_length > 0) {
	cout << "contact server for license with URL: " << test_url << endl;
	// sleep 1 second to similate server interaction
	usleep(500 * 1000);
	client->streamUpdate(test_drm, puc_lic_response, cb_lic_response);
  }

  client->streamDecrypt(test_drm, encryptedData, 16, iv, 16);
  printBytes(cout, "decrypted data dump", encryptedData, 16, true);
  client->streamCloseStream(test_drm);
  return 0;
}
