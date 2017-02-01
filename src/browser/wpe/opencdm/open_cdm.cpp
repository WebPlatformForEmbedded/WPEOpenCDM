#include <open_cdm_mediaengine_factory.h>
#include <open_cdm_platform_factory.h>
#include <open_cdm_common.h>
#include <cdm_logging.h>

#include "open_cdm.h"
#include <cstdlib>
using namespace std;
using namespace media;

OpenCdm::OpenCdm()
    : media_engine_(NULL),
      platform_(NULL)
{
    CDM_DLOG() << "OpenDecryptor construct: key_system";
    platform_ = OpenCdmPlatformInterfaceFactory::Create(this);
    m_eState = KEY_SESSION_INIT;
}

OpenCdm::~OpenCdm() {
    CDM_DLOG() << "OpenCDM destruct";
    // clean up resources
    if (media_engine_) {
        delete(media_engine_);
    }

    if (platform_) {
        platform_->MediaKeySessionRelease(m_session_id.session_id,
                                          m_session_id.session_id_len);
        delete(platform_);
    }
}

void OpenCdm::SelectKeySystem(const std::string& key_system)
{
    CDM_DLOG() << "OpenCdm: SelectKeySystem$" << "\n";
    m_key_system = key_system;
    platform_->MediaKeys(key_system);
    m_eState = KEY_SESSION_INIT;
}

void OpenCdm::SelectSession(const std::string& session_id_rcvd)
{
    CDM_DLOG() << " Enter : SelectSession";
    m_session_id.session_id = strdup(session_id_rcvd.c_str());
    m_session_id.session_id_len = (uint32_t)session_id_rcvd.size();
}

int OpenCdm::CreateSession(const std::string& mimeType, unsigned char *pbInitData, int cbInitData, std::string& session_id)
{
    int ret = 1;
    m_eState = KEY_SESSION_INIT;
    CDM_DLOG() << " Enter : CreateSession";

    MediaKeysCreateSessionResponse response = platform_->MediaKeysCreateSession(mimeType, pbInitData, cbInitData);
    CDM_DLOG() << "Contin : CreateSession ";
    if (response.platform_response == PLATFORM_CALL_SUCCESS) {
        CDM_DLOG() << "New Session created";
        m_session_id = response.session_id;
        if (KEY_SESSION_INIT == m_eState)
            m_eState = KEY_SESSION_WAITING_FOR_MESSAGE;
        ret = 0;
    } else {
        CDM_DLOG() << "FAIL to create session!";
        m_eState = KEY_SESSION_ERROR;
    }

    session_id.assign(m_session_id.session_id, m_session_id.session_id_len);//initializing out parameter.

    return ret;
}

//caller provided buffer, MAX_LENGTH...
int OpenCdm::GetKeyMessage(std::string& challenge, int *challengeLength,
                           unsigned char *licenseURL, int *urlLength){

    std::unique_lock<std::mutex> lck(m_mtx);
       CDM_DLOG() << "GetKeyMessage >> invoked from opdm :: estate = " << m_eState << "\n";

    while (m_eState == KEY_SESSION_WAITING_FOR_MESSAGE) {
        CDM_DLOG() << "Waiting for key message!";
        m_cond_var.wait(lck);
    }

    CDM_DLOG() << "Key message should be ready or no need key challenge/message."<< "\n" ;

    if(m_eState == KEY_SESSION_MESSAGE_RECEIVED) {
        int i = 0;
        char temp[m_message.length()];

        m_message.copy(temp,m_message.length(),0);
        challenge.assign((const char*)temp, m_message.length());
        strncpy((char *)licenseURL, (const char *)m_dest_url.c_str(), m_dest_url.length());
        *challengeLength = m_message.length();
        *urlLength = m_dest_url.length();
        char msg[m_message.length()];
        m_message.copy( msg, m_message.length() , 0);
        char test[m_message.length()];
        m_eState = KEY_SESSION_WAITING_FOR_LICENSE;
    }

    if(m_eState == KEY_SESSION_READY) {
        *challengeLength = 0;
	    *licenseURL= 0;
    }
    return 0;
}

int OpenCdm::Update(unsigned char *pbResponse, int cbResponse, std::string& responseMsg) {

    std::unique_lock<std::mutex> lck(m_mtx);
    CDM_DLOG() << "Update >> invoked from opdm :: estate = " << m_eState << "\n";

    int ret = 1;

    CDM_DLOG() << "Update session with info from server.";
    platform_->MediaKeySessionUpdate((uint8_t*)pbResponse, cbResponse,
                                      m_session_id.session_id, m_session_id.session_id_len);

    while (m_eState == KEY_SESSION_WAITING_FOR_LICENSE) {
        CDM_DLOG() << "Waiting for license update status!" << "\n";
        m_cond_var.wait(lck);
    }
    if (m_eState == KEY_SESSION_UPDATE_LICENSE) {
        ret = 0;
    }
    responseMsg.assign(m_message.c_str(), m_message.length());
    return ret;
}

int OpenCdm::ReleaseMem(){
  return media_engine_->ReleaseMem();
}

int OpenCdm::Decrypt(unsigned char *encryptedData, uint32_t encryptedDataLength,
	             unsigned char *ivData, uint32_t ivDataLength) {

    int ret = 1;
    uint32_t outSize;
    CDM_DLOG() << "OpenCdm::Decrypt session_id : " << m_session_id.session_id << endl;
    CDM_DLOG() << "OpenCdm::Decrypt session_id_len : " << m_session_id.session_id_len << endl;
    CDM_DLOG() << "OpenCdm::Decrypt encryptedDataLength : " << encryptedDataLength << endl;
    CDM_DLOG() << "OpenCdm::Decrypt ivDataLength : " << ivDataLength << endl;
    // mediaengine instantiation
    if (!media_engine_) {
        // TODO(ska): handle mutiple sessions
        media_engine_ = OpenCdmMediaengineFactory::Create(m_key_system, m_session_id);
        CDM_DLOG() << "::" << endl;
        if(!media_engine_){
            CDM_DLOG() << "::" << endl;
	    return ret;
        }
    }
    CDM_DLOG() << "Returned back to OpenCdm::Decrypt";
    DecryptResponse dr = media_engine_->Decrypt((const uint8_t *)ivData, ivDataLength,
                                                (const uint8_t *)encryptedData, encryptedDataLength,
                                                (uint8_t *)encryptedData, outSize);

    CDM_DLOG() << "media_engine_->Decrypt done " << dr.platform_response;
    return 0;
}

bool OpenCdm::IsTypeSupported(const  std::string& keySystem,const  std::string& mimeType) {

    MediaKeyTypeResponse ret;

    ret = platform_->IsTypeSupported(keySystem, mimeType);
    CDM_DLOG() << "IsTypeSupported ";

    if (ret.platform_response ==  PLATFORM_CALL_SUCCESS )
        return (true);
    else
        return (false);
}

void OpenCdm::ReadyCallback(OpenCdmPlatformSessionId platform_session_id) {

    CDM_DLOG() << "OpenCdm::ReadyCallback";

    std::unique_lock<std::mutex> lck(m_mtx);
    m_eState = KEY_SESSION_READY;
    m_cond_var.notify_all();

    CDM_DLOG() << "OpenCdm::ReadyCallback";
}

void OpenCdm::ErrorCallback(OpenCdmPlatformSessionId platform_session_id,
			    uint32_t sys_err, std::string err_msg) {

    CDM_DLOG() << "OpenCdm::ErrorCallback";
}

void OpenCdm::MessageCallback(OpenCdmPlatformSessionId platform_session_id,
			      std::string& message,
			      std::string destination_url) {

    CDM_DLOG() << "OpenCdm::MessageCallback:";

    std::unique_lock<std::mutex> lck(m_mtx);
    m_message = message;
    m_dest_url = destination_url;
    m_eState = KEY_SESSION_MESSAGE_RECEIVED;
    m_cond_var.notify_all();
}

void OpenCdm::OnKeyStatusUpdateCallback(OpenCdmPlatformSessionId platform_session_id,
			    std::string message) {

    std::string expectedMsg = "KeyUsable";
    if (message == expectedMsg) {
        m_eState = KEY_SESSION_UPDATE_LICENSE;
    } else {
        m_eState = KEY_SESSION_ERROR;
    }
    m_message = message;
    m_cond_var.notify_all();

    CDM_DLOG() << "Got key status update ->  " << message;
}
