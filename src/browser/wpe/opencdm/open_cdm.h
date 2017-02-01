
#ifndef OCDM_WRAPPER_H_
#define OCDM_WRAPPER_H_
#include <string.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>

#include <stdlib.h>
#include <open_cdm_mediaengine.h>
#include <open_cdm_platform.h>
#include <open_cdm_common.h>
#include <open_cdm_platform_com_callback_receiver.h>

using namespace media;

class OpenCdm : public media::OpenCdmPlatformComCallbackReceiver {
private:
    enum InternalSessionState {
        //initialized.
        KEY_SESSION_INIT = 0,
        //Session created, waiting for message callback.
        KEY_SESSION_WAITING_FOR_MESSAGE = 1,
        KEY_SESSION_MESSAGE_RECEIVED = 2,
        KEY_SESSION_WAITING_FOR_LICENSE = 3,
        KEY_SESSION_UPDATE_LICENSE = 4,
        KEY_SESSION_READY = 5,
        KEY_SESSION_ERROR = 6,
        KEY_SESSION_CLOSED = 7
    };

public:
    OpenCdm();
    ~OpenCdm() override;

    int CreateSession(const std::string& ,unsigned char * , int, std::string&);
    int GetKeyMessage(std::string&, int *, unsigned char *, int *);
    int Update(unsigned char *, int, std::string&);
    void SelectKeySystem(const std::string& );
    void SelectSession(const std::string& );
    bool IsTypeSupported(const  std::string& keySystem,const  std::string& mimeType);
    int Decrypt(unsigned char *, uint32_t, unsigned char *, uint32_t);
    int ReleaseMem();

private:
    OpenCdmMediaengine       *media_engine_;
    OpenCdmPlatform          *platform_;
    OpenCdmPlatformSessionId m_session_id;

    std::string m_key_system;
    std::mutex  m_mtx;
    std::string m_message;
    std::string m_dest_url;

    std::condition_variable  m_cond_var;
    volatile InternalSessionState m_eState;

    void ReadyCallback(OpenCdmPlatformSessionId platform_session_id) override;
    void ErrorCallback(OpenCdmPlatformSessionId platform_session_id,
                       uint32_t sys_err, std::string err_msg) override;
    void MessageCallback(OpenCdmPlatformSessionId platform_session_id, std::string& message,
                         std::string destination_url) override;
    void OnKeyStatusUpdateCallback(OpenCdmPlatformSessionId platform_session_id,
                                   std::string message) override;

};
#endif
