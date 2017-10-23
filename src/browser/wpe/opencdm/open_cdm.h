/*
 * Copyright 2016-2017 TATA ELXSI
 * Copyright 2016-2017 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OCDM_WRAPPER_H_
#define OCDM_WRAPPER_H_

#include <condition_variable>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <open_cdm_common.h>
#include <open_cdm_mediaengine.h>
#include <open_cdm_platform.h>
#include <open_cdm_platform_com_callback_receiver.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace media {

class OpenCdm : public media::OpenCdmPlatformComCallbackReceiver {
private:
  enum InternalSessionState {
    // Initialized.
    KEY_SESSION_INIT = 0,
    // Session created, waiting for message callback.
    KEY_SESSION_WAITING_FOR_MESSAGE = 1,
    KEY_SESSION_MESSAGE_RECEIVED = 2,
    KEY_SESSION_WAITING_FOR_LICENSE = 3,
    KEY_SESSION_UPDATE_LICENSE = 4,
    KEY_SESSION_READY = 5,
    KEY_SESSION_ERROR = 6,
    KEY_SESSION_LOADED = 7,
    KEY_SESSION_WAITING_FOR_LICENSE_REMOVAL = 8,
    KEY_SESSION_WAITING_FOR_LOAD_SESSION = 9,
    KEY_SESSION_REMOVED = 10,
    KEY_SESSION_CLOSED = 11,
    KEY_SESSION_EXPIRED = 12
  };

public:
  OpenCdm();
  ~OpenCdm() override;

  typedef enum {
      Temporary = 0,
      PersistentUsageRecord,
      PersistentLicense
  } LicenseType;

  bool CreateSession(const std::string& ,unsigned char* , int, std::string&, LicenseType);
  void GetKeyMessage(std::string&, int*, unsigned char*, int*);
  int SetServerCertificate(const uint8_t*, uint32_t);
  int Load(std::string&);
  int Update(unsigned char*, int, std::string&);
  int Remove(std::string&);
  int Close();
  void SelectKeySystem(const std::string& );
  void SelectSession(const std::string& );
  bool IsTypeSupported(const  std::string& keySystem,const  std::string& mimeType);
  int Decrypt(unsigned char*, uint32_t, unsigned char*, uint32_t);
  int ReleaseMem();

  static const char* sessionStateToString(InternalSessionState state) {
      switch (state) {
      case KEY_SESSION_INIT: return "KEY_SESSION_INIT";
      case KEY_SESSION_WAITING_FOR_MESSAGE: return "KEY_SESSION_WAITING_FOR_MESSAGE";
      case KEY_SESSION_MESSAGE_RECEIVED: return "KEY_SESSION_MESSAGE_RECEIVED";
      case KEY_SESSION_WAITING_FOR_LICENSE: return "KEY_SESSION_WAITING_FOR_LICENSE";
      case KEY_SESSION_UPDATE_LICENSE: return "KEY_SESSION_UPDATE_LICENSE";
      case KEY_SESSION_READY: return "KEY_SESSION_READY";
      case KEY_SESSION_ERROR: return "KEY_SESSION_ERROR";
      case KEY_SESSION_LOADED: return "KEY_SESSION_LOADED";
      case KEY_SESSION_REMOVED: return "KEY_SESSION_REMOVED";
      case KEY_SESSION_CLOSED: return "KEY_SESSION_CLOSED";
      default: return "UNKNOWN";
      }
  }

private:
  OpenCdmMediaengine* media_engine_;
  OpenCdmPlatform* platform_;
  OpenCdmPlatformSessionId m_session_id;

  std::string m_key_system;
  std::mutex  m_mtx;
  std::string m_message;
  std::string m_dest_url;

  std::condition_variable  m_cond_var;
  // REVIEW: This volatile seems weird, if we're not protecting this state with
  // our mutex, then we need to fix that bug. Volatile is about make sure r/w's
  // are visible on a **single thread**, they have nothing to do with multiple
  // threads.
  volatile InternalSessionState m_eState;

  void ReadyCallback(OpenCdmPlatformSessionId platform_session_id) override;
  void ErrorCallback(OpenCdmPlatformSessionId platform_session_id,
                     uint32_t sys_err, std::string err_msg) override;
  void MessageCallback(OpenCdmPlatformSessionId platform_session_id, std::string& message,
                       std::string destination_url) override;
  void OnKeyStatusUpdateCallback(OpenCdmPlatformSessionId platform_session_id,
                                 std::string message) override;

};
} // namespace media
#endif
