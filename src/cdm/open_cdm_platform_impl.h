/*
 * Copyright 2014 Fraunhofer FOKUS
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

#ifndef MEDIA_CDM_PPAPI_EXTERNAL_OPEN_CDM_CDM_OPEN_CDM_PLATFORM_IMPL_H_
#define MEDIA_CDM_PPAPI_EXTERNAL_OPEN_CDM_CDM_OPEN_CDM_PLATFORM_IMPL_H_

#include <string>
#include "open_cdm_platform_common.h"
#include "open_cdm_platform_com_callback_receiver.h"
#include "open_cdm_platform.h"
#include "open_cdm_platform_com.h"

namespace media {

class OpenCdmPlatformImpl : public OpenCdmPlatform,
    public OpenCdmPlatformComCallbackReceiver {
 public:
  // NEW EME based interface
  // on errors tear down media keys and media key session objects

  // EME equivalent: new MediaKeys()
  MediaKeysResponse MediaKeys(std::string key_system) override;

  // EME equivalent: media_keys_.createSession()
  MediaKeysCreateSessionResponse MediaKeysCreateSession(
      int license_type, const std::string& init_data_type,
      const uint8_t* init_data, int init_data_length) override;

  // EME equivalent: media_keys_.loadSession()
  MediaKeySessionLoadResponse MediaKeySessionLoad(
      char *session_id_val, uint32_t session_id_len) override;

  // EME equivalent: media_key_session_.update()
  MediaKeySessionUpdateResponse MediaKeySessionUpdate(
      const uint8_t *pbKey, uint32_t cbKey, char *session_id_val,
      uint32_t session_id_len) override;

  // EME equivalent: media_key_.set_server_certificate()
  MediaKeySetServerCertificateResponse MediaKeySetServerCertificate(
      const uint8_t *pbServerCert, uint32_t cbServerCert) override;

  // EME equivalent: media_key_session_.remove()
  MediaKeySessionRemoveResponse MediaKeySessionRemove(
      char *session_id_val, uint32_t session_id_len) override;

  // EME equivalent: media_key_session_.close()
  MediaKeySessionCloseResponse MediaKeySessionClose(
      char *session_id_val, uint32_t session_id_len) override;

  MediaKeySessionReleaseResponse MediaKeySessionRelease(
      char *session_id_val, uint32_t session_id_len) override;
    
  //EME equivalent : media_key_.isTypeSupported()
  MediaKeyTypeResponse IsTypeSupported(const std::string&,
                                            const std::string&) override;

  // OpenCdmComCallbackReceiver inheritance
  void ErrorCallback(OpenCdmPlatformSessionId platform_session_id,
                             uint32_t sys_err, std::string err_msg) override;
  void MessageCallback(OpenCdmPlatformSessionId platform_session_id,
                               std::string&  message,
                               std::string destination_url) override;
  void OnKeyStatusUpdateCallback(OpenCdmPlatformSessionId platform_session_id,
                               std::string message) override;
  void ReadyCallback(OpenCdmPlatformSessionId platform_session_id) override;

  ~OpenCdmPlatformImpl() override {
  }
  OpenCdmPlatformImpl(
      OpenCdmPlatformComCallbackReceiver *callback_receiver);

 private:
  OpenCdmPlatformComCallbackReceiver *callback_receiver_;
  OpenCdmPlatformCom *com_handler_;
};
}  // namespace media

#endif  // MEDIA_CDM_PPAPI_EXTERNAL_OPEN_CDM_CDM_OPEN_CDM_PLATFORM_IMPL_H_
