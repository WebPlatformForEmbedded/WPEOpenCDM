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

#include "open_cdm_platform_impl.h"
#include <open_cdm_platform_com_handler_factory.h>
#include <cdm_logging.h>

namespace media {

OpenCdmPlatformImpl::OpenCdmPlatformImpl(
    OpenCdmPlatformComCallbackReceiver *callback_receiver)
    : callback_receiver_(callback_receiver) {
  com_handler_ = OpenCdmPlatformComHandlerFactory::Create(this);
}

MediaKeysResponse OpenCdmPlatformImpl::MediaKeys(std::string key_system) {
  MediaKeysResponse response = com_handler_->MediaKeys(key_system);

  return response;
}

MediaKeysCreateSessionResponse OpenCdmPlatformImpl::MediaKeysCreateSession(
    int license_type, const std::string& init_data_type,
    const uint8_t* init_data, int init_data_length) {
  MediaKeysCreateSessionResponse response;

  response = com_handler_->MediaKeysCreateSession(license_type, init_data_type, init_data,
                                                  init_data_length);

  return response;
}

MediaKeySessionLoadResponse OpenCdmPlatformImpl::MediaKeySessionLoad(
    char *session_id_val, uint32_t session_id_len) {
  MediaKeySessionLoadResponse response;

  response = com_handler_->MediaKeySessionLoad(session_id_val, session_id_len);

  return response;
}

MediaKeySessionUpdateResponse OpenCdmPlatformImpl::MediaKeySessionUpdate(
    const uint8_t *pbKey, uint32_t cbKey, char *session_id_val,
    uint32_t session_id_len) {
  MediaKeySessionUpdateResponse response;

  response = com_handler_->MediaKeySessionUpdate(pbKey, cbKey, session_id_val,
                                                 session_id_len);

  return response;
}

MediaKeySetServerCertificateResponse OpenCdmPlatformImpl::MediaKeySetServerCertificate(
    const uint8_t *pbServerCert, uint32_t cbServerCert) {
  MediaKeySetServerCertificateResponse response;

  response = com_handler_->MediaKeySetServerCertificate(pbServerCert, cbServerCert);

  return response;
}

MediaKeySessionRemoveResponse OpenCdmPlatformImpl::MediaKeySessionRemove(
    char *session_id_val, uint32_t session_id_len) {
  MediaKeySessionRemoveResponse response;

  response = com_handler_->MediaKeySessionRemove(session_id_val,
                                                  session_id_len);

  return response;
}

MediaKeySessionCloseResponse OpenCdmPlatformImpl::MediaKeySessionClose(
    char *session_id_val, uint32_t session_id_len) {
  MediaKeySessionCloseResponse response;

  response = com_handler_->MediaKeySessionClose(session_id_val,
                                                session_id_len);

  return response;
}

MediaKeySessionReleaseResponse OpenCdmPlatformImpl::MediaKeySessionRelease(
    char *session_id_val, uint32_t session_id_len) {
  MediaKeySessionReleaseResponse response;

  response = com_handler_->MediaKeySessionRelease(session_id_val,
                                                  session_id_len);

  return response;
}

MediaKeyTypeResponse OpenCdmPlatformImpl::IsTypeSupported(
    const std::string& keysystem,const std::string& mimeType) {
    MediaKeyTypeResponse response = com_handler_->IsTypeSupported(keysystem,mimeType);
    return response;
}

void OpenCdmPlatformImpl::ErrorCallback(
    OpenCdmPlatformSessionId platform_session_id, uint32_t sys_err,
    std::string err_msg) {
  callback_receiver_->ErrorCallback(platform_session_id, sys_err, err_msg);
}

void OpenCdmPlatformImpl::MessageCallback(
    OpenCdmPlatformSessionId platform_session_id, std::string& message,
    std::string destination_url) {
  callback_receiver_->MessageCallback(platform_session_id, message,
                                      destination_url);
}

void OpenCdmPlatformImpl::OnKeyStatusUpdateCallback(
    OpenCdmPlatformSessionId platform_session_id, std::string message
    ) {
  callback_receiver_->OnKeyStatusUpdateCallback(platform_session_id, message);
}
void OpenCdmPlatformImpl::ReadyCallback(
    OpenCdmPlatformSessionId platform_session_id) {
  callback_receiver_->ReadyCallback(platform_session_id);
}

}  // namespace media
