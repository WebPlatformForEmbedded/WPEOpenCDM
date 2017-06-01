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

#include <pthread.h>
#include <sys/types.h>
#include <wchar.h>
#include <map>
#include "rpc_cdm_platform_handler.h"
#include <cdm_logging.h>
#include <rpc/pmap_clnt.h>

extern "C" {
#include <opencdm_xdr.h>
}

typedef struct {
  int prognum;
  int sock;
} thread_parm_t;
// TODO(ska): rename thread_parm_t


namespace media {

unsigned long gettransient(int proto, int vers, int *sockp) {
  static int prognum = 0x40000000;
  int s, len, socktype;
  struct sockaddr_in addr;
  switch (proto) {
    case IPPROTO_UDP:
      socktype = SOCK_DGRAM;
      break;
    case IPPROTO_TCP:
      socktype = SOCK_STREAM;
      break;
    default:
      CDM_DLOG() << "unknown protocol type";
      return 0;
  }
  if (*sockp == RPC_ANYSOCK) {
    if ((s = socket(AF_INET, socktype, 0)) < 0) {
      perror("socket");
      return (0);
    }
    *sockp = s;
  } else {
    s = *sockp;
  }
  addr.sin_addr.s_addr = 0;
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  len = sizeof(addr);
  // may be already bound, so don't check for error
  bind(s, (const sockaddr*) &addr, len);
  if (getsockname(s, reinterpret_cast<sockaddr*>(&addr),
                  reinterpret_cast<socklen_t*>(&len)) < 0)  {
    perror("getsockname");
    return (0);
  }
  while (!pmap_set(prognum++, vers, proto, ntohs(addr.sin_port)))
    continue;
  return (prognum - 1);
}

static std::map<int, RpcCdmPlatformHandler *> rpc_cdm_platform_con_map;

struct RpcThreadCallParam {
  RpcCdmPlatformHandler *caller;
  thread_parm_t *thread_parm;
};

RpcCdmPlatformHandler::RpcCdmPlatformHandler(
    OpenCdmPlatformComCallbackReceiver *callback_receiver)
: callback_receiver_(callback_receiver) {

  // FIXME: This is used as a flag to indicate the state of our sever initialization:
  //     UNITIALIZED - Server thread failed to launch.
  //     FAULTY      - Failed to get an RPC socket.
  //   It's super easy to change that interface in the code below tho,
  //   and our caller's aren't even taking notice of this in a consistent
  //   way. Probably should look at exceptions at some point. Be careful intreprid traveller.
  com_state = UNINITIALIZED;

  rpc_server_host = "localhost";
  CDM_LOG_LINE("initializing RPC server on %s", rpc_server_host.c_str());

  // prepare starting threaded RPC Server
  // FIXME: Let's use C++ threads and not pthreads.
  pthread_t thread1;
  thread_parm_t *parm = NULL;

  int sock = RPC_ANYSOCK;
  int prognum = gettransient(IPPROTO_TCP, 1, &sock);
  rpc_prog = prognum;
  rpc_client = NULL;

  if (prognum == 0) {
    com_state = FAULTY;
    CDM_LOG_LINE("failed to get an RPC socket");
    return;
  }
  rpc_cdm_platform_con_map[prognum] = this;

  /* set up multiple parameters to pass to the thread */
  // I like lots of different comment styles.
  parm = reinterpret_cast<thread_parm_t*>(malloc(sizeof(thread_parm_t)));
  parm->sock = sock;
  parm->prognum = prognum;
  RpcThreadCallParam *call_params = new RpcThreadCallParam();
  call_params->caller = this;
  call_params->thread_parm = parm;
  if (pthread_create(&thread1, NULL, RpcCdmPlatformHandler::DelegateRpcInit, call_params) != 0) {
      CDM_LOG_LINE("failed to create a thread: %s", strerror(errno));
      return;
  }

  com_state = INITIALIZED;
  // TODO(sph): pthread_exit to terminate thread // Oh dear.
}

void *RpcCdmPlatformHandler::DelegateRpcInit(void *call_params) {
  RpcThreadCallParam *call_param =
      reinterpret_cast<RpcThreadCallParam *>(call_params);
  // delegate call to caller instance
  return call_param->caller->RpcInitPrivate(call_param->thread_parm);
}


void RpcCdmPlatformHandler::OnMessage1SvcDelegate(rpc_cb_message *kmm, struct svc_req *rqstp, RpcCdmPlatformHandler *p_instance)
{
  p_instance->OnMessage1Svc(kmm, rqstp);
}

void RpcCdmPlatformHandler::OnKeyStatusUpdate1SvcDelegate(
    rpc_cb_key_status_update *kmm, struct svc_req *rqstp,
    RpcCdmPlatformHandler *p_instance)
{
  OpenCdmPlatformSessionId session_id;
  std::string message(kmm->message);

  session_id.session_id_len = kmm->session_id.session_id_len;
  session_id.session_id = kmm->session_id.session_id_val;

  p_instance->callback_receiver_->OnKeyStatusUpdateCallback(session_id, message);
}


void RpcCdmPlatformHandler::OnMessage1Svc(rpc_cb_message *kmm, struct svc_req *)
{
  std::string delimiter = "#SPLIT#";
  std::string laURL;
  std::string message;
  OpenCdmPlatformSessionId session_id;

  session_id.session_id_len = kmm->session_id.session_id_len;
  session_id.session_id = kmm->session_id.session_id_val;

  std::string s(kmm->message.message_val,kmm->message.message_len);
  laURL = s.substr(0, s.find(delimiter));

  message = s.substr(s.find(delimiter) + delimiter.size(), s.size());

  //get open_media_keys instance to execute callbacks
  this->callback_receiver_->MessageCallback(session_id, message, laURL);
}

void RpcCdmPlatformHandler::OnReady1SvcDelegate(rpc_cb_ready *keyready_param, struct svc_req *rqstp, RpcCdmPlatformHandler *p_instance)
{
  p_instance->OnReady1Svc(keyready_param, rqstp);
}

void RpcCdmPlatformHandler::OnReady1Svc(rpc_cb_ready *kr, struct svc_req *)
{
  OpenCdmPlatformSessionId session_id;

  session_id.session_id_len = kr->session_id.session_id_len;
  session_id.session_id = kr->session_id.session_id_val;
  this->callback_receiver_->ReadyCallback(session_id);

}

void RpcCdmPlatformHandler::OnError1SvcDelegate(rpc_cb_error *err_param, struct svc_req *rqstp, RpcCdmPlatformHandler *p_instance)
{
  p_instance->OnError1Svc(err_param, rqstp);
}

void RpcCdmPlatformHandler::OnError1Svc(rpc_cb_error * ke, struct svc_req *)
{
  OpenCdmPlatformSessionId session_id;

  session_id.session_id_len = ke->session_id.session_id_len;
  session_id.session_id = ke->session_id.session_id_val;
  int sys_error = 0;
  // TODO (sph): set real error message if there is any
  this->callback_receiver_->ErrorCallback(session_id, sys_error,"KEY_ERROR");
}

void RpcCdmPlatformHandler::RpcCallbackPrivate(struct svc_req *rqstp, register SVCXPRT *transp)
{
  union {
    rpc_cb_message on_message_1_arg;
    rpc_cb_ready on_ready_1_arg;
    rpc_cb_error on_error_1_arg;
  } argument;
  char *result;
  xdrproc_t _xdr_argument, _xdr_result;
  char *(*local)(char *, struct svc_req *, RpcCdmPlatformHandler *);

  switch (rqstp->rq_proc) {
  case NULLPROC:
    CDM_LOG_LINE("received request for NULLPROC function");
    (void) svc_sendreply (transp, (xdrproc_t) xdr_void, (char *)NULL);
    return;

  case ON_KEY_MESSAGE:
    CDM_LOG_LINE("received request for ON_KEY_MESSAGE function");
    _xdr_argument = (xdrproc_t) xdr_rpc_cb_message;
    _xdr_result = (xdrproc_t) xdr_void;
    local = (char *(*)(char *, struct svc_req *, RpcCdmPlatformHandler *)) RpcCdmPlatformHandler::OnMessage1SvcDelegate;
    break;

  case ON_KEY_READY:
    CDM_LOG_LINE("received request for ON_KEY_READY function");
    _xdr_argument = (xdrproc_t) xdr_rpc_cb_ready;
    _xdr_result = (xdrproc_t) xdr_void;
    local = (char *(*)(char *, struct svc_req *, RpcCdmPlatformHandler *)) RpcCdmPlatformHandler::OnReady1SvcDelegate;
    break;

  case ON_KEY_ERROR:
    CDM_LOG_LINE("received request for ON_KEY_ERROR function");
    _xdr_argument = (xdrproc_t) xdr_rpc_cb_error;
    _xdr_result = (xdrproc_t) xdr_void;
    local = (char *(*)(char *, struct svc_req *, RpcCdmPlatformHandler *)) RpcCdmPlatformHandler::OnError1SvcDelegate;
    break;

  case ON_KEY_STATUS_UPDATE:
    CDM_LOG_LINE("received request for ON_KEY_STATUS_UPDATE function");
    _xdr_argument = (xdrproc_t) xdr_rpc_cb_key_status_update;
    _xdr_result = (xdrproc_t) xdr_void;
    local = (char *(*)(char *, struct svc_req *, RpcCdmPlatformHandler *))
          RpcCdmPlatformHandler::OnKeyStatusUpdate1SvcDelegate;
    break;

  default:
    CDM_LOG_LINE("received request for known function");
    svcerr_noproc (transp);
    return;
  }
  memset ((char *)&argument, 0, sizeof (argument));
  if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
    CDM_LOG_LINE("failed to get service arguments");
    svcerr_decode (transp);
    return;
  }
  result = (*local)((char *)&argument, rqstp, this);
  if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
    CDM_LOG_LINE("failed to send result back");
    svcerr_systemerr (transp);
  }
  if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
    CDM_LOG_LINE("failed to free the response arguments");
    // FIXME: Really? We decide to bomb here but in no other cases??
    exit (1);
  }
  return;
}


void *RpcCdmPlatformHandler::RpcInitPrivate(void *thread_parm) {
  // async callback stuff

  SVCXPRT *xprt;
  thread_parm_t *p = reinterpret_cast<thread_parm_t*>(thread_parm);
  int sock = p->sock;
  int prognum = p->prognum;

  if ((xprt = svctcp_create(sock, 0, 0)) == NULL) {
    return NULL;
  }

  // protocol is 0 - gettransient does registering
  (void) svc_register(xprt, prognum, 1,
                      RpcCdmPlatformHandler::DelegateRpcCallback, IPPROTO_TCP);

  rpc_prog = prognum;

  svc_run();
  CDM_DLOG() << "svc_run executed";
  free(p);
  return NULL;
}

void RpcCdmPlatformHandler::DelegateRpcCallback(struct svc_req *rqstp,
                                                register SVCXPRT *transp) {
  if (rpc_cdm_platform_con_map.find(rqstp->rq_prog)
      != rpc_cdm_platform_con_map.end()) {
    RpcCdmPlatformHandler *caller = rpc_cdm_platform_con_map[rqstp->rq_prog];
    caller->RpcCallbackPrivate(rqstp, transp);
  }
}

MediaKeysResponse RpcCdmPlatformHandler::MediaKeys(std::string key_system) {
  CDM_LOG_LINE("requesting media keys for %s", key_system.c_str());
  MediaKeysResponse response;

  // rpc not ready
  if (com_state == FAULTY) {
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_LOG_LINE("connection state faulty");
    return response;
  }

  if ((rpc_client = clnt_create(rpc_server_host.c_str(), OPEN_CDM,
                                OPEN_CDM_EME_5,
                                "tcp")) == NULL) {
    com_state = FAULTY;
    clnt_pcreateerror(rpc_server_host.c_str());
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_LOG_LINE("connection to server failed");
    return response;
  } else {
    CDM_LOG_LINE("connected to the server");
  }
  // Cdm_MediaKeys
  rpc_response_generic *rpc_response;
  rpc_request_mediakeys rpc_param;
  rpc_param.key_system.key_system_val = reinterpret_cast<char *>(
      malloc(key_system.size()));
  memcpy(rpc_param.key_system.key_system_val, key_system.c_str(),
         key_system.size());
  rpc_param.key_system.key_system_len = key_system.size();
  if ((rpc_response = rpc_open_cdm_mediakeys_1(&rpc_param, rpc_client))
      == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
  }

  if (rpc_response->platform_val == 0) {
    CDM_LOG_LINE("successfully received from server");
    response.platform_response = PLATFORM_CALL_SUCCESS;
  } else {
    CDM_LOG_LINE("failed to receive keys from server");
    response.platform_response = PLATFORM_CALL_FAIL;
  }
  free(rpc_param.key_system.key_system_val);
  return response;
}
  //EME equivalent : media_key_.isTypeSupported()
MediaKeyTypeResponse RpcCdmPlatformHandler::IsTypeSupported(const std::string& key_system,
                                            const std::string& mime_type) {
  CDM_LOG_LINE("asking if key system '%s' and MIME type '%s' are supported", key_system.c_str(), mime_type.c_str());
  MediaKeyTypeResponse response;

  // RPC not ready.
  if (com_state == FAULTY) {
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_LOG_LINE("connection state faulty");
    return response;
  }

  if ((rpc_client = clnt_create(rpc_server_host.c_str(), OPEN_CDM,
                                OPEN_CDM_EME_5,
                                "tcp")) == NULL) {
    com_state = FAULTY;
    clnt_pcreateerror(rpc_server_host.c_str());
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_LOG_LINE("connection to server failed");
    return response;
  } else {
    CDM_LOG_LINE("connected to server");
  }

  // Pass Keysystem.
  rpc_response_generic *rpc_response;
  rpc_request_is_type_supported rpc_param;
  rpc_param.key_system.key_system_val = reinterpret_cast<char *>(
      malloc(key_system.size()));
  memcpy(rpc_param.key_system.key_system_val, key_system.c_str(),
         key_system.size());
  rpc_param.key_system.key_system_len = key_system.size();

  // Pass MIME type.
  rpc_param.mime_type.mime_type_val = reinterpret_cast<char *>(
      malloc(mime_type.size()));
  memcpy(rpc_param.mime_type.mime_type_val, mime_type.c_str(),
         mime_type.size());
  rpc_param.mime_type.mime_type_len = mime_type.size();

  // RPC call to the server.
  if ((rpc_response = rpc_open_cdm_is_type_supported_1(&rpc_param, rpc_client))
      == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
  }

  if (rpc_response->platform_val == 0) {
    CDM_LOG_LINE("received good response from server");
    response.platform_response = PLATFORM_CALL_SUCCESS;
  } else {
    CDM_LOG_LINE("received a bad response from server");
    response.platform_response = PLATFORM_CALL_FAIL;
  }

  free(rpc_param.mime_type.mime_type_val);
  free(rpc_param.key_system.key_system_val);

  return response;
}

MediaKeySetServerCertificateResponse RpcCdmPlatformHandler::MediaKeySetServerCertificate(
  const uint8_t *pbServerCert, uint32_t cbServerCert) {
  CDM_DLOG() << "RpcCdmPlatformHandler::MediaKeySetServerCertificate";
  fflush(stdout);
  MediaKeySetServerCertificateResponse response;
  rpc_response_generic *rpc_response;
  rpc_request_certificate rpc_param;
  // rpc not ready
  if (com_state == FAULTY) {
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_DLOG()
    << "RpcCdmPlatformHandler::MediaKeySetServerCertificate connection state faulty";
    return response;
  }
  rpc_param.certificate.certificate_val = reinterpret_cast<uint8_t *>(malloc(cbServerCert));
  memcpy(rpc_param.certificate.certificate_val, pbServerCert, cbServerCert);
  rpc_param.certificate.certificate_len = cbServerCert;
  if ((rpc_response = rpc_open_cdm_mediakeys_set_server_certificate_1(
      &rpc_param, rpc_client)) == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
  }
  if (rpc_response) {
    if (rpc_response->platform_val == 0) {
       CDM_DLOG() << "MediaKeySetServerCertificate success\n ";
       response.platform_response = PLATFORM_CALL_SUCCESS;
    } else {
       CDM_DLOG() << "MediaKeySetServerCertificate failed\n ";
       response.platform_response = PLATFORM_CALL_FAIL;
    }
  }
  free(rpc_param.certificate.certificate_val);
  return response;
}

MediaKeysCreateSessionResponse RpcCdmPlatformHandler::MediaKeysCreateSession(
    const std::string& init_data_type, const uint8_t* init_data,
    int init_data_length) {
  CDM_LOG_LINE("create session for ID type %s", init_data_type.c_str());
  MediaKeysCreateSessionResponse response;

  // rpc not ready
  if (com_state == FAULTY) {
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_LOG_LINE("rpc faulty, bailing");
    return response;
  }
  rpc_response_create_session *rpc_response;
  rpc_request_create_session rpc_param;

  rpc_param.init_data_type.init_data_type_val = reinterpret_cast<char *>(malloc(
      init_data_type.size()));
  memcpy(rpc_param.init_data_type.init_data_type_val, init_data_type.c_str(),
         init_data_type.size());
  rpc_param.init_data_type.init_data_type_len = init_data_type.size();

  rpc_param.init_data.init_data_val = reinterpret_cast<uint8_t *>(
      malloc(init_data_length));
  memcpy(rpc_param.init_data.init_data_val, init_data, init_data_length);
  rpc_param.init_data.init_data_len = init_data_length;

  std::string hostname = "localhost";
  // TODO(ska): specify dynamically, encapsulate RPC
  rpc_param.callback_info.hostname.hostname_val = reinterpret_cast<char *>(
      malloc(hostname.size()));
  memcpy(rpc_param.callback_info.hostname.hostname_val, hostname.c_str(),
         hostname.size());
  rpc_param.callback_info.hostname.hostname_len = hostname.size();
  rpc_param.callback_info.prog_num = rpc_prog;
  rpc_param.callback_info.prog_version = 1;
  // TODO(ska): specify dynamically, encapsulate RPC

  if ((rpc_response = rpc_open_cdm_mediakeys_create_session_1(&rpc_param,
                                                              rpc_client))
      == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
    CDM_LOG_LINE("failed to connect to server");
  }

  // TODO(ska): parse session_id from csresult into
  OpenCdmPlatformSessionId session_id;
  if (rpc_response->platform_val == 0) {
    CDM_LOG_LINE("successfully got a session id of length %d:", rpc_response->session_id.session_id_len);
    CDMDumpMemory(reinterpret_cast<const uint8_t*>(rpc_response->session_id.session_id_val),
                  rpc_response->session_id.session_id_len);

    response.sys_err = rpc_response->platform_val;
    response.platform_response = PLATFORM_CALL_SUCCESS;
    session_id.session_id = rpc_response->session_id.session_id_val;
    session_id.session_id_len = rpc_response->session_id.session_id_len;
    response.session_id = session_id;
  } else {
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_LOG_LINE("failed to create a session id");
  }

  free(rpc_param.callback_info.hostname.hostname_val);
  free(rpc_param.init_data.init_data_val);
  free(rpc_param.init_data_type.init_data_type_val);

  return response;
}

MediaKeySessionLoadResponse RpcCdmPlatformHandler::MediaKeySessionLoad(
    char *session_id_val, uint32_t session_id_len) {
  CDM_DLOG() << "RpcCdmPlatformHandler::MediaKeySessionLoad";
  MediaKeySessionLoadResponse response;

  rpc_response_generic *rpc_response;
  rpc_request_session_load rpc_param;

  // rpc not ready
  if (com_state == FAULTY) {
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_DLOG()
    << "RpcCdmPlatformHandler::MediaKeySessionLoad connection state faulty";
    return response;
  }

  rpc_param.session_id.session_id_val = session_id_val;
  rpc_param.session_id.session_id_len = session_id_len;

  if ((rpc_response = rpc_open_cdm_mediakeysession_load_1(
      &rpc_param, rpc_client)) == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
  }

  if (rpc_response->platform_val == 0) {
    CDM_DLOG() << "MediaKeySessionLoad success\n ";
    response.platform_response = PLATFORM_CALL_SUCCESS;
  } else {
    CDM_DLOG() << "MediaKeySessionLoad failed\n ";
    response.platform_response = PLATFORM_CALL_FAIL;
  }

  return response;
}

MediaKeySessionUpdateResponse RpcCdmPlatformHandler::MediaKeySessionUpdate(
    const uint8_t *pbKey, uint32_t cbKey, char *session_id_val,
    uint32_t session_id_len) {
  MediaKeySessionUpdateResponse response;

  rpc_response_generic *rpc_response;
  rpc_request_session_update rpc_param;

  if (com_state == FAULTY) {
    CDM_LOG_LINE("rpc connection faulty");
    response.platform_response = PLATFORM_CALL_FAIL;
    return response;
  }

  rpc_param.session_id.session_id_val = session_id_val;
  rpc_param.session_id.session_id_len = session_id_len;
  rpc_param.key.key_val = reinterpret_cast<uint8_t *>(malloc(cbKey));
  memcpy(rpc_param.key.key_val, pbKey, cbKey);
  rpc_param.key.key_len = cbKey;

  if ((rpc_response = rpc_open_cdm_mediakeysession_update_1(
      &rpc_param, rpc_client)) == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
  }
  if (rpc_response) {
    if (rpc_response->platform_val == 0) {
       CDM_LOG_LINE("successfully called platform");
       response.platform_response = PLATFORM_CALL_SUCCESS;
    } else {
       CDM_LOG_LINE("platform call failed");
       response.platform_response = PLATFORM_CALL_FAIL;
    }
  }

  free(rpc_param.key.key_val);

  return response;
}

MediaKeySessionRemoveResponse RpcCdmPlatformHandler::MediaKeySessionRemove(
    char *session_id_val, uint32_t session_id_len) {
  CDM_DLOG() << "RpcCdmPlatformHandler::MediaKeySessionRemove";
  MediaKeySessionRemoveResponse response;

  rpc_response_generic *rpc_response;
  rpc_request_session_remove rpc_param;

  if (!rpc_client && ((rpc_client = clnt_create(rpc_server_host.c_str(), OPEN_CDM,
                                OPEN_CDM_EME_5,
                                "tcp")) == NULL)) {
    com_state = FAULTY;
    clnt_pcreateerror(rpc_server_host.c_str());
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_DLOG() << "RpcCdmPlatformHandler connection to server failed";
    return response;
  } else {
    CDM_DLOG() << "RpcCdmPlatformHandler connected to server";
  }

  rpc_param.session_id.session_id_val = session_id_val;
  rpc_param.session_id.session_id_len = session_id_len;

  if ((rpc_response = rpc_open_cdm_mediakeysession_remove_1(&rpc_param,
                                                             rpc_client))
      == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
  }

  if (rpc_response->platform_val == 0) {
    CDM_DLOG() << "MediaKeySessionRemove success\n ";
    response.platform_response = PLATFORM_CALL_SUCCESS;
  } else {
    CDM_DLOG() << "MediaKeySessionRemove failed\n ";
    response.platform_response = PLATFORM_CALL_FAIL;
  }

  return response;
}

MediaKeySessionCloseResponse RpcCdmPlatformHandler::MediaKeySessionClose(
    char *session_id_val, uint32_t session_id_len) {
  CDM_DLOG() << "RpcCdmPlatformHandler::MediaKeySessionClose";
  MediaKeySessionCloseResponse response;

  rpc_response_generic *rpc_response;
  rpc_request_session_close rpc_param;

  if (!rpc_client && ((rpc_client = clnt_create(rpc_server_host.c_str(), OPEN_CDM,
                                                OPEN_CDM_EME_5,
                                                "tcp")) == NULL)) {
    com_state = FAULTY;
    clnt_pcreateerror(rpc_server_host.c_str());
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_DLOG() << "RpcCdmPlatformHandler connection to server failed";
    return response;
  } else {
    CDM_DLOG() << "RpcCdmPlatformHandler connected to server";
  }

  rpc_param.session_id.session_id_val = session_id_val;
  rpc_param.session_id.session_id_len = session_id_len;

  if ((rpc_response = rpc_open_cdm_mediakeysession_close_1(&rpc_param,
                                                           rpc_client))
      == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
  }

  if (rpc_response->platform_val == 0) {
    CDM_DLOG() << "MediaKeySessionClose success\n ";
    response.platform_response = PLATFORM_CALL_SUCCESS;
  } else {
    CDM_DLOG() << "MediaKeySessionClose failed\n ";
    response.platform_response = PLATFORM_CALL_FAIL;
  }

  return response;
}

MediaKeySessionReleaseResponse RpcCdmPlatformHandler::MediaKeySessionRelease(
    char *session_id_val, uint32_t session_id_len) {
  CDM_DLOG() << "RpcCdmPlatformHandler::MediaKeySessionRelease";
  MediaKeySessionReleaseResponse response;

  rpc_response_generic *rpc_response;
  rpc_request_session_release rpc_param;

  if (!rpc_client && ((rpc_client = clnt_create(rpc_server_host.c_str(), OPEN_CDM,
                                OPEN_CDM_EME_5,
                                "tcp")) == NULL)) {
    com_state = FAULTY;
    clnt_pcreateerror(rpc_server_host.c_str());
    response.platform_response = PLATFORM_CALL_FAIL;
    CDM_DLOG() << "RpcCdmPlatformHandler connection to server failed";
    return response;
  } else {
    CDM_DLOG() << "RpcCdmPlatformHandler connected to server";
  }

  rpc_param.session_id.session_id_val = session_id_val;
  rpc_param.session_id.session_id_len = session_id_len;

  if ((rpc_response = rpc_open_cdm_mediakeysession_release_1(&rpc_param,
                                                             rpc_client))
      == NULL) {
    clnt_perror(rpc_client, rpc_server_host.c_str());
  }

  if (rpc_response->platform_val == 0) {
    CDM_DLOG() << "MediaKeySessionRelease success\n ";
    response.platform_response = PLATFORM_CALL_SUCCESS;
  } else {
    CDM_DLOG() << "MediaKeySessionRelease failed\n ";
    response.platform_response = PLATFORM_CALL_FAIL;
  }

  return response;
}

}  // namespace media
