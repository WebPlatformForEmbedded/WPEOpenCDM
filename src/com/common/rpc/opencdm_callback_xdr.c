/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "opencdm_callback.h"

bool_t
xdr_rpc_cb_message (XDR *xdrs, rpc_cb_message *objp)
{
	register int32_t *buf;

	 if (!xdr_array (xdrs, (char **)&objp->session_id.session_id_val, (u_int *) &objp->session_id.session_id_len, ~0,
		sizeof (char), (xdrproc_t) xdr_char))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->message.message_val, (u_int *) &objp->message.message_len, ~0,
		sizeof (char), (xdrproc_t) xdr_char))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->destination_url, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_rpc_cb_key_status_update (XDR *xdrs, rpc_cb_key_status_update *objp)
{
	register int32_t *buf;

	 if (!xdr_array (xdrs, (char **)&objp->session_id.session_id_val, (u_int *) &objp->session_id.session_id_len, ~0,
		sizeof (char), (xdrproc_t) xdr_char))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->message, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_rpc_cb_ready (XDR *xdrs, rpc_cb_ready *objp)
{
	register int32_t *buf;

	 if (!xdr_array (xdrs, (char **)&objp->session_id.session_id_val, (u_int *) &objp->session_id.session_id_len, ~0,
		sizeof (char), (xdrproc_t) xdr_char))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_rpc_cb_error (XDR *xdrs, rpc_cb_error *objp)
{
	register int32_t *buf;

	 if (!xdr_array (xdrs, (char **)&objp->session_id.session_id_val, (u_int *) &objp->session_id.session_id_len, ~0,
		sizeof (char), (xdrproc_t) xdr_char))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->error))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->error_message, ~0))
		 return FALSE;
	return TRUE;
}
