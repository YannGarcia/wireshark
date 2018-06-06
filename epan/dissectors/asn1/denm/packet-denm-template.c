/* packet-denm.c
 * Routines for DENM packet dissection
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

# include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-per.h>
#include <epan/prefs.h>

#include <stdio.h>
#include <string.h>

#include "packet-denm.h"

void proto_register_denm(void);
void proto_reg_handoff_denm(void);

/*ETSI EN 302 637-3 Intelligent Transport Systems (ITS); Vehicular Communications; Basic Set of Applications; Part 2: Specification of Dangerous Event Notification Service */
#define PNAME  "DENM"
#define PSNAME "DENM"
#define PFNAME "denm"
#define DENM_PORT 2002    /* BTP port */

/* Initialize the protocol and registered fields */
static int proto_denm = -1;
static int global_denm_port = DENM_PORT;

#include "packet-denm-hf.c"

/* Initialize the subtree pointers */
static int ett_denm = -1;

#include "packet-denm-ett.c"

#include "packet-denm-fn.c"

extern guint32 dissect_per_UTF8String(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);
/*** Yann
guint32
dissect_per_UTF8String(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension)
{
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index, min_len, max_len, has_extension, NULL);
  return offset;
}
***/

static int
dissect_denm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *denm_item = NULL;
    proto_tree      *denm_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* create the denm protocol tree */
    if (tree) {
        denm_item = proto_tree_add_item(tree, proto_denm, tvb, 0, -1, FALSE);
        denm_tree = proto_item_add_subtree(denm_item, ett_denm);
        dissect_DENM_PDU(tvb, pinfo, denm_tree, NULL);
    }

    return tvb_captured_length(tvb);
}
/*--- proto_register_denm -------------------------------------------*/
void proto_register_denm(void) {

  module_t *denm_module;

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-denm-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_denm,
#include "packet-denm-ettarr.c"
  };


  /* Register protocol */
  proto_denm = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("denm", dissect_denm, proto_denm);

  /* Register fields and subtrees */
  proto_register_field_array(proto_denm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register preferences module */
  denm_module = prefs_register_protocol(proto_denm, proto_reg_handoff_denm);

  /* Register a sample port preference   */
  prefs_register_uint_preference(denm_module, "btp.dport", "BTP destination port",
				 "BTP destination port",
				 10, &global_denm_port);

}


/*--- proto_reg_handoff_denm ---------------------------------------*/
void
proto_reg_handoff_denm(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t denm_handle;
  static guint16 denm_port;

  if (!initialized) {
    denm_handle = create_dissector_handle(dissect_denm, proto_denm);
    dissector_add_for_decode_as("btp.dport", denm_handle);
    initialized = TRUE;
  } else {
    if (denm_port != 0) {
      dissector_delete_uint("btp.dport", denm_port, denm_handle);
    }
  }
  if (global_denm_port != 0) {
    dissector_add_uint("btp.dport", global_denm_port, denm_handle);
  }
  denm_port = global_denm_port;
}
