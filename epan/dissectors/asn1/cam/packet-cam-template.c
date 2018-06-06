/* packet-cam.c
 * Routines for CAM packet dissection
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

#include "packet-cam.h"

void proto_register_cam(void);
void proto_reg_handoff_cam(void);

/*ETSI EN 302 637-2 Intelligent Transport Systems (ITS); Vehicular Communications; Basic Set of Applications; Part 2: Specification of Cooperative Awareness Basic Service */
#define PNAME  "CAM"
#define PSNAME "CAM"
#define PFNAME "cam"
#define CAM_PORT 2001    /* BTP port */

/* Initialize the protocol and registered fields */
static int proto_cam = -1;
static int global_cam_port = CAM_PORT;

#include "packet-cam-hf.c"

/* Initialize the subtree pointers */
static int ett_cam = -1;

#include "packet-cam-ett.c"

#include "packet-cam-fn.c"

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
dissect_cam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *cam_item = NULL;
    proto_tree      *cam_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* create the cam protocol tree */
    if (tree) {
        cam_item = proto_tree_add_item(tree, proto_cam, tvb, 0, -1, FALSE);
        cam_tree = proto_item_add_subtree(cam_item, ett_cam);
        dissect_CAM_PDU(tvb, pinfo, cam_tree, NULL);
    }

    return tvb_captured_length(tvb);
}
/*--- proto_register_cam -------------------------------------------*/
void proto_register_cam(void) {

  module_t *cam_module;

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-cam-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_cam,
#include "packet-cam-ettarr.c"
  };


  /* Register protocol */
  proto_cam = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("cam", dissect_cam, proto_cam);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cam, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register preferences module */
  cam_module = prefs_register_protocol(proto_cam, proto_reg_handoff_cam);

  /* Register a sample port preference   */
  prefs_register_uint_preference(cam_module, "btp.dport", "BTP destination port",
				 "BTP destination port",
				 10, &global_cam_port);

}


/*--- proto_reg_handoff_cam ---------------------------------------*/
void
proto_reg_handoff_cam(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t cam_handle;
  static guint16 cam_port;

  if (!initialized) {
    cam_handle = create_dissector_handle(dissect_cam, proto_cam);
    dissector_add_for_decode_as("btp.dport", cam_handle);
    initialized = TRUE;
  } else {
    if (cam_port != 0) {
      dissector_delete_uint("btp.dport", cam_port, cam_handle);
    }
  }
  if (global_cam_port != 0) {
    dissector_add_uint("btp.dport", global_cam_port, cam_handle);
  }
  cam_port = global_cam_port;
}
