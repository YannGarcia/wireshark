/* Packet-poi.c
 * Routines for POI packet dissection
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
#include <epan/asn1.h>
#include <epan/dissectors/packet-per.h>
#include <epan/prefs.h>

#include <stdio.h>
#include <string.h>

#include "packet-poi.h"

#define PNAME  "POI"
#define PSNAME "POI"
#define PFNAME "poi"
#define POI_PORT 2010    /* BTP port */

void proto_reg_handoff_poi(void);

/* Initialize the protocol and registered fields */
static int proto_poi = -1;
static int global_poi_port = POI_PORT;

#include "packet-poi-hf.c"

/* Initialize the subtree pointers */
static int ett_poi = -1;

#include "packet-poi-ett.c"

#include "packet-poi-fn.c"

extern guint32 dissect_per_UTF8String(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension);

static int
dissect_poi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *poi_item = NULL;
    proto_tree      *poi_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* create the poi protocol tree */
    if (tree) {
        poi_item = proto_tree_add_item(tree, proto_poi, tvb, 0, -1, FALSE);
        poi_tree = proto_item_add_subtree(poi_item, ett_poi);
        dissect_EvcsnPdu_PDU(tvb, pinfo, poi_tree, NULL);
    }

    return tvb_captured_length(tvb);
}
/*--- proto_register_poi -------------------------------------------*/
void proto_register_poi(void) {

  module_t *poi_module;

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-poi-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_poi,
#include "packet-poi-ettarr.c"
  };


  /* Register protocol */
  proto_poi = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("poi", dissect_poi, proto_poi);

  /* Register fields and subtrees */
  proto_register_field_array(proto_poi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register preferences module */
  poi_module = prefs_register_protocol(proto_poi, proto_reg_handoff_poi);

  /* Register a sample port preference   */
  prefs_register_uint_preference(poi_module, "btp.dport", "BTP destination port",
				 "BTP destination port",
				 10, &global_poi_port);

}


/*--- proto_reg_handoff_poi ---------------------------------------*/
void
proto_reg_handoff_poi(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t poi_handle;
  static guint16 poi_port;

  if (!initialized) {
    poi_handle = create_dissector_handle(dissect_poi, proto_poi);
    dissector_add_for_decode_as("btp.dport", poi_handle);
    initialized = TRUE;
  } else {
    if (poi_port != 0) {
      dissector_delete_uint("btp.dport", poi_port, poi_handle);
    }
  }
  if (global_poi_port != 0) {
    dissector_add_uint("btp.dport", global_poi_port, poi_handle);
  }
  poi_port = global_poi_port;
}
