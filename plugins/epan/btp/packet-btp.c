/* packet-btp.c
 * Routines for Basic Transport Protocol dissection
 * Copyright 2011, AMB Consulting <alexandre.berge@amb-consulting.com>
 *
 * $Id: packet-btp.c 2 2014-12-18 12:54:29Z berge $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

# include "config.h"

#include <glib.h>
#include <stdio.h>

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

void proto_register_gn(void);
void proto_reg_handoff_gn(void);

#define MIN_PDU_SIZE 4

#define GN_NH_BTP_A 1
#define GN_NH_BTP_B 2

/* Masks */

/* Initialize the protocol and registered fields */
static int proto_btp = -1;
static int hf_btp_dport = -1;
static int hf_btp_dportinfo = -1;
static int hf_btp_sport = -1;

/* Initialize the subtree pointers */
static gint ett_btp = -1;

static const value_string btp_type_names[] = {
    { GN_NH_BTP_A, "Type A" },
    { GN_NH_BTP_B, "Type B" },
    { 0, NULL}
};

/* Code to actually dissect the packets */
static gboolean 
dissect_btp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint16 btp_dport = -1;
  tvbuff_t *next_tvb;
  const char *str_btp_type = NULL;
  dissector_handle_t data_handle;
  dissector_table_t btp_port_dissector_table;

  /* Check that there's enough data */
  if(tvb_captured_length(tvb) < MIN_PDU_SIZE)
    return 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BTP");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  str_btp_type = val_to_str(pinfo->match_uint, btp_type_names, "Unknown");
  col_add_str(pinfo->cinfo, COL_INFO, str_btp_type);

  btp_dport = tvb_get_ntohs(tvb, 0);
 
  if (tree) { /* we are being asked for details */
    proto_item *ti = NULL;
    proto_tree *btp_tree = NULL;

    ti = proto_tree_add_item(tree, proto_btp, tvb, 0, 4, FALSE);
    btp_tree = proto_item_add_subtree(ti, ett_btp);
    proto_item_append_text(ti, " (%s)", str_btp_type);

    proto_tree_add_item(btp_tree, hf_btp_dport, tvb, 0, 2, FALSE);

    if(pinfo->match_uint == GN_NH_BTP_A) {
      proto_tree_add_item(btp_tree, hf_btp_sport, tvb, 2, 2, FALSE);
    }
    if(pinfo->match_uint == GN_NH_BTP_B) {
      proto_tree_add_item(btp_tree, hf_btp_dportinfo, tvb, 2, 2, FALSE);
    }
  }

  next_tvb = tvb_new_subset_remaining(tvb, 4);
  btp_port_dissector_table = find_dissector_table("btp.dport");
  if(dissector_try_uint(btp_port_dissector_table, btp_dport, next_tvb, pinfo, tree))
    return 4;

  /* Get a handle for the generic data dissector. */
  data_handle = find_dissector("data");
  call_dissector(data_handle, next_tvb, pinfo, tree);
  
  return 4;
}

/* Register the protocol with Wireshark */
void
proto_register_btp(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_btp_dport,
      {"Destination Port", "btp.dport", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_btp_dportinfo,
      {"Destination Port Info", "btp.dportinfo", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_btp_sport,
      {"Source Port", "btp.sport", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_btp,
  };

  /* Register the protocol name and description */
  proto_btp = proto_register_protocol (
				       "Basic Transport Protocol", /* name       */
				       "BTP",                      /* short name */
				       "btp"                       /* abbrev     */
				       );
  register_dissector("btp", dissect_btp, proto_btp);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_btp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector_table("btp.dport", "BTP port", proto_btp, FT_UINT16, BASE_DEC);
}

void
proto_reg_handoff_btp(void)
{
  dissector_handle_t btp_handle;
  btp_handle = create_dissector_handle(dissect_btp, proto_btp);
  dissector_add_uint("gn.nh", GN_NH_BTP_A, btp_handle);
  dissector_add_uint("gn.nh", GN_NH_BTP_B, btp_handle);
}
