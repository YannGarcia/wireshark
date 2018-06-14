/* Packet-itsis.c
 * Routines for ITSIS packet dissection
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

#include "packet-itsis.h"

//#define PNAME  "ETSI TS 103301 ITS Infrastructure Services"
#define PNAME  "ETSI TS 103301"
#define PSNAME "ITSIS"
#define PFNAME "itsis"
#define MAPEM_PORT  2003    /* MAPEM BTP port */
#define SPATEM_PORT 2004    /* SPATEM BTP port */
#define IVIM_PORT   2006    /* IVIM BTP port */
#define SREM_PORT   2007    /* SREM BTP port */
#define SSEM_PORT   2008    /* SSEM BTP port */

void proto_reg_handoff_itsis(void);

/* Initialize the protocol and registered fields */
static int proto_itsis = -1;

/* Dissector tables */
static int global_mapem_port = MAPEM_PORT;
static int global_spatem_port = SPATEM_PORT;
static int global_ivim_port = IVIM_PORT;
static int global_srem_port = SREM_PORT;
static int global_ssem_port = SSEM_PORT;
/* Used to identify MessageFrame */
static guint8 Ref_DSRCmsgID;
/* Used to identify RegionalExtension */
static guint16 Ref_RegionId;

typedef enum _RefDSRCmsgID_enum {
  mapData                     = 18,
  signalPhaseAndTimingMessage = 19,
  signalRequestMessage        = 20,
  signalStatusMessage         = 30
} refDSRCmsgID_enum;

typedef enum _RefRegionID_enum {
  noRegion = 0,
  addGrpA  = 1,
  addGrpB  = 2,
  addGrpC  = 3
} RefRegionId_enum;

#include "packet-itsis-hf.c"

/* Initialize the subtree pointers */
static int ett_itsis = -1;

static dissector_table_t dissect_messageframe_pdu_type_table;
static dissector_table_t dissect_regionalextension_pdu_type_table;

static int dissect_messageframe_pdu_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int dissect_regionalextension_pdu_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int dissect_xxx_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#include "packet-itsis-ett.c"

#include "packet-itsis-fn.c"

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
dissect_xxx_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  printf("### dissect_XXX_container: Unsupported\n");
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}

static int dissect_messageframe_pdu_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(dissect_messageframe_pdu_type_table, Ref_DSRCmsgID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_regionalextension_pdu_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(dissect_regionalextension_pdu_type_table, Ref_RegionId, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_itsis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *itsis_item = NULL;
    proto_tree      *itsis_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* create the mapem protocol tree */
    if (tree) {
      guint8 messageId;
      
      itsis_item = proto_tree_add_item(tree, proto_itsis, tvb, 0, -1, FALSE);
      itsis_tree = proto_item_add_subtree(itsis_item, ett_itsis);
      messageId = tvb_get_guint8(tvb, 1);
      switch(messageId) {
      case 0x04:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPATEM");
        dissect_SPATEM_PDU(tvb, pinfo, itsis_tree, NULL);
        break;
      case 0x05:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAPEM");
        dissect_MAPEM_PDU(tvb, pinfo, itsis_tree, NULL);
        break;
      case 0x06:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IVIM");
        dissect_IVIM_PDU(tvb, pinfo, itsis_tree, NULL);
        break;
      case 0x09:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SREM");
        dissect_SREM_PDU(tvb, pinfo, itsis_tree, NULL);
        break;
      case 0x0a:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSEM");
        dissect_SSEM_PDU(tvb, pinfo, itsis_tree, NULL);
        break;
      default:
        dissect_MAPEM_PDU(tvb, pinfo, itsis_tree, NULL);
      } // End of 'switch' statement
    }

    return tvb_captured_length(tvb);
}
/*--- proto_register_mapem -------------------------------------------*/
void proto_register_mapem(void) {

  module_t *itsis_module;

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-itsis-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_itsis,
#include "packet-itsis-ettarr.c"
  };


  /* Register protocol */
  proto_itsis = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("itsis", dissect_itsis, proto_itsis);

  /* Register fields and subtrees */
  proto_register_field_array(proto_itsis, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register CLASS dissector tables */
  dissect_messageframe_pdu_type_table = register_dissector_table("dsrc.dsrcmsgid", "DSRC DSRCmsgID", proto_itsis, FT_UINT8, BASE_DEC);
  dissect_regionalextension_pdu_type_table = register_dissector_table("dsrc.regionid", "DSRC RegionId", proto_itsis, FT_UINT16, BASE_DEC);

  /* Register preferences module */
  itsis_module = prefs_register_protocol(proto_itsis, proto_reg_handoff_itsis);

  /* Register a sample port preference   */
  prefs_register_uint_preference(itsis_module, "btp.dport", "BTP destination port",
                 "BTP destination port",
                 10, &global_mapem_port);

}


/*--- proto_reg_handoff_itsis ---------------------------------------*/
void
proto_reg_handoff_itsis(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t itsis_handle;
  static guint16 mapem_port, spatem_port, ivim_port, srem_port, ssem_port;

  if (!initialized) {
    itsis_handle = create_dissector_handle(dissect_itsis, proto_itsis);
    dissector_add_for_decode_as("btp.dport", itsis_handle);
    initialized = TRUE;

    dissector_add_uint("dsrc.dsrcmsgid", mapData, create_dissector_handle(dissect_MAPEM_PDU, proto_itsis));

    dissector_add_uint("dsrc.dsrcmsgid", signalPhaseAndTimingMessage, create_dissector_handle(dissect_SPATEM_PDU, proto_itsis));

    dissector_add_uint("dsrc.dsrcmsgid", signalRequestMessage, create_dissector_handle(dissect_SREM_PDU, proto_itsis));

    dissector_add_uint("dsrc.dsrcmsgid", signalStatusMessage, create_dissector_handle(dissect_SSEM_PDU, proto_itsis));

  } else {
    if (mapem_port != 0) {
      dissector_delete_uint("btp.dport", mapem_port, itsis_handle);
    }
    if (spatem_port != 0) {
      dissector_delete_uint("btp.dport", spatem_port, itsis_handle);
    }
    if (ivim_port != 0) {
      dissector_delete_uint("btp.dport", ivim_port, itsis_handle);
    }
    if (srem_port != 0) {
      dissector_delete_uint("btp.dport", srem_port, itsis_handle);
    }
    if (ssem_port != 0) {
      dissector_delete_uint("btp.dport", ssem_port, itsis_handle);
    }
  }
  if (global_mapem_port != 0) {
    dissector_add_uint("btp.dport", global_mapem_port, itsis_handle);
  }
  if (global_spatem_port != 0) {
    dissector_add_uint("btp.dport", global_spatem_port, itsis_handle);
  }
  if (global_ivim_port != 0) {
    dissector_add_uint("btp.dport", global_ivim_port, itsis_handle);
  }
  if (global_srem_port != 0) {
    dissector_add_uint("btp.dport", global_srem_port, itsis_handle);
  }
  if (global_ssem_port != 0) {
    dissector_add_uint("btp.dport", global_ssem_port, itsis_handle);
  }
  mapem_port = global_mapem_port;
  spatem_port = global_spatem_port;
  ivim_port = global_ivim_port;
  srem_port = global_srem_port;
  ssem_port = global_ssem_port;
}

