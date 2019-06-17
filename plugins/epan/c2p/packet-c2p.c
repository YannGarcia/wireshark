/* packet-c2p.c
 * Routines for Basic Transport Protocol dissection
 * Copyright 2015, Commsignia Ltd. <andras.takacs@commsignia.com>
 *
 * $Id: packet-c2p.c 2 2014-12-18 12:54:29Z berge $
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
#include <math.h>
#include <stdlib.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

void proto_register_gn(void);
void proto_reg_handoff_gn(void);

#define C2P_UPD_PORT                7943

#define C2P_PDU_HEADER              1
#define C2P_PDU_V0_RX               (C2P_PDU_HEADER + 8 + 7*1 + 2*2 + 2*4 + 2*2)
#define C2P_PDU_V0_TX               (C2P_PDU_HEADER + 8 + 6*1       + 2*4 + 2*2)
#define C2P_PDU_V1_RX               (C2P_PDU_HEADER + 8 + 9*1 + 2*2 + 2*4 + 2*2)
#define C2P_PDU_V1_TX               (C2P_PDU_HEADER + 8 + 8*1       + 2*4 + 2*2)

#define C2P_VER_0_RX                0x01u
#define C2P_VER_0_TX                0x02u
#define C2P_VER_1_RX                0x11u
#define C2P_VER_1_TX                0x12u

/** 2004.01.01-00:00:00.000 in absolute time (ms since 1970) */
#define L_U64_2004_IN_ABSTIME       1072915200ULL

/* Masks */

/* Initialize the protocol and registered fields */
static int proto_c2p = -1;
static int hf_c2p_ver_typ= -1;
static int hf_c2p_tst= -1;
static int hf_c2p_tst_sec= -1;
static int hf_c2p_tst_msec= -1;
static int hf_c2p_channel_pri = -1;
static int hf_c2p_channel_sec = -1;
static int hf_c2p_channel_used = -1;
static int hf_c2p_txp= -1;
static int hf_c2p_tssi_1= -1;
static int hf_c2p_tssi_2= -1;
static int hf_c2p_data_rate= -1;
static int hf_c2p_antenna= -1;
static int hf_c2p_rssi_1= -1;
static int hf_c2p_rssi_2= -1;
static int hf_c2p_noise_1= -1;
static int hf_c2p_noise_2= -1;
static int hf_c2p_cbr_1= -1;
static int hf_c2p_cbr_2= -1;
static int hf_c2p_lat= -1;
static int hf_c2p_lon= -1;
static int hf_c2p_speed= -1;
static int hf_c2p_heading = -1; 

/* Initialize the subtree pointers */
static gint ett_c2p = -1;
static gint ett_tst = -1;

static const value_string ver_type_names[] = {
    { C2P_VER_0_RX, "Reception, Version 0" },
    { C2P_VER_0_TX, "Transmission, Version 0" },
    { C2P_VER_1_RX, "Reception, Version 1" },
    { C2P_VER_1_TX, "Transmission, Version 1" },
    { 0, NULL}
};

static const value_string used_channel_names[] = {
    { 1, "Primary Channel of interface 1" },
    { 2, "Primary Channel of interface 2" },
    { 3, "Secondary Channel of interface 1" },
    { 4, "Secondary Channel of interface 2" },
    { 0, NULL}
};


/* Code to actually dissect the packets */
static int
_dissect_c2p(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 c2p_ver_typ = -1;
  const char *str_ver_type = NULL;
  const char *str_channel_used = NULL;
  tvbuff_t *next_tvb;
  int offset = -1;
  int offset_step = -1;
  proto_item *ti = NULL;
  proto_tree *c2p_tree = NULL;
  proto_tree *tst_tree = NULL;
  guint32 time32_s;
  guint32 time32_msec_s;
  time_t time_sec;
  struct tm *time_tm;
  char time_buf[40];
  guint32 value32;
  gint32 value32_s;
  gint64 tmp_ll = 0;
  double coordinate = 0.0;
  gint16 tmp_sh = 0;
  gint16 tmp_perc = 0;
  dissector_handle_t mac80211_handle;

  /* Check that there's enough data */
  if(tvb_captured_length(tvb) < C2P_PDU_HEADER)
    return 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "C2P");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  /* Version and type */
  c2p_ver_typ = tvb_get_guint8(tvb, 0);
  str_ver_type = val_to_str(c2p_ver_typ, ver_type_names, "Unknown");

  if (c2p_ver_typ == C2P_VER_0_RX) {
    if(tvb_captured_length(tvb) < C2P_PDU_V0_RX)
        return 0;
    offset = C2P_PDU_V0_RX;
  } else if (c2p_ver_typ == C2P_VER_0_TX) {
    if(tvb_captured_length(tvb) < C2P_PDU_V0_TX)
        return 0;
    offset = C2P_PDU_V0_TX;
  } else if (c2p_ver_typ == C2P_VER_1_RX) {
    if(tvb_captured_length(tvb) < C2P_PDU_V1_RX)
        return 0;
    offset = C2P_PDU_V1_RX;
  } else if (c2p_ver_typ == C2P_VER_1_TX) {
    if(tvb_captured_length(tvb) < C2P_PDU_V1_TX)
        return 0;
    offset = C2P_PDU_V1_TX;
  }

  ti = proto_tree_add_item(tree, proto_c2p, tvb, 0, offset, c2p_ver_typ);
  c2p_tree = proto_item_add_subtree(ti, ett_c2p); 
  proto_item_append_text(ti, " (%s)", str_ver_type);

  proto_tree_add_uint_format_value(c2p_tree, hf_c2p_ver_typ, tvb, 0, 1, 
          c2p_ver_typ, "%s (%u)", str_ver_type, c2p_ver_typ);
  offset_step = 1;

  /* Times */
  time32_s = tvb_get_ntohl(tvb, offset_step);
  offset_step += 4;
  time_sec = time32_s + L_U64_2004_IN_ABSTIME;
  time_tm = gmtime(&time_sec);
  time32_msec_s = tvb_get_ntohl(tvb, offset_step);
  offset_step += 4;
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", time_tm);

  ti = proto_tree_add_item(c2p_tree, hf_c2p_tst, tvb, 1, 8, /*(guint64)*/(time32_s * 1000uLL + time32_msec_s));
  tst_tree = proto_item_add_subtree(ti, ett_tst);
  proto_item_append_text(ti, " (%s.%d)", time_buf, time32_msec_s);

  proto_tree_add_uint_format_value(tst_tree, hf_c2p_tst_sec, tvb, 1, 4, time32_s,
                             "%s", time_buf);
  proto_tree_add_uint_format_value(tst_tree, hf_c2p_tst_msec, tvb, 5, 4, time32_msec_s,
                             "%d", time32_msec_s);

  value32 = tvb_get_guint8(tvb, offset_step);
  /* primary channel */
  if (value32 == 0) {
    proto_tree_add_uint_format_value(c2p_tree, hf_c2p_channel_pri, tvb, offset_step, 1, value32,
            "N/A (%d)", value32);
  } else {
    proto_tree_add_item(c2p_tree, hf_c2p_channel_pri, tvb, offset_step, 1, value32);
  }
  offset_step += 1;

  if (c2p_ver_typ == C2P_VER_1_TX || c2p_ver_typ == C2P_VER_1_RX) {
    /* secondary channel */
    value32 = tvb_get_guint8(tvb, offset_step);
    if (value32 == 0) {
        proto_tree_add_uint_format_value(c2p_tree, hf_c2p_channel_sec, tvb, offset_step, 1, value32,
                "N/A (%d)", value32);
    } else {
        proto_tree_add_item(c2p_tree, hf_c2p_channel_sec, tvb, offset_step, 1, value32);
    }
    offset_step += 1;
    
    /* Used interface */
    value32 = tvb_get_guint8(tvb, offset_step);
    str_channel_used = val_to_str(value32, used_channel_names, "Unknown");
    if (value32 == 0) {
        proto_tree_add_uint_format_value(c2p_tree, hf_c2p_channel_used, tvb, offset_step, 1, value32,
                "Unknown (%d)", value32);
    } else {
        proto_tree_add_uint_format_value(c2p_tree, hf_c2p_channel_used, tvb, offset_step, 1, 
                  value32, "%s (%u)", str_channel_used, value32);
    }
    offset_step += 1;
  }

  /* data rate */
  value32 = tvb_get_guint8(tvb, offset_step);
  if (value32 == 0) {
    proto_tree_add_uint_format_value(c2p_tree, hf_c2p_data_rate, tvb, offset_step, 1, value32,
            "N/A (%d)", value32);
  } else {
    proto_tree_add_uint_format_value(c2p_tree, hf_c2p_data_rate, tvb, offset_step, 1, value32,
            "%d kbit/sec (%d)", value32 * 500, value32);
  }
  offset_step += 1;

  /* antenna */
  value32 = tvb_get_guint8(tvb, offset_step);
  if (value32 == 0) {
    proto_tree_add_uint_format_value(c2p_tree, hf_c2p_antenna, tvb, offset_step, 1, value32,
            "N/A (%d)", value32);
  } else {
    proto_tree_add_item(c2p_tree, hf_c2p_antenna, tvb, offset_step, 1, value32);
  }
  offset_step += 1;

  /* latitude */
  tmp_ll = (gint64)tvb_get_ntohl(tvb, offset_step);
  if (tmp_ll == 9000000001) {
    proto_tree_add_int_format_value(c2p_tree, hf_c2p_lat, tvb, offset_step, 4, (gint32)tmp_ll,
            "N/A (%lld)", (long long)tmp_ll);
  } else {
    coordinate = tmp_ll / 10000000.0;
    proto_tree_add_int_format_value(c2p_tree, hf_c2p_lat, tvb, offset_step, 4, (gint32)tmp_ll,
	  			  "%02d°%02d'%02.2f\"%c (%lld)",
	  			  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600,60)),
				  (coordinate >= 0.0)?'N':'S',
				  (long long)tmp_ll);
  }
  offset_step += 4;

  /* longitude */
  tmp_ll = (gint64)tvb_get_ntohl(tvb, offset_step);
  if (tmp_ll == 180000000001) {
    proto_tree_add_int_format_value(c2p_tree, hf_c2p_lon, tvb, offset_step, 4, (gint32)tmp_ll,
            "N/A (%lld)", (long long)tmp_ll);
  } else {
    coordinate = tmp_ll / 10000000.0;
    proto_tree_add_int_format_value(c2p_tree, hf_c2p_lon, tvb, offset_step, 4, (gint32)tmp_ll,
	  			  "%02d°%02d'%02.2f\"%c (%lld)",
	  			  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600,60)),
				  (coordinate >= 0.0)?'E':'W',
				  (long long)tmp_ll);
  }
  offset_step += 4;

  /* speed */
  tmp_sh = tvb_get_ntohs(tvb, offset_step);
  if (tmp_sh == 32766) {
    proto_tree_add_int_format_value(c2p_tree, hf_c2p_speed, tvb, offset_step, 2, tmp_sh,
            "N/A (%d)", tmp_sh);
  } else {
    proto_tree_add_int_format_value(c2p_tree, hf_c2p_speed, tvb, offset_step, 2, tmp_sh,
				  "%.2f m/s | %.2f km/h (%d)",
				  tmp_sh / 100.0,
				  tmp_sh * 0.036,
				  tmp_sh);
  }
  offset_step += 2;

  /* heading */
  tmp_sh = tvb_get_ntohs(tvb, offset_step);
  if (tmp_sh == 3601) {
    proto_tree_add_uint_format_value(c2p_tree, hf_c2p_heading, tvb, offset_step, 2, tmp_sh,
            "N/A (%d)", tmp_sh);
  } else {
    proto_tree_add_uint_format_value(c2p_tree, hf_c2p_heading, tvb, offset_step, 2, tmp_sh,
				  "%.1f° (%d)",
				  (tmp_sh % 3600) / 10.0,
				  tmp_sh);
  }
  offset_step += 2;
  
  if (c2p_ver_typ == C2P_VER_0_RX || c2p_ver_typ == C2P_VER_1_RX) {
    /* tx */
    value32_s = (gint8)tvb_get_guint8(tvb, offset_step);
    if (value32_s == 127) {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_rssi_1, tvb, offset_step, 1, value32_s,
            "N/A (%d)", value32_s);
    } else {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_rssi_1, tvb, offset_step, 1, value32_s,
            "%d dbm", value32_s);
    }
    offset_step += 1;
    /* tssi ant 1 */
    value32_s = (gint8)tvb_get_guint8(tvb, offset_step);
    if (value32_s == 127) {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_rssi_2, tvb, offset_step, 1, value32_s,
            "N/A (%d)", value32_s);
    } else {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_rssi_2, tvb, offset_step, 1, value32_s,
            "%d dbm", value32_s);
    }
    offset_step += 1;

    /* tssi ant 2 */
    value32_s = (gint8)tvb_get_guint8(tvb, offset_step);
    if (value32_s == 127) {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_noise_1, tvb, offset_step, 1, value32_s,
            "N/A (%d)", value32_s);
    } else {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_noise_1, tvb, offset_step, 1, value32_s,
            "%d dbm", value32_s);
    }
    offset_step += 1;
  } else if (c2p_ver_typ == C2P_VER_0_TX || c2p_ver_typ == C2P_VER_1_TX) {
    value32_s = (gint8)tvb_get_guint8(tvb, offset_step);
    if (value32_s == 127) {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_txp, tvb, offset_step, 1, value32_s,
            "N/A (%d)", value32_s);
    } else {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_txp, tvb, offset_step, 1, value32_s,
            "%d dbm", value32_s);
    }
    offset_step += 1;

    value32_s = (gint8)tvb_get_guint8(tvb, offset_step);
    if (value32_s == 127) {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_tssi_1, tvb, offset_step, 1, value32_s,
            "N/A (%d)", value32_s);
    } else {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_tssi_1, tvb, offset_step, 1, value32_s,
            "%d dbm", value32_s);
    }
    offset_step += 1;

    value32_s = (gint8)tvb_get_guint8(tvb, offset_step);
    if (value32_s == 127) {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_tssi_2, tvb, offset_step, 1, value32_s,
            "N/A (%d)", value32_s);
    } else {
      proto_tree_add_int_format_value(c2p_tree, hf_c2p_tssi_2, tvb, offset_step, 1, value32_s,
            "%d dbm", value32_s);
    }
    offset_step += 1;
  } 

  next_tvb = tvb_new_subset_length(tvb, offset, -1);

  /* Get a handle for the IEEE 802.11 MAC dissector. */
  mac80211_handle = find_dissector("wlan");
  if (mac80211_handle != NULL) {
    return call_dissector(mac80211_handle, next_tvb, pinfo, tree);
  } else {
    return offset;
  }
}

static int
dissect_c2p(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return _dissect_c2p(tvb, pinfo, tree);
}

static int 
dissect_c2p_new(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * ctx)
{
    (void)ctx;

    return _dissect_c2p(tvb, pinfo, tree);
}

/* Register the protocol with Wireshark */
void
proto_register_c2p(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_c2p_ver_typ,          {"Version and Type",    "c2p.vertyp",       FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_tst,              {"Timestamp",           "c2p.tst",          FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_tst_sec,          {"Date and time",       "c2p.datetime",     FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_tst_msec,         {"Milliseconds",        "c2p.msec",         FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_channel_pri,      {"Channel (Primary)",   "c2p.channel",      FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_channel_sec,      {"Channel (Secondary)", "c2p.channel_sec",  FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_channel_used,     {"Used channel",        "c2p.channel_used", FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_txp,              {"TX power",            "c2p.txp",          FT_INT8,   BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_tssi_1,           {"TSSI (ant 1)",        "c2p.tssi1",        FT_INT8,   BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_tssi_2,           {"TSSI (ant 2)",        "c2p.tssi1",        FT_INT8,   BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_data_rate,        {"Data Rate",           "c2p.datarate",     FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_antenna,          {"Antenna",             "c2p.antenna",      FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_rssi_1,           {"RSSI (ant 1)",        "c2p.rssi1",        FT_INT8,   BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_rssi_2,           {"RSSI (ant 2)",        "c2p.rssi2",        FT_INT8,   BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_noise_1,          {"Noise (ant 1)",       "c2p.noise1",       FT_INT8,   BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_noise_2,          {"Noise (ant 2)",       "c2p.noise2",       FT_INT8,   BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_cbr_1,            {"Channel Busy Ratio (ant 1)", "c2p.cbr1",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_cbr_2,            {"Channel Busy Ratio (ant 2)", "c2p.cbr2",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_lat,              {"Latitude",            "c2p.lat",          FT_INT32,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_lon,              {"Longitude",           "c2p.lon",          FT_INT32,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_speed,            {"Speed",               "c2p.speed",        FT_INT16,  BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_c2p_heading,          {"Heading",             "c2p.heading",      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL} },
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_c2p,
    &ett_tst
  };

  /* Register the protocol name and description */
  proto_c2p = proto_register_protocol (
				       "Commsignia Capture Protocol", /* name       */
				       "C2P",                      /* short name */
				       "c2p"                       /* abbrev     */
				       );
  register_dissector("c2p", dissect_c2p, proto_c2p);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_c2p, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_c2p(void)
{
  dissector_handle_t c2p_handle;
  c2p_handle = create_dissector_handle(dissect_c2p_new, proto_c2p);
  dissector_add_uint("udp.port", C2P_UPD_PORT, c2p_handle);
}
