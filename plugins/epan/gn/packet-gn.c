/* packet-gn.c
 * Routines for GeoNetworking dissetion
 * Copyright 2013, AMB Consulting <alexandre.berge@amb-consulting.com>
 *                 Secured Packet dissection by Cohda Wireless <info@cohdawireless.com>
 *
 * $Id: packet-gn.c 44 2015-03-24 14:00:05Z garciay $
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

#include "config.h"

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>

void proto_register_gn(void);
void proto_reg_handoff_gn(void);

#define ETHER_TYPE 0x8947
#define EX_ETHER_TYPE 0x0707

#define GN_VERSION 0

/* Header lengths */
#define L_BH      4
#define L_CH      8
#define L_BEACON  L_LPV
#define L_GUC     L_LPV + L_SPV + 4
#define L_GAC     L_LPV + 20
#define L_GBC     L_LPV + 20
#define L_TSB_SGL L_LPV + 4
#define L_TSB_MUL L_LPV + 4
#define L_LS      L_LPV + 4
#define L_LS_RQ   L_GN_ADDR
#define L_LS_RY   L_SPV
#define L_LPV     24
#define L_SPV     20
#define L_GN_ADDR 8

/* Masks */
#define M_VERSION            0xF0
#define M_NH                 0xF0
#define M_BNH                0x0F
#define M_NH                 0xF0
#define M_RESERVED0          0x0F
#define M_HT                 0xF0
#define M_HST                0x0F
#define M_FLAGS_MOBILE       0x80
#define M_FLAGS_RESERVED0    0x7F
#define M_FLAGS_RESERVED1    0xFC
#define M_FLAGS_STATION_TYPE 0x02
#define M_FLAGS_RESERVED2    0x01
#define M_TC_SCF             0x80
#define M_TC_CHANOFF         0x40
#define M_TC_TCID            0x3F
#define M_ADDR_M             0x8000
#define M_ADDR_ST            0x7C00
#define M_ADDR_SCC           0x03FF
#define M_LT_MULTIPLIER      0xFC
#define M_LT_BASE            0x03
#define M_PAI                0x8000
#define M_SPEED              0x7FFF
#define M_SPEED_SIGN         0x4000

static int dissect_ieee1609dot2_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_ieee1609dot2_content_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int  dissect_ieee1609dot2_signature_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf);

static guint gETHERTYPE_PREF = ETHER_TYPE;

/* Initialise the protocol and registered fields */
static int proto_gn = -1;

/* Initialise the subtree pointers */
static gint ett_gn = -1;
static gint ett_bh = -1;
static gint ett_sh = -1;
static gint ett_shf = -1;
static gint ett_shfc = -1;
static gint ett_certchain = -1;
static gint ett_sig = -1;
static gint ett_pubkey = -1;
static gint ett_ch = -1;
static gint ett_ch_flags = -1;
static gint ett_ch_tc = -1;
static gint ett_guc = -1;
static gint ett_gac = -1;
static gint ett_gbc = -1;
static gint ett_tsb = -1;
static gint ett_lt = -1;
static gint ett_ls = -1;
static gint ett_ls_addr = -1;
static gint ett_sopv = -1;
static gint ett_sopv_addr = -1;
static gint ett_depv = -1;
static gint ett_depv_addr = -1;
static gint ett_st = -1;
static gint ett_secdata = -1;
static gint ett_2dlocation = -1;
static gint ett_3dlocation = -1;
static gint ett_assurance_level_flags = -1;
/* Secured packet IEE1906.2 */
static gint ett_1609dot2_data_packet = -1;
static gint ett_1609dot2_content_packet = -1;
static gint ett_1609dot2_signed_data_packet = -1;
static gint ett_1609dot2_to_be_signed_data_packet = -1;
static gint ett_1609dot2_unsecured_content = -1;
static gint ett_encrypted_content = -1;
static gint ett_1609dot2_certificate_packet = -1;
static gint ett_1609dot2_issuer_identifier = -1;
static gint ett_1609dot2_signer_identifier_packet = -1;
static gint ett_1609dot2_r_sig = -1;
static gint ett_tbs_data = -1;
static gint ett_1609dot2_header_info_packet = -1;
static gint ett_1609dot2_tbs_certificate_packet = -1;
static gint ett_1609dot2_tbs_certificate_packet_id = -1;
static gint ett_1609dot2_app_permissions_packet = -1;
static gint ett_1609dot2_ssp_packet = -1;
static gint ett_1609dot2_public_enc_key = -1;
static gint ett_1609dot2_base_public_enc_key = -1;
static gint ett_1609dot2_signed_data_payload_packet = -1;
static gint ett_tbs_verification_key = -1;
static gint ett_1609dot2_public_verification_key = -1;
static gint ett_1609dot2_geographical_region_packet = -1;
static gint ett_1609dot2_circular_region_packet = -1;
static gint ett_1609dot2_rectangular_region_packet = -1;
static gint ett_1609dot2_rectangle_region_packet = -1;
static gint ett_1609dot2_polygonal_region_packet = -1;
static gint ett_1609dot2_point_region_packet = -1;
static gint ett_1609dot2_2d_location_packet = -1;
static gint ett_1609dot2_identified_region_packet = -1;
static gint ett_1609dot2_country_region = -1;

/* Basic Header fields */
static int hf_gn_basicheader = -1;
static int hf_gn_version = -1;
static int hf_gn_bnh = -1;
static int hf_gn_reserved = -1;
static int hf_gn_reserved0 = -1;
static int hf_gn_lt = -1;
static int hf_gn_lt_multiplier = -1;
static int hf_gn_lt_base = -1;
static int hf_gn_hl = -1;

/* Common Header fields */
static int hf_gn_commonheader = -1;
static int hf_gn_nh = -1;
static int hf_gn_ht = -1;
static int hf_gn_hst_unspecified = -1;
static int hf_gn_hst_geoarea = -1;
static int hf_gn_hst_tsb = -1;
static int hf_gn_hst_ls = -1;
static int hf_gn_reserved1 = -1;
static int hf_gn_flags = -1;
static int hf_gn_flags_reserved0 = -1;
static int hf_gn_flags_mobile = -1;
static int hf_gn_pl = -1;
static int hf_gn_tc = -1;
static int hf_gn_tc_scf = -1;
static int hf_gn_tc_chanoff = -1;
static int hf_gn_tc_tcid = -1;
static int hf_gn_mhl = -1;

/* Extended Header fields */
static int hf_gn_sn = -1;
static int hf_gn_reserved2 = -1;

/* GeoUnicast fields */
static int hf_gn_guc = -1;

/* GeoArea fields, 2D/3DLocation */
static int hf_gn_area_lat = -1;
static int hf_gn_area_long = -1;
static int hf_gn_area_elev = -1;
static int hf_gn_area_a = -1;
static int hf_gn_area_b = -1;
static int hf_gn_area_angle = -1;
static int hf_gn_area_reserved = -1;

/* GeoAnycast fields */
static int hf_gn_gac = -1;

/* GeoBroadcast fields */
static int hf_gn_gbc = -1;

/* TSB fields */
static int hf_gn_tsb = -1;
static int hf_gn_tsb_reserved = -1;

/* LS fields */
static int hf_gn_ls = -1;
static int hf_gn_ls_addr = -1;
static int hf_gn_ls_addr_m = -1;
static int hf_gn_ls_addr_st = -1;
static int hf_gn_ls_addr_scc = -1;
static int hf_gn_ls_addr_mid = -1;

/* SOPV fields */
static int hf_gn_sopv = -1;
static int hf_gn_so_addr = -1;
static int hf_gn_so_addr_m = -1;
static int hf_gn_so_addr_st = -1;
static int hf_gn_so_addr_scc = -1;
static int hf_gn_so_addr_mid = -1;
static int hf_gn_so_tst = -1;
static int hf_gn_so_lat = -1;
static int hf_gn_so_long = -1;
static int hf_gn_so_pai = -1;
static int hf_gn_so_speed = -1;
static int hf_gn_so_heading = -1;

/* DEPV fields */
static int hf_gn_depv = -1;
static int hf_gn_de_addr = -1;
static int hf_gn_de_addr_m = -1;
static int hf_gn_de_addr_st = -1;
static int hf_gn_de_addr_scc = -1;
static int hf_gn_de_addr_mid = -1;
static int hf_gn_de_tst = -1;
static int hf_gn_de_lat = -1;
static int hf_gn_de_long = -1;

/* Secured packet IEE1906.2 */
static int hf_1609dot2_secured_message = -1;
static int hf_1609dot2_content_packet = -1;
static int hf_1609dot2_signed_data_packet = -1;
static int hf_1609dot2_hash_algorithm = -1;
static int hf_1609dot2_to_be_signed_data_packet = -1;
static int hf_1609dot2_to_be_signed_data_payload_packet = -1;
static int hf_1609dot2_to_be_signed_certificate_packet = -1;
static int hf_1609dot2_unsecured_data_packet = -1;
static int hf_1609dot2_header_info_packet = -1;
static int hf_1609dot2_certificate_packet = -1;
static int hf_1609dot2_certificate_packet_type = -1;
static int hf_1609dot2_signer_identifier_packet = -1;
static int hf_1609dot2_issuer_identifier = -1;
static int hf_1609dot2_ssp_bitmap_mask = -1;
static int hf_1609dot2_sha256AndDigest = -1;
static int hf_1609dot2_sha384AndDigest = -1;
static int hf_1609dot2_to_be_signed_data = -1;
static int hf_1609dot2_to_be_signed_data_nistp256 = -1;
static int hf_1609dot2_to_be_signed_data_brainpoolp256 = -1;
static int hf_1609dot2_to_be_signed_data_brainpoolp384 = -1;
static int hf_1609dot2_certificate_signature = -1;
static int hf_1609dot2_certificate_packet_id = -1;
static int hf_1609dot2_certificate_packet_name = -1;
static int hf_1609dot2_certificate_packet_none = -1;
static int hf_1609dot2_certificate_packet_crlseries = -1;
static int hf_1609dot2_validity_period = -1;
static int hf_1609dot2_app_permissions_packet = -1;
static int hf_1609dot2_ssp_packet = -1;
static int hf_1609dot2_public_enc_key = -1;
static int hf_1609dot2_base_public_enc_key = -1;
static int hf_1609dot2_symm_algorithm = -1;
static int hf_1609dot2_verification_key = -1;
static int hf_1609dot2_public_verification_key = -1;
static int hf_1609dot2_r_sig = -1;
static int hf_1609dot2_s_sig = -1;
static int hf_1609dot2_x_only = -1;
static int hf_1609dot2_compressed_y_0 = -1;
static int hf_1609dot2_compressed_y_1 = -1;
static int hf_1609dot2_ecies_nistp_256 = -1;
static int hf_1609dot2_ecdsa_nistp_256 = -1;
static int hf_1609dot2_ecies_brainpoolp_256 = -1;
static int hf_1609dot2_ecdsa_brainpoolp_256 = -1;
static int hf_1609dot2_ecies_brainpoolp_384 = -1;
static int hf_1609dot2_ecdsa_brainpoolp_384 = -1;
static int hf_1609dot2_geographical_region_packet = -1;
static int hf_1609dot2_circular_region_packet = -1;
static int hf_1609dot2_rectangular_region_packet = -1;
static int hf_1609dot2_rectangle_region_packet = -1;
static int hf_1609dot2_polygonal_region_packet = -1;
static int hf_1609dot2_point_region_packet = -1;
static int hf_1609dot2_2d_location_packet = -1;
static int hf_1609dot2_identified_region_packet = -1;
static int hf_1609dot2_country_region = -1;
















/* Secured packet */
static int hf_sec_data = -1;
static int hf_gn_sh = -1;
static int hf_gn_sh_version = -1;
static int hf_gn_sh_len = -1;
static int hf_gn_sh_field = -1;
static int hf_gn_sh_field_type = -1;
static int hf_gn_sh_field_cert_chain = -1;
static int hf_gn_sh_field_cert_chain_length = -1;
static int hf_gn_sh_field_sig = -1;
static int hf_gn_sh_2dlocation = -1;
static int hf_gn_sh_3dlocation = -1;
static int hf_gn_sh_field_pubkey = -1;
static int hf_gn_sh_field_gentime = -1;
static int hf_gn_sh_field_gentimestddev = -1;
static int hf_gn_sh_field_exptime = -1;
static int hf_gn_sh_field_starttime = -1;
static int hf_gn_sh_field_endtime = -1;
static int hf_gn_sh_field_startendtime = -1;
static int hf_gn_sh_field_startduration = -1;
static int hf_gn_sh_field_elev = -1;
static int hf_gn_sh_field_hashedid3_list = -1;
static int hf_gn_sh_field_hashedid3 = -1;
static int hf_gn_sh_field_hashedid8 = -1;
static int hf_gn_sh_field_self = -1;
static int hf_gn_sh_field_itsaid = -1;
static int hf_gn_sh_field_signinfo_type = -1;
static int hf_gn_sh_field_subject_type = -1;
static int hf_gn_sh_field_subjectattr_type = -1;
static int hf_gn_sh_field_validityrestr_type = -1;
static int hf_gn_st_field_assurelev = -1;
static int hf_gn_st_field_assurelev_flags_levels_bits = -1;
static int hf_gn_st_field_assurelev_flags_reserved_bits = -1;
static int hf_gn_st_field_assurelev_flags_confidence_bits = -1;
static int hf_gn_sh_field_geo_region_type = -1;
static int hf_gn_sh_field_geo_circle_radius = -1;
static int hf_gn_sh_field_geo_region_dict = -1;
static int hf_gn_sh_field_geo_region_id = -1;
static int hf_gn_sh_field_geo_region_local = -1;
static int hf_gn_sh_field_pk_alg = -1;
static int hf_gn_sh_field_cert = -1;
static int hf_gn_sh_field_maxprio = -1;
static int hf_gn_shpl_len = -1;
static int hf_gn_shpl_type = -1;
static int hf_gn_shpl_datalen = -1;
static int hf_gn_st_opaquelen = -1;
//static int hf_gn_st_signinfolen = -1;
static int hf_gn_st_subjectattrlen = -1;
static int hf_gn_st_aid_val = -1;
static int hf_gn_st = -1;
static int hf_gn_st_len = -1;
static int hf_gn_st_type = -1;
static int hf_gn_st_pka = -1;
static int hf_gn_st_symmalg = -1;
static int hf_gn_st_ecc_pt = -1;
static int hf_gn_st_opaque = -1;

/*-------------------------------------
 * UAT for ESP
 *-------------------------------------
 */
/* UAT entry structure. */
typedef struct {
  guint8 protocol;
  gchar *srcIP;
  gchar *dstIP;
  gchar *spi;

  guint8 encryption_algo;
  gchar *encryption_key_string;
  gchar *encryption_key;
  gint encryption_key_length;
  gboolean         cipher_hd_created;

  guint8 authentication_algo;
  gchar *authentication_key_string;
  gchar *authentication_key;
  gint authentication_key_length;
} uat_esp_sa_record_t;

//static uat_esp_sa_record_t *uat_esp_sa_records = NULL;

/* Extra SA records that may be set programmatically */
/* 'records' array is now allocated on the heap */
#define MAX_EXTRA_SA_RECORDS 16
typedef struct extra_esp_sa_records_t {
  guint num_records;
  uat_esp_sa_record_t *records;
} extra_esp_sa_records_t;
//static extra_esp_sa_records_t extra_esp_sa_records;

//static uat_t * esp_uat = NULL;
//static guint num_sa_uat = 0;

static const value_string basic_next_header_names[] = {
  { 0, "Any" },
  { 1, "Common" },
  { 2, "Secured" },
  { 0, NULL}
};

static const value_string next_header_names[] = {
  { 0, "Any" },
  { 1, "BTP-A" },
  { 2, "BTP-B" },
  { 3, "IPv6" },
  { 0, NULL}
};

static const value_string header_type_names[] = {
  { 0, "Any" },
  { 1, "Beacon" },
  { 2, "GeoUnicast" },
  { 3, "GeoAnycast" },
  { 4, "GeoBroadcast" },
  { 5, "TSB" },
  { 6, "LS" },
  { 0, NULL}
};

static const value_string header_subtype_unspecified_names[] = {
  { 0, "Unspecified" },
  { 0, NULL}
};

static const value_string header_subtype_geoarea_names[] = {
  { 0, "Circle" },
  { 1, "Rectangle" },
  { 2, "Ellipse" },
  { 0, NULL}
};

static const value_string header_subtype_tsb_names[] = {
  { 0, "Single Hop" },
  { 1, "Multi Hop" },
  { 0, NULL}
};

static const value_string header_subtype_ls_names[] = {
  { 0, "Request" },
  { 1, "Reply" },
  { 0, NULL}
};

static const value_string assignement_names[] = {
  { 0, "Automatic" },
  { 1, "Manual" },
  { 0, NULL}
};

static const value_string station_type_names[] = {
  { 0, "Unknown" },
  { 1, "Pedestrian" },
  { 2, "Cyclist" },
  { 3, "Moped" },
  { 4, "Motorcycle" },
  { 5, "Passenger Car" },
  { 6, "Bus" },
  { 7, "Light Truck" },
  { 8, "Heavy Truck" },
  { 9, "Trailer" },
  { 10, "Special Vehicle" },
  { 11, "Tram" },
  { 12, "Reserved" },
  { 13, "Reserved" },
  { 14, "Reserved" },
  { 15, "Road Side Unit" },
  { 0, NULL}
};

static const value_string mobile_names[] = {
  { 0, "Stationary" },
  { 1, "Mobile" },
  { 0, NULL}
};

static const value_string lifetime_base_names[] = {
  { 0, "50 ms" },
  { 1, "1 s" },
  { 2, "10 s" },
  { 3, "100 s" },
  { 0, NULL}
};

static const int lifetime_base_values[] = {
  50,
  1000,
  10000,
  100000
};

static const value_string sh_field_names[] = { // Draft ETSI TS 103 097 V1.1.13 Clause 7 Security profiles
  { 0, "Generation Time" },
  { 1, "Generation Time with Confidence" },
  { 2, "Expiration" },
  { 3, "Generation Location" },
  { 4, "Request Unrecognised Certificate" },
  { 5, "Its AID" },
  { 6, "Trust Data" },
  { 7, "Certificate Request" },
  { 128, "Signer Info" },
  { 129, "Encryption Parameters" },
  { 130, "Recipient Info" },

  { 0, NULL}
};

static const value_string sh_itsaid_names[] = { // Draft ETSI TS 103 097 V1.1.13 Clause 5.4 HeaderField
  { 36, "CAM" },
  { 37, "DENM" },
  {137, "SPATEM"},
  {138, "MAPEM"},
  {139, "IVIM"},
  {140, "SREM/SSEM"},
  { 0, NULL}
};

static const value_string sh_signerinfotype_names[] = { // Draft ETSI TS 103 097 V1.1.13 Clause 4.1.11 SignerInfoType
  { 0, "self" },
  { 1, "certificate digest with SHA256" },
  { 2, "certificate" },
  { 3, "certificate chain" },
  { 4, "certificate digest with other alg" },
  { 0, NULL}
};

static const value_string sh_subjectinfotype_names[] = { // Draft ETSI TS 103 097 V1.1.13 Clause 6.3 SubjectType
  { 0, "enrollment credential" },
  { 1, "authorization ticket" },
  { 2, "authorization authority" },
  { 3, "enrollment authority" },
  { 4, "root ca" },
  { 5, "crl signer" },
  { 0, NULL}
};

static const value_string sh_subjectattrtype_names[] = { // Draft ETSI TS 103 097 V1.1.13 Clause 6.4 SubjectAttribut
  { 0, "verification key" },
  { 1, "encryption key" },
  { 2, "assurance level" },
  { 3, "reconstruction value" },
  { 32, "its aid list" },
  { 33, "its aid ssp list" },
  { 34, "priority its aid list" },
  { 35, "priority ssp list" },
  { 0, NULL}
};

static const value_string sh_validityrestrtype_names[] = {
  { 0, "time end" },
  { 1, "time start and end" },
  { 2, "time start and duration" },
  { 3, "region" },
  { 0, NULL}
};

static const value_string sh_georegiontype_names[] = {
  { 0, "none" },
  { 1, "circle" },
  { 2, "rectangle" },
  { 3, "polygon" },
  { 4, "id" },
  { 0, NULL}
};

static const value_string sh_georegiondicttype_names[] = {
  { 0, "iso_3166_1" },
  { 1, "un_stats" },
  { 0, NULL}
};

static const value_string sh_publickeyalg_names[] = {
  { 0, "ecdsa nistp256 with sha256" },
  { 1, "ecdsa nistp256" },
  { 0, NULL}
};

static const value_string sh_trailertype_names[] = {
  { 0, "signer info (DRAFT!)" },
  { 1, "signature" },
  { 2, "recipient info (DRAFT!)" },
  { 3, "encryption parameters (DRAFT!)" },
  { 0, NULL}
};

static const value_string sh_payloadtype_names[] = {
  { 0, "unsecured" },
  { 1, "signed" },
  { 2, "encrypted" },
  { 3, "signed external" },
  { 4, "signed and encrypted" },
  { 0, NULL}
};

static const value_string st_pka_names[] = {
  { 0, "ecdsa nistp256 with sha256" },
  { 1, "ecdsa nistp256" },
  { 0, NULL}
};

static const value_string st_symmal_gnames[] = {
  { 0, "aes 128 ccm" },
  { 0, NULL}
};

static const value_string st_eccpt_type_names[] = {
  { 0, "x-coordinate only" },
  { 2, "compressed lsb y-0" },
  { 3, "compressed lsb y-1" },
  { 4, "uncompressed" },
  { 0, NULL}
};

static const value_string st_1609dot2_hash_algorithm[] = {
  { 0, "SHA-256 algorithm" },
  { 2, "SHA-384 algorithm" },
  { 0, NULL}
};

static const value_string st_1609dot2_certificate_type[] = {
  { 0, "explicit certificate type" },
  { 2, "implicit certificate type" },
  { 0, NULL}
};

static gint32
dissect_var_val (tvbuff_t *tvb, 
                 proto_tree *tree,
                 gint offset,
                 gint *varval)
{
  gint8 tmp;
  gint32 len = 0;
  gint32 offsetdiff = 0;

  (void)tree;

  tmp = tvb_get_guint8(tvb, offset);
  if ((tmp & 0x80) == 0x00) {
    len = tvb_get_guint8(tvb, offset);
    len = len & 0x0000007f;
    offsetdiff = 1;
  } else if ((tmp & 0xC0) == 0x80) {
    len = tvb_get_ntohs(tvb, offset);
    len = len & 0x00003fff;
    offsetdiff = 2;
  } else if ((tmp & 0xE0) == 0xC0) {
    len = tvb_get_ntoh24(tvb, offset);
    len = len & 0x001fffff;
    offsetdiff = 3;
  } else if ((tmp & 0xF0) == 0xE0) {
    len = tvb_get_ntohl(tvb, offset);
    len = len & 0x0fffffff;
    offsetdiff = 4;
  }

  *varval = len;
  return offsetdiff;
}

/* Interpret Time64 type */
static int tree_gn_cert_time64(tvbuff_t *tvb, proto_tree *ext_tree, int hf_gn_type, int offset)
{
  guint64 time64_us;
  guint32 time_us;
  time_t time_sec;
  struct tm *time_tm;
  char time_buf[256] = { 0, };

  time64_us = tvb_get_ntoh64(tvb, offset); // 2004/01/01 00:00:00 epoch
  time_us = (guint32)((time64_us % 1000000) & 0xffffffffULL);
  time_sec = (time_t)(((time64_us / 1000000) + 1072915200) & 0x7fffffffULL); // 1970/01/01 epoch
  time_tm = gmtime(&time_sec);
  memset(time_buf, '\0', 256);
  strftime(time_buf, 255, "%Y-%m-%d %H:%M:%S", time_tm);
  time_buf[255] = '\0';

  proto_tree_add_uint64_format(ext_tree, hf_gn_type, tvb, offset, 8, time64_us,
			       "Generation Time: %19s.%06d (%lu)",
                               time_buf, time_us, time64_us);     

  return 8;
}

/* Interpret Time32 type */
static int tree_gn_cert_time32(tvbuff_t *tvb, proto_tree *ext_tree, int hf_gn_type, int offset)
{
  guint32 time32_s;
  time_t time_sec;
  struct tm *time_tm;
  char time_buf[40];

  time32_s = tvb_get_ntohl(tvb, offset); // 2004/01/01 00:00:00 epoch
  time_sec = time32_s + 1072915200; // 1970/01/01 epoch
  time_tm = gmtime(&time_sec);
  strftime(time_buf, 40, "%Y-%m-%d %H:%M:%S", time_tm);

  proto_tree_add_uint_format(ext_tree, hf_gn_type, tvb, offset, 4, time32_s,
                             "Time: %19s (%d)",
                             time_buf, time32_s);
  return 4;
}

/* Interpret 3D location */
static int tree_gn_3dpos(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  double coordinate = 0.0;
  guint16 elevation = 0;
  gint32 tmp_ll = 0;
  guint16 offset_extra = 0;

  proto_item *ti = NULL;
  proto_tree *loc_tree = NULL;

  ti = proto_tree_add_item(ext_tree, hf_gn_sh_3dlocation, tvb, offset, 10, FALSE); 
  loc_tree = proto_item_add_subtree(ti, ett_3dlocation);

  /* Latitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(loc_tree, hf_gn_area_lat, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600,60)),
				  (coordinate >= 0.0)?'N':'S',
				  tmp_ll
				  );
  offset_extra += 4;
  offset += 4;

  /* Longitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(loc_tree, hf_gn_area_long, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600,60)),
				  (coordinate >= 0.0)?'E':'W',
				  tmp_ll
				  );
  offset_extra += 4;
  offset += 4;

  elevation = (guint16)(tvb_get_guint8(tvb, offset) << 8) | (guint16)tvb_get_guint8(tvb, offset + 1);
  proto_tree_add_uint_format_value(loc_tree, hf_gn_area_elev, tvb, offset, 2, elevation,
				  "%d meter(s)",
				  elevation
				  );
  offset_extra += 2;
  offset += 2;
  
  return offset_extra;
}

/* Interpret 2D location */
static int tree_gn_2dpos(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  double coordinate = 0.0;
  gint32 tmp_ll = 0;
  guint16 offset_extra = 0;

  proto_item *ti = NULL;
  proto_tree *loc_tree = NULL;

  ti = proto_tree_add_item(ext_tree, hf_gn_sh_2dlocation, tvb, offset, 8, FALSE); 
  loc_tree = proto_item_add_subtree(ti, ett_2dlocation);

  /* Latitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(loc_tree, hf_gn_area_lat, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600,60)),
				  (coordinate >= 0.0)?'N':'S',
				  tmp_ll
				  );
  offset_extra += 4;
  offset += 4;

  /* Longitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(loc_tree, hf_gn_area_long, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600,60)),
				  (coordinate >= 0.0)?'E':'W',
				  tmp_ll
				  );
  offset_extra += 4;
  offset += 4;

  return offset_extra;
}

/* Interpret HashedID3 list */
static int tree_hashedId3_list(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  guint16 offset_extra = 0;
  guint8 lengthHashed3;
  proto_item *ti = NULL;
  proto_tree *loc_tree = NULL;
  
  // FIXME length
  lengthHashed3 = tvb_get_guint8(tvb, offset); // One octet
  offset += 1;
  offset_extra += 1;
  
  ti = proto_tree_add_item(ext_tree, hf_gn_sh_field_hashedid3_list, tvb, offset, 8, FALSE); 
  loc_tree = proto_item_add_subtree(ti, ett_2dlocation);
  
  while (lengthHashed3 > 0) {
    
    proto_tree_add_item(loc_tree, hf_gn_sh_field_hashedid3, tvb, offset, 3, FALSE);
    offset += 3;
    offset_extra += 3;
    lengthHashed3 -= 3;
  } // End of 'while' version
  
  return offset_extra;
}

/* Interpret ECC point */
static int tree_gn_ecc_point(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  guint8 ecc_point_type;
  guint16 offset_extra = 0;
  int opaque_len;
  int opaque_len_size;

  ecc_point_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(ext_tree, hf_gn_st_ecc_pt, tvb, offset, 1, FALSE);
  offset_extra += 1;
  offset += 1;

  proto_tree_add_item(ext_tree, hf_gn_st_opaque, tvb, offset, 32, FALSE);
  offset_extra += 32;
  offset += 32;

  switch (ecc_point_type) {
  case 0: // x_coord
  case 2: // compressed_y_0
  case 3: // compressed_y_1
    break;
  case 4: // uncompressed
    proto_tree_add_item(ext_tree, hf_gn_st_opaque, tvb, offset, 32, FALSE);     
    offset_extra += 32;
    offset += 32;
    break;
  default: // unknown
    opaque_len_size = dissect_var_val(tvb, ext_tree, offset, &opaque_len);
    proto_tree_add_uint(ext_tree, hf_gn_st_opaquelen, tvb, offset, opaque_len_size, opaque_len);     
    offset_extra += opaque_len_size;
    offset += opaque_len_size;

    proto_tree_add_item(ext_tree, hf_gn_st_opaque, tvb, offset, opaque_len, FALSE);     
    offset_extra += opaque_len;
    break;
  }

  return offset_extra;
}

/* Interpret Signature */
static int tree_gn_signature(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  guint8 signature_type;
  guint16 offset_extra = 0;

  int opaque_len;
  int opaque_len_size;

  proto_item *ti = NULL;
  proto_tree *sig_tree = NULL;

  ti = proto_tree_add_item(ext_tree, hf_gn_sh_field_sig, tvb, offset, -1, FALSE); 
  sig_tree = proto_item_add_subtree(ti, ett_sig);

  /* public key alg */
  signature_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(sig_tree, hf_gn_st_pka, tvb, offset, 1, FALSE);     
  offset_extra += 1;
  offset += 1;

  if (signature_type == 0) {
    int ecc_len;
    // ecdsa_nistp256_with_sha256
    ecc_len = tree_gn_ecc_point(tvb, sig_tree, offset);
    offset_extra += ecc_len;
    offset += ecc_len;

    proto_tree_add_item(sig_tree, hf_gn_st_opaque, tvb, offset, 32, FALSE);     
    offset_extra += 32;
    offset += 32;
  } else {
    opaque_len_size = dissect_var_val(tvb, ext_tree, offset, &opaque_len);
    proto_tree_add_uint(ext_tree, hf_gn_st_opaquelen, tvb, offset, opaque_len_size, opaque_len);     
    offset_extra += opaque_len_size;
    offset += opaque_len_size;

    proto_tree_add_item(ext_tree, hf_gn_st_opaque, tvb, offset, opaque_len, FALSE);     
    offset_extra += opaque_len;
  }

  return offset_extra;
}

/* Interpret Public Key */
static int tree_gn_publickey(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  guint8 signature_type;
  guint16 offset_extra = 0;

  int opaque_len;
  int opaque_len_size;

  proto_item *ti = NULL;
  proto_tree *pk_tree = NULL;

  ti = proto_tree_add_item(ext_tree, hf_gn_sh_field_pubkey, tvb, offset, -1, FALSE); 
  pk_tree = proto_item_add_subtree(ti, ett_pubkey);

  /* public key alg */
  signature_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(pk_tree, hf_gn_st_pka, tvb, offset, 1, FALSE);     
  offset_extra += 1;
  offset += 1;

  switch (signature_type) {
    guint16 ecc_offset;

  case 0: // ecdsa_nistp256_with_sha256
    ecc_offset = tree_gn_ecc_point(tvb, pk_tree, offset);
    offset_extra += ecc_offset;
    offset += ecc_offset;
    break;
  case 1: // ecies_nistp256
    proto_tree_add_item(pk_tree, hf_gn_st_symmalg, tvb, offset, 1, FALSE);     
    offset_extra += 1;
    offset += 1;

    ecc_offset = tree_gn_ecc_point(tvb, pk_tree, offset);
    offset_extra += ecc_offset;
    offset += ecc_offset;
    break;
  default:
    opaque_len_size = dissect_var_val(tvb, pk_tree, offset, &opaque_len);
    proto_tree_add_uint(pk_tree, hf_gn_st_opaquelen, tvb, offset, opaque_len_size, opaque_len);     
    offset_extra += opaque_len_size;
    offset += opaque_len_size;

    proto_tree_add_item(pk_tree, hf_gn_st_opaque, tvb, offset, opaque_len, FALSE);     
    offset_extra += opaque_len;
    break;
  }

  return offset_extra;
}


/* Code to build tree for Source Position Vector (LPV) */
static int tree_gn_sopv(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_item *addr_ti = NULL;
  proto_tree *addr_tree = NULL;
  proto_item *sopv_ti = NULL;
  proto_tree *tree = NULL;
  double coordinate = 0.0;
  gint16 speed = 0;
  gint32 tmp_ll = 0;

  /* SOPV tree */
  sopv_ti = proto_tree_add_item(header_tree, hf_gn_sopv, tvb, offset, L_LPV, FALSE); 
  tree = proto_item_add_subtree(sopv_ti, ett_sopv);

  /* GN Address */
  addr_ti = proto_tree_add_item(tree, hf_gn_so_addr, tvb, offset, L_GN_ADDR, FALSE); 
  addr_tree = proto_item_add_subtree(addr_ti, ett_sopv_addr);
  proto_tree_add_item(addr_tree, hf_gn_so_addr_m, tvb, offset, 2, FALSE); 
  proto_tree_add_item(addr_tree, hf_gn_so_addr_st, tvb, offset, 2, FALSE); 
  proto_tree_add_item(addr_tree, hf_gn_so_addr_scc, tvb, offset, 2, FALSE); 
  offset += 2;
  proto_tree_add_item(addr_tree, hf_gn_so_addr_mid, tvb, offset, 6, FALSE); 
  offset += 6;

  /* Timestamp */
  proto_tree_add_item(tree, hf_gn_so_tst, tvb, offset, 4, FALSE); 
  offset += 4;

  /* Latitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(tree, hf_gn_so_lat, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600, 60)),
				  (coordinate >= 0.0)?'N':'S',
				  tmp_ll
				  );
  offset += 4;

  /* Longitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(tree, hf_gn_so_long, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600, 60)),
				  (coordinate >= 0.0)?'E':'W',
				  tmp_ll
				  );
  offset += 4;

  /* PAI */
  proto_tree_add_item(tree, hf_gn_so_pai, tvb, offset, 2, FALSE); 

  /* Speed */
  speed = tvb_get_ntohs(tvb, offset) & M_SPEED;
  if((speed & M_SPEED_SIGN) == M_SPEED_SIGN) {
    speed |= M_PAI;
  }
  proto_tree_add_int_format_value(tree, hf_gn_so_speed, tvb, offset, 2, speed,
				  "%.2f m/s | %.2f km/h (%d)",
				  speed / 100.0,
				  speed * 0.036,
				  speed
				  );
  offset += 2;

  /* Heading */
  proto_tree_add_uint_format_value(tree, hf_gn_so_heading, tvb, offset, 2, tvb_get_ntohs(tvb, offset),
				   "%.1f° (%d)",
				   (tvb_get_ntohs(tvb, offset) % 3600) / 10.0,
				   tvb_get_ntohs(tvb, offset)
				   );
  offset += 2;

  return offset;
}

/* Code to build tree for Destination Position Vector (SPV) */
static int tree_gn_depv(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_item *addr_ti = NULL;
  proto_tree *addr_tree = NULL;
  proto_item *depv_ti = NULL;
  proto_tree *tree = NULL;
  double coordinate = 0.0;
  gint32 tmp_ll = 0;

  /* DEPV tree */
  depv_ti = proto_tree_add_item(header_tree, hf_gn_depv, tvb, offset, L_SPV, FALSE); 
  tree = proto_item_add_subtree(depv_ti, ett_depv);

  /* GN Address */
  addr_ti = proto_tree_add_item(tree, hf_gn_de_addr, tvb, offset, L_GN_ADDR, FALSE); 
  addr_tree = proto_item_add_subtree(addr_ti, ett_depv_addr);
  proto_tree_add_item(addr_tree, hf_gn_de_addr_m, tvb, offset, 2, FALSE); 
  proto_tree_add_item(addr_tree, hf_gn_de_addr_st, tvb, offset, 2, FALSE); 
  proto_tree_add_item(addr_tree, hf_gn_de_addr_scc, tvb, offset, 2, FALSE); 
  offset += 2;
  proto_tree_add_item(addr_tree, hf_gn_de_addr_mid, tvb, offset, 6, FALSE); 
  offset += 6;

  /* Timestamp */
  proto_tree_add_item(tree, hf_gn_de_tst, tvb, offset, 4, FALSE); 
  offset += 4;

  /* Latitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(tree, hf_gn_de_lat, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600, 60)),
				  (coordinate >= 0.0)?'N':'S',
				  tmp_ll
				  );
  offset += 4;

  /* Longitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(tree, hf_gn_de_long, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600, 60)),
				  (coordinate >= 0.0)?'E':'W',
				  tmp_ll
				  );
  offset += 4;

  return offset;
}

/* Code to build tree for Multihop Extended Header */
static int tree_gn_ext_multihop(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  /* Sequence Number */
  proto_tree_add_item(ext_tree, hf_gn_sn, tvb, offset, 2, FALSE); 
  offset += 2; 

  /* Reserved */
  proto_tree_add_item(ext_tree, hf_gn_reserved2, tvb, offset, 2, FALSE); 
  offset += 2;
  
  /* SOPV */
  offset = tree_gn_sopv(tvb, ext_tree, offset);

  return offset;
}

/* Code to build tree for GeoArea Extended Header */
static int tree_gn_ext_geoarea(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  double coordinate = 0.0;
  gint32 tmp_ll = 0;

  /* Latitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(ext_tree, hf_gn_area_lat, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600, 60)),
				  (coordinate >= 0.0)?'N':'S',
				  tmp_ll
				  );
  offset += 4;

  /* Longitude */
  tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
  coordinate = tmp_ll / 10000000.0;
  proto_tree_add_int_format_value(ext_tree, hf_gn_area_long, tvb, offset, 4, tmp_ll,
				  "%02d°%02d'%02.2f\"%c (%d)",
				  abs((int)coordinate),
				  abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600, 60)),
				  (coordinate >= 0.0)?'E':'W',
				  tmp_ll
				  );
  offset += 4;

  /* Distance A */
  proto_tree_add_uint_format_value(ext_tree, hf_gn_area_a, tvb, offset, 2, tvb_get_ntohs(tvb, offset),
				   "%d m (%d)",
				   tvb_get_ntohs(tvb, offset),
				   tvb_get_ntohs(tvb, offset)
				   );
  offset += 2;

  /* Distance B */
  proto_tree_add_uint_format_value(ext_tree, hf_gn_area_b, tvb, offset, 2, tvb_get_ntohs(tvb, offset),
				   "%d m (%d)",
				   tvb_get_ntohs(tvb, offset),
				   tvb_get_ntohs(tvb, offset)
				   );
  offset += 2;

  /* Angle */
  proto_tree_add_uint_format_value(ext_tree, hf_gn_area_angle, tvb, offset, 2, tvb_get_ntohs(tvb, offset),
				   "%d° (%d)",
				   tvb_get_ntohs(tvb, offset),
				   tvb_get_ntohs(tvb, offset)
				   );
  offset += 2;

  /* Reserved */
  proto_tree_add_item(ext_tree, hf_gn_area_reserved, tvb, offset, 2, FALSE);
  offset += 2;

  return offset;
}

/* Interpret CertChain */
static int tree_gn_cert(tvbuff_t *tvb, proto_tree *ext_tree, int offset)
{
  int opaque_len;
  int opaque_len_size;

  proto_item *ti = NULL;
  proto_tree *shfc_tree = NULL;

  /* Read length */
  opaque_len_size = dissect_var_val(tvb, ext_tree, offset, &opaque_len);
  proto_tree_add_uint(ext_tree, hf_gn_sh_field_cert_chain_length, tvb, offset, opaque_len_size, opaque_len);
  offset += opaque_len_size;  
  
  ti = proto_tree_add_item(ext_tree, hf_gn_sh_field_cert_chain, tvb, offset, opaque_len, FALSE); 
  shfc_tree = proto_item_add_subtree(ti, ett_sig);
  
  /* loop through each certificate item */
  { // Start block #1
    gint hdrlen = opaque_len;
    while (hdrlen > 0) {
      { // Start block #2
//	int extralen;
	int extraoffset;
	int validr_len;
	int validr_len_size;
	int opaqlen;
	int attrlen;
	int siglen;
	guint8 subjattr_type;
	guint8 signinfo_type;
	guint8 validr_type;

	// cert
	// version
	proto_tree_add_item(shfc_tree, hf_gn_sh_version, tvb, offset, 1, FALSE);
	offset += 1;
	hdrlen -= 1;
	
	signinfo_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(shfc_tree, hf_gn_sh_field_signinfo_type, tvb, offset, 1, FALSE);
	offset += 1;
	hdrlen -= 1;
	
	switch (signinfo_type) {
	case 0:
	  // self
	  offset += 1;
	  hdrlen -= 1;
	  break;
	case 1:
	  // cert digest with ecdsap256
	  proto_tree_add_item(shfc_tree, hf_gn_sh_field_hashedid8, tvb, offset, 8, FALSE);
	  offset += 8;
	  hdrlen -= 8;
	  break;
	case 2:
	  // cert
	  offset += tree_gn_cert(tvb, shfc_tree, offset);
	  break;
	case 3:
	  // TODO cert chain
	  break;
	case 4:
	  // TODO cert digest with other alg
	  break;
	default:
	  break;
	} // End of 'switch' statement
	
	// subject info
	proto_tree_add_item(shfc_tree, hf_gn_sh_field_subject_type, tvb, offset, 1, FALSE);
	offset += 1;
	hdrlen -= 1;
	
	extraoffset = dissect_var_val(tvb, shfc_tree, offset, &opaqlen);
	proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, extraoffset, opaqlen);     
	offset += extraoffset;
	hdrlen -= extraoffset;
	
	if (opaqlen) {
	  // Should be max 32 octets
	  proto_tree_add_item(shfc_tree, hf_gn_st_opaque, tvb, offset, opaqlen, FALSE);
	  offset += opaqlen;
	  hdrlen -= opaqlen;
	}
	
	// subject attribute
	extraoffset = dissect_var_val(tvb, shfc_tree, offset, &attrlen);
	proto_tree_add_uint(shfc_tree, hf_gn_st_subjectattrlen, tvb, offset, extraoffset, attrlen);     
	offset += extraoffset;
	hdrlen -= extraoffset;
	
	if (attrlen) {
      proto_tree *tree_assurance_level = NULL;
      proto_item *ti_assurance_level = NULL;
      guint8 assurance_level_flags = -1;
      
	  while (attrlen > 0) {
	    subjattr_type = tvb_get_guint8(tvb, offset);
	    proto_tree_add_item(shfc_tree, hf_gn_sh_field_subjectattr_type, tvb, offset, 1, FALSE);
	    offset += 1;
	    hdrlen -= 1;
	    attrlen -= 1;
	    
	    switch (subjattr_type) {
	      int aids_len;
	      int aids_len_size;
	      int sig_len;
	      
	    case 0:
	      // verification key
	    case 1:
	      // encryption key
	      sig_len = tree_gn_publickey(tvb, shfc_tree, offset);
	      offset += sig_len;
	      hdrlen -= sig_len;
	      attrlen -= sig_len;
	      break;
	    case 2:
	      // assurance level
	      ti_assurance_level = proto_tree_add_item(shfc_tree, hf_gn_st_field_assurelev, tvb, offset, 1, FALSE); 
          tree_assurance_level = proto_item_add_subtree(ti_assurance_level, ett_assurance_level_flags);
          assurance_level_flags = tvb_get_guint8(tvb, offset);
          if ((assurance_level_flags & 0xe0) != 0x00) {
            proto_tree_add_item(tree_assurance_level, hf_gn_st_field_assurelev_flags_levels_bits, tvb, offset, 1, FALSE);
          }
          if ((assurance_level_flags & 0x1c) != 0x00) {
            proto_tree_add_item(tree_assurance_level, hf_gn_st_field_assurelev_flags_reserved_bits, tvb, offset, 1, FALSE);
          }
          if ((assurance_level_flags & 0x03) != 0x00) {
            proto_tree_add_item(tree_assurance_level, hf_gn_st_field_assurelev_flags_confidence_bits, tvb, offset, 1, FALSE);
          }
	      offset += 1;
	      hdrlen -= 1;
	      attrlen -= 1;
	      break;
	    case 3:
	      // reconstruction value
	      sig_len = tree_gn_ecc_point(tvb, shfc_tree, offset);
	      offset += sig_len;
	      hdrlen -= sig_len;
	      attrlen -= sig_len;
	      break;
	    case 32:
	      // its aid list
	      // Get list size
	      aids_len_size = dissect_var_val(tvb, shfc_tree, offset, &aids_len);
	      proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, aids_len_size, aids_len);     
	      offset += aids_len_size;
	      hdrlen -= aids_len_size;
	      attrlen -= aids_len_size + aids_len;

	      // Loop through AID values
	      while (aids_len > 0) {
		int aids_size;
		int aids_val;
		
		aids_size = dissect_var_val(tvb, shfc_tree, offset, &aids_val);
		proto_tree_add_uint(shfc_tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);     
		aids_len -= aids_size;
		offset += aids_size;
		hdrlen -= aids_size;
	      }
	      
	      break;
	    case 33:
	      // its aid ssp list
	      // Get list size
	      aids_len_size = dissect_var_val(tvb, shfc_tree, offset, &aids_len);
	      proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, aids_len_size, aids_len);     
	      offset += aids_len_size;
	      hdrlen -= aids_len_size;
	      attrlen -= aids_len_size + aids_len;
	      
	      // Loop through AID values
	      while (aids_len > 0) {
		int aids_size;
		int aids_val;
		int ssp_len;
		int ssp_len_size;
		
		aids_size = dissect_var_val(tvb, shfc_tree, offset, &aids_val);
		proto_tree_add_uint(shfc_tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);     
		aids_len -= aids_size;
		offset += aids_size;
		hdrlen -= aids_size;
		
		ssp_len_size = dissect_var_val(tvb, shfc_tree, offset, &ssp_len);
		proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, ssp_len_size, ssp_len);     
		aids_len -= ssp_len_size;
		offset += ssp_len_size;
		hdrlen -= ssp_len_size;
		
		if (ssp_len) {
		  proto_tree_add_item(shfc_tree, hf_gn_st_opaque, tvb, offset, ssp_len, FALSE);
		  aids_len -= ssp_len;
		  offset += ssp_len;
		  hdrlen -= ssp_len;
		}
	      } // End of 'while' statement
	      
	      break;
	    case 34:
	      // priority its aid list
	      // Get list size
	      aids_len_size = dissect_var_val(tvb, shfc_tree, offset, &aids_len);
	      proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, aids_len_size, aids_len);     
	      offset += aids_len_size;
	      hdrlen -= aids_len_size;
	      attrlen -= aids_len_size + aids_len;
	      
	      // Loop through AID values
	      while (aids_len > 0) {
		int aids_size;
		int aids_val;
		
		aids_size = dissect_var_val(tvb, shfc_tree, offset, &aids_val);
		proto_tree_add_uint(shfc_tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);     
		aids_len -= aids_size;
		offset += aids_size;
		hdrlen -= aids_size;
		
		proto_tree_add_item(shfc_tree, hf_gn_sh_field_maxprio, tvb, offset, 1, FALSE);     
		aids_len -= 1;
		offset += 1;
		hdrlen -= 1;
		
	      }
	      
	      break;
	    case 35:
	      // priority ssp list
	      // Get list size
	      aids_len_size = dissect_var_val(tvb, shfc_tree, offset, &aids_len);
	      proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, aids_len_size, aids_len);     
	      offset += aids_len_size;
	      hdrlen -= aids_len_size;
	      attrlen -= aids_len_size + aids_len;
	      
	      // Loop through AID values
	      while (aids_len > 0) {
		int aids_size;
		int aids_val;
		int ssp_len;
		int ssp_len_size;
		
		aids_size = dissect_var_val(tvb, shfc_tree, offset, &aids_val);
		proto_tree_add_uint(shfc_tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);     
		aids_len -= aids_size;
		offset += aids_size;
		hdrlen -= aids_size;
		
		proto_tree_add_item(shfc_tree, hf_gn_sh_field_maxprio, tvb, offset, 1, FALSE);     
		aids_len -= 1;
		offset += 1;
		hdrlen -= 1;
		
		ssp_len_size = dissect_var_val(tvb, shfc_tree, offset, &ssp_len);
		proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, ssp_len_size, ssp_len);     
		aids_len -= ssp_len_size;
		offset += ssp_len_size;
		hdrlen -= ssp_len_size;
		
		if (ssp_len) {
		  proto_tree_add_item(shfc_tree, hf_gn_st_opaque, tvb, offset, ssp_len, FALSE);
		  aids_len -= ssp_len;
		  offset += ssp_len;
		  hdrlen -= ssp_len;
		}
	      } // End of 'while' statement
	      
	      break;
	    default:
	      break;
	    }
	  } // End 'while' statement
	}
	
	// validity restriction
	validr_len_size = dissect_var_val(tvb, shfc_tree, offset, &validr_len);
	proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, validr_len_size, validr_len);
	offset += validr_len_size;
	hdrlen -= validr_len_size;
	
	while (validr_len > 0) {
	  guint8 geor_type;
	  
	  validr_type = tvb_get_guint8(tvb, offset);
	  proto_tree_add_item(shfc_tree, hf_gn_sh_field_validityrestr_type, tvb, offset, 1, FALSE);
	  offset += 1;
	  hdrlen -= 1;
	  validr_len -= 1;
	  
	  switch (validr_type) {
	    guint16 off_size;
	    
	  case 0:
	    // time end
	    tree_gn_cert_time32(tvb, shfc_tree, hf_gn_sh_field_endtime, offset);
	    offset += 4;
	    hdrlen -= 4;
	    validr_len -= 4;
	    break;
	  case 1:
	    // time start and end
	    tree_gn_cert_time32(tvb, shfc_tree, hf_gn_sh_field_startendtime, offset);
	    offset += 4;
	    hdrlen -= 4;
	    validr_len -= 4;
	    tree_gn_cert_time32(tvb, shfc_tree, hf_gn_sh_field_endtime, offset);
	    offset += 4;
	    hdrlen -= 4;
	    validr_len -= 4;
	    break;
	  case 2:
	    // time start and duration
	    tree_gn_cert_time32(tvb, shfc_tree, hf_gn_sh_field_startduration, offset);
	    offset += 4;
	    hdrlen -= 4;
	    validr_len -= 4;
	    break;
	  case 3:
	    // region
	    geor_type = tvb_get_guint8(tvb, offset);
	    proto_tree_add_item(shfc_tree, hf_gn_sh_field_geo_region_type, tvb, offset, 1, FALSE);
	    offset += 1;
	    hdrlen -= 1;
	    validr_len -= 1;
	    
	    switch(geor_type) {
	      int local_region;
	      int local_region_size;
	      
	    case 0:
	      // none
	      break;
	    case 1:
	      // circle
	      off_size = tree_gn_2dpos(tvb, shfc_tree, offset);
	      offset += off_size;
	      hdrlen -= off_size;
	      validr_len -= off_size;
	      proto_tree_add_item(shfc_tree, hf_gn_sh_field_geo_circle_radius, tvb, offset, 2, FALSE);
	      offset += 2;
	      hdrlen -= 2;
	      validr_len -= 2;
	      break;
	    case 2: {
	      // rectangle
 	        int rectangle_len;
	        int rectangle_len_size;
         
            rectangle_len_size = dissect_var_val(tvb, shfc_tree, offset, &rectangle_len);
            proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, rectangle_len_size, rectangle_len);
            offset += rectangle_len_size;
            hdrlen -= rectangle_len_size;
            validr_len -= rectangle_len_size;
            
            while (rectangle_len > 0) {              
	      off_size = tree_gn_2dpos(tvb, shfc_tree, offset);
	      offset += off_size;
	      hdrlen -= off_size;
	      validr_len -= off_size;
              rectangle_len -= off_size;
	      off_size = tree_gn_2dpos(tvb, shfc_tree, offset);
	      offset += off_size;
	      hdrlen -= off_size;
	      validr_len -= off_size;
              rectangle_len -= off_size;
            } // End of 'while' statement
          }
	      break;
	    case 3: {
	      // polygon
 	        int poly_list_len;
	        int poly_list_len_size;
         
            poly_list_len_size = dissect_var_val(tvb, shfc_tree, offset, &poly_list_len);
            proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, poly_list_len_size, poly_list_len);
            offset += poly_list_len_size;
            hdrlen -= poly_list_len_size;
            validr_len -= poly_list_len_size;
	      
	      // Loop through Polygons values
	      while (poly_list_len > 0) {
		off_size = tree_gn_2dpos(tvb, shfc_tree, offset);
		offset += off_size;
		hdrlen -= off_size;
		poly_list_len -= off_size;
	      }
          }
	      break;
	    case 4:
	      // id
	      proto_tree_add_item(shfc_tree, hf_gn_sh_field_geo_region_dict, tvb, offset, 1, FALSE);
	      offset += 1;
	      hdrlen -= 1;
	      validr_len -= 1;
	      proto_tree_add_item(shfc_tree, hf_gn_sh_field_geo_region_id, tvb, offset, 2, FALSE);
	      offset += 2;
	      hdrlen -= 2;
	      validr_len -= 2;
	      local_region_size = dissect_var_val(tvb, shfc_tree, offset, &local_region);
	      proto_tree_add_uint(shfc_tree, hf_gn_sh_field_geo_region_local, tvb, offset, local_region_size, local_region);     
	      offset += local_region_size;
	      hdrlen -= local_region_size;
	      validr_len -= local_region_size;
	      break;
	    default:
	      break;
	    }
	    
	    break;
	  default: {
	    int data_len;
	    int data_len_size;
	    data_len_size = dissect_var_val(tvb, shfc_tree, offset, &data_len);
	    proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, data_len_size, data_len);     
	    offset += data_len_size;
	    hdrlen -= data_len_size;
	    validr_len -= data_len_size;
	  }
	    break;
	  }
	} // End of while (validr_len > 0)
	
	// signature
	siglen = tree_gn_signature(tvb, shfc_tree, offset);
	offset += siglen;
	hdrlen -= siglen;

      } // End block #2
    }// End block #1
  } // End of 'while' statement
     
	return opaque_len + opaque_len_size;
} // End of function tree_gn_cert

static int 
dissect_basic_header(tvbuff_t *tvb/*, packet_info *pinfo*/, proto_tree *tree, int offset)
{
  
  if(tree) {
    proto_tree *bh_tree = NULL;
    proto_item *bh_ti = NULL;
    proto_item *gn_lt_ti = NULL;
    proto_tree *gn_lt_tree = NULL;
    guint8 gn_lt_multiplier = 0;
    guint8 gn_lt_base = 0;
    
    /* === Basic Header tree === */
    bh_ti = proto_tree_add_item(tree, hf_gn_basicheader, tvb, offset, L_BH, FALSE);
    bh_tree = proto_item_add_subtree(bh_ti, ett_bh);
    
    /* Version & Next Header */
    proto_tree_add_item(bh_tree, hf_gn_version, tvb, offset, 1, FALSE); 
    proto_tree_add_item(bh_tree, hf_gn_bnh, tvb, offset, 1, FALSE); 
    offset += 1;
  
    /* Reserved */
    proto_tree_add_item(bh_tree, hf_gn_reserved, tvb, offset, 1, FALSE);     
    offset += 1;
    
    /* Lifetime */
    gn_lt_multiplier = (tvb_get_guint8(tvb, offset) & M_LT_MULTIPLIER) >> 2;
    gn_lt_base = tvb_get_guint8(tvb, offset) & M_LT_BASE;
    gn_lt_ti = proto_tree_add_item(bh_tree, hf_gn_lt, tvb, offset, 1, FALSE); 
    gn_lt_tree = proto_item_add_subtree(gn_lt_ti, ett_lt);
    proto_item_append_text(gn_lt_ti, " %d ms", gn_lt_multiplier * lifetime_base_values[gn_lt_base]);
    proto_tree_add_item(gn_lt_tree, hf_gn_lt_multiplier, tvb, offset, 1, FALSE);
    proto_tree_add_item(gn_lt_tree, hf_gn_lt_base, tvb, offset, 1, FALSE);
    offset += 1;
    
    /* Router Hop limit */
    proto_tree_add_item(bh_tree, hf_gn_hl, tvb, offset, 1, FALSE);
    offset += 1;
  } else {
    offset += L_BH;
  }

  return offset;
}

static int
dissect_unsecured_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint8 size = 0;
  guint8 header_type = 0;
  guint8 header_subtype = 0;
  guint8 gn_nh = 0;
  guint16 gn_pl = 0;
  const char *str_header_type = NULL;
  const char *str_header_subtype = NULL;
  tvbuff_t *next_tvb;
  dissector_table_t gn_nh_dissector_table;
  dissector_handle_t data_handle;
  int initial_offset = offset;
  
  /* Check that there's enough data */
  if(tvb_captured_length(tvb) < L_CH)
    return 0;

  /* Extract some header values */
  gn_nh = (tvb_get_guint8(tvb, offset + 0) & M_NH) >> 4;
  gn_pl = tvb_get_ntohs(tvb, offset + 4);
  header_type = (tvb_get_guint8(tvb, offset + 1) & M_HT) >> 4;
  header_subtype = (tvb_get_guint8(tvb, offset + 1) & M_HST);

  /* Update COL_INFO using header type */
  str_header_type = val_to_str(header_type, header_type_names, " (0x%02x)");
  col_add_str(pinfo->cinfo, COL_INFO, str_header_type);

  /* Compute length & display header subtype*/
  size = L_CH; /* Common Header */
  switch(header_type) {
  case 0: /* Any */
    break;
  case 1: /* Beacon */
    size += L_BEACON;
    break;
  case 2: /* GeoUnicast */
    size += L_GUC;
    break;
  case 3: /* GeoAnycast */
  case 4: /* GeoBroadcast */
    size += L_GBC;
    str_header_subtype = val_to_str(header_subtype, header_subtype_geoarea_names, " (0x%02x)");
    break;
  case 5: /* TSB */
    switch(header_subtype) {
    case 0: /* SHB */
      size += L_TSB_SGL;
      break;
    case 1: /* MultiHop */
      size += L_TSB_MUL;
      break;
    }
    str_header_subtype = val_to_str(header_subtype, header_subtype_tsb_names, " (0x%02x)");
    break;
  case 6: /* LS */
    size += L_LS;
    switch(header_subtype) {
    case 0: /* LS Request */
      size += L_LS_RQ;
      break;
    case 1: /* LS Reply */
      size += L_LS_RY;
      break;
    }
    str_header_subtype = val_to_str(header_subtype, header_subtype_ls_names, " (0x%02x)");
    break;
  }
  
  /* Update COL_INFO using header subtype */
  if(str_header_subtype) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", str_header_subtype);
  }

  /* Check if message is truncated */
  if((unsigned int)(size + gn_pl + offset) > (unsigned int)tvb_captured_length(tvb)) {
    col_append_str(pinfo->cinfo, COL_INFO, "[Truncated]");
  }

  if (tree) { /* we are being asked for details */
    proto_item *ti = NULL;
    //    proto_tree *gn_tree = NULL;
    proto_tree *ch_tree = NULL;
    proto_item *ch_ti = NULL;
    proto_item *ch_pl_ti = NULL;
    proto_item *ch_flags_ti = NULL;
    proto_tree *ch_flags_tree = NULL;
    proto_item *ch_tc_ti = NULL;
    proto_tree *ch_tc_tree = NULL;
    int hf_gn_hst = 0;

    ti = proto_tree_get_parent(tree);
    if(header_type < 3) {
      proto_item_append_text(ti, " (%s)", str_header_type);
    } else {
      proto_item_append_text(ti, " (%s %s)", str_header_type, str_header_subtype);
    }
    /* === Common Header tree === */
    ch_ti = proto_tree_add_item(tree, hf_gn_commonheader, tvb, offset, L_CH, FALSE);
    ch_tree = proto_item_add_subtree(ch_ti, ett_ch);

    /* Next Header & Reserved*/
    proto_tree_add_item(ch_tree, hf_gn_nh, tvb, offset, 1, FALSE); 
    proto_tree_add_item(ch_tree, hf_gn_reserved0, tvb, offset, 1, FALSE); 
    offset += 1;

    /* Header Type and Subtype */
    proto_tree_add_item(ch_tree, hf_gn_ht, tvb, offset, 1, FALSE); 
    switch(header_type) {
    case 3:
    case 4:
      hf_gn_hst = hf_gn_hst_geoarea;
      break;
    case 5:
      hf_gn_hst = hf_gn_hst_tsb;
      break;
    case 6:
      hf_gn_hst = hf_gn_hst_ls;
      break;
    case 0:
    case 1:
    case 2:
    default:
      hf_gn_hst = hf_gn_hst_unspecified;
      break;
    }
    proto_tree_add_item(ch_tree, hf_gn_hst, tvb, offset, 1, FALSE);     
    offset += 1;

    /* Traffic Class */
    ch_tc_ti = proto_tree_add_item(ch_tree, hf_gn_tc, tvb, offset, 1, FALSE);
    ch_tc_tree = proto_item_add_subtree(ch_tc_ti, ett_ch_tc);
    proto_tree_add_item(ch_tc_tree, hf_gn_tc_scf, tvb, offset, 1, FALSE);
    proto_tree_add_item(ch_tc_tree, hf_gn_tc_chanoff, tvb, offset, 1, FALSE);
    proto_tree_add_item(ch_tc_tree, hf_gn_tc_tcid, tvb, offset, 1, FALSE);
    offset += 1;

    /* Flags */ 
    ch_flags_ti = proto_tree_add_item(ch_tree, hf_gn_flags, tvb, offset, 1, FALSE); 
    ch_flags_tree = proto_item_add_subtree(ch_flags_ti, ett_ch_flags);
    proto_tree_add_item(ch_flags_tree, hf_gn_flags_mobile, tvb, offset, 1, FALSE); 
    proto_tree_add_item(ch_flags_tree, hf_gn_flags_reserved0, tvb, offset, 1, FALSE); 
    offset += 1;

    /* Payload length */
    ch_pl_ti = proto_tree_add_item(ch_tree, hf_gn_pl, tvb, offset, 2, FALSE); 
    if((unsigned int)(size + gn_pl + initial_offset) > (unsigned int)tvb_captured_length(tvb)) {
      expert_field ef = { PI_MALFORMED, PI_WARN };
      proto_item_append_text(ch_pl_ti, " [Truncated]");
      expert_add_info_format(pinfo, ch_pl_ti, &ef, 
			     "Payload is shorter than expected (actual length: %d bytes)", 
			     tvb_captured_length(tvb) - size);    
    }

    offset += 2;

    /* Maximum Hop limit */
    proto_tree_add_item(ch_tree, hf_gn_mhl, tvb, offset, 1, FALSE);
    offset += 1;

    /* Reserved */
    proto_tree_add_item(ch_tree, hf_gn_reserved1, tvb, offset, 1, FALSE);     
    offset += 1;

    /* === Beacon === */
    if(header_type == 1) {
      offset = tree_gn_sopv(tvb, tree, offset);
    }

    /* === GeoUnicast === */
    if(header_type == 2) {

      proto_item *guc_ti = NULL;
      proto_tree *guc_tree = NULL;

      /* GeoUnicast tree */
      guc_ti = proto_tree_add_item(tree, hf_gn_guc, tvb, offset, L_GUC, FALSE);
      guc_tree = proto_item_add_subtree(guc_ti, ett_guc);

      /* Extended Header Multihop */
      offset = tree_gn_ext_multihop(tvb, guc_tree, offset);

      /* DEPV */
      offset = tree_gn_depv(tvb, guc_tree, offset);      
    }

    /* GeoAnycast */
    if(header_type == 3) {

      proto_item *gac_ti = NULL;
      proto_tree *gac_tree = NULL;

      /* GeoAnycast tree */
      gac_ti = proto_tree_add_item(tree, hf_gn_gac, tvb, offset, L_GAC, FALSE);
      gac_tree = proto_item_add_subtree(gac_ti, ett_gac);

      /* Extended Header Multihop */
      offset = tree_gn_ext_multihop(tvb, gac_tree, offset);

      /* GeoArea */
      offset = tree_gn_ext_geoarea(tvb, gac_tree, offset);
    }

    /* GeoBroadcast */
    if(header_type == 4) {

      proto_item *gbc_ti = NULL;
      proto_tree *gbc_tree = NULL;

      /* GeoBroadcast tree */
      gbc_ti = proto_tree_add_item(tree, hf_gn_gbc, tvb, offset, L_GBC, FALSE);
      gbc_tree = proto_item_add_subtree(gbc_ti, ett_gbc);

      /* Extended Header Multihop */
      offset = tree_gn_ext_multihop(tvb, gbc_tree, offset);

      /* GeoArea */
      offset = tree_gn_ext_geoarea(tvb, gbc_tree, offset);
    }

    /* TSB */
    if(header_type == 5) {

      proto_item *tsb_ti = NULL;
      proto_tree *tsb_tree = NULL;

      tsb_ti = proto_tree_add_item(tree, hf_gn_tsb, tvb, offset, L_TSB_MUL, FALSE);
      tsb_tree = proto_item_add_subtree(tsb_ti, ett_tsb);

      /* TSB tree */
      if(header_subtype == 0) {
	offset = tree_gn_sopv(tvb, tsb_tree, offset);
	proto_tree_add_item(tsb_tree, hf_gn_tsb_reserved, tvb, offset, 4, FALSE);
	offset += 4;
      }
      if(header_subtype == 1) {	
	/* Extended Header Multihop */
	offset = tree_gn_ext_multihop(tvb, tsb_tree, offset);
      }
    }

    /* LS */
    if(header_type == 6) {

      proto_item *ls_ti = NULL;
      proto_tree *ls_tree = NULL;

      /* LS tree */
      ls_ti = proto_tree_add_item(tree, hf_gn_ls, tvb, offset, size - offset, FALSE);
      ls_tree = proto_item_add_subtree(ls_ti, ett_ls);

      /* Extended Header Multihop */
      offset = tree_gn_ext_multihop(tvb, ls_tree, offset);

      /* LS Request */
      if(header_subtype == 0) {
	proto_item *addr_ti = NULL;
	proto_tree *addr_tree = NULL;

	/* Target GN Address */
	addr_ti = proto_tree_add_item(ls_tree, hf_gn_ls_addr, tvb, offset, L_GN_ADDR, FALSE); 
	addr_tree = proto_item_add_subtree(addr_ti, ett_ls_addr);
	proto_tree_add_item(addr_tree, hf_gn_de_addr_m, tvb, offset, 2, FALSE); 
	proto_tree_add_item(addr_tree, hf_gn_de_addr_st, tvb, offset, 2, FALSE); 
	proto_tree_add_item(addr_tree, hf_gn_de_addr_scc, tvb, offset, 2, FALSE); 
	offset += 2;
	proto_tree_add_item(addr_tree, hf_gn_de_addr_mid, tvb, offset, 6, FALSE); 
	offset += 6;
      }
      
      /* LS Reply */
      if(header_subtype == 1) {
        offset = tree_gn_depv(tvb, ls_tree, offset);      
      }
    }
    tree = proto_tree_get_parent(tree);
  }

  /* call sub-dissector if any */
  next_tvb = tvb_new_subset_length(tvb, size + initial_offset, gn_pl);
  gn_nh_dissector_table = find_dissector_table("gn.nh");
  if(dissector_try_uint(gn_nh_dissector_table, gn_nh, next_tvb, pinfo, proto_tree_get_parent(tree))) {
    return size + gn_pl;
  }

  /* default to data dissector for remaining bytes */
  next_tvb = tvb_new_subset_length(tvb, size + initial_offset, gn_pl);
  data_handle = find_dissector("data");
  call_dissector(data_handle, next_tvb, pinfo, tree);

  return size + gn_pl;
} // End of function dissect_unsecured_packet

static int
dissect_ieee1609dot2_eccP256CurvePoint_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int hf, gint ett)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_eccP256CurvePoint_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett);
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_eccP256CurvePoint_packet: tag: '%x'\n", tag);
    offset += 1;
    if ((tag & 0x7f) == 0x00) { // Decode x-only
      proto_tree_add_item(sh_tree, hf_1609dot2_x_only, tvb, offset, 32, FALSE);
      offset += 32;
    } else if ((tag & 0x7f) == 0x02) { // Decode compressed-y-0
      proto_tree_add_item(sh_tree, hf_1609dot2_compressed_y_0, tvb, offset, 32, FALSE);
      offset += 32;
    } else if ((tag & 0x7f) == 0x03) { // Decode compressed-y-1
      proto_tree_add_item(sh_tree, hf_1609dot2_compressed_y_1, tvb, offset, 32, FALSE);
      offset += 32;
    } // TODO

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_eccP256CurvePoint_packet

static int
dissect_ieee1609dot2_eccP384CurvePoint_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int hf, gint ett)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_eccP384CurvePoint_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett);
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_eccP384CurvePoint_packet: tag: '%x'\n", tag);
    offset += 1;
    if ((tag & 0x7f) == 0x00) { // Decode x-only
      proto_tree_add_item(sh_tree, hf_1609dot2_x_only, tvb, offset, 48, FALSE);
      offset += 48;
    } else if ((tag & 0x7f) == 0x02) { // Decode compressed-y-0
      proto_tree_add_item(sh_tree, hf_1609dot2_compressed_y_0, tvb, offset, 48, FALSE);
      offset += 48;
    } else if ((tag & 0x7f) == 0x03) { // Decode compressed-y-1
      proto_tree_add_item(sh_tree, hf_1609dot2_compressed_y_1, tvb, offset, 48, FALSE);
      offset += 48;
    } // TODO

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_eccP384CurvePoint_packet

static int
dissect_ieee1609dot2_public_verification_key_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_public_verification_key_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint sh_len;
    guint8 tag;
    
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_public_verification_key, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_public_verification_key);

    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_verification_key_packet: tag: '%x'\n", tag);
    offset += 1;

    if ((tag & 0x7f) == 0x00) {
      offset = dissect_ieee1609dot2_eccP256CurvePoint_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecdsa_nistp_256, ett_1609dot2_public_verification_key);
    } else {
      offset = dissect_ieee1609dot2_eccP384CurvePoint_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecdsa_brainpoolp_384, ett_1609dot2_public_verification_key);
    }

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_public_verification_key_packet

static int
dissect_ieee1609dot2_verification_key_packet(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_verification_key_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint sh_len;
    guint8 tag;
    
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_verification_key, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_tbs_verification_key);

    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_verification_key_packet: tag: '%x'\n", tag);
    offset += 1;

    if ((tag & 0x7f) == 0x00) {
      offset = dissect_ieee1609dot2_public_verification_key_packet(tvb, pinfo, sh_tree, offset);
    }

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_verification_key_packet

static int
dissect_ieee1609dot2_base_public_encryption_key_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_base_public_encryption_key_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint sh_len;
    guint8 tag;
    
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_base_public_enc_key, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_base_public_enc_key);

    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_base_public_encryption_key_packet: tag: '%x'\n", tag);
    offset += 1;

    if ((tag & 0x7f) == 0x00) {
      offset = dissect_ieee1609dot2_eccP256CurvePoint_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecies_nistp_256, ett_1609dot2_base_public_enc_key);
    } else {
      offset = dissect_ieee1609dot2_eccP256CurvePoint_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecies_brainpoolp_256, ett_1609dot2_base_public_enc_key);
    }

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_base_public_encryption_key_packet

static int
dissect_ieee1609dot2_public_encryption_key_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_public_encryption_key_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint sh_len;

    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_public_enc_key, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_public_enc_key);

    /* SymmAlgorithm */
    proto_tree_add_item(sh_tree, hf_1609dot2_symm_algorithm, tvb, offset, 1, FALSE);
    offset += 1;
    /* BasePublicEncryptionKey */
    offset = dissect_ieee1609dot2_base_public_encryption_key_packet(tvb, pinfo, sh_tree, offset);

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_public_encryption_key_packet

static int
dissect_ieee1609dot2_issuerIdentifier_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_issuerIdentifier_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_issuerIdentifier_packet: tag: '%x'\n", tag);
    offset += 1;
    
    if ((tag & 0x7f) == 0x00) { // sha256AndDigest
      sh_ti = proto_tree_add_item(tree, hf_1609dot2_issuer_identifier, tvb, offset, 8, FALSE);
      sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_issuer_identifier);
      proto_tree_add_item(sh_tree, hf_1609dot2_sha256AndDigest, tvb, offset, 8, FALSE);
      offset += 8;
    } else if ((tag & 0x7f) == 0x01) { // self
      sh_ti = proto_tree_add_item(tree, hf_1609dot2_issuer_identifier, tvb, offset, 1, FALSE);
      sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_issuer_identifier);
      /* TODO NULL is 0 byte length */
    } else { // sha384AndDigest
      sh_ti = proto_tree_add_item(tree, hf_1609dot2_certificate_packet, tvb, offset, 8, FALSE);
      sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_issuer_identifier);
      proto_tree_add_item(sh_tree, hf_1609dot2_sha384AndDigest, tvb, offset, 8, FALSE);
      offset += 8;
    }
  }

  return offset;
} // End of function dissect_ieee1609dot2_issuerIdentifier_packet

static int
dissect_ieee1609dot2_certificate_id_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_certificate_id_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_certificate_id_packet: tag: '%x'\n", tag);
    offset += 1;
    if ((tag & 0x7f) == 0x01) { // name
      gint len;
      
      /* Sec Header tree - See IEEE Std 1609.2a-2017 */
      len = tvb_get_guint8(tvb, offset);
      offset += 1;
      printf("dissect_ieee1609dot2_certificate_id_packet: len = %d\n", len);
      sh_ti = proto_tree_add_item(tree, hf_1609dot2_certificate_packet_id, tvb, offset, len, FALSE);
      sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_tbs_certificate_packet_id);
      proto_tree_add_item(sh_tree, hf_1609dot2_certificate_packet_name, tvb, offset, len, FALSE);
      offset += len;
    } else if ((tag & 0x7f) == 0x03) {
      sh_ti = proto_tree_add_item(tree, hf_1609dot2_certificate_packet_id, tvb, offset, 1, FALSE);
      sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_tbs_certificate_packet_id);
      //proto_tree_add_item(sh_tree, hf_1609dot2_certificate_packet_none, tvb, offset, 1, FALSE);
      //offset += 1;
    } else {
      // TODO
    }
  }

  return offset;
} // End of function dissect_ieee1609dot2_certificate_id_packet

static int
dissect_ieee1609dot2_psid_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  printf(">>> dissect_ieee1609dot2_psid_packet: offset=0x%02x\n", offset);
  //printf("dissect_ieee1609dot2_psid_packet: %02x - %02x - %02x - %02x - %02x\n", tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1), tvb_get_guint8(tvb, offset + 2), tvb_get_guint8(tvb, offset + 3), tvb_get_guint8(tvb, offset + 4));
  if (tree) { /* we are being asked for details */
    //guint8 len;
    gint aids_size = 1;
    gint aids_val = 0;

    aids_size = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_psid_packet: aids_size in byte=%d\n", aids_size);
    offset += 1;
    if (aids_size == 1) {
      aids_val = tvb_get_guint8(tvb, offset);
    } else if (aids_size == 2) {
      aids_val = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    } else if (aids_size == 3) {
      aids_val = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN);
    } else {
      // TODO: Not reallistic
    }
    printf("dissect_ieee1609dot2_psid_packet: aids_val=%d\n", aids_val);
    proto_tree_add_uint(tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);
    offset += aids_size;
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_psid_packet

static int
dissect_ieee1609dot2_ssp_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_ssp_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_ssp_packet: tag: '%x'\n", tag);
    offset += 1;

    /* TODO Check if both case can be unified */
    /* Octetstring */
    if ((tag & 0x7f) == 0x00) {
      /*guint8 full_len;*/
      guint8 len;

      /*full_len = tvb_get_guint8(tvb, offset);
        printf("dissect_ieee1609dot2_ssp_packet: full_len=%d\n", full_len);*/
      offset += 1;
      len = tvb_get_guint8(tvb, offset);
      offset += 1;
      sh_ti = proto_tree_add_item(tree, hf_1609dot2_ssp_packet, tvb, offset, len, FALSE);
      sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_ssp_packet);
      proto_tree_add_item(sh_tree, hf_gn_st_opaque, tvb, offset, len, FALSE);
      offset += len;
    }
    /* SspBitmap */
    if ((tag & 0x7f) == 0x01) {
      /*guint8 full_len;*/
      guint8 len;

      /*full_len = tvb_get_guint8(tvb, offset);
        printf("dissect_ieee1609dot2_ssp_packet: full_len=%d\n", full_len);*/
      offset += 1;
      len = tvb_get_guint8(tvb, offset);
      printf("dissect_ieee1609dot2_ssp_packet: len=%d\n", len);
      offset += 1;
      sh_ti = proto_tree_add_item(tree, hf_1609dot2_ssp_packet, tvb, offset, len, FALSE);
      sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_ssp_packet);
      proto_tree_add_item(sh_tree, hf_1609dot2_ssp_bitmap_mask, tvb, offset, len, FALSE);
      offset += len;
    }
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_ssp_packet

static int
dissect_ieee1609dot2_psid_ssp_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  printf(">>> dissect_ieee1609dot2_psid_ssp_packet: offset=0x%02x\n", offset);
  
  if (tree) { /* we are being asked for details */
    guint8 tag;
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_psid_ssp_packet: tag: '%x'\n", tag);
    offset += 1;

    /* Psid */
    offset = dissect_ieee1609dot2_psid_packet(tvb, pinfo, tree, offset);
    /* Ssp */
    if (tag == 0x80) {
      offset = dissect_ieee1609dot2_ssp_packet(tvb, pinfo, tree, offset);
    }
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_psid_ssp_packet

static int
dissect_ieee1609dot2_appPermissions_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_appPermissions_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_len;
    guint8 items = 0;
    guint8 len = 0;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_app_permissions_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_app_permissions_packet);
    
    len = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: len=%d\n", len);
    offset += 1;
    if (len == 1) {
      items = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    } if (len == 2) {
      items = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } // else, not reallistic
    offset += len;
    printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: #items=%d\n", items);
    for (int i = 0; i < items; i++) {
      offset = dissect_ieee1609dot2_psid_ssp_packet(tvb, pinfo, sh_tree, offset);
    } // End of 'for' statement

    proto_item_set_len(sh_ti, offset - sh_len);
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_appPermissions_packet

static int
dissect_ieee1609dot2_2d_location_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_2d_location_packet: offset=0x%02x\n", offset);
  if (tree) {
    double coordinate = 0.0;
    gint32 tmp_ll = 0;
    
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_2d_location_packet, tvb, offset, 8, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_2d_location_packet);

    /* Latitude */
    tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
    coordinate = tmp_ll / 10000000.0;
    proto_tree_add_int_format_value(sh_tree, hf_gn_area_lat, tvb, offset, 4, tmp_ll,
				    "%02d°%02d'%02.2f\"%c (%d)",
				    abs((int)coordinate),
				    abs((int)((coordinate - (int)coordinate) * 60)),
				    fabs(fmod((coordinate - (int)coordinate) * 3600,60)),
				    (coordinate >= 0.0)?'N':'S',
				    tmp_ll
				    );
    offset += 4;
    
    /* Longitude */
    tmp_ll = (gint32)tvb_get_ntohl(tvb, offset);
    coordinate = tmp_ll / 10000000.0;
    proto_tree_add_int_format_value(sh_tree, hf_gn_area_long, tvb, offset, 4, tmp_ll,
				    "%02d°%02d'%02.2f\"%c (%d)",
				    abs((int)coordinate),
				    abs((int)((coordinate - (int)coordinate) * 60)),
				  fabs(fmod((coordinate - (int)coordinate) * 3600,60)),
				    (coordinate >= 0.0)?'E':'W',
				    tmp_ll
				    );
    offset += 4; 
  }

  return offset;
} // End of function dissect_ieee1609dot2_2d_location_packet

static int
dissect_ieee1609dot2_circular_region_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_circular_region_packet: offset=0x%02x\n", offset);
  if (tree) {
    gint sh_len;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_circular_region_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_circular_region_packet);
    
    /* center */
    offset = dissect_ieee1609dot2_2d_location_packet(tvb, pinfo, sh_tree, offset);
    /* radius */
    proto_tree_add_item(sh_tree, hf_gn_sh_field_geo_circle_radius, tvb, offset, 2, FALSE);
    offset += 2;

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_circular_region_packet

static int
dissect_ieee1609dot2_rectangle_region_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_rectangle_region_packet: offset=0x%02x\n", offset);
  if (tree) {
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_rectangle_region_packet, tvb, offset, 8, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_rectangle_region_packet);

    offset = dissect_ieee1609dot2_2d_location_packet(tvb, pinfo, sh_tree, offset);
    offset = dissect_ieee1609dot2_2d_location_packet(tvb, pinfo, sh_tree, offset);
  }

  return offset;
} // End of function dissect_ieee1609dot2_rectangle_region_packet

static int
dissect_ieee1609dot2_point_region_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_point_region_packet: offset=0x%02x\n", offset);
  if (tree) {
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_point_region_packet, tvb, offset, 8, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_point_region_packet);

    offset = dissect_ieee1609dot2_2d_location_packet(tvb, pinfo, sh_tree, offset);
  }

  return offset;
} // End of function dissect_ieee1609dot2_point_region_packet

static int
dissect_ieee1609dot2_country_region(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  /* proto_tree *sh_tree = NULL; */
  /* proto_item *sh_ti = NULL; */

  printf(">>> dissect_ieee1609dot2_country_region: offset=0x%02x\n", offset);
  if (tree) {
    guint8 tag;
    
    /* sh_ti = proto_tree_add_item(tree, hf_1609dot2_country_region, tvb, offset, 3, FALSE); */
    /* sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_country_region); */

    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_country_region: tag: '%x'\n", tag);
    offset += 1;

    if ((tag & 0x7f) == 0) { // CountryOnly
      proto_tree_add_item(tree, hf_1609dot2_country_region, tvb, offset, 2, FALSE);
      offset += 2;
    } else {
      // TODO regions: SequenceOfUint8
    }
  }

  return offset;
} // End of function dissect_ieee1609dot2_country_region

static int
dissect_ieee1609dot2_rectangular_region_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_rectangular_region_packet: offset=0x%02x\n", offset);
  if (tree) {
    guint sh_len = 0;
    guint len = 0;
    guint items = 0;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_rectangular_region_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_rectangular_region_packet);

    len = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    printf("dissect_ieee1609dot2_rectangular_region_packet: len=%d\n", len);
    offset += 1;
    if (len == 1) {
      items = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    } else if (len == 2) {
      items = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } else if (len == 3) {
      items = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } else if (len == 4) {
      items = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } // else, not reallistic
    offset += len;
    printf("dissect_ieee1609dot2_rectangular_region_packet: #items=%d\n", items);
    for (guint i = 0; i < items; i++) {
      offset = dissect_ieee1609dot2_2d_location_packet(tvb, pinfo, sh_tree, offset);
    } // End of 'for' statement

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_rectangular_region_packet

static int
dissect_ieee1609dot2_polygonal_region_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_polygonal_region_packet: offset=0x%02x\n", offset);
  if (tree) {
    guint sh_len = 0;
    guint len = 0;
    guint items = 0;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_polygonal_region_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_polygonal_region_packet);

    len = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    printf("dissect_ieee1609dot2_polygonal_region_packet: len=%d\n", len);
    offset += 1;
    if (len == 1) {
      items = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    } else if (len == 2) {
      items = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } else if (len == 3) {
      items = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } else if (len == 4) {
      items = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } // else, not reallistic
    offset += len;
    printf("dissect_ieee1609dot2_polygonal_region_packet: #items=%d\n", items);
    for (guint i = 0; i < items; i++) {
      offset = dissect_ieee1609dot2_point_region_packet(tvb, pinfo, sh_tree, offset);
    } // End of 'for' statement

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_polygonal_region_packet

static int
dissect_ieee1609dot2_identified_region_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_identified_region_packet: offset=0x%02x\n", offset);
  if (tree) {
    guint sh_len;
    guint len = 0;
    guint items = 0;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_identified_region_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_identified_region_packet);

    len = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    printf("dissect_ieee1609dot2_identified_region_packet: len=%d\n", len);
    offset += 1;
    if (len == 1) {
      items = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    } else if (len == 2) {
      items = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } else if (len == 3) {
      items = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } else if (len == 4) {
      items = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } // else, not reallistic
    offset += len;
    printf("dissect_ieee1609dot2_identified_region_packet: #items=%d\n", items);
    for (guint i = 0; i < items; i++) {
      offset = dissect_ieee1609dot2_country_region(tvb, pinfo, sh_tree, offset);
    } // End of 'for' statement

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_identified_region_packet

static int
dissect_ieee1609dot2_geographical_region_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_geographical_region_packet: offset=0x%02x\n", offset);
  if (tree) {
    guint8 tag;
    gint sh_len;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_geographical_region_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_geographical_region_packet);
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_geographical_region_packet: tag: '%x'\n", tag);
    offset += 1;

    if ((tag & 0x7f) == 0x00) {
      offset = dissect_ieee1609dot2_circular_region_packet(tvb, pinfo, sh_tree, offset);
    } else if ((tag & 0x7f) == 0x01) {
      offset = dissect_ieee1609dot2_rectangular_region_packet(tvb, pinfo, sh_tree, offset);
    } else if ((tag & 0x7f) == 0x03) {
      offset = dissect_ieee1609dot2_identified_region_packet(tvb, pinfo, sh_tree, offset);
    }

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_geographical_region_packet

static int
dissect_ieee1609dot2_toBeSignedCertificate_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_toBeSignedCertificate_packet: offset=0x%02x\n", offset);
  if (tree) {
    guint8 tag;
    gint sh_len;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_len = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_to_be_signed_certificate_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_tbs_certificate_packet);
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: tag: '%x'\n", tag);
    offset += 1;
    
    /* CertificateId */
    offset = dissect_ieee1609dot2_certificate_id_packet(tvb, pinfo, sh_tree, offset);
    
    /* HashedId3 */
    proto_tree_add_item(sh_tree, hf_gn_sh_field_hashedid3, tvb, offset, 3, FALSE);
    offset += 3;
    
    /* CrlSeries */
    proto_tree_add_item(sh_tree, hf_1609dot2_certificate_packet_crlseries, tvb, offset, 2, FALSE);
    offset += 2;
    
    /* ValidityPeriod */
    proto_tree_add_item(sh_tree, hf_1609dot2_validity_period, tvb, offset, 7, FALSE);
    offset += 7;

    if ((tag & 0x40) == 0x40) { /* region */
      printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: Process GeographicalRegion\n");
      offset = dissect_ieee1609dot2_geographical_region_packet(tvb, pinfo, sh_tree, offset);
    }
    if ((tag & 0x20) == 0x20) { /* assuranceLevel */
      printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: Process AssuranceLevel\n");
      proto_tree_add_item(sh_tree, hf_gn_st_field_assurelev, tvb, offset, 1, FALSE);
      offset += 1;
    }
    if ((tag & 0x10) == 0x10) { /* appPermissions */
      offset = dissect_ieee1609dot2_appPermissions_packet(tvb, pinfo, sh_tree, offset);
    }
    if ((tag & 0x08) == 0x08) { /* certIssuePermissions */
      printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: Process certIssuePermissions\n");
    }
    if ((tag & 0x04) == 0x04) { /* certRequestPermissions */
      printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: Process certRequestPermissions\n");
    }
    if ((tag & 0x02) == 0x02) { /* canRequestRollover */
      printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: Process canRequestRollover\n");
    }
    if ((tag & 0x01) == 0x01) { /* encryptionKey */
      printf("dissect_ieee1609dot2_toBeSignedCertificate_packet: Process encryptionKey\n");
      offset = dissect_ieee1609dot2_public_encryption_key_packet(tvb, pinfo, sh_tree, offset);
    }
    
    /* Verification key */
    offset = dissect_ieee1609dot2_verification_key_packet(tvb, pinfo, sh_tree, offset);

    proto_item_set_len(sh_ti, offset - sh_len);
  }

  return offset;
} // End of function dissect_ieee1609dot2_toBeSignedCertificate_packet

static int
dissect_ieee1609dot2_certificate_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_certificate_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    guint8 tag;
    
    //printf("dissect_ieee1609dot2_certificate_packet: %02x %02x %02x %02x %02x\n", tvb_get_guint8(tvb, offset),tvb_get_guint8(tvb, offset+1),tvb_get_guint8(tvb, offset+2),tvb_get_guint8(tvb, offset+3),tvb_get_guint8(tvb, offset+4));
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_certificate_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_certificate_packet);

    offset += 2; /* EtsiTs103097Certificate or SingleEtisTs103097Certificate */

    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_certificate_packet: tag: '%x'\n", tag);
    offset += 1;
    
    if ((tag & 0x7f) == 0x00) {
      /* Protocol version*/
      tag = tvb_get_guint8(tvb, offset);
      printf("dissect_ieee1609dot2_certificate_packet: version: '%x'\n", tag);
      proto_tree_add_item(sh_tree, hf_gn_sh_version, tvb, offset, 1, FALSE);
      offset += 1;
      
      /* Certificate type */
      tag = tvb_get_guint8(tvb, offset);
      printf("dissect_ieee1609dot2_certificate_packet: certificate_type: '%x'\n", tag);
      proto_tree_add_item(sh_tree, hf_1609dot2_certificate_packet_type, tvb, offset, 1, FALSE);
      offset += 1;
      
      // Issuer
      printf("dissect_ieee1609dot2_certificate_packet: Process Issuer\n");
      offset = dissect_ieee1609dot2_issuerIdentifier_packet(tvb, pinfo, sh_tree, offset);
      
      // ToBeSignedCertificate
      printf("dissect_ieee1609dot2_certificate_packet: Process ToBeSignedCertificate\n");
      offset = dissect_ieee1609dot2_toBeSignedCertificate_packet(tvb, pinfo, sh_tree, offset);
      
      // Signature
      if ((tag & 0x01) == 0x00) {
	printf("dissect_ieee1609dot2_certificate_packet: Process signature\n");
	offset = dissect_ieee1609dot2_signature_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_certificate_signature);
      }
    } else {
      // TODO
    }

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_certificate_packet

static int
dissect_ieee1609dot2_eccP256CurvePoint_r_sig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_eccP256CurvePoint_r_sig: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_r_sig, tvb, offset, 32, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_r_sig);
    
    offset = dissect_ieee1609dot2_eccP256CurvePoint_packet(tvb, pinfo, sh_tree, offset, hf, ett_1609dot2_r_sig);
  }

  return offset;
} // End of function dissect_ieee1609dot2_eccP256CurvePoint_r_sig

static int
dissect_ieee1609dot2_eccP384CurvePoint_r_sig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_eccP384CurvePoint_r_sig: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_r_sig, tvb, offset, 48, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_r_sig);
    
    offset = dissect_ieee1609dot2_eccP384CurvePoint_packet(tvb, pinfo, sh_tree, offset, hf, ett_1609dot2_r_sig);
  }

  return offset;
} // End of function dissect_ieee1609dot2_eccP384CurvePoint_r_sig

static int
dissect_ieee1609dot2_ecdsaNistP256Signature_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_ecdsaNistP256Signature_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signer_identifier_packet);

    // EccP256CurvePoint
    offset = dissect_ieee1609dot2_eccP256CurvePoint_r_sig(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecdsa_nistp_256);
    // OCTET STRING (SIZE (32))
    proto_tree_add_item(sh_tree, hf_1609dot2_s_sig, tvb, offset, 32, FALSE);
    offset += 32;

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_ecdsaNistP256Signature_packet

static int
dissect_ieee1609dot2_ecdsaBrainpoolP256Signature_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_ecdsaBrainpoolP256Signature_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signer_identifier_packet);

    // EccP256CurvePoint
    offset = dissect_ieee1609dot2_eccP256CurvePoint_r_sig(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecdsa_brainpoolp_256);
    // OCTET STRING (SIZE (32))
    proto_tree_add_item(sh_tree, hf_1609dot2_s_sig, tvb, offset, 32, FALSE);
    offset += 32;

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_ecdsaBrainpoolP256Signature_packet

static int
dissect_ieee1609dot2_ecdsaBrainpoolP384Signature_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_ecdsaBrainpoolP384Signature_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, sh_length, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signer_identifier_packet);

    // EccP384CurvePoint
    offset = dissect_ieee1609dot2_eccP384CurvePoint_r_sig(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecdsa_brainpoolp_384);
    // OCTET STRING (SIZE (48))
    proto_tree_add_item(sh_tree, hf_1609dot2_s_sig, tvb, offset, 48, FALSE);
    offset += 48;

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_ecdsaBrainpoolP384Signature_packet

static int
dissect_ieee1609dot2_signature_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_signature_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signer_identifier_packet);

    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_signature_packet: tag: '%x'\n", tag);
    offset += 1;
    
    if ((tag & 0x7f) == 0x00) {
      offset = dissect_ieee1609dot2_ecdsaNistP256Signature_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_to_be_signed_data_nistp256);
    } else if ((tag & 0x7f) == 0x01) {
      offset = dissect_ieee1609dot2_ecdsaBrainpoolP256Signature_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_to_be_signed_data_brainpoolp256);
    } else if ((tag & 0x7f) == 0x02) {
      offset = dissect_ieee1609dot2_ecdsaBrainpoolP384Signature_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_to_be_signed_data_brainpoolp384);
    }

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  return offset;
}

static int
dissect_ieee1609dot2_unsecured_data_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_unsecured_data_packet: offset=0x%02x\n", offset);
  //printf("dissect_ieee1609dot2_unsecured_data_packet: %02x - %02x - %02x - %02x - %02x\n", tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1), tvb_get_guint8(tvb, offset + 2), tvb_get_guint8(tvb, offset + 3), tvb_get_guint8(tvb, offset + 4));
  if (tree) { /* we are being asked for details */
    //guint8 tag;
    gint len;
    tvbuff_t *next_tvb;
    
    len = tvb_get_guint8(tvb, offset);
    offset += 1;
    printf("dissect_ieee1609dot2_unsecured_data_packet: len = %d - offset = %d\n", len, offset);
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_unsecured_data_packet, tvb, offset, len, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_unsecured_content);

    /* Dissect GN Packet */
    next_tvb = tvb_new_subset_length(tvb, offset, len);
    dissect_unsecured_packet(next_tvb, pinfo, sh_tree, 0);
    offset += len;
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_unsecured_data_packet

static int
dissect_ieee1609dot2_header_info_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_header_info_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_header_info_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_header_info_packet);
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_header_info_packet: tag: '%x'\n", tag);
    offset += 1;

    offset = dissect_ieee1609dot2_psid_packet(tvb, pinfo, sh_tree, offset);
    if ((tag & 0x40) == 0x40) { // Decode generation_time
      tree_gn_cert_time64(tvb, sh_tree, hf_gn_sh_field_gentime, offset);
      offset += 8;
    }
    if ((tag & 0x20) == 0x20) { // Decode expiry_time
      tree_gn_cert_time64(tvb, sh_tree, hf_gn_sh_field_exptime, offset);
      offset += 8;
    }
    /* TODO with 10, 08, 04, 02, 01
    if ((tag & 0x20) == 0x20) { // Decode generation_time
      tree_gn_cert_time64(tvb, sh_tree, hf_gn_sh_field_gentime, offset);
      offset += 8;
      }*/

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_header_info_packet

static int
dissect_ieee1609dot2_signed_data_payload_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_signed_data_payload_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_to_be_signed_data_payload_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signed_data_payload_packet);
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_signed_data_payload_packet: tag: '%x'\n", tag);
    offset += 1;
    offset = dissect_ieee1609dot2_data_packet(tvb, pinfo, sh_tree, offset);
    /* TODO offset = dissect_ieee1609dot2_hashed_data_packet(tvb, pinfo, sh_tree, offset); */

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_signed_data_payload_packet

static int
dissect_ieee1609dot2_to_be_signed_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_to_be_signed_data_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_to_be_signed_data_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_to_be_signed_data_packet);

    offset = dissect_ieee1609dot2_signed_data_payload_packet(tvb, pinfo, sh_tree, offset);
    offset = dissect_ieee1609dot2_header_info_packet(tvb, pinfo, sh_tree, offset);

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_to_be_signed_data_packet

static int
dissect_ieee1609dot2_signer_identifier_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_signer_identifier_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_signer_identifier_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signer_identifier_packet);

    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_signer_identifier_packet: tag: '%x'\n", tag);
    offset += 1;
    if ((tag & 0x7f) == 0x00) {
      proto_tree_add_item(sh_tree, hf_gn_sh_field_hashedid8, tvb, offset, 8, FALSE);
      offset += 8;
    } else if ((tag & 0x7f) == 0x01) {
      offset = dissect_ieee1609dot2_certificate_packet(tvb, pinfo, sh_tree, offset);
    } else if ((tag & 0x7f) == 0x02) {
      proto_tree_add_item(tree, hf_gn_sh_field_self, tvb, offset, 1, FALSE);
      //offset += 1;
    }

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_signer_identifier_packet

static int
dissect_ieee1609dot2_signed_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_signed_data_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    /* guint8 tag; */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_signed_data_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signed_data_packet);

    /* HashAlgoritm */
    /* tag = tvb_get_guint8(tvb, offset); */
    proto_tree_add_item(sh_tree, hf_1609dot2_hash_algorithm, tvb, offset, 1, FALSE);
    offset += 1;
    
    offset = dissect_ieee1609dot2_to_be_signed_data_packet(tvb, pinfo, sh_tree, offset);
    offset = dissect_ieee1609dot2_signer_identifier_packet(tvb, pinfo, sh_tree, offset);
    offset = dissect_ieee1609dot2_signature_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_to_be_signed_data);

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  printf("dissect_ieee1609dot2_signed_data_packet: certificate_type: Process Signature: offset=0x%02x\n", offset);
  return offset;
} // End of function dissect_ieee1609dot2_signed_data_packet

static int
dissect_ieee1609dot2_encrypted_data_packet(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int offset)
{
  return offset;
} // End of dissect_ieee1609dot2_encrypted_data_packet

static int
dissect_ieee1609dot2_content_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_content_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length =  offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_content_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_content_packet);
    
    /* Choice Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_content_packet: tag: '%x'\n", tag);
    offset += 1;
    
    if ((tag & 0x7f) == 0x00) {
      offset = dissect_ieee1609dot2_unsecured_data_packet(tvb, pinfo, sh_tree, offset);
    } else if ((tag & 0x7f) == 0x01) {
      offset = dissect_ieee1609dot2_signed_data_packet(tvb, pinfo, sh_tree, offset);
    } else if ((tag & 0x7f) == 0x02) {
      offset = dissect_ieee1609dot2_encrypted_data_packet(tvb, pinfo, sh_tree, offset);
    } else {
      /* TODO: signedCertificateRequest */
    }

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_content_packet

static int
dissect_ieee1609dot2_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_data_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_secured_message, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_data_packet);
    
    /* Protocol version*/
    proto_tree_add_item(sh_tree, hf_gn_sh_version, tvb, offset, 1, FALSE);
    offset += 1;
    /* Content */
    offset = dissect_ieee1609dot2_content_packet(tvb, pinfo, sh_tree, offset);
    proto_item_set_len(sh_ti, offset - sh_length);    
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_data_packet

/* Dissector for SecuredMessage - See Draft ETSI TS 103 097 V1.1.13 Clause 5 Specifications of security header */
static int
dissect_secured_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_tree *shf_tree = NULL;
  proto_tree *shfc_tree = NULL;
  proto_tree *st_tree = NULL;
  proto_item *sh_ti = NULL;
  proto_item *shf_ti = NULL;
  proto_item *shfc_ti = NULL;
  proto_item *st_ti = NULL;
  tvbuff_t *next_tvb;
  gint bytes;
  gint hdrlen;
  gint hdroffset;
  gint gn_sh_hdrlen = 0;
  gint gn_pl_len = -1;
  gint gn_draft_ver = 0;
  gint tlrlen;
  gint tlroffset;
  gint tlr_type;
  
  gint opaque_len;
  gint opaque_len_size;

  if (tree) { /* we are being asked for details */

    guint sec_hdr_len = tvb_get_guint8(tvb, offset + 2) + 8;
    
    /* Sec Header tree - See Draft ETSI TS 103 097 V1.1.13 Clause 5 Specification os security header */
    sh_ti = proto_tree_add_item(tree, hf_gn_sh, tvb, offset, sec_hdr_len, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_sh);
  
    /* Sec header ver */
    proto_tree_add_item(sh_tree, hf_gn_sh_version, tvb, offset, 1, FALSE);
    offset += 1;
  
    /* Sec header length - See Draft ETSI TS 103 097 V1.1.13 Clause 5.3 HeaderField */
    hdroffset = dissect_var_val(tvb, sh_tree, offset, &hdrlen);
    proto_tree_add_uint(sh_tree, hf_gn_sh_len, tvb, offset, hdroffset, hdrlen);     
    offset += hdroffset;
  
    gn_sh_hdrlen += hdroffset; // count this header size
    gn_sh_hdrlen += hdrlen; // count data in header
  
    /* Sec Header Field tree */
    shf_ti = proto_tree_add_item(sh_tree, hf_gn_sh_field, tvb, offset, hdrlen, FALSE);
    shf_tree = proto_item_add_subtree(shf_ti, ett_shf);
  
    // loop through each secure header item
    while (hdrlen > 0) {
      guint8 hdrfld_type;
      guint8 signinfo_type;
      guint8 subjattr_type;
      guint8 validr_type;
      int extralen;
      int extraoffset;
      int validr_len;
      int validr_len_size;
      int off_size;
    
      /* Header Field Type */
      hdrfld_type = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(shf_tree, hf_gn_sh_field_type, tvb, offset, 1, FALSE);     
      offset += 1;
      hdrlen -= 1;

      /* Header Field value */
      switch (hdrfld_type) {
      case 0:
	// gen time
	tree_gn_cert_time64(tvb, shf_tree, hf_gn_sh_field_gentime, offset);
	offset += 8;
	hdrlen -= 8;
	break;
      case 1:
	// gen time and confidence
	tree_gn_cert_time64(tvb, shf_tree, hf_gn_sh_field_gentime, offset);
	offset += 8;
	hdrlen -= 8;
	proto_tree_add_item(shf_tree, hf_gn_sh_field_gentimestddev, tvb, offset, 1, FALSE);     
	offset += 1;
	hdrlen -= 1;
	break;
      case 2:
	// expiration
	tree_gn_cert_time32(tvb, shf_tree, hf_gn_sh_field_exptime, offset);
	offset += 4;
	hdrlen -= 4;
	break;
      case 3:
	// gen location
    off_size = tree_gn_3dpos(tvb, shf_tree, offset);
	offset += off_size;
	hdrlen -= off_size;
	break;
      case 4: {
	// req unrecognised certificate
    offset += tree_hashedId3_list(tvb, shf_tree, offset);
	break;
      }
      case 5: {
	// itsaid
	extraoffset = dissect_var_val(tvb, shfc_tree, offset, &extralen);
	proto_tree_add_uint(shf_tree, hf_gn_sh_field_itsaid, tvb, offset, extraoffset, extralen);     
	offset += extraoffset;
	hdrlen -= extraoffset;
      }
	break;
      case 6:
	// trust data (DRAFT ONLY)
	extraoffset = dissect_var_val(tvb, st_tree, offset, &extralen);
	proto_tree_add_uint(shf_tree, hf_gn_st_opaque, tvb, offset, extraoffset, extralen);
	offset += extraoffset;
	hdrlen -= extraoffset;
	break;
      case 7:
	// certificate request
	extraoffset = dissect_var_val(tvb, st_tree, offset, &extralen);
	proto_tree_add_uint(shf_tree, hf_gn_st_opaquelen, tvb, offset, extraoffset, extralen);     
	offset += extraoffset;
	hdrlen -= extraoffset;
	proto_tree_add_item(shf_tree, hf_gn_st_opaque, tvb, offset, extralen, FALSE);
	offset += extralen;
	hdrlen -= extralen;
	break;
      case 128:
	// signer info
	signinfo_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(shf_tree, hf_gn_sh_field_signinfo_type, tvb, offset, 1, FALSE);     
	offset += 1;
	hdrlen -= 1;
      
	switch (signinfo_type) {
	  int attrlen;
	  int opaqlen;
	  int siglen;
	  int certchainlen;

	case 0:
	  // self
	  break;
	case 1:
	  // cert digest with ecdsap256
	  proto_tree_add_item(shf_tree, hf_gn_sh_field_hashedid8, tvb, offset, 8, FALSE);
	  offset += 8;
	  hdrlen -= 8;
	  break;
	case 2:
	  // cert
	  // version
	  shfc_ti = proto_tree_add_item(shf_tree, hf_gn_sh_field_cert, tvb, offset, hdrlen, FALSE);
	  shfc_tree = proto_item_add_subtree(shfc_ti, ett_shfc);
	  proto_tree_add_item(shfc_tree, hf_gn_sh_version, tvb, offset, 1, FALSE);
	  offset += 1;
	  hdrlen -= 1;
	
	  // signer info
	  /*extraoffset = dissect_var_val(tvb, shfc_tree, offset, &extralen);
	  proto_tree_add_uint(shfc_tree, hf_gn_st_signinfolen, tvb, offset, extraoffset, extralen);     
	  offset += extraoffset;
	  hdrlen -= extraoffset;*/
	
	  signinfo_type = tvb_get_guint8(tvb, offset);
	  proto_tree_add_item(shfc_tree, hf_gn_sh_field_signinfo_type, tvb, offset, 1, FALSE);
	  offset += 1;
	  hdrlen -= 1;
	  //extralen -= 1;
	
	  switch (signinfo_type) {
	  case 0:
	    // self
	    //offset += extralen;
	    //hdrlen -= extralen;
	    break;
	  case 1:
	    // cert digest with ecdsap256
	    proto_tree_add_item(shfc_tree, hf_gn_sh_field_hashedid8, tvb, offset, 8, FALSE);
	    offset += 8;
	    hdrlen -= 8;
	    break;
	  case 2:
	    // cert
	    //offset += extralen;
	    //hdrlen -= extralen;
	    break;
	  case 3:
	    // cert chain
	    //offset += extralen;
	    //hdrlen -= extralen;
	    break;
	  case 4:
	    // cert digest with other alg
	    //offset += extralen;
	    //hdrlen -= extralen;
	    break;
	  default:
	    //offset += extralen;
	    //hdrlen -= extralen;
	    break;
	  } // End of 'switch' statement
	
	  // subject info
	  proto_tree_add_item(shfc_tree, hf_gn_sh_field_subject_type, tvb, offset, 1, FALSE);
	  offset += 1;
	  hdrlen -= 1;
	
	  extraoffset = dissect_var_val(tvb, shfc_tree, offset, &opaqlen);
	  proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, extraoffset, opaqlen);     
	  offset += extraoffset;
	  hdrlen -= extraoffset;
	
	  if (opaqlen) {
	    // Should be max 32 octets
	    proto_tree_add_item(shfc_tree, hf_gn_st_opaque, tvb, offset, opaqlen, FALSE);
	    offset += opaqlen;
	    hdrlen -= opaqlen;
	  }
	
	  // subject attribute
	  extraoffset = dissect_var_val(tvb, shfc_tree, offset, &attrlen);
	  proto_tree_add_uint(shfc_tree, hf_gn_st_subjectattrlen, tvb, offset, extraoffset, attrlen);     
	  offset += extraoffset;
	  hdrlen -= extraoffset;
	
	  if (attrlen) {
        proto_tree *tree_assurance_level = NULL;
        proto_item *ti_assurance_level = NULL;
        guint8 assurance_level_flags = -1;
        
	    while (attrlen > 0) {
	      subjattr_type = tvb_get_guint8(tvb, offset);
	      proto_tree_add_item(shfc_tree, hf_gn_sh_field_subjectattr_type, tvb, offset, 1, FALSE);
	      offset += 1;
	      hdrlen -= 1;
	      attrlen -= 1;
	    
	      switch (subjattr_type) {
		int aids_len;
		int aids_len_size;
		int sig_len;
	      
	      case 0:
		// verification key
	      case 1:
		// encryption key
		sig_len = tree_gn_publickey(tvb, shfc_tree, offset);
		offset += sig_len;
		hdrlen -= sig_len;
		attrlen -= sig_len;
		break;
	      case 2:
		// assurance level
	      ti_assurance_level = proto_tree_add_item(shfc_tree, hf_gn_st_field_assurelev, tvb, offset, 1, FALSE); 
          tree_assurance_level = proto_item_add_subtree(ti_assurance_level, ett_assurance_level_flags);
          assurance_level_flags = tvb_get_guint8(tvb, offset);
          if ((assurance_level_flags & 0xe0) != 0x00) {
            proto_tree_add_item(tree_assurance_level, hf_gn_st_field_assurelev_flags_levels_bits, tvb, offset, 1, FALSE);
          }
          if ((assurance_level_flags & 0x1c) != 0x00) {
            proto_tree_add_item(tree_assurance_level, hf_gn_st_field_assurelev_flags_reserved_bits, tvb, offset, 1, FALSE);
          }
          if ((assurance_level_flags & 0x03) != 0x00) {
            proto_tree_add_item(tree_assurance_level, hf_gn_st_field_assurelev_flags_confidence_bits, tvb, offset, 1, FALSE);
          }
		offset += 1;
		hdrlen -= 1;
		attrlen -= 1;
		break;
	      case 3:
		// reconstruction value
		sig_len = tree_gn_ecc_point(tvb, shfc_tree, offset);
		offset += sig_len;
		hdrlen -= sig_len;
		attrlen -= sig_len;
		break;
	      case 32:
		// its aid list
		// Get list size
		aids_len_size = dissect_var_val(tvb, shfc_tree, offset, &aids_len);
		proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, aids_len_size, aids_len);     
		offset += aids_len_size;
		hdrlen -= aids_len_size;
		attrlen -= aids_len_size + aids_len;

		// Loop through AID values
		while (aids_len > 0) {
		  int aids_size;
		  int aids_val;
		
		  aids_size = dissect_var_val(tvb, shfc_tree, offset, &aids_val);
		  proto_tree_add_uint(shfc_tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);     
		  aids_len -= aids_size;
		  offset += aids_size;
		  hdrlen -= aids_size;
		}
	      
		break;
	      case 33:
		// its aid ssp list
		// Get list size
		aids_len_size = dissect_var_val(tvb, shfc_tree, offset, &aids_len);
		proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, aids_len_size, aids_len);     
		offset += aids_len_size;
		hdrlen -= aids_len_size;
		attrlen -= aids_len_size + aids_len;
	      
		// Loop through AID values
		while (aids_len > 0) {
		  int aids_size;
		  int aids_val;
		  int ssp_len;
		  int ssp_len_size;
		
		  aids_size = dissect_var_val(tvb, shfc_tree, offset, &aids_val);
		  proto_tree_add_uint(shfc_tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);     
		  aids_len -= aids_size;
		  offset += aids_size;
		  hdrlen -= aids_size;
		
		  ssp_len_size = dissect_var_val(tvb, shfc_tree, offset, &ssp_len);
		  proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, ssp_len_size, ssp_len);     
		  aids_len -= ssp_len_size;
		  offset += ssp_len_size;
		  hdrlen -= ssp_len_size;
		
		  if (ssp_len) {
		    proto_tree_add_item(shfc_tree, hf_gn_st_opaque, tvb, offset, ssp_len, FALSE);
		    aids_len -= ssp_len;
		    offset += ssp_len;
		    hdrlen -= ssp_len;
		  }
		}
	      
		break;
	      case 34:
		// priority its aid list
		// Get list size
		aids_len_size = dissect_var_val(tvb, shfc_tree, offset, &aids_len);
		proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, aids_len_size, aids_len);     
		offset += aids_len_size;
		hdrlen -= aids_len_size;
		attrlen -= aids_len_size + aids_len;
	      
		// Loop through AID values
		while (aids_len > 0) {
		  int aids_size;
		  int aids_val;
		
		  aids_size = dissect_var_val(tvb, shfc_tree, offset, &aids_val);
		  proto_tree_add_uint(shfc_tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);     
		  aids_len -= aids_size;
		  offset += aids_size;
		  hdrlen -= aids_size;
		
		  proto_tree_add_item(shfc_tree, hf_gn_sh_field_maxprio, tvb, offset, 1, FALSE);     
		  aids_len -= 1;
		  offset += 1;
		  hdrlen -= 1;
		
		}
	      
		break;
	      case 35:
		// priority ssp list
		// Get list size
		aids_len_size = dissect_var_val(tvb, shfc_tree, offset, &aids_len);
		proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, aids_len_size, aids_len);     
		offset += aids_len_size;
		hdrlen -= aids_len_size;
		attrlen -= aids_len_size + aids_len;
	      
		// Loop through AID values
		while (aids_len > 0) {
		  int aids_size;
		  int aids_val;
		  int ssp_len;
		  int ssp_len_size;
		
		  aids_size = dissect_var_val(tvb, shfc_tree, offset, &aids_val);
		  proto_tree_add_uint(shfc_tree, hf_gn_st_aid_val, tvb, offset, aids_size, aids_val);     
		  aids_len -= aids_size;
		  offset += aids_size;
		  hdrlen -= aids_size;
		
		  proto_tree_add_item(shfc_tree, hf_gn_sh_field_maxprio, tvb, offset, 1, FALSE);     
		  aids_len -= 1;
		  offset += 1;
		  hdrlen -= 1;
		
		  ssp_len_size = dissect_var_val(tvb, shfc_tree, offset, &ssp_len);
		  proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, ssp_len_size, ssp_len);     
		  aids_len -= ssp_len_size;
		  offset += ssp_len_size;
		  hdrlen -= ssp_len_size;
		
		  if (ssp_len) {
		    proto_tree_add_item(shfc_tree, hf_gn_st_opaque, tvb, offset, ssp_len, FALSE);
		    aids_len -= ssp_len;
		    offset += ssp_len;
		    hdrlen -= ssp_len;
		  }
		}
	      
		break;
	      default:
		break;
	      }
	    }
	  }
	
	  // validity restriction
	  validr_len_size = dissect_var_val(tvb, shfc_tree, offset, &validr_len);
	  proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, validr_len_size, validr_len);
	  offset += validr_len_size;
	  hdrlen -= validr_len_size;
	
	  while (validr_len > 0) {
	    guint8 geor_type;
	  
	    validr_type = tvb_get_guint8(tvb, offset);
	    proto_tree_add_item(shfc_tree, hf_gn_sh_field_validityrestr_type, tvb, offset, 1, FALSE);
	    offset += 1;
	    hdrlen -= 1;
	    validr_len -= 1;
	  
	    switch (validr_type) {
	      guint16 off_size_;
	    
	    case 0:
	      // time end
	      tree_gn_cert_time32(tvb, shfc_tree, hf_gn_sh_field_endtime, offset);
	      offset += 4;
	      hdrlen -= 4;
	      validr_len -= 4;
	      break;
	    case 1:
	      // time start and end
	      tree_gn_cert_time32(tvb, shfc_tree, hf_gn_sh_field_starttime, offset);
	      offset += 4;
	      hdrlen -= 4;
	      validr_len -= 4;
	      tree_gn_cert_time32(tvb, shfc_tree, hf_gn_sh_field_startendtime, offset);
	      offset += 4;
	      hdrlen -= 4;
	      validr_len -= 4;
	      break;
	    case 2:
	      // time start and duration
	      tree_gn_cert_time32(tvb, shfc_tree, hf_gn_sh_field_starttime, offset);
	      offset += 4;
	      hdrlen -= 4;
	      validr_len -= 4;
	      break;
	    case 3:
	      // region
	      geor_type = tvb_get_guint8(tvb, offset);
	      proto_tree_add_item(shfc_tree, hf_gn_sh_field_geo_region_type, tvb, offset, 1, FALSE);
	      offset += 1;
	      hdrlen -= 1;
	      validr_len -= 1;
	    
	      switch(geor_type) {
		int local_region;
		int local_region_size;
	      
	      case 0:
		// none
		break;
	      case 1:
		// circle
		off_size_ = tree_gn_2dpos(tvb, shfc_tree, offset);
		offset += off_size_;
		hdrlen -= off_size_;
		validr_len -= off_size_;
		proto_tree_add_item(shfc_tree, hf_gn_sh_field_geo_circle_radius, tvb, offset, 2, FALSE);
		offset += 2;
		hdrlen -= 2;
		validr_len -= 2;
		break;
	      case 2: {
		// rectangle
 	        int rectangle_len;
	        int rectangle_len_size;
         
            rectangle_len_size = dissect_var_val(tvb, shfc_tree, offset, &rectangle_len);
            proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, rectangle_len_size, rectangle_len);
            offset += rectangle_len_size;
            hdrlen -= rectangle_len_size;
            validr_len -= rectangle_len_size;
            
            while (rectangle_len > 0) {              
		off_size_ = tree_gn_2dpos(tvb, shfc_tree, offset);
		offset += off_size_;
		hdrlen -= off_size_;
		validr_len -= off_size_;
              rectangle_len -= off_size_;
		off_size_ = tree_gn_2dpos(tvb, shfc_tree, offset);
		offset += off_size_;
		hdrlen -= off_size_;
		validr_len -= off_size_;
              rectangle_len -= off_size_;
            } // End of 'while' statement
          }
		break;
	      case 3: {
		// polygon
 	        int poly_list_len;
	        int poly_list_len_size;
         
            poly_list_len_size = dissect_var_val(tvb, shfc_tree, offset, &poly_list_len);
            proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, poly_list_len_size, poly_list_len);
            offset += poly_list_len_size;
            hdrlen -= poly_list_len_size;
            validr_len -= poly_list_len_size;
	      
		// Loop through Polygons values
		while (poly_list_len > 0) {
		  off_size_ = tree_gn_2dpos(tvb, shfc_tree, offset);
		  offset += off_size_;
		  hdrlen -= off_size_;
		  poly_list_len -= off_size_;
		}
          }
		break;
	      case 4:
		// id
		proto_tree_add_item(shfc_tree, hf_gn_sh_field_geo_region_dict, tvb, offset, 1, FALSE);
		offset += 1;
		hdrlen -= 1;
		validr_len -= 1;
		proto_tree_add_item(shfc_tree, hf_gn_sh_field_geo_region_id, tvb, offset, 2, FALSE);
		offset += 2;
		hdrlen -= 2;
		validr_len -= 2;
		local_region_size = dissect_var_val(tvb, shfc_tree, offset, &local_region);
		proto_tree_add_uint(shfc_tree, hf_gn_sh_field_geo_region_local, tvb, offset, local_region_size, local_region);     
		offset += local_region_size;
		hdrlen -= local_region_size;
		validr_len -= local_region_size;
		break;
	      default:
		break;
	      }
	    
	      break;
	    default: {
	      int data_len;
	      int data_len_size;
	      data_len_size = dissect_var_val(tvb, shfc_tree, offset, &data_len);
	      proto_tree_add_uint(shfc_tree, hf_gn_st_opaquelen, tvb, offset, data_len_size, data_len);     
	      offset += data_len_size;
	      hdrlen -= data_len_size;
	      validr_len -= data_len_size;
	    }
	      break;
	    } // End of 'switch' statement
	  } // End of while (validr_len > 0)
	
	  // signature
	  siglen = tree_gn_signature(tvb, shfc_tree, offset);
	  offset += siglen;
	  hdrlen -= siglen;
	  break;
	case 3:
	  // cert chain
	  certchainlen = tree_gn_cert(tvb, shf_tree, offset);
	  offset += certchainlen;
	  hdrlen -= certchainlen;
	  break;
	case 4:
	  // cert digest with other alg
	  proto_tree_add_item(shf_tree, hf_gn_sh_field_pk_alg, tvb, offset, 1, FALSE);
	  offset += 1;
	  hdrlen -= 1;
	  proto_tree_add_item(shf_tree, hf_gn_sh_field_hashedid8, tvb, offset, 8, FALSE);
	  offset += 8;
	  hdrlen -= 8;
	  break;
	}
	break;
      case 129:
	// TODO encryption params
	break;
      case 130:
	// TODO recepient info
	break;
      }  
    }

    /* Payload Type - See Draft ETSI TS 103 097 V1.1.13 Clause 5.2 Payload */
    proto_tree_add_item(sh_tree, hf_gn_shpl_type, tvb, offset, 1, FALSE);     
    offset += 1;
    gn_sh_hdrlen += 1;
  
    /* Payload data length */
    hdroffset = dissect_var_val(tvb, sh_tree, offset, &hdrlen);
    proto_tree_add_uint(sh_tree, hf_gn_shpl_datalen, tvb, offset, hdroffset, hdrlen);     
    offset += hdroffset;
    gn_sh_hdrlen += hdroffset; // count this header size
  
    /* Remember size of payload i.e. BTP/CAM/... */
    gn_pl_len = hdrlen;
  
    /* Dissect GN Packet */
    next_tvb = tvb_new_subset_length(tvb, offset, gn_pl_len);
    offset += dissect_unsecured_packet(next_tvb, pinfo, tree, 0);

    /* Secure Trailer */
    /* Let user know that packet is secured */
    col_append_str(pinfo->cinfo, COL_INFO, "[Secured]");
  
    if(gn_draft_ver) {
      col_append_str(pinfo->cinfo, COL_INFO, "[DRAFT!]");
    }

    /* What is used in BTP/Facilities */ 
    //    bytes = tvb_reported_length(tvb) - offset;
    bytes = offset;

    /* Sec Trailer tree */
    st_ti = proto_tree_add_item(tree, hf_gn_st, tvb, bytes, -1, FALSE);
    st_tree = proto_item_add_subtree(st_ti, ett_st);
  
    /* Sec Trailer length */
    tlroffset = dissect_var_val(tvb, st_tree, offset, &tlrlen);
    proto_tree_add_uint(st_tree, hf_gn_st_len, tvb, offset, tlroffset, tlrlen);     
    offset += tlroffset;
  
    /* Sec Trailer Type */
    tlr_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(st_tree, hf_gn_st_type, tvb, offset, 1, FALSE);     
    offset += 1;
    switch (tlr_type) {
    case 0:
      // signer info (DRAFT) - just dump
      proto_tree_add_item(st_tree, hf_gn_st_opaque, tvb, offset, -1, FALSE);     
      break;
    case 1:
      // signature
      offset += tree_gn_signature(tvb, st_tree, offset);
      break;
    default:
      opaque_len_size = dissect_var_val(tvb, st_tree, offset, &opaque_len);
      proto_tree_add_uint(st_tree, hf_gn_st_opaquelen, tvb, offset, opaque_len_size, opaque_len);     
      offset += opaque_len_size;
      proto_tree_add_item(st_tree, hf_gn_st_opaque, tvb, offset, opaque_len, FALSE);     
      offset += opaque_len;
      break;
    }
  }  

  return offset;
} // End of function dissect_secured_packet

/* Code to actually dissect the packets */
static gboolean 
dissect_gn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree *gn_tree = tree;
  guint8 gn_version = 0;
  guint8 gn_bnh = 0;
  guint8 offset = 0;
  const char *str_packet_type = NULL;

  /* Check that there's enough data */
  if(tvb_captured_length(tvb) < L_BH)
    return 0;

  /* Check GN version */
  gn_version = (tvb_get_guint8(tvb, 0) & M_VERSION) >> 4;
  if(gn_version != GN_VERSION)
    return 0;
  
  /* Update COL_PROTOCOL */ 
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GeoNetworking");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  /* Extract some header values */
  gn_bnh = (tvb_get_guint8(tvb, 0) & M_BNH);
  str_packet_type = val_to_str(gn_bnh, basic_next_header_names, " (0x%02x)");

  if (tree) { /* we are being asked for details */
    proto_item *ti = NULL;

    /* Main GN tree */
    ti = proto_tree_add_item(tree, proto_gn, tvb, offset, -1, FALSE);
    proto_item_append_text(ti, ": %s", str_packet_type);
    gn_tree = proto_item_add_subtree(ti, ett_gn);
  }

  /* Dissect*/
  offset = dissect_basic_header(tvb/*, pinfo*/, gn_tree, offset);
  switch(gn_bnh) {
  case 1:
    return dissect_unsecured_packet(tvb, pinfo, gn_tree, offset);
  case 2: // ETSI TS 103 077 < 2017
    col_add_str(pinfo->cinfo, COL_INFO, str_packet_type);
    if (tvb_get_guint8(tvb, offset) == 0x03) {
      return dissect_ieee1609dot2_data_packet(tvb, pinfo, gn_tree, offset);
      /*dissector_handle_t ieee1609dot2_handle;
        
        col_add_str(pinfo->cinfo, COL_INFO, str_packet_type);
        ieee1609dot2_handle = find_dissector("ieee1609dot2");
        printf("============> ieee1609dot2_handle = '%p'\n", ieee1609dot2_handle);
        if (ieee1609dot2_handle != NULL) {
        tvbuff_t *next_tvb = next_tvb = tvb_new_subset_length(tvb, offset, tvb_captured_length(tvb) - offset);
        printf("============> offset = '%d'\n", offset);
        offset += call_dissector(ieee1609dot2_handle, next_tvb, pinfo, tree);
        printf("============> return offset = '%d'\n", offset);
        return offset;
        }
        
        return 0;*/
    } else {
      return dissect_secured_packet(tvb, pinfo, gn_tree, offset);
    }
  default:
    col_add_str(pinfo->cinfo, COL_INFO, str_packet_type);
    return 0; /*FIXME*/
  }
}

/* Register the protocol with Wireshark */
void
proto_register_gn(void)
{
  module_t *gn_module;

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    /* Basic Header */
    { &hf_gn_basicheader,
      {"Basic Header", "gn.bh", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_version,
      {"Version", "gn.version", FT_UINT8, BASE_DEC, NULL, M_VERSION, NULL, HFILL}
    },
    { &hf_gn_bnh,
      {"Next Header", "gn.bnh", FT_UINT8, BASE_DEC, VALS(basic_next_header_names), M_BNH, NULL, HFILL}
    },
    { &hf_gn_reserved,
      {"Reserved", "gn.reserved", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_lt,
      {"Lifetime", "gn.lt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_lt_multiplier,
      {"Multiplier", "gn.lt.multiplier", FT_UINT8, BASE_DEC, NULL, M_LT_MULTIPLIER, NULL, HFILL}
    },
    { &hf_gn_lt_base,
      {"Base", "gn.lt.base", FT_UINT8, BASE_DEC, VALS(lifetime_base_names), M_LT_BASE, NULL, HFILL}
    },
    { &hf_gn_hl,
      {"Router Hop Limit", "gn.hl", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },





    /* Secured Packet - See IEEE Std 1609.2a-2017 */
    { &hf_1609dot2_secured_message,
      { "IEEE 1609.2 Message", "gn.msg.sec", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_content_packet,
      { "IEEE 1609.2 Content", "gn.sec.content", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_signed_data_packet,
      { "IEEE 1609.2 SignedData", "gn.sec.signed_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_hash_algorithm,
      {"Hash Algorithm", "gn.sec.signed_data.hash_algotithm", FT_UINT8, BASE_DEC, VALS(st_1609dot2_hash_algorithm), 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_to_be_signed_data_packet,
      { "IEEE 1609.2 To Be Signed Data", "gn.sec.signed_data.tbs_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_to_be_signed_data_payload_packet,
      { "IEEE 1609.2 To Be Signed Data Payload", "gn.sec.signed_data.tbs_data.payload", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_to_be_signed_certificate_packet,
      { "IEEE 1609.2 To Be Signed Certificate", "gn.sec.signed_data.tbs_data.certificate", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_unsecured_data_packet,
      { "IEEE 1609.2 Unsecured Data", "gn.sec.signed_data.tbs_data.unsecured_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_header_info_packet,
      { "IEEE 1609.2 Header Info", "gn.sec.signed_data.tbs_data.header_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_certificate_packet,
      {"IEEE 1609.2 Certificate", "gn.sec.cert", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_certificate_packet_type,
      {"IEEE 1609.2 Certificate type", "gn.cert.type", FT_UINT8, BASE_DEC, VALS(st_1609dot2_certificate_type), 0X00, NULL, HFILL}
    },
    { &hf_1609dot2_issuer_identifier,
      {"IEEE 1609.2 Certicate Issuer", "gn.sec.cert.issuer", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_signer_identifier_packet,
      {"IEEE 1609.2 Signer Identifier", "gn.sgnid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_validity_period,
      { "IEEE 1609.2 Validity period", "gn.sec.validity_period", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_app_permissions_packet,
      { "IEEE 1609.2 App. Permissions", "gn.sec.psid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_ssp_packet,
      { "IEEE 1609.2 App. SSP", "gn.sec.ssp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_ssp_bitmap_mask,
      { "IEEE 1609.2 SSP bit mask", "gn.sec.ssp.bitmask", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_sha256AndDigest,
      {"IEEE 1609.2 Sha256AndDigest", "gn.sec.sha256AndDigest", FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_sha384AndDigest,
      {"IEEE 1609.2 Sha384AndDigest", "gn.sec.sha384AndDigest", FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_self,
      {"IEEE 1609.2 Signer Identifier", "gn.sec.signerIdentifier", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_to_be_signed_data,
      {"IEEE 1609.2 Message signature", "gn.sec.toBeSignedData", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_to_be_signed_data_nistp256,
      {"NistP256", "gn.sh.toBeSignedData_nistp256", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_to_be_signed_data_brainpoolp256,
      {"BrainpoolP256r1", "gn.sh.toBeSignedData_brainpoolp256", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_to_be_signed_data_brainpoolp384,
      {"BrainpollP384r1", "gn.sh.toBeSignedData_brainpoolp384", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_certificate_signature,
      {"IEEE 1609.2 Certificate Signature", "gn.sec.cert.toBeSignedCertificate.signature", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_certificate_packet_id,
      {"IEEE 1609.2 Certificate Id", "gn.sec.cert.toBeSignedCertificate.id", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_certificate_packet_name,
      {"IEEE 1609.2 Certificate name", "gn.sec.cert.toBeSignedCertificate.id.name", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_certificate_packet_none,
      {"IEEE 1609.2 Certificate none", "gn.sec.cert.toBeSignedCertificate.id.none", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_certificate_packet_crlseries,
      {"CrlSeries", "gn.sec.cert.toBeSignedCertificate.crlseries", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_1609dot2_public_enc_key,
      {"Public Encryption key", "gn.sec.pekey", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_base_public_enc_key,
      {"Base public Encryption key", "gn.sec.pbekey", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_symm_algorithm,
      {"Symmetric Encryption Algorithm", "gn.sec.symalg", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_verification_key,
      {"Verification key", "gn.sec.vfkey", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_public_verification_key,
      {"IEEE1909.2 Public Verification key", "gn.sec.pvfkey", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_r_sig,
      {"IEEE 1609dot2 Signature r", "gn.sec.signature.r", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_s_sig,
      {"IEEE 1609dot2 Signature s", "gn.sec.signature.s", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_x_only,
      {"ECC Curve Point x-only", "gn.sec.curve.x_only", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_compressed_y_0,
      {"ECC Curve Point compressed-y-0", "gn.sec.curve.compressed_y_0", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_compressed_y_1,
      {"ECC Curve Point compressed-y-1", "gn.sec.curve.compressed_y_1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_ecies_nistp_256,
      {"ECIES NistP256", "gn.sec.ecies_nistp_256", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_ecdsa_nistp_256,
      {"ECDSA NistP256", "gn.sec.ecdsa_nistp_256", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_ecies_brainpoolp_256,
      {"ECIES BrainpoolP256r1", "gn.sec.ecies_brainpoolp_256", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_ecdsa_brainpoolp_256,
      {"ECDSA BrainpoolP256r1", "gn.sec.ecdsa_brainpoolp_256", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_ecies_brainpoolp_384,
      {"ECIES BrainpoolP384r1", "gn.sec.ecies_brainpoolp_384", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_ecdsa_brainpoolp_384,
      {"ECDSA BrainpoolP384r1", "gn.sec.ecdsa_brainpoolp_384", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_geographical_region_packet,
      {"IEEE 1609.2 Geo. Region", "gn.sec.geo_region", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_circular_region_packet,
      {"IEEE 1609.2 Circular Region", "gn.sec.geo_region.circular", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_rectangular_region_packet,
      {"IEEE 1609.2 Rectangular Region", "gn.sec.geo_region.rectangular", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_rectangle_region_packet,
      {"IEEE 1609.2 Rectangle corners", "gn.sec.geo_region.rectangular.corner", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_polygonal_region_packet,
      {"IEEE 1609.2 Polygonal Region", "gn.sec.geo_region.polygonal", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_point_region_packet,
      {"IEEE 1609.2 Polygon Point", "gn.sec.geo_region.polygonal.point", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_2d_location_packet,
      {"IEEE 1609.2 2D Location", "gn.sec.geo_region.circular.loc_2d", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_identified_region_packet,
      {"IEEE 1609.2 Identified Region", "gn.sec.geo_region.id", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_1609dot2_country_region,
      {"IEEE 1609.2 Country code", "gn.sec.geo_region.id.country", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },






    










    


    






    
    /* Secured Packet - See Draft ETSI TS 103 097 V1.1.13 Clause 5.1 Secured message */
    { &hf_sec_data,
      { "Secured Data", "gn.secdata", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    /* Secure Header  - See Draft ETSI TS 103 097 V1.1.13 Clause 5.4 HeaderField */
    { &hf_gn_sh,
      {"Secure Header", "gn.sh", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_sh_version, // See Draft ETSI TS 103 097 V1.1.13 Clause 5.1 Secured message
      {"Version", "gn.sh.version", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_len,
      {"Header Length", "gn.sh.len", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field,
      {"Header Fields", "gn.sh.headers", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_type,
      {"Header Field", "gn.sh.header.type", FT_UINT8, BASE_DEC, VALS(sh_field_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_cert_chain,
      {"Certificates Chain", "gn.sh.certchain", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },	
    { &hf_gn_sh_field_cert_chain_length,
      {"Certificates Chain Length", "gn.sh.certchain.length",  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_pubkey,
      {"Public Key", "gn.sh.pubkey", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_sig,
      {"Signature", "gn.sh.sig", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_2dlocation,
      {"2DLocation", "gn.sh.2dlocation", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_3dlocation,
      {"3DLocation", "gn.sh.3dlocation", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_gentime,
      {"Generation Time", "gn.sh.gentime", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_gentimestddev,
      {"Std Dev", "gn.sh.gentime.stddev", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_exptime,
      {"Expiration Time", "gn.sh.exptime", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_starttime,
      {"Start Time", "gn.sh.starttime", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_startduration,
      {"Start Time", "gn.sh.startduration", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_endtime,
      {"End Time", "gn.sh.endtime", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_startendtime,
      {"End Time", "gn.sh.startendtime", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_elev,
      {"Elevation", "gn.sh.elev", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_hashedid3_list,
      {"HashedId3 list", "gn.sh.hashedid3s", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_hashedid3,
      {"HashedId3", "gn.sh.hashedid3", FT_UINT24, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_hashedid8,
      {"HashedId8", "gn.sh.hashedid8", FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_itsaid,
      {"Its AID", "gn.sh.itsaid", FT_UINT16, BASE_DEC, VALS(sh_itsaid_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_signinfo_type,
      {"SignerInfo Type", "gn.sh.signinfotype", FT_UINT8, BASE_DEC, VALS(sh_signerinfotype_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_subject_type,
      {"Subject Info", "gn.sh.subjecttype", FT_UINT8, BASE_DEC, VALS(sh_subjectinfotype_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_subjectattr_type,
      {"Subject Attribute", "gn.sh.subjectattrtype", FT_UINT8, BASE_DEC, VALS(sh_subjectattrtype_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_validityrestr_type,
      {"Validity Restriction", "gn.sh.validityrestrtype", FT_UINT8, BASE_DEC, VALS(sh_validityrestrtype_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_st_field_assurelev,
      {"Assurance Level", "gn.sh.assurelev", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_st_field_assurelev_flags_levels_bits,
      {"Levels bits", "gn.sh.assurelev.flags.lbits", FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
    },
    { &hf_gn_st_field_assurelev_flags_reserved_bits,
      {"Reserved bits", "gn.sh.assurelev.flags.rbits", FT_UINT8, BASE_HEX, NULL, 0x1c, NULL, HFILL}
    },
    { &hf_gn_st_field_assurelev_flags_confidence_bits,
      {"Confidence bits", "gn.sh.assurelev.flags.cbits", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL}
    },
    { &hf_gn_sh_field_geo_region_type,
      {"Geographic Region", "gn.sh.georegion", FT_UINT8, BASE_DEC, VALS(sh_georegiontype_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_geo_circle_radius,
      {"Circle Radius", "gn.sh.georegion.radius", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_geo_region_dict,
      {"Region Dictionary", "gn.sh.georegion.dict", FT_UINT8, BASE_DEC, VALS(sh_georegiondicttype_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_geo_region_id,
      {"Region Identifier", "gn.sh.georegion.id", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_geo_region_local,
      {"Local Region", "gn.sh.georegion.local", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_sh_field_pk_alg,
      {"Public Key Alg", "gn.sh.pk.algo", FT_UINT8, BASE_DEC, VALS(sh_publickeyalg_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_shpl_len,
      {"Payload Length", "gn.sh.pl.len", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_shpl_type,
      {"Payload Type", "gn.sh.pl.type", FT_UINT8, BASE_DEC, VALS(sh_payloadtype_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_shpl_datalen,
      {"Payload Data Length", "gn.sh.pl.datalen", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_st_opaquelen,
      { "Length", "gn.st.opaquelen", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_sh_field_cert,
      {"Certificate", "gn.sh.cert", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_st_aid_val,
      { "AID", "gn.st.aid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_sh_field_maxprio,
      { "AID max priority", "gn.sh.maxprio", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
//    { &hf_gn_st_signinfolen,
//      { "SignInfo Len", "gn.sh.signinfolen", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
//    },
    { &hf_gn_st_subjectattrlen,
      { "Subject Attr Len", "gn.sh.subjectattrlen", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_st,
      { "Secure Trailer", "gn.st", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_st_len,
      {"Trailer Length", "gn.st.len", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_st_type,
      { "Trailer Type", "gn.st.type", FT_UINT8, BASE_DEC, VALS(sh_trailertype_names), 0x0, NULL, HFILL}
    },
    { &hf_gn_st_pka,
      {"Public Key Alg", "gn.st.pka", FT_UINT8, BASE_DEC, VALS(st_pka_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_st_symmalg,
      {"Symmetric Algorithm", "gn.st.symmalgo", FT_UINT8, BASE_DEC, VALS(st_symmal_gnames), 0x00, NULL, HFILL}
    },
    { &hf_gn_st_ecc_pt,
      {"ECC Point Type", "gn.st.eccpointtype", FT_UINT8, BASE_DEC, VALS(st_eccpt_type_names), 0x00, NULL, HFILL}
    },
    { &hf_gn_st_opaque,
      { "Opaque", "gn.st.opaque", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* Common Header */
    { &hf_gn_commonheader,
      {"Common Header", "gn.ch", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_nh,
      {"Next Header", "gn.nh", FT_UINT8, BASE_DEC, VALS(next_header_names), M_NH, NULL, HFILL}
    },
    { &hf_gn_reserved0,
      {"Reserved", "gn.reserved0", FT_UINT8, BASE_DEC, NULL, M_RESERVED0, NULL, HFILL}
    },
    { &hf_gn_ht,
      {"Header Type", "gn.ht", FT_UINT8, BASE_DEC, VALS(header_type_names), M_HT, NULL, HFILL}
    },
    { &hf_gn_hst_unspecified,
      {"Header Subtype", "gn.hst", FT_UINT8, BASE_DEC, VALS(header_subtype_unspecified_names), M_HST, NULL, HFILL}
    },
    { &hf_gn_hst_geoarea,
      {"Header Subtype", "gn.hst", FT_UINT8, BASE_DEC, VALS(header_subtype_geoarea_names), M_HST, NULL, HFILL}
    },
    { &hf_gn_hst_tsb,
      {"Header Subtype", "gn.hst", FT_UINT8, BASE_DEC, VALS(header_subtype_tsb_names), M_HST, NULL, HFILL}
    },
    { &hf_gn_hst_ls,
      {"Header Subtype", "gn.hst", FT_UINT8, BASE_DEC, VALS(header_subtype_ls_names), M_HST, NULL, HFILL}
    },

    /* Flags */
    { &hf_gn_flags,
      {"Flags", "gn.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_flags_mobile,
      {"Mobile Flag", "gn.flags.mobile", FT_UINT8, BASE_DEC, VALS(mobile_names), M_FLAGS_MOBILE, NULL, HFILL}
    },
    { &hf_gn_flags_reserved0,
      {"Reserved", "gn.flags.reserved0", FT_UINT8, BASE_HEX, NULL, M_FLAGS_RESERVED0, NULL, HFILL}
    },
    
    { &hf_gn_pl,
      {"Payload Length", "gn.pl", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    
    /* Traffic Class*/
    {
      &hf_gn_tc,
      {"Traffic Class", "gn.tc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {
      &hf_gn_tc_scf,
      {"Store-Carry-Forward", "gn.tc.scf", FT_UINT8, BASE_DEC, NULL, M_TC_SCF, NULL, HFILL}
    },
    {
      &hf_gn_tc_chanoff,
      {"Channel Offload", "gn.tc.chanoff", FT_UINT8, BASE_DEC, NULL, M_TC_CHANOFF, NULL, HFILL}
    },
    {
      &hf_gn_tc_tcid,
      {"TC ID (DCC Profile Id)", "gn.tc.tcid", FT_UINT8, BASE_DEC, NULL, M_TC_TCID, NULL, HFILL}
    },
    
    { &hf_gn_mhl,
      {"Maximum Hop Limit", "gn.mhl", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_reserved1,
      {"Reserved", "gn.reserved1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    
    /* Extended Header Multihop fields*/
    { &hf_gn_sn,
      {"Sequence Number", "gn.sn", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_reserved2,
      {"Reserved", "gn.reserved2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    
    /* GeoUnicast */
    { &hf_gn_guc,
      {"GeoUnicast", "gn.guc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* GeoAnycast */
    { &hf_gn_gac,
      {"GeoAnycast", "gn.gac", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* GeoBroadcast */
    { &hf_gn_gbc,
      {"GeoBroadcast", "gn.gbc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* Area */
    { &hf_gn_area_lat,
      {"Latitude", "gn.area.lat", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_area_long,
      {"Longitude", "gn.area.long", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_area_elev,
      {"Elevation", "gn.area.elev", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_area_a,
      {"Distance A", "gn.area.a", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_area_b,
      {"Distance B", "gn.area.b", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_area_angle,
      {"Angle", "gn.area.angle", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_area_reserved,
      {"Reserved", "gn.area.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },

    /* TSB */
    { &hf_gn_tsb,
      {"Topology-Scoped Broadcast", "gn.tsb", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_tsb_reserved,
      {"Reserved", "gn.tsb.reserved", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* LS */
    { &hf_gn_ls,
      {"Location Service", "gn.ls", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_ls_addr,
      {"Requested GN Address", "gn.ls.addr", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_ls_addr_m,
      {"Assignement", "gn.ls.addr.m", FT_UINT16, BASE_DEC, VALS(assignement_names), M_ADDR_M, NULL, HFILL}
    },
    { &hf_gn_ls_addr_st,
      {"Station Type", "gn.ls.addr.st", FT_UINT16, BASE_DEC, VALS(station_type_names), M_ADDR_ST, NULL, HFILL}
    },
    { &hf_gn_ls_addr_scc,
      {"Country Code", "gn.ls.addr.ssc", FT_UINT16, BASE_DEC, NULL, M_ADDR_SCC, NULL, HFILL}
    },
    { &hf_gn_ls_addr_mid,
      {"Link-Layer Address", "gn.ls.addr.mid", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* SOPV */
    { &hf_gn_sopv,
      {"Source Position Vector", "gn.sopv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_so_addr,
      {"GN Address", "gn.sopv.addr", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_so_addr_m,
      {"Assignement", "gn.sopv.addr.m", FT_UINT16, BASE_DEC, VALS(assignement_names), M_ADDR_M, NULL, HFILL}
    },
    { &hf_gn_so_addr_st,
      {"Station Type", "gn.sopv.addr.st", FT_UINT16, BASE_DEC, VALS(station_type_names), M_ADDR_ST, NULL, HFILL}
    },
    { &hf_gn_so_addr_scc,
      {"Country Code", "gn.sopv.addr.ssc", FT_UINT16, BASE_DEC, NULL, M_ADDR_SCC, NULL, HFILL}
    },
    { &hf_gn_so_addr_mid,
      {"Link-Layer Address", "gn.sopv.addr.mid", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_so_tst,
      {"Timestamp", "gn.sopv.tst", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_so_lat,
      {"Latitude", "gn.sopv.lat", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_so_long,
      {"Longitude", "gn.sopv.long", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_so_pai,
      {"PAI", "gn.sopv.pai", FT_UINT16, BASE_DEC, NULL, M_PAI, NULL, HFILL}
    },
    { &hf_gn_so_speed,
      {"Speed", "gn.sopv.speed", FT_INT16, BASE_DEC, NULL, M_SPEED, NULL, HFILL}
    },
    { &hf_gn_so_heading,
      {"Heading", "gn.sopv.heading", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },

    /* DEPV */
    { &hf_gn_depv,
      {"Destination Position Vector", "gn.depv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_de_addr,
      {"GN Address", "gn.depv.addr", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_de_addr_m,
      {"Assignement", "gn.depv.addr.m", FT_UINT16, BASE_DEC, VALS(assignement_names), M_ADDR_M, NULL, HFILL}
    },
    { &hf_gn_de_addr_st,
      {"Station Type", "gn.depv.addr.st", FT_UINT16, BASE_DEC, VALS(station_type_names), M_ADDR_ST, NULL, HFILL}
    },
    { &hf_gn_de_addr_scc,
      {"Country Code", "gn.depv.addr.ssc", FT_UINT16, BASE_DEC, NULL, M_ADDR_SCC, NULL, HFILL}
    },
    { &hf_gn_de_addr_mid,
      {"Link-Layer Address", "gn.depv.addr.mid", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_de_tst,
      {"Timestamp", "gn.depv.tst", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_de_lat,
      {"Latitude", "gn.depv.lat", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_de_long,
      {"Longitude", "gn.depv.long", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },

  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_gn,
    &ett_bh,
    &ett_ch,
    &ett_sh,
    &ett_shf,
    &ett_shfc,
    &ett_certchain,
    &ett_sig,
    &ett_pubkey,
    &ett_st,
    &ett_ch_flags,
    &ett_ch_tc,
    &ett_guc,
    &ett_gac,
    &ett_gbc,
    &ett_tsb,
    &ett_lt,
    &ett_ls,
    &ett_ls_addr,
    &ett_sopv,
    &ett_sopv_addr,
    &ett_depv,
    &ett_depv_addr,
    &ett_secdata,
    &ett_2dlocation,
    &ett_3dlocation,
    &ett_assurance_level_flags,
    &ett_1609dot2_data_packet,
    &ett_1609dot2_content_packet,
    &ett_1609dot2_to_be_signed_data_packet,
    &ett_1609dot2_signed_data_packet,
    &ett_1609dot2_unsecured_content,
    &ett_encrypted_content,
    &ett_1609dot2_certificate_packet,
    &ett_1609dot2_signer_identifier_packet,
    &ett_1609dot2_r_sig,
    &ett_1609dot2_issuer_identifier,
    &ett_tbs_data,
    &ett_1609dot2_header_info_packet,
    &ett_1609dot2_tbs_certificate_packet,
    &ett_1609dot2_tbs_certificate_packet_id,
    &ett_1609dot2_app_permissions_packet,
    &ett_1609dot2_ssp_packet,
    &ett_1609dot2_public_enc_key,
    &ett_1609dot2_base_public_enc_key,
    &ett_1609dot2_signed_data_payload_packet,
    &ett_tbs_verification_key,
    &ett_1609dot2_public_verification_key,
    &ett_1609dot2_geographical_region_packet,
    &ett_1609dot2_circular_region_packet,
    &ett_1609dot2_rectangular_region_packet,
    &ett_1609dot2_rectangle_region_packet,
    &ett_1609dot2_polygonal_region_packet,
    &ett_1609dot2_point_region_packet,
    &ett_1609dot2_2d_location_packet,
    &ett_1609dot2_identified_region_packet,
    &ett_1609dot2_country_region
  };

  /* Register the protocol name and description */
  proto_gn = proto_register_protocol (
				      "GeoNetworking", /* name       */
				      "GN",            /* short name */
				      "gn"             /* abbrev     */
				      );

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_gn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector_table("gn.nh", "GeoNetworking payload ID", proto_gn, FT_UINT8, BASE_DEC);
  
  /* Register preferences module */
  gn_module = prefs_register_protocol(proto_gn, proto_reg_handoff_gn);
//  new_register_dissector("gn", dissect_gn, proto_gn);
  register_dissector("gn", dissect_gn, proto_gn);
  

  /* Register a sample port preference   */
  prefs_register_uint_preference(gn_module, "ethertype", "GeoNetworking Ethertype (in hex)",
				 "GeoNetworking Ethertype (in hex)",
				 16, &gETHERTYPE_PREF);
}

void
proto_reg_handoff_gn(void)
{
  dissector_handle_t gn_handle, ipv6_handle/*, ieee1609dot2_handle*/;
  gn_handle = create_dissector_handle(dissect_gn, proto_gn);
  dissector_add_uint("ethertype", gETHERTYPE_PREF, gn_handle);
  // Continue to support former ethertype for a while
  dissector_add_uint("ethertype", EX_ETHER_TYPE, gn_handle);
  
  /* register IPv6 sub-dissector */
  ipv6_handle = find_dissector("ipv6");
  dissector_add_uint("gn.nh", 3, ipv6_handle);

  /* register IEEE 1609.2 sub-dissector */
  /*ieee1609dot2_handle = find_dissector("ieee1609dot2");
    dissector_add_uint("gn.bnh", 2, ieee1609dot2_handle);*/
}
