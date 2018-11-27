/* packet-etsi_ieee1609dot2.c
 * Routines for GeoNetworking dissetion
 * Copyright 2013, AMB Consulting <alexandre.berge@amb-consulting.com>
 *                 Secured Packet dissection by Cohda Wireless <info@cohdawireless.com>
 *
 * $Id: packet-etsi_ieee1609dot2.c 44 2015-03-24 14:00:05Z garciay $
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
#include <ctype.h>

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include "epan/proto_data.h"

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>

#include <wsutil/wsgcrypt.h>

void proto_register_etsi_ieee1609dot2(void);
void proto_reg_handoff_etsi_ieee1609dot2(void);

#define MEDIA_TYPE "application/x-its"

static int dissect_ieee1609dot2_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_ieee1609dot2_content_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_ieee1609dot2_signature_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf);
static int decrypt_and_decode_pki_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int len);

#define ETSI_1609DOT2_VERSION 3

static int proto_etsi_ieee1609dot2 = -1;

/* Secured packet IEE1906.2 */
static int proto_ah = -1;

static gint ett_proto_etsi_ieee1609dot2 = -1;
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
static gint ett_1609dot2_encrypted_data_packet = -1;
static gint ett_1609dot2_recipient_info_data_packet = -1;
static gint ett_1609dot2_recipient_info_packet = -1;
static gint ett_1609dot2_pk_recipient_info_packet = -1;
static gint ett_1609dot2_enc_data_key_data_packet = -1;
static gint ett_1609dot2_ciphertext_data_packet = -1;
static gint ett_1609dot2_aes_128_ccm_cipher_text_data_packet = -1;

/* Secured packet IEE1906.2 */
static int hf_1609dot2_protocol_version = -1;
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
static int hf_1609dot2_encrypted_data_packet = -1;
static int hf_1609dot2_recipient_info_data_packet = -1;
static int hf_1609dot2_recipient_info_packet = -1;
static int hf_1609dot2_pk_recipient_info_packet = -1;
static int hf_1609dot2_enc_data_key_data_packet = -1;
static int hf_1609dot2_c = -1;
static int hf_1609dot2_t = -1;
static int hf_1609dot2_ciphertext_data_packet = -1;
static int hf_1609dot2_aes_128_ccm_cipher_text_data_packet = -1;
static int hf_1609dot2_nonce = -1;

static int hf_gn_st_aid_val = -1;
static int hf_gn_st_opaque = -1;
static int hf_gn_area_lat = -1;
static int hf_gn_area_long = -1;
static int hf_gn_sh_field_geo_circle_radius = -1;
static int hf_gn_sh_field_hashedid3 = -1;
static int hf_gn_sh_field_hashedid8 = -1;
static int hf_gn_sh_field_gentime = -1;
static int hf_gn_sh_field_exptime = -1;
static int hf_gn_sh_field_self = -1;
static int hf_gn_st_field_assurelev = -1;

static const value_string st_1609dot2_certificate_type[] = {
							    { 0, "explicit certificate type" },
							    { 2, "implicit certificate type" },
							    { 0, NULL}
};

static const value_string st_1609dot2_hash_algorithm[] = {
							  { 0, "SHA-256 algorithm" },
							  { 2, "SHA-384 algorithm" },
							  { 0, NULL}
};

/* Decrypt entry structure. */
typedef struct { 
  guint8 encryption_algo;
  guint8 encryption_compressed_key_mode;
  gchar* encryption_compressed_key;
  gchar* nonce;
  gchar* tag;
  gchar* encrypted_aes_symmetric_key;
} decrypt_record_t;
static decrypt_record_t g_decrypt_record = { 0xff, 0xff, NULL, NULL, NULL, NULL };

/*************************************/
/* Preference settings               */

typedef struct etsi_ieee1609dot2_common_options {
  gboolean enable_encryption_decode;
  const gchar* ts_private_enc_key;
  const gchar* ts_public_enc_key;
  const gchar* ts_public_sign_key;
  const gchar* iut_private_enc_key;
  const gchar* iut_public_enc_key;
  const gchar* iut_public_sign_key;
} etsi_ieee1609dot2_common_options_t;
static etsi_ieee1609dot2_common_options_t g_options = { FALSE, NULL, NULL, NULL, NULL, NULL, NULL };





static void
show_hex(const char *prefix, const void *buffer, size_t buflen)
{
  const unsigned char*s;

  fprintf (stderr, "%s: ", prefix);
  for (s= (unsigned char*)buffer; buflen; buflen--, s++)
    fprintf (stderr, "%02x", *s);
  putc ('\n', stderr);
}

static
unsigned char* hex_to_bin(const char* input, size_t* buffer_length) {
  char a;
  size_t i, len;
  unsigned char *retval = NULL;
  if (!input) return NULL;
  if((len = strlen(input)) & 1) return NULL;
  retval = (unsigned char*)gcry_malloc(len >> 1);
  for ( i = 0; i < len; i ++) {
    a = toupper(input[i]);
    if (!isxdigit(a)) break;
    if (isdigit(a)) a -= '0';
    else a = a - 'A' + 0x0A; 
   
    if (i & 1) retval[i >> 1] |= a;
    else retval[i >> 1] = a<<4;
  }
  if (i < len) {
    gcry_free(retval);
    retval = NULL;
  }
  *buffer_length = len >> 1;

  return retval;
}

static void
show_sexp(const char *prefix, gcry_sexp_t a)
{
  char* buf;
  size_t size;

  if (prefix)
    fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = (char*)gcry_xmalloc (size);

  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  gcry_free (buf);
}

static void
show_mpi(const char *text, const char *text2, gcry_mpi_t a)
{
  gcry_error_t err;
  char *buf;
  void *bufaddr = &buf;

  err = gcry_mpi_aprint(GCRYMPI_FMT_HEX, (unsigned char**)bufaddr, NULL, a);
  if (err)
    fprintf(stderr, "%s%s: [error printing number: %s]\n",
             text, text2? text2:"", gcry_strerror (err));
  else
    {
      fprintf(stderr, "%s%s: %s\n", text, text2? text2:"", buf);
      gcry_free (buf);
    }
}

static unsigned char*
sha256(const unsigned char* p_data, const size_t p_data_length) {
  gcry_error_t result;
  gcry_md_hd_t hd;
  unsigned int digestlen;
  unsigned char* digest;
  unsigned char* ret_value = NULL;
  
  if ((result = gcry_md_open(&hd, GCRY_MD_SHA256, 0)) != 0) {
    printf("Failed for %s/%s\n", gcry_strsource(result), gcry_strerror(result));
    return NULL;
  }
  digestlen = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
  gcry_md_write(hd, p_data, p_data_length);
  digest = gcry_md_read(hd, GCRY_MD_SHA256);
  // Do not free digest
  ret_value = (unsigned char*)gcry_malloc(digestlen);
  memcpy((void*)ret_value, (const void*)digest, digestlen);
  gcry_md_close(hd);

  return ret_value;
}

static int
compressed_hex_key_to_sexp(const unsigned char* p_comp_key, const size_t p_comp_key_size, const int p_comp_mode, const char* p_curve, const char* p_algo, gcry_sexp_t* p_key) {
  unsigned char* x_buffer = NULL;
  unsigned char* y_buffer = NULL;
  unsigned char* xy_buffer = NULL;
  size_t buffer_size;
  gcry_sexp_t keyparm = NULL;
  gcry_sexp_t key = NULL, private_key = NULL, e_key = NULL;
  
  gcry_ctx_t ctx = NULL;
  gcry_mpi_t a, b, p, p_plus_1, p_minus_5, x, q, r;
  gcry_mpi_t two, three, four, x_3, axb, y_2, y;
    
  gcry_error_t rc;

  printf(">>> compressed_hex_key_to_sexp: %zu - %d - %s - %s\n", p_comp_key_size, p_comp_mode, p_curve, p_algo);
  show_hex(">> compressed_hex_key_to_sexp: ", p_comp_key, p_comp_key_size);
  
  // Extract (p, a, b) parameters from curve
  if ((rc = gcry_sexp_build (&keyparm, NULL, "(genkey(ecc(curve %s)(flags param)))", p_curve)) != 0) {
    printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
    return -1;
  }
  show_sexp("keyparm: ", keyparm);
  if ((rc = gcry_pk_genkey(&key, keyparm)) != 0) {
    printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
    return -2;
  }
  private_key = gcry_sexp_find_token(key, "private-key", 0);
  if ((rc = gcry_mpi_ec_new (&ctx, private_key, NULL)) != 0) {
    printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
    return -3;
  }
  if ((a = gcry_mpi_ec_get_mpi ("a", ctx, 0)) == NULL) {
    printf("Failed gcry_mpi_ec_get_mpi\n");
    return -4;
  }
  if ((b = gcry_mpi_ec_get_mpi ("b", ctx, 0)) == NULL) {
    printf("Failed gcry_mpi_ec_get_mpi\n");
    return -5;
  }
  if ((p = gcry_mpi_ec_get_mpi ("p", ctx, 0)) == NULL) {
    printf("Failed gcry_mpi_ec_get_mpi\n");
    return -6;
  }
  gcry_ctx_release (ctx);
  // Initialise x public key
  buffer_size = p_comp_key_size;
  x_buffer = (unsigned char*)gcry_malloc(buffer_size);
  if (x_buffer == NULL) {
    printf("Failed to allocate memory\n");
    return -7;
  }
  memcpy((void*)x_buffer, (const void*)p_comp_key, buffer_size);
  if ((rc = gcry_sexp_build(&e_key, NULL, "(e-key(x %b))", buffer_size, x_buffer)) != 0) {
    printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
    return -8;
  }
  if ((x = gcry_sexp_nth_mpi(gcry_sexp_find_token(e_key, "x", 0), 1, GCRYMPI_FMT_USG)) == NULL) {
    printf("Failed gcry_mpi_ec_get_mpi\n");
    return -9;
  }
  gcry_sexp_release(e_key);
  
  /* Ecc curve equation: y^2=x^3+a*x+b */
  /* Compute y^2 */
  two   = gcry_mpi_set_ui (NULL, 2);
  three = gcry_mpi_set_ui (NULL, 3);
  four = gcry_mpi_set_ui (NULL, 4);
  x_3   = gcry_mpi_new (0);
  axb   = gcry_mpi_new (0);
  y_2   = gcry_mpi_new (0);
  gcry_mpi_powm (x_3, x, three, p); // w = b^e \bmod m. 
  gcry_mpi_mulm (axb, a, x, p);
  gcry_mpi_addm (axb, axb, b, p);
  gcry_mpi_addm (y_2, x_3, axb, p);
  show_mpi("y_2", "", y_2);

  /* Compute sqrt(y^2): two solutions */
  q     = gcry_mpi_new (0);
  r     = gcry_mpi_new (0);
  y     = gcry_mpi_new (0);
  if (p_comp_mode == 0) {
    /* Solution one: y = p + 1 / 4 */
    p_plus_1   = gcry_mpi_new (0);
    gcry_mpi_add_ui(p_plus_1, p, 1);
    gcry_mpi_div(q, r, p_plus_1, four, 0);
    gcry_mpi_release(p_plus_1);
  } else {
    /* Solution two: p - 5 / 4 */
    p_minus_5  = gcry_mpi_new (0);
    gcry_mpi_sub_ui(p_minus_5, p, 5);
    gcry_mpi_div(q, r, p_minus_5, four, 0);
    gcry_mpi_release(p_minus_5);
  }
  gcry_mpi_powm(y, y_2, q, p);
  show_mpi("y", "", y);
  gcry_mpi_release (four);
  gcry_mpi_release (q);
  gcry_mpi_release (r);
  gcry_mpi_release (y_2);

  //show_hex(x_buffer, buffer_size, "x_buffer="),
  y_buffer = (unsigned char*)gcry_malloc(buffer_size);
  gcry_mpi_print (GCRYMPI_FMT_USG, y_buffer, buffer_size, NULL, y);
  //show_hex(y_buffer, buffer_size, "y_buffer="),
  xy_buffer = (unsigned char*)gcry_malloc(2 * buffer_size + 1);
  *xy_buffer = 0x04;
  memcpy((void*)(xy_buffer + 1), (const void*)x_buffer, buffer_size);
  memcpy((void*)(char*)(xy_buffer + buffer_size + 1), (const void*)y_buffer, buffer_size);
  //show_hex(xy_buffer, 2 * buffer_size, "xy_buffer=");

  if (strcmp(p_algo, "ecc") == 0) {
    if ((rc = gcry_sexp_build (p_key, NULL, "(public-key(ecc(curve %s)(q %b)))", p_curve, 2 * buffer_size + 1, xy_buffer)) != 0) {
      printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
      return -10;
    }
  } else if (strcmp(p_algo, "ecdsa") == 0) {
    if ((rc = gcry_sexp_build (p_key, NULL, "(public-key(ecdsa(curve %s)(q %b)))", p_curve, 2 * buffer_size + 1, xy_buffer)) != 0) {
      printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
      return -10;
    }
  } else {
    if ((rc = gcry_sexp_build (p_key, NULL, "(key-data(public-key(ecdh(curve %s)(q %b))))", p_curve, 2 * buffer_size + 1, xy_buffer)) != 0) {
      printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
      return -11;
    }
  }
  show_sexp("compressed_hex_key_to_sexp: p_key=", *p_key);
  
  /* Release resources */
  gcry_free(x_buffer);
  gcry_free(y_buffer);
  gcry_free(xy_buffer);
  gcry_mpi_release(x);
  gcry_mpi_release(y);

  gcry_mpi_release(two);
  gcry_mpi_release(three);
  gcry_mpi_release(a);
  gcry_mpi_release(b);
  gcry_mpi_release(p);
  gcry_mpi_release(x_3);
  gcry_mpi_release(axb);
  
  gcry_sexp_release(private_key);
  gcry_sexp_release(key);
  gcry_sexp_release(keyparm);
 
  return 0;
} // End of function compressed_hex_key_to_sexp

static void etsi_ieee1609dot2_cleanup(void)
{
  printf(">>> ieee1609dot2_cleanup\n");
  
  if (g_decrypt_record.encryption_algo != 0xff) {
    g_decrypt_record.encryption_algo = 0xff;
    /* FIXME wmem_free generate a trap :(
    if (g_decrypt_record.encryption_compressed_key != NULL) {
      wmem_free(wmem_packet_scope(), g_decrypt_record.encryption_compressed_key);
      g_decrypt_record.encryption_compressed_key = NULL;
    }
    if (g_decrypt_record.nonce != NULL) {
      wmem_free(wmem_packet_scope(), g_decrypt_record.nonce);
      g_decrypt_record.nonce = NULL;
    }
    if (g_decrypt_record.tag != NULL) {
      wmem_free(wmem_packet_scope(), g_decrypt_record.tag);
      g_decrypt_record.tag = NULL;
    }
    if (g_decrypt_record.encrypted_aes_symmetric_key != NULL) {
      wmem_free(wmem_packet_scope(), g_decrypt_record.encrypted_aes_symmetric_key);
      g_decrypt_record.encrypted_aes_symmetric_key = NULL;
      }*/
  }
}

static void ah_prompt(packet_info *pinfo, gchar *result)
{
  printf(">>> ah_prompt\n");
  
  g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "ETSI IEEE 1609dot2 Protocol %u as",
	     GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_ah, pinfo->curr_layer_num)));
}

static gpointer ah_value(packet_info *pinfo)
{
  printf(">>> ah_value\n");
  
  return p_get_proto_data(pinfo->pool, pinfo, proto_ah, pinfo->curr_layer_num);
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
      g_decrypt_record.encryption_compressed_key_mode = 0x02;
      g_decrypt_record.encryption_compressed_key = (gchar*)wmem_alloc(wmem_packet_scope(), 32);
      tvb_memcpy(tvb, (char*)g_decrypt_record.encryption_compressed_key, offset, 32);
      proto_tree_add_item(sh_tree, hf_1609dot2_compressed_y_0, tvb, offset, 32, FALSE);
      offset += 32;
    } else if ((tag & 0x7f) == 0x03) { // Decode compressed-y-1
      g_decrypt_record.encryption_compressed_key_mode = 0x03;
      g_decrypt_record.encryption_compressed_key = (gchar*)wmem_alloc(wmem_packet_scope(), 32);
      tvb_memcpy(tvb, (char*)g_decrypt_record.encryption_compressed_key, offset, 32);
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
      /* guint8 full_len; */
      guint8 len;

      /* full_len = tvb_get_guint8(tvb, offset);
        printf("dissect_ieee1609dot2_ssp_packet: full_len=%d\n", full_len); */
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
      /* guint8 full_len; */
      guint8 len;

      /* full_len = tvb_get_guint8(tvb, offset);
         printf("dissect_ieee1609dot2_ssp_packet: full_len=%d\n", full_len); */
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
      proto_tree_add_item(sh_tree, hf_1609dot2_protocol_version, tvb, offset, 1, FALSE);
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
  /* proto_tree *sh_tree = NULL; */
  /* proto_item *sh_ti = NULL; */

  printf(">>> dissect_ieee1609dot2_unsecured_data_packet: offset=0x%02x\n", offset);
  //printf("dissect_ieee1609dot2_unsecured_data_packet: %02x - %02x - %02x - %02x - %02x\n", tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1), tvb_get_guint8(tvb, offset + 2), tvb_get_guint8(tvb, offset + 3), tvb_get_guint8(tvb, offset + 4));
  if (tree) { /* we are being asked for details */
    //guint8 tag;
    gint len;
    /* tvbuff_t *next_tvb; */
    
    len = tvb_get_guint8(tvb, offset);
    offset += 1;
    printf("dissect_ieee1609dot2_unsecured_data_packet: len = %d - offset = %d\n", len, offset);
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    /* TODO Dissect GN Packet
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_unsecured_data_packet, tvb, offset, len, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_unsecured_content);

    next_tvb = tvb_new_subset_length(tvb, offset, len);
    Call GN codec dissect_unsecured_packet(next_tvb, pinfo, sh_tree, 0); */
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
dissect_ieee1609dot2_enc_data_key_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_enc_data_key_data_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_enc_data_key_data_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_enc_data_key_data_packet);

    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_enc_data_key_data_packet: tag: '%x'\n", tag);
    offset += 1;
    if ((tag & 0x7f) == 0x00) {
      g_decrypt_record.encryption_algo = 0;
      offset = dissect_ieee1609dot2_eccP256CurvePoint_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecies_nistp_256, ett_1609dot2_base_public_enc_key);
    } else {
      g_decrypt_record.encryption_algo = 1;
      offset = dissect_ieee1609dot2_eccP256CurvePoint_packet(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecies_brainpoolp_256, ett_1609dot2_base_public_enc_key);
    }
    // OCTET STRING (SIZE (16))
    g_decrypt_record.encrypted_aes_symmetric_key = (gchar*)wmem_alloc(wmem_packet_scope(), 16);
    tvb_memcpy(tvb, (char*)g_decrypt_record.encrypted_aes_symmetric_key, offset, 16);
    proto_tree_add_item(sh_tree, hf_1609dot2_c, tvb, offset, 16, FALSE); /* Encrypted AES symmetric key */
    offset += 16;
    // OCTET STRING (SIZE (16))
    g_decrypt_record.tag = (gchar*)wmem_alloc(wmem_packet_scope(), 16);
    tvb_memcpy(tvb, (char*)g_decrypt_record.tag, offset, 16);
    proto_tree_add_item(sh_tree, hf_1609dot2_t, tvb, offset, 16, FALSE); /* Tag */
    offset += 16;    

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_enc_data_key_data_packet

static int
dissect_ieee1609dot2_pk_recipient_info_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_pk_recipient_info_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_pk_recipient_info_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_pk_recipient_info_packet);

    sh_length = offset;
    
    proto_tree_add_item(sh_tree, hf_gn_sh_field_hashedid8, tvb, offset, 8, FALSE);
    offset += 8;
    offset = dissect_ieee1609dot2_enc_data_key_data_packet(tvb, pinfo, sh_tree, offset);

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_pk_recipient_info_packet

static int
dissect_ieee1609dot2_recipient_info_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_recipient_info_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_recipient_info_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_recipient_info_packet);

    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_recipient_info_packet: tag: '%x'\n", tag);
    offset += 1;
    if ((tag & 0x7f) == 0x00) {
      //offset = 
    } else if ((tag & 0x7f) == 0x01) {
      //offset = dissect_ieee1609dot2_certificate_packet(tvb, pinfo, sh_tree, offset);
    } else if ((tag & 0x7f) == 0x02) {
      offset = dissect_ieee1609dot2_pk_recipient_info_packet(tvb, pinfo, sh_tree, offset);
    } else if ((tag & 0x7f) == 0x03) {
      offset = dissect_ieee1609dot2_pk_recipient_info_packet(tvb, pinfo, sh_tree, offset);
    } else if ((tag & 0x7f) == 0x04) {
      offset = dissect_ieee1609dot2_pk_recipient_info_packet(tvb, pinfo, sh_tree, offset);
    }

    proto_item_set_len(sh_ti, offset - sh_length);
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_recipient_info_packet

static int
dissect_ieee1609dot2_recipient_info_data_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_recipient_info_data_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    guint8 items;

    sh_ti = proto_tree_add_item(tree, hf_1609dot2_recipient_info_data_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_recipient_info_data_packet);

    sh_length = offset;
    /* Number of recipients */
    items = tvb_get_guint8(tvb, offset);
    offset += 1;
    printf("dissect_ieee1609dot2_recipient_info_data_packet: #items=%d\n", items);
    for (int i = 0; i < items; i++) {
      offset += 1; // Skip item id
      offset = dissect_ieee1609dot2_recipient_info_packet(tvb, pinfo, sh_tree, offset);
    } // End of 'for' statement

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_recipient_info_data_packet

static int
dissect_ieee1609dot2_aes_128_ccm_cipher_text_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_aes_128_ccm_cipher_text_data_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    gint sh_length;
    gint len;

    sh_ti = proto_tree_add_item(tree, hf_1609dot2_aes_128_ccm_cipher_text_data_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_aes_128_ccm_cipher_text_data_packet);

    sh_length = offset;
    
    // OCTET STRING (SIZE (12))
    g_decrypt_record.nonce = (gchar*)wmem_alloc(wmem_packet_scope(), 12);
    tvb_memcpy(tvb, (char*)g_decrypt_record.nonce, offset, 12);
    proto_tree_add_item(sh_tree, hf_1609dot2_nonce, tvb, offset, 12, FALSE);
    offset += 12;
    // Ciphered text
    len = tvb_get_guint8(tvb, offset);
    offset += 1;
    if ((len & 0x80) == 0x80) { // TODO To be refined, assume that cyphered text length is less than 65535 (2 bytes)
      len = (guint16)(tvb_get_guint8(tvb, offset) << 8) | (guint16)tvb_get_guint8(tvb, offset + 1);
      offset += 2;
    }
    proto_tree_add_item(sh_tree, hf_gn_st_opaque, tvb, offset, len, FALSE);
    if (g_options.enable_encryption_decode) {
      printf("dissect_ieee1609dot2_aes_128_ccm_cipher_text_data_packet: Start decryption");
      decrypt_and_decode_pki_message(tvb, pinfo, tree, offset, len);
    }
    
    offset += len;    
    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_aes_128_ccm_cipher_text_data_packet

static int
dissect_ieee1609dot2_ciphertext_data_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  printf(">>> dissect_ieee1609dot2_ciphertext_data_packet: offset=0x%02x\n", offset);
  if (tree) { /* we are being asked for details */
    guint8 tag;
    gint sh_length;

    sh_ti = proto_tree_add_item(tree, hf_1609dot2_ciphertext_data_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_ciphertext_data_packet);

    sh_length = offset;
    
    /* Sequence Tag */
    tag = tvb_get_guint8(tvb, offset);
    printf("dissect_ieee1609dot2_ciphertext_data_packet: tag: '%x'\n", tag);
    offset += 1;
    if ((tag & 0x7f) == 0x00) {
      offset = dissect_ieee1609dot2_aes_128_ccm_cipher_text_data_packet(tvb, pinfo, sh_tree, offset);
    }
    
    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_ciphertext_data_packet

static int
dissect_ieee1609dot2_encrypted_data_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;

  /* Number of recipients */
  printf(">>> dissect_ieee1609dot2_encrypted_data_packet: offset=0x%02x\n", offset);

  printf("dissect_ieee1609dot2_encrypted_data_packet: enable_encryption_decode=%x\n", g_options.enable_encryption_decode);
  printf("dissect_ieee1609dot2_encrypted_data_packet: ts_private_enc_key=%s\n", (g_options.ts_private_enc_key == NULL) ? "(null)" : g_options.ts_private_enc_key);
  printf("dissect_ieee1609dot2_encrypted_data_packet: ts_public_enc_key=%s\n", (g_options.ts_public_enc_key == NULL) ? "(null)" : g_options.ts_public_enc_key);
  printf("dissect_ieee1609dot2_encrypted_data_packet: iut_private_enc_key=%s\n", (g_options.iut_private_enc_key == NULL) ? "(null)" : g_options.iut_private_enc_key);
  printf("dissect_ieee1609dot2_encrypted_data_packet: iut_public_enc_key=%s\n", (g_options.iut_public_enc_key == NULL) ? "(null)" : g_options.iut_public_enc_key);

  if (tree) { /* we are being asked for details */  
    gint sh_len;
	
    sh_ti = proto_tree_add_item(tree, hf_1609dot2_encrypted_data_packet, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_encrypted_data_packet);

    sh_len =  offset;
    offset = dissect_ieee1609dot2_recipient_info_data_packet(tvb, pinfo, sh_tree, offset);
    offset = dissect_ieee1609dot2_ciphertext_data_packet(tvb, pinfo, sh_tree, offset);
    proto_item_set_len(sh_ti, offset - sh_len);
  }
  
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
    proto_tree_add_item(sh_tree, hf_1609dot2_protocol_version, tvb, offset, 1, FALSE);
    offset += 1;
    /* Content */
    offset = dissect_ieee1609dot2_content_packet(tvb, pinfo, sh_tree, offset);
    proto_item_set_len(sh_ti, offset - sh_length);    
  }
  
  return offset;
} // End of function dissect_ieee1609dot2_data_packet

static gboolean
dissect_ieee1609dot2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree *sh_tree = NULL;
  proto_item *sh_ti = NULL;
  guint8 version = 0;
  gint offset = 0;

  printf(">>> dissect_ieee1609dot2: offset=0x%02x\n", offset);
  /* Check version */
  version = tvb_get_guint8(tvb, 0);
  if(version != ETSI_1609DOT2_VERSION) {
    return 0;
  }
  
  /* Update COL_PROTOCOL */ 
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETSI IEEE 1609dot2 Protocol");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  if (tree) { /* we are being asked for details */
    /* Main tree */
    sh_ti = proto_tree_add_item(tree, proto_etsi_ieee1609dot2, tvb, offset, -1, FALSE);
    proto_item_append_text(sh_ti, ": ETSI IEEE 1609dot2 Protocol");
    sh_tree = proto_item_add_subtree(sh_ti, ett_proto_etsi_ieee1609dot2);

    /* Dissect*/
    offset = dissect_ieee1609dot2_data_packet(tvb, pinfo, sh_tree, offset);
    proto_item_set_len(sh_ti, offset);    
  }
  
  return offset;
} // End of function dissect_ieee1609dot2


static void etsi_ieee1609dot2_cleanup_protocol(void)
{
  printf(">>> etsi_ieee1609dot2_cleanup_protocol\n");  
}

/* Register the protocol with Wireshark */
void
proto_register_etsi_ieee1609dot2(void)
{
  module_t *etsi_ieee1609dot2_module;
  static build_valid_func ah_da_build_value[1] = {ah_value};
  static decode_as_value_t ah_da_values = {ah_prompt, 1, ah_da_build_value};
  static decode_as_t ah_da = {"ah", "ETSI IEEE 1609dot2", "http.media_type", 1, 0, &ah_da_values, NULL, NULL,
			      decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};


  /* Setup list of header fields */
  static hf_register_info hf[] = {
				  /* Secured Packet - See IEEE Std 1609.2a-2017 */
				  { &hf_1609dot2_protocol_version,
				    {"Version", "gn.version", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
				  },
				  { &hf_1609dot2_secured_message,
				    { "IEEE 1609.2 Message", "gn.sec", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
				  { &hf_1609dot2_encrypted_data_packet,
				    {"IEEE 1609.2 EncryptedData", "gn.sec.enc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_recipient_info_data_packet,
				    {"IEEE 1609.2 RecipientInfo list", "gn.sec.enc.ris", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_recipient_info_packet,
				    {"IEEE 1609.2 RecipientInfo", "gn.sec.enc.ris.ri", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_pk_recipient_info_packet,
				    {"IEEE 1609.2 PKRecipientInfo", "gn.sec.enc.ris.ri.pkri", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_enc_data_key_data_packet,
				    {"IEEE 1609.2 Encrypted DataEncryptionKey", "gn.sec.enc.ris.ri.pkri.enckey", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_c,
				    {"IEEE 1609.2 Encrypted AES Symmetric keys", "gn.sec.enc.ris.ri.pkri.c", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_t,
				    {"IEEE 1609.2 Tag", "gn.sec.enc.ris.ri.pkri.t", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_ciphertext_data_packet,
				    {"IEEE 1609.2 Ciphered data", "gn.sec.enc.cyphered_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_aes_128_ccm_cipher_text_data_packet,
				    {"IEEE 1609.2 Aes128 Ccm Ciphered data", "gn.sec.enc.cyphered_data.aes128ccm", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
				  { &hf_1609dot2_nonce,
				    {"IEEE 1609.2 Nonce", "gn.sec.enc.cyphered_data.aes128ccm.nonce", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
				  },
    { &hf_gn_sh_field_hashedid8,
      {"HashedId8", "gn.sec.hashedid8", FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_st_opaque,
      { "Opaque", "gn.sec.opaque", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
			&ett_proto_etsi_ieee1609dot2,
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
			&ett_1609dot2_country_region,
			&ett_1609dot2_encrypted_data_packet,
			&ett_1609dot2_recipient_info_data_packet,
			&ett_1609dot2_recipient_info_packet,
			&ett_1609dot2_pk_recipient_info_packet,
			&ett_1609dot2_enc_data_key_data_packet,
			&ett_1609dot2_ciphertext_data_packet,
			&ett_1609dot2_aes_128_ccm_cipher_text_data_packet
  };

  /* Register the protocol name and description */
  /*proto_etsi_ieee1609dot2 = proto_register_protocol (
						     "ItsEtsiIEEE1609dot2",
						     "ItsEtsiIEEE1609dot2",
						     "ItsEtsiIEEE1609dot2"
						     );*/
  proto_etsi_ieee1609dot2 = proto_register_protocol (
						     "Its Etsi IEEE 1609dot2", /* name       */
						     "Its Etsi IEEE 1609dot2", /* short name */
						     "its_etsi_ieee_1609dot2"  /* abbrev     */
						     );

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_etsi_ieee1609dot2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("etsi_ieee1609dot2", dissect_ieee1609dot2, proto_etsi_ieee1609dot2);
  
  etsi_ieee1609dot2_module = prefs_register_protocol(proto_etsi_ieee1609dot2, proto_reg_handoff_etsi_ieee1609dot2);
  /* Register preferences module */
  prefs_register_bool_preference(etsi_ieee1609dot2_module,
				 "enable_encryption_decode",
				 "Attempt to detect/decode encrypted ETSI IEEE 1609dot2 PKI payloads",
                                 "TODO1.",
                                 &(g_options.enable_encryption_decode)
				 );
  prefs_register_string_preference(etsi_ieee1609dot2_module,
				   "ts_private_enc_key",
				   "TS Private encryption key ",
				   "Test System private encryption key",
				   &(g_options.ts_private_enc_key)
				   );
  prefs_register_string_preference(etsi_ieee1609dot2_module,
				   "ts_public_enc_key",
				   "TS Public encryption key ",
				   "Test System public encryption key",
				   &(g_options.ts_public_enc_key)
				   );
  prefs_register_string_preference(etsi_ieee1609dot2_module,
				   "ts_public_sign_key",
				   "TS Public verification key ",
				   "Test System public verification key",
				   &(g_options.ts_public_enc_key)
				   );
  prefs_register_string_preference(etsi_ieee1609dot2_module,
				   "iut_private_enc_key",
				   "IUT Private encryption key ",
				   "IUT private encryption key",
				   &(g_options.iut_private_enc_key)
				   );
  prefs_register_string_preference(etsi_ieee1609dot2_module,
				   "iut_public_enc_key",
				   "IUT Public encryption key ",
				   "IUT public encryption key",
				   &(g_options.iut_public_enc_key)
				   );
  prefs_register_string_preference(etsi_ieee1609dot2_module,
				   "iut_public_sign_key",
				   "IUT Public verification key ",
				   "TIUT public verification key",
				   &(g_options.iut_public_enc_key)
				   );
  
  register_cleanup_routine(&etsi_ieee1609dot2_cleanup_protocol);
  register_decode_as(&ah_da);
}

void
proto_reg_handoff_etsi_ieee1609dot2(void)
{
  printf(">>> proto_reg_handoff_etsi_ieee1609dot2\n");
  
  dissector_handle_t etsi_ieee1609dot2_handle;
  etsi_ieee1609dot2_handle = create_dissector_handle(dissect_ieee1609dot2, proto_etsi_ieee1609dot2);

  dissector_add_for_decode_as("udp.port", etsi_ieee1609dot2_handle);
  dissector_add_for_decode_as("http.port", etsi_ieee1609dot2_handle);

  dissector_add_string("media_type", "application/x-its", etsi_ieee1609dot2_handle);
  dissector_add_string("media_type", "application/x-its-request", etsi_ieee1609dot2_handle);
  dissector_add_string("media_type", "application/x-its-response", etsi_ieee1609dot2_handle);

  dissector_add_uint_range_with_preference("tcp.port", "", etsi_ieee1609dot2_handle);
  dissector_add_uint_range_with_preference("udp.port", "", etsi_ieee1609dot2_handle);

  register_cleanup_routine(etsi_ieee1609dot2_cleanup);

  /* register IEEE 1609.2 sub-dissector */
  /*gn_handle = find_dissector("gn");
    dissector_add_uint("gn.bnh", 2, etsi_ieee1609dot2_handle);*/
}

static int
decrypt_and_decode_pki_message(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int offset _U_, int len _U_) // TODO Remove _U_
{
  size_t size = 0;                                   /* Working buiffer size */
  //char *buffer = NULL;                               /* Working buffer */
  unsigned char* ts_private_key = NULL;              /* Binary Test System privqte key */
  /* unsigned char* ts_public_enc_key; */
  /* unsigned char* ts_public_sign_key; */
  /* unsigned char* iut_private_key; */
  /* unsigned char* iut_public_enc_key; */
  /* unsigned char* iut_public_sign_key; */
  char* nist_curve = "NIST P-256";
  char* brainpool_curve = "brainpoolP256r1";
  gcry_error_t	err;                                 /* gcry_ function return code */
  gcry_ctx_t ctx;
  gcry_mpi_t q;                                      /* Calculate public key based on private k */
  gcry_sexp_t gcry_ts_private_key = NULL;            /* Private key s-exp */
  gcry_sexp_t gcry_ts_public_key = NULL;             /* Public key s-exp */
  gcry_cipher_hd_t cipher = NULL;
  //gcry_sexp_t key = NULL;
  //char* w_buffer = NULL;                             /* Wireshark decoding buffer containing cyphered data */
  /* char* clear_data = NULL; */
  //tvbuff_t* clear_tvb = NULL;

  printf(">>> decrypt_and_decode_pki_message\n");
  
  /* w_buffer = (char*)tvb_memdup(wmem_packet_scope(), tvb, offset, len); */
  printf("decrypt_and_decode_pki_message: algo: %02x\n", g_decrypt_record.encryption_algo);
  printf("decrypt_and_decode_pki_message: comp.mode: %02x\n", g_decrypt_record.encryption_compressed_key_mode);
  
  /* guint8 encryption_algo; */
  /* guint8 encryption_compressed_key_mode; */
  /* gchar* encryption_compressed_key; */
  /* gchar* nonce; */
  /* gchar* tag; */
  /* gchar* encrypted_aes_symmetric_key; */
  
  // 1. Convert hexadecimal key into binary
  /* ts_public_enc_key = hex_to_bin(g_options.ts_public_enc_key); */
  /* ts_public_sign_key = hex_to_bin(g_options.ts_public_sign_key); */
  /* iut_private_key = hex_to_bin(g_options.iut_private_enc_key); */
  /* iut_public_enc_key = hex_to_bin(g_options.iut_public_enc_key); */
  /* iut_public_sign_key = hex_to_bin(g_options.iut_public_sign_key); */
  
  // 2. Convert encryption keys into S-expression
  // 2.1 Convert private key into sexp
  ts_private_key = hex_to_bin(g_options.ts_private_enc_key, &size);
  printf("decrypt_and_decode_pki_message: size: %zu\n", size);
  show_hex("ts_private_key:", ts_private_key, size);
  if (g_decrypt_record.encryption_algo == 0) {
    err = gcry_sexp_build(&gcry_ts_private_key, NULL, "(private-key(ecc(curve %s)(d %b)))", nist_curve, size, ts_private_key);
  } else {
    err = gcry_sexp_build(&gcry_ts_private_key, NULL, "(private-key(ecc(curve %s)(d %b)))", brainpool_curve, size, ts_private_key);
  }
  if (gcry_err_code(err)) {
    fprintf(stderr, "decrypt_and_decode_pki_message: Failed %s/%s\n", gcry_strsource(err), gcry_strerror(err));
    goto decrypt_and_decode_pki_message_label;
  }
  // TODO Test the private key is on the curve 
  // 2.2 Convert public keys into sexp
  if ((err = gcry_mpi_ec_new(&ctx, gcry_ts_private_key, NULL)) != 0) {
    fprintf(stderr, "decrypt_and_decode_pki_message: Failed %s/%s\n", gcry_strsource(err), gcry_strerror(err));
    goto decrypt_and_decode_pki_message_label;
  }
  if ((q = gcry_mpi_ec_get_mpi("q", ctx, 0)) == NULL) {
    fprintf(stderr, "decrypt_and_decode_pki_message: Failed gcry_mpi_ec_get_mpi\n");
    goto decrypt_and_decode_pki_message_label;
  }
  if (g_decrypt_record.encryption_algo == 0) {
    err = gcry_sexp_build(&gcry_ts_public_key, NULL, "(public-key(ecc(curve %s)(q %m)))", nist_curve, q);
  } else {
    err = gcry_sexp_build(&gcry_ts_public_key, NULL, "(public-key(ecc(curve %s)(q %m)))", brainpool_curve, q);
  }
  if (gcry_err_code(err)) {
    fprintf(stderr, "decrypt_and_decode_pki_message: Failed %s/%s\n", gcry_strsource(err), gcry_strerror(err));
    goto decrypt_and_decode_pki_message_label;
  }
  gcry_mpi_release(q);
  gcry_ctx_release(ctx);
  // TODO Test the public key is on the curve 
  show_sexp("ts_private_key: ", gcry_ts_private_key);
  show_sexp("ts_public_key: ", gcry_ts_public_key);
  // 1. Derive ephemeral key
  show_hex("encryption_compressed_key:", g_decrypt_record.encryption_compressed_key, 32);
  show_hex("nonce:", g_decrypt_record.nonce, 12);
  show_hex("tag:", g_decrypt_record.tag, 16);
  show_hex("encrypted_aes_symmetric_key:", g_decrypt_record.encrypted_aes_symmetric_key, 16);

  {
    /*const guint8 secret_key_length = 32; // TODO Get length from grcy_ API
    const guint8 nonce_length = 12;
    const guint8 sym_key_length = 16;
    const guint8 tag_length = 16;
    const guint8 k_length = 32;*/

    /* Convert encryption_compressed_key into sexp */
    char* curve = "NIST P-256";
    char* algo = "ecdh";
    gcry_sexp_t gcry_ephemeral_key;
    compressed_hex_key_to_sexp(g_decrypt_record.encryption_compressed_key, 32, g_decrypt_record.encryption_compressed_key_mode, curve, algo, &gcry_ephemeral_key);
    show_sexp("gcry_ephemeral_key=", gcry_ephemeral_key);
    /* Derive ephemeral key */
    
    
    
    
    /* Release resources */
    gcry_sexp_release(gcry_ephemeral_key);
  }








  
  // 2. Decrypt the message
  err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0);
  if (gcry_err_code(err)) {
    fprintf(stderr, "decrypt_and_decode_pki_message: Failed to retrieve cyphering handle\n");
    goto decrypt_and_decode_pki_message_label;
  }
  /* clear_data = (char*)wmem_alloc(wmem_packet_scope(), len); /\* Encrypted and clear messages have the same length *\/   */
  // TODO Decrypt
  gcry_cipher_close(cipher);

  // Release resources
  /* free(clear_data); */
  gcry_sexp_release(gcry_ts_public_key);
  gcry_sexp_release(gcry_ts_private_key);
  free(ts_private_key);
  /* free(ts_public_enc_key); */
  /* free(ts_public_sign_key); */
  /* free(iut_private_key); */
  /* free(iut_public_enc_key); */
  /* free(iut_public_sign_key); */
  
  /* clear_data contains the decrypted data */
  
  //clear_tvb = tvb_new_child_real_data(tvb, (const guint8 *)clear_data, 0, len);
  
  /* now try and decode it */
  //dissect_ieee1609dot2_data_packet(clear_tvb, pinfo, tree, 0);
  
  return 0;
 decrypt_and_decode_pki_message_label:
  free(ts_private_key);
  /* free(ts_public_enc_key); */
  /* free(ts_public_sign_key); */
  /* free(iut_private_key); */
  /* free(iut_public_enc_key); */
  /* free(iut_public_sign_key); */
  
  return -1;
} // End of function decrypt_and_decode_pki_message
