#include <wsutil/wsgcrypt.h>

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
char* bin_to_hex(const unsigned char* input, const size_t buffer_length) {
  char* buf = NULL;
  size_t i = 0, j = 0;
  
  if (buffer_length == 0) {
    return "";
  }
  buf = (char*)gcry_malloc(buffer_length << 1);
  
  do {
    *(buf + j) = "0123456789ABCDEF"[(*(input + i) >> 4) & 0x0F];
    *(buf + j + 1) = "0123456789ABCDEF"[*(input + i) & 0x0F];
    i += 1; j += 2;
  } while (i < buffer_length);

  return buf;
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
  gcry_sexp_t key = NULL;
  gcry_sexp_t private_key = NULL;
  gcry_sexp_t e_key = NULL;
  
  gcry_ctx_t ctx = NULL;
  gcry_mpi_t a, b, p, p_plus_1, x, q, r;
  gcry_mpi_t two, three, four, x_3, axb, y_2, y_prime, y_s, y;
    
  gcry_error_t rc;

  printf(">>> compressed_hex_key_to_sexp: %zu - %d - %s - %s\n", p_comp_key_size, p_comp_mode, p_curve, p_algo);
  
  /* Extract (p, a, b) parameters from elliptic curve */
  if ((rc = gcry_sexp_build (&keyparm, NULL, "(genkey(ecc(curve %s)(flags param)))", p_curve)) != 0) {
    printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
    return -1;
  }
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
  gcry_sexp_release(key);
  gcry_sexp_release(private_key);
  gcry_sexp_release(keyparm);
  
  /* Initialise x public key to compute y_2 */
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
  
  /* NIST P-256 Ecc curve equation: y^2=x^3+a*x+b */
  /* Compute y^2 */
  two = gcry_mpi_set_ui(NULL, 2);
  three = gcry_mpi_set_ui(NULL, 3);
  four = gcry_mpi_set_ui(NULL, 4);
  x_3 = gcry_mpi_new(0);
  axb = gcry_mpi_new(0);
  y_2 = gcry_mpi_new(0);
  gcry_mpi_powm(x_3, x, three, p); // w = b^e \bmod m. 
  gcry_mpi_mulm(axb, a, x, p);
  gcry_mpi_addm(axb, axb, b, p);
  gcry_mpi_addm(y_2, x_3, axb, p);
  gcry_mpi_release(two);
  gcry_mpi_release(three);
  gcry_mpi_release(a);
  gcry_mpi_release(b);
  gcry_mpi_release(x_3);
  gcry_mpi_release(axb);
  gcry_mpi_release(x);

  /**
   * Compute sqrt(y^2): two solutions
   * NIST P-256 curve: p congruant to 1 (mod 4) = 3 - https://www.ietf.org/archive/id/draft-jivsov-ecc-compact-05.txt Clause 4.3.  The efficient square root algorithm for p=4*k+3
   * Solution: y' sqrt(y_2) = y' = y2^((p+1)/4)
   */
  q = gcry_mpi_new(0);
  r = gcry_mpi_new(0);
  p_plus_1 = gcry_mpi_new(0);
  y_prime = gcry_mpi_new(0);
  gcry_mpi_add_ui(p_plus_1, p, 1);
  gcry_mpi_div(q, r, p_plus_1, four, 0);
  gcry_mpi_release(p_plus_1);
  gcry_mpi_powm(y_prime, y_2, q, p);
  gcry_mpi_release(four);
  gcry_mpi_release(q);
  gcry_mpi_release(r);
  gcry_mpi_release(y_2);

  /* The solution to y_2 is y = min(y',p-y') */
  y = gcry_mpi_new (0);
  /* Test LSB bit of y' */
  if (gcry_mpi_test_bit(y_prime, 0) && (p_comp_mode == 1)) {
    gcry_mpi_add_ui(y, y_prime, 0);  // y = y'
  } else {
    y_s = gcry_mpi_new (0);
    gcry_mpi_subm(y_s, p, y_prime, p); /* y_s = p - y_prime (mod p) */
    gcry_mpi_add_ui(y, y_s, 0);  // y = p-y'
    gcry_mpi_release(y_s);
  }
  gcry_mpi_release(y_prime);
  
  //show_hex(x_buffer, buffer_size, "x_buffer="),
  y_buffer = (unsigned char*)gcry_malloc(buffer_size);
  gcry_mpi_print (GCRYMPI_FMT_USG, y_buffer, buffer_size, NULL, y);
  gcry_mpi_release (y);
  //show_hex(y_buffer, buffer_size, "y_buffer="),
  xy_buffer = (unsigned char*)gcry_malloc(1 + 2 * buffer_size);
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
      return -11;
    }
  } else {
    if ((rc = gcry_sexp_build (p_key, NULL, "(key-data(public-key(ecdh(curve %s)(q %b))))", p_curve, 2 * buffer_size + 1, xy_buffer)) != 0) {
      printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
      return -12;
    }
  }
  
  /* Release resources */
  gcry_free(x_buffer);
  gcry_free(y_buffer);
  gcry_free(xy_buffer);
  
  return 0;
} // End of function compressed_hex_key_to_sexp

static void etsi_gn_cleanup(void)
{
  printf(">>> gn_cleanup\n");
  
  if (g_sign_record.sign_algo != 0xff) {
    g_sign_record.sign_algo = 0xff;
  }
}

static void
etsi_gn_cleanup_protocol(void)
{
  printf(">>> etsi_gn_cleanup_protocol\n");  
}

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

static void ah_prompt(packet_info *pinfo, gchar *result)
{
  printf(">>> ah_prompt\n");
  
  g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "ETSI ITS GeoNetworking Protocol %u as",
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
      g_sign_record.sign_compressed_key_mode = 0;
      g_sign_record.sign_public_compressed_key = (gchar*)wmem_alloc(wmem_packet_scope(), 32);
      tvb_memcpy(tvb, (char*)g_sign_record.sign_public_compressed_key, offset, 32);
      proto_tree_add_item(sh_tree, hf_1609dot2_compressed_y_0, tvb, offset, 32, FALSE);
      offset += 32;
    } else if ((tag & 0x7f) == 0x03) { // Decode compressed-y-1
      g_sign_record.sign_compressed_key_mode = 1;
      g_sign_record.sign_public_compressed_key = (gchar*)wmem_alloc(wmem_packet_scope(), 32);
      tvb_memcpy(tvb, (char*)g_sign_record.sign_public_compressed_key, offset, 32);
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
      g_sign_record.sign_compressed_key_mode = 0;
      g_sign_record.sign_public_compressed_key = (gchar*)wmem_alloc(wmem_packet_scope(), 48);
      tvb_memcpy(tvb, (char*)g_sign_record.sign_public_compressed_key, offset, 48);
      proto_tree_add_item(sh_tree, hf_1609dot2_compressed_y_0, tvb, offset, 48, FALSE);
      offset += 48;
    } else if ((tag & 0x7f) == 0x03) { // Decode compressed-y-1
      g_sign_record.sign_compressed_key_mode = 1;
      g_sign_record.sign_public_compressed_key = (gchar*)wmem_alloc(wmem_packet_scope(), 48);
      tvb_memcpy(tvb, (char*)g_sign_record.sign_public_compressed_key, offset, 48);
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

    if (((tag & 0x7f) == 0x00) || ((tag & 0x7f) == 0x01)) {
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
    printf("dissect_ieee1609dot2_appPermissions_packet: len=%d\n", len);
    offset += 1;
    if (len == 0) {
      return offset;
    } else if (len == 1) {
      items = tvb_get_guint8(tvb, offset); /* Length in bytes of the number of items */
    } if (len == 2) {
      items = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN); /* Length in bytes of the number of items */
    } // else, not reallistic
    offset += len;
    printf("dissect_ieee1609dot2_appPermissions_packet: #items=%d\n", items);
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
      gint issuer_offset = offset - 1;
      
      printf("dissect_ieee1609dot2_certificate_packet: issuer_offset: '%x'\n", issuer_offset);
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
      printf("dissect_ieee1609dot2_certificate_packet: offset: '%x'\n", offset);
      g_sign_record.issuer_length = offset - issuer_offset;
      printf("dissect_ieee1609dot2_certificate_packet: Certificate length: %zu\n", g_sign_record.issuer_length);
      g_sign_record.issuer = (gchar*)wmem_alloc(wmem_packet_scope(), g_sign_record.issuer_length);
      tvb_memcpy(tvb, (char*)g_sign_record.issuer, issuer_offset, g_sign_record.issuer_length);
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
    
    g_sign_record.sign_r = (gchar*)wmem_alloc(wmem_packet_scope(), 32);
    tvb_memcpy(tvb, (char*)g_sign_record.sign_r, offset + 1, 32);
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
    
    g_sign_record.sign_r = (gchar*)wmem_alloc(wmem_packet_scope(), 48);
    tvb_memcpy(tvb, (char*)g_sign_record.sign_r, offset + 1, 48);
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
  g_sign_record.sign_algo = 0;
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signer_identifier_packet);
    g_sign_record.sh_ti = sh_ti;

    // EccP256CurvePoint
    offset = dissect_ieee1609dot2_eccP256CurvePoint_r_sig(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecdsa_nistp_256);
    // OCTET STRING (SIZE (32))
    g_sign_record.sign_s = (gchar*)wmem_alloc(wmem_packet_scope(), 32);
    tvb_memcpy(tvb, (char*)g_sign_record.sign_s, offset, 32);
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
  g_sign_record.sign_algo = 1;
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, -1, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signer_identifier_packet);
    g_sign_record.sh_ti = sh_ti;

    // EccP256CurvePoint
    offset = dissect_ieee1609dot2_eccP256CurvePoint_r_sig(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecdsa_brainpoolp_256);
    // OCTET STRING (SIZE (32))
    g_sign_record.sign_s = (gchar*)wmem_alloc(wmem_packet_scope(), 32);
    tvb_memcpy(tvb, (char*)g_sign_record.sign_s, offset, 32);
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
  g_sign_record.sign_algo = 2;
  if (tree) { /* we are being asked for details */
    gint sh_length;
    
    /* Sec Header tree - See IEEE Std 1609.2a-2017 */
    sh_length = offset;
    sh_ti = proto_tree_add_item(tree, hf, tvb, offset, sh_length, FALSE);
    sh_tree = proto_item_add_subtree(sh_ti, ett_1609dot2_signer_identifier_packet);
    g_sign_record.sh_ti = sh_ti;

    // EccP384CurvePoint
    offset = dissect_ieee1609dot2_eccP384CurvePoint_r_sig(tvb, pinfo, sh_tree, offset, hf_1609dot2_ecdsa_brainpoolp_384);
    // OCTET STRING (SIZE (48))
    g_sign_record.sign_s = (gchar*)wmem_alloc(wmem_packet_scope(), 48);
    tvb_memcpy(tvb, (char*)g_sign_record.sign_s, offset, 48);
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
    if ((len & 0x80) == 0x00) {
      len = tvb_get_guint8(tvb, offset);
      offset += 1;
    } else if ((len & 0x01) == 0x01) { // Length on on byte
      len = tvb_get_guint8(tvb, offset + 1);
      offset += 2;
    } else if ((len & 0x02) == 0x02) { // Lenght on two bytes
      offset += 1;
      len = tvb_get_guint8(tvb, offset) << 8 | tvb_get_guint8(tvb, offset + 1);
      offset += 2;
    } // Assume length <= 65535
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
    if ((tag & 0x10) == 0x10) { // Decode generation_time
      tree_gn_cert_time64(tvb, sh_tree, hf_gn_sh_field_gentime, offset);
      offset += 8;
    }
    /* TODO with 10, 08, 04, 02, 01
    if ((tag & 0x20) == 0x20) { // Decode generation_time
      tree_gn_cert_time64(tvb, sh_tree, hf_gn_sh_field_gentime, offset);
      offset += 8;
      }*/
    if ((tag & 0x02) == 0x02) { // Decode inlineP2pcdRequest (request unrecognised certificate)
      offset += 4;
      offset += tree_hashedId3_list(tvb, sh_tree, offset);
    }

    proto_item_set_len(sh_ti, offset - sh_length);
  }

  return offset;
} // End of function dissect_ieee1609dot2_header_info_packet<

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
    
    // Copy the toBeSigned block
    g_sign_record.to_be_signed_length = offset - sh_length;
    printf("dissect_ieee1609dot2_to_be_signed_data_packet: g_sign_record.to_be_signed_length=%zu\n", g_sign_record.to_be_signed_length);
    g_sign_record.to_be_signed = (gchar*)wmem_alloc(wmem_packet_scope(), g_sign_record.to_be_signed_length);
    tvb_memcpy(tvb, (char*)g_sign_record.to_be_signed, sh_length, g_sign_record.to_be_signed_length);
    
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

static void
ieee1609dot2_verify_signature(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
  printf(">>> ieee1609dot2_verify_signature\n");

  if (g_sign_record.sign_public_compressed_key != NULL) {
    char* curve = NULL;
    int key_length = 0;
    gcry_sexp_t gcry_sexp_key = NULL;
    gcry_sexp_t gcry_sexp_sign_key = NULL;
    gcry_sexp_t gcry_sexp_sign_message = NULL;
    gcry_error_t rc;
    size_t hash_len = 0;
    unsigned char* hash_data = NULL;
    unsigned char* hash_signer = NULL;
    unsigned char* hash_signature = NULL;
    
    switch (g_sign_record.sign_algo) {
    case 0x00: /* Nist P-256 */
      key_length = 32;
      curve = "NIST P-256";
      break;
    case 0x01: /* Brainpool P-256 r1 */
      key_length = 32;
      curve = "brainpoolP256r1";
      break;
    case 0x02: /* Brainpool P-384 r1 */
      key_length = 48;
      curve = "brainpoolP384r1";
      break;
    default:
      goto ieee1609dot2_verify_signature_end;
    } /* End of 'switch' statement */
    if (compressed_hex_key_to_sexp(g_sign_record.sign_public_compressed_key, key_length, g_sign_record.sign_compressed_key_mode, curve, "ecc", &gcry_sexp_key) != 0) {
      col_append_str(pinfo->cinfo, COL_INFO, "[Secured]: Cannot not verify signature");
      goto ieee1609dot2_verify_signature_end;
    }
    // Request for signature
    if ((rc = gcry_sexp_build(&gcry_sexp_sign_key, NULL, "(sig-val(ecdsa(r %b)(s %b)))", key_length, g_sign_record.sign_r, key_length, g_sign_record.sign_s)) != 0) {
      printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
      gcry_sexp_release(gcry_sexp_key);
      col_append_str(pinfo->cinfo, COL_INFO, "[Secured]: Cannot not verify signature");
      goto ieee1609dot2_verify_signature_end;
    }
    hash_len = 32; /* Signature witheither Nist P-256 or Brainpool P-256 r1 ==> haf is 32 bytes length */
    hash_data = sha256(g_sign_record.to_be_signed, g_sign_record.to_be_signed_length);
    hash_signer = sha256(g_sign_record.issuer, g_sign_record.issuer_length);
    hash_signature = (unsigned char*)gcry_malloc(2 * hash_len);
    memcpy((void*)hash_signature, (const void*)hash_data, hash_len);
    memcpy((void*)(hash_signature + hash_len), (const void*)hash_signer, hash_len);
    if ((rc = gcry_sexp_build(&gcry_sexp_sign_message, NULL, "(data(flags raw)(value %b))", hash_len, sha256(hash_signature, 2 * hash_len))) != 0) {
      printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
      gcry_free(hash_data);
      gcry_free(hash_signer);
      gcry_free(hash_signature);
      gcry_sexp_release(gcry_sexp_sign_key);
      gcry_sexp_release(gcry_sexp_key);
      col_append_str(pinfo->cinfo, COL_INFO, "[Secured]: Cannot not verify signature");
      goto ieee1609dot2_verify_signature_end;
    }
    gcry_free(hash_data);
    gcry_free(hash_signer);
    gcry_free(hash_signature);
    if ((rc = gcry_pk_verify(gcry_sexp_sign_key, gcry_sexp_sign_message, gcry_sexp_key)) != 0) {
      expert_field ef = { PI_PROTOCOL, PI_NOTE };
      
      printf("Failed for %s/%s\n", gcry_strsource(rc), gcry_strerror(rc));
      gcry_sexp_release(gcry_sexp_key);
      gcry_sexp_release(gcry_sexp_sign_key);
      gcry_sexp_release(gcry_sexp_sign_message);
      col_append_str(pinfo->cinfo, COL_INFO, "[Secured]: Signature cannot be verified");
      expert_add_info_format(pinfo, g_sign_record.sh_ti, &ef, "Signature cannot be verified");

      goto ieee1609dot2_verify_signature_end;
    }
    
    gcry_sexp_release(gcry_sexp_key);
    gcry_sexp_release(gcry_sexp_sign_key);
    gcry_sexp_release(gcry_sexp_sign_message);
    
    col_append_str(pinfo->cinfo, COL_INFO, "[Secured]: Signature verified");

    goto ieee1609dot2_verify_signature_end;
  } else {
    //col_append_str(pinfo->cinfo, COL_INFO, "[Secured]: Signature not verified");
  }
  
 ieee1609dot2_verify_signature_end:    
  g_sign_record.sign_algo = 0xff;
  g_sign_record.sign_compressed_key_mode = 0xff;
  g_sign_record.to_be_signed_length = 0;
  if (g_sign_record.sign_public_compressed_key != NULL) {
    wmem_free(wmem_packet_scope(), g_sign_record.sign_public_compressed_key);
    g_sign_record.sign_public_compressed_key = NULL;
  }
  if (g_sign_record.issuer != NULL) {
    wmem_free(wmem_packet_scope(), g_sign_record.issuer);
    g_sign_record.issuer = NULL;
  }
  g_sign_record.issuer_length = 0;
  if (g_sign_record.to_be_signed != NULL) {
    wmem_free(wmem_packet_scope(), g_sign_record.to_be_signed);
    g_sign_record.to_be_signed = NULL;
  }
  g_sign_record.to_be_signed_length = 0;
  if (g_sign_record.sign_r != NULL) {
    wmem_free(wmem_packet_scope(), g_sign_record.sign_r);
    g_sign_record.sign_r = NULL;
  }
  if (g_sign_record.sign_s != NULL) {
    wmem_free(wmem_packet_scope(), g_sign_record.sign_s);
    g_sign_record.sign_s = NULL;
  }
}

