/* packet-itsut.c
 * Routines for ITS Upper Tester Protocol dissection
 * Copyright 2015, AMB Consulting <alexandre.berge@amb-consulting.com>
 *
 * $Id: packet-itsut.c 40 2015-03-21 17:15:56Z garciay $
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

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

void proto_register_gn(void);
void proto_reg_handoff_gn(void);

#define ITSUT_PROTOCOL_PORT                12345 

#define MIN_PDU_SIZE                    2 

#define ITSUT_INITIALISE                   0x00 /* Refer to Draft ETSI TR 103 099 V1.5.0 (2014-12) Annex C */
#define ITSUT_INITIALISE_RESULT            0x01
#define ITSUT_CHANGEPOSITION               0x02
#define ITSUT_CHANGEPOSITION_RESULT        0x03
#define ITSUT_CHANGEPSEUDONYM              0x04
#define ITSUT_CHANGEPSEUDONYM_RESULT       0x05
#define ITSUT_ACTIVATEPOSITIONTIME         0x06
#define ITSUT_ACTIVATEPOSITIONTIMERESULT   0x07
#define ITSUT_DEACTIVATEPOSITIONTIME       0x08
#define ITSUT_DEACTIVATEPOSITIONTIMERESULT 0x09
/* CAM */
#define ITSUT_CHANGECURVATURE              0x30
#define ITSUT_CHANGESPEED                  0x31
#define ITSUT_SETACCELERATIONCONTROLSTATUS 0x32
#define ITSUT_SETEXTERIORLIGHTSSTATUS      0x33
#define ITSUT_CHANGEHEADING                0x34
#define ITSUT_SETDRIVEDIRECTION            0x35
#define ITSUT_CHANGEYAWRATE                0x36
#define ITSUT_CAMEVENTINDICATION           0x23
#define ITSUT_SETSTATIONTYPE               0x39
#define ITSUT_SETVEHICLEROLE               0x3a
#define ITSUT_SETEMBARKATIONSTATUS         0x3b
#define ITSUT_SETPTACTIVATION              0x3c
#define ITSUT_SETDANGEROUSGOODS            0x3d
#define ITSUT_SETDANGEROUSGOODSEXT         0x3e
#define ITSUT_SETLIGHTBARSIREN             0x3f
#define ITSUT_CAMTRIGGER_RESULT            0x21
/* DENM */
#define ITSUT_DENMTRIGGER                  0x10
#define ITSUT_DENMTRIGGER_RESULT           0x11
#define ITSUT_DENMUPDATE                   0x12
#define ITSUT_DENMUPDATE_RESULT            0x13
#define ITSUT_TERMINATE_DENMEVENT          0x14
#define ITSUT_TERMINATE_DENMEVENT_RESULT   0x15
#define ITSUT_DENMEVENTINDICATION          0x17
/* GN */
#define ITSUT_GENERATEGEOUNICAST           0x50
#define ITSUT_GENERATEGEOBROADCAST         0x51
#define ITSUT_GENERATEGEOANYCAST           0x52
#define ITSUT_GENERATEGEOSHB               0x53
#define ITSUT_GENERATEGEOTSB               0x54
#define ITSUT_GNEVENTINDICATION            0x55
#define ITSUT_GNTRIGGER_RESULT             0x41
/* MAPEM/SPATEM */
#define ITSUT_MAPEMSPATEM_TRIGGER_EVENT        0xA0
#define ITSUT_MAPEMSPATEM_TRIGGER_EVENT_RESULT 0xA1
#define ITSUT_MAPEMEVENTINDICATION             0xA2
#define ITSUT_SPATEMEVENTINDICATION            0xA3
/* IVIM */
#define ITSUT_IVIM_TRIGGER_EVENT               0xA4
#define ITSUT_IVIM_TRIGGER_EVENT_RESULT        0xA5
#define ITSUT_IVIM_UPDATE_EVENT                0xA6
#define ITSUT_IVIM_UPDATE_EVENT_RESULT         0xA7
#define ITSUT_IVIM_TERMINATE_EVENT             0xA8
#define ITSUT_IVIM_TERMINATE_EVENT_RESULT      0xA9
#define ITSUT_IVIMEVENTINDICATION              0xAA
/* SREM/SSEM */
#define ITSUT_SREM_TRIGGER_EVENT               0xAB
#define ITSUT_SREM_TRIGGER_EVENT_RESULT        0xAC
#define ITSUT_SREM_UPDATE_EVENT                0xAD
#define ITSUT_SREM_UPDATE_EVENT_RESULT         0xAE
#define ITSUT_SREMEVENTINDICATION              0xAF
#define ITSUT_SSEMEVENTINDICATION              0xB0
/* PKI */
#define ITSUT_PKI_TRIGGER_EVENT_EC             0xBB
#define ITSUT_PKI_TRIGGER_EVENT_AT             0xBD
#define ITSUT_PKI_TRIGGER_EVENT_RESULT         0xBC

/* Names table indexes */
#define IDX_RESULT_OK                   0x01
#define IDX_RESULT_KO                   0x00
#define IDX_SECUREDMODE_DISABLE         0x00
#define IDX_SECUREDMODE_ENABLE          0xFF

/* Messages length */
/* General */
#define L_ITSUT_COMMAND                     1
#define L_ITSUT_FLAGS                       1
#define L_ITSUT_INITIALISE                  9
#define L_ITSUT_INITIALISE_RESULT           2
#define L_ITSUT_INITIALISE_RESULT_CODE      1
#define L_ITSUT_CHANGEPOSITION              10
#define L_ITSUT_CHANGEPOSITION_RESULT       2
#define L_ITSUT_CHANGEPOSITION_RESULT_CODE  1
#define L_ITSUT_CHANGEPSEUDONYM             1
#define L_ITSUT_CHANGEPSEUDONYM_RESULT      2
#define L_ITSUT_CHANGEPSEUDONYM_RESULT_CODE 1
#define L_ITSUT_ACTIVATEPOSITIONTIME        1
#define L_ITSUT_ACTIVATEPOSITIONTIME_RESULT        2
#define L_ITSUT_ACTIVATEPOSITIONTIME_RESULT_CODE   1
#define L_ITSUT_DEACTIVATEPOSITIONTIME             1
#define L_ITSUT_DEACTIVATEPOSITIONTIME_RESULT      2
#define L_ITSUT_DEACTIVATEPOSITIONTIME_RESULT_CODE 1
/* CAM */
#define L_ITSUT_CHANGECURVATURE            3
#define L_ITSUT_CHANGESPEED                3
#define L_ITSUT_SETACCELERATIONCONTROLSTATUS 2
#define L_ITSUT_SETEXTERIORLIGHTSSTATUS    2
#define L_ITSUT_CHANGEHEADING              3
#define L_ITSUT_SETDRIVEDIRECTION          2
#define L_ITSUT_CAM_TRIGGER_RESULT         2
#define L_ITSUT_CHANGEYAWRATE              3
#define L_ITSUT_SETSTATIONTYPE             2
#define L_ITSUT_SETVEHICLEROLE             2
#define L_ITSUT_SETEMBARKATIONSTATUS       2
#define L_ITSUT_SETDANGEROUSGOODS          2
#define L_ITSUT_SETDANGEROUSGOODSEXT       2
#define L_ITSUT_SETLIGHTBARSIREN           2
#define L_ITSUT_CAM_TRIGGER_RESULT_CODE    1
/* DENM */
#define L_ITSUT_DENMM_TRIGGER_RESULT       8
#define L_ITSUT_DENMM_TRIGGER_RESULT_CODE  1
#define L_ITSUT_DENMM_EVENT_RESULT         8
#define L_ITSUT_DENMM_EVENT_RESULT_CODE    1
/* GN */
#define L_ITSUT_GNTRIGGER_RESULT           2
#define L_ITSUT_GNTRIGGER_RESULT_CODE      1
/* MAPEM/SPATEM */
#define L_ITSUT_MAPEMSPATEM_TRIGGER_EVENT             2
#define L_ITSUT_MAPEMSPATEM_TRIGGER_EVENT_RESULT      2
#define L_ITSUT_MAPEMSPATEM_TRIGGER_EVENT_RESULT_CODE 1
/* IVIM */
#define L_ITSUT_IVIM_TRIGGER_EVENT_RESULT             4
#define L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_CODE        1
#define L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_ID          2
#define L_ITSUT_IVIM_UPDATE_EVENT_RESULT              4
#define L_ITSUT_IVIM_UPDATE_EVENT_RESULT_CODE         1
#define L_ITSUT_IVIM_UPDATE_EVENT_RESULT_ID           2
#define L_ITSUT_IVIM_TERMINATE_EVENT_RESULT           4
#define L_ITSUT_IVIM_TERMINATE_EVENT_RESULT_CODE      1
#define L_ITSUT_IVIM_TERMINATE_EVENT_RESULT_ID        2
/* SREM/SSEM */
#define L_ITSUT_SREM_TRIGGER_EVENT                    1
#define L_ITSUT_SREM_TRIGGER_EVENT_RESULT             2
#define L_ITSUT_SREM_TRIGGER_EVENT_RESULT_CODE        1
#define L_ITSUT_SREM_UPDATE_EVENT                     1
#define L_ITSUT_SREM_UPDATE_EVENT_RESULT              2
#define L_ITSUT_SREM_UPDATE_EVENT_RESULT_CODE         1
/* PKI */
#define L_ITSUT_PKI_TRIGGER_EVENT_EC      1
#define L_ITSUT_PKI_TRIGGER_EVENT_AT      1
#define L_ITSUT_PKIM_TRIGGER_EVENT_RESULT 2
#define L_ITSUT_PKIM_TRIGGER_RESULT_CODE  1

/* Parameters length */
#define L_HASHEDID8                     8
#define L_DELTALATITUDE                 4
#define L_DELTALONGITUDE                4
#define L_DELTAELEVATION                1
#define L_CURVATURE                     2
#define L_SPEEDVARIATION                2
#define L_HEADING_DIRECTION             2
#define L_DRIVE_DIRECTION               1
#define L_YAWRATE                       2
#define L_STATIONTYPE                   1
#define L_VEHICLEROLE                   1
#define L_EMBARKATIONSTATUS             1
#define L_PTACTIVATIONTYPE              1
#define L_PTACTIVATIONDATALENGTH        1
#define L_DANGEROUSGOODS                1
#define L_STATIONID                     4
#define L_SEQNUM                        2
#define L_DETECTIONTIME                 6
#define L_VALIDITYDURATION              3
#define L_REPETITIONDURATION            3
#define L_INFOQUALITY                   1
#define L_CAUSE                         1
#define L_SUBCAUSE                      1
#define L_RELEVANCEDISTANCE             1
#define L_RELEVANCETRAFFICDIRECTION     1
#define L_TRANSMISSIONINTERVAL          2
#define L_REPETITIONINTERVAL            2
#define L_ALACARTELENGTH                1
#define L_CAMEVENTLENGTH                2
#define L_DENMEVENTLENGTH               2
#define L_SETPTACTIVATIONTYPE           1
#define L_SETPTACTIVATIONLENGTH         1
#define L_SHAPE                         1
#define L_LIFETIME                      2
#define L_TRAFFICCLASS                  1
#define L_RESERVEDGEOBROADCAST          3
#define L_LATITUDE                      4
#define L_LONGITUDE                     4
#define L_DISTANCEA                     2
#define L_DISTANCEB                     2
#define L_ANGLE                         2
#define L_PAYLOADLENGTH                 2
#define L_NBHOPS                        1
#define L_DSTGNADDR                     8
#define L_MAPEMSPATEM_TRIGGER_EVENT     1
#define L_IVIIDENTIFICATIONNUMBER       2
#define L_VALIDITYFROM                  6
#define L_VALIDITYTO                    6
#define L_REPETITIONINTERVAL_IVIM       6
#define L_SREM_TRIGGER_EVENT            1
#define L_SREM_UPDATE_EVENT             1
#define L_PKI_TRIGGER_EVENT_RESULT      1
#define L_PKI_TRIGGER_EVENT_RESULT_CODE 1
#define L_PKI_TRIGGER_EVENT_EC          1
#define L_PKI_TRIGGER_EVENT_AT          1

/* Function declarations */
void proto_reg_handoff_itsut(void);

static guint gPORT_PREF = ITSUT_PROTOCOL_PORT;

/* Masks */

/* Initialise the protocol and registered fields */
static int proto_itsut = -1;
static int hf_command = -1;

/* ITSUT Initialise */
static int hf_initialize = -1;
static int hf_hashed_id8 = -1;
static int hf_initialize_result = -1;
static int hf_initialize_result_code = -1;

/* ITSUT Change Position */
static int hf_change_position = -1;
static int hf_change_position_result = -1;
static int hf_change_position_result_code = -1;

/* ITSUT Change Pseudonym */
static int hf_change_pseudonym = -1;
static int hf_change_pseudonym_result = -1;
static int hf_change_pseudonym_result_code = -1;

/* ITSUT Change Curvature */
static int hf_change_curvature = -1;

/* ITSUT Change Speed */
static int hf_change_speed = -1;

/* ITSUT Set Acceleration Control Status */
static int hf_set_acceleration_control_status = -1;
static int hf_set_acceleration_control_status_flags = -1;
static int hf_set_acceleration_control_status_flags_B_bit = -1;
static int hf_set_acceleration_control_status_flags_G_bit = -1;
static int hf_set_acceleration_control_status_flags_E_bit = -1;
static int hf_set_acceleration_control_status_flags_C_bit = -1;
static int hf_set_acceleration_control_status_flags_A_bit = -1;
static int hf_set_acceleration_control_status_flags_CC_bit = -1;
static int hf_set_acceleration_control_status_flags_L_bit = -1;

/* ITSUT Set Exterior Lights Status */
static int hf_set_exterior_lights_status = -1;
static int hf_set_exterior_lights_status_flags = -1;
static int hf_set_exterior_lights_status_flags_LB_bit = -1;
static int hf_set_exterior_lights_status_flags_HB_bit = -1;
static int hf_set_exterior_lights_status_flags_LT_bit = -1;
static int hf_set_exterior_lights_status_flags_RT_bit = -1;
static int hf_set_exterior_lights_status_flags_D_bit = -1;
static int hf_set_exterior_lights_status_flags_R_bit = -1;
static int hf_set_exterior_lights_status_flags_F_bit = -1;
static int hf_set_exterior_lights_status_flags_P_bit = -1;

/* ITSUT Change Heading */
static int hf_change_heading = -1;

/* ITSUT Set Drive Direction */
static int hf_set_drive_direction = -1;

/* ITSUT Change YawRate */
static int hf_change_yawrate = -1;

/* ITSUT CAM Event Indication */
static int hf_cam_event_indication = -1;
static int hf_cam_event_indication_length = -1;
static int hf_cam_event_indication_payload = -1;

/* ITSUT Set Station Type */
static int hf_set_station_type = -1;

/* ITSUT Set Vehicle Role */
static int hf_set_vehicle_role = -1;

/* ITSUT Set Embarkation Status */
static int hf_set_embarkation_status = -1;

/* ITSUT Set Pt Activation */
static int hf_set_pt_activation = -1;
static int hf_set_pt_activation_type = -1;
static int hf_set_pt_activation_length = -1;
static int hf_set_pt_activation_payload = -1;

/* ITSUT Set Dangerous Goods */
static int hf_set_dangerous_goods = -1;
static int hf_set_dangerous_goods_ext = -1;

/* ITSUT Set Light Bar Siren */
static int hf_set_light_bar_siren = -1;
static int hf_set_light_bar_siren_flags = -1;
static int hf_set_light_bar_siren_flags_LB_bit = -1;
static int hf_set_light_bar_siren_flags_S_bit = -1;

/* ITSUT CAM Trigger */
static int hf_cam_trigger_result = -1;
static int hf_cam_trigger_result_code = -1;

/* ITSUT DENM Trigger */
static int hf_denm_trigger = -1;
static int hf_denm_trigger_result = -1;
static int hf_denm_trigger_result_code = -1;
static int hf_denm_trigger_flags = -1;
static int hf_denm_trigger_flags_V_bit = -1;
static int hf_denm_trigger_flags_R_bit = -1;
static int hf_denm_trigger_flags_K_bit = -1;
static int hf_denm_trigger_flags_I_bit = -1;

/* ITSUT DENM Event */
static int hf_denm_event = -1;
static int hf_denm_event_result = -1;
static int hf_denm_event_result_code = -1;
static int hf_denm_event_flags = -1;
static int hf_denm_event_flags_V_bit = -1;
static int hf_denm_event_flags_S_bit = -1;
static int hf_denm_event_flags_D_bit = -1;
static int hf_denm_event_flags_T_bit = -1;
static int hf_denm_event_flags_C_bit = -1;
static int hf_denm_event_flags_K_bit = -1;
static int hf_denm_event_flags_I_bit = -1;
static int hf_denm_event_flags_X_bit = -1;

/* ITSUT DENM Terminate Event */
static int hf_terminate_denm_event = -1;
static int hf_terminate_denm_event_result = -1;
static int hf_denm_terminate_event_result_code = -1;

/* ITSUT DENM Event Indication */
static int hf_denm_event_indication = -1;
static int hf_denm_event_indication_length = -1;
static int hf_denm_event_indication_payload = -1;

/* ITSUT GN Generate Unicast */
static int hf_gn_geounicast = -1;

/* ITSUT GN Generate Broadcast */
static int hf_gn_geobroadcast = -1;

/* ITSUT GN Generate Antcast */
static int hf_gn_geoanycast = -1;

/* ITSUT GN Generate SHB */
static int hf_gn_geoshb = -1;

/* ITSUT GN Generate TSB */
static int hf_gn_geotsb = -1;

/* ITSUT GN Event Indication */
static int hf_gn_event_indication = -1;
static int hf_gn_event_indication_length = -1;
static int hf_gn_event_indication_payload = -1;

/* ITSUT GN Trigger Result */
static int hf_gntrigger_result = -1;
static int hf_gntrigger_result_code = -1;

/* ITSUT MAPEM/SPATEM Trigger Event */
static int hf_mapemspatem_trigger_event = -1;

/* ITSUT MAPEM/SPATEM Trigger Result */
static int hf_mapemspatem_trigger_event_result = -1;
static int hf_mapemspatem_trigger_event_result_code = -1;

/* ITSUT MAPEM Event Indication */
static int hf_mapem_event_indication = -1;
static int hf_mapem_event_indication_length = -1;
static int hf_mapem_event_indication_payload = -1;

/* ITSUT SPATEM Event Indication */
static int hf_spatem_event_indication = -1;
static int hf_spatem_event_indication_length = -1;
static int hf_spatem_event_indication_payload = -1;

/* ITSUT IVIM Trigger */
static int hf_ivim_trigger_event = -1;
static int hf_ivim_trigger_event_result = -1;
static int hf_ivim_trigger_event_result_code = -1;
static int hf_ivim_trigger_event_result_id = -1;
static int hf_ivim_trigger_event_flags = -1;
static int hf_ivim_trigger_event_flags_F_bit = -1;
static int hf_ivim_trigger_event_flags_T_bit = -1;
static int hf_ivim_trigger_event_flags_R_bit = -1;
static int hf_ivim_trigger_event_flags_X_bit = -1;

/* ITSUT IVIM Update */
static int hf_ivim_update_event = -1;
static int hf_ivim_update_event_result = -1;
static int hf_ivim_update_event_result_code = -1;
static int hf_ivim_update_event_result_id = -1;
static int hf_ivim_update_event_flags = -1;
static int hf_ivim_update_event_flags_F_bit = -1;
static int hf_ivim_update_event_flags_T_bit = -1;
static int hf_ivim_update_event_flags_R_bit = -1;
static int hf_ivim_update_event_flags_X_bit = -1;

/* ITSUT IVIM Terminate Event */
static int hf_ivim_terminate_event = -1;
static int hf_ivim_terminate_event_result = -1;
static int hf_ivim_terminate_event_result_code = -1;
static int hf_ivim_terminate_event_result_id = -1;

/* ITSUT IVIM Event Indication */
static int hf_ivim_event_indication = -1;
static int hf_ivim_event_indication_length = -1;
static int hf_ivim_event_indication_payload = -1;

/* ITSUT SREM Trigger Event */
static int hf_srem_trigger_event = -1;

/* ITSUT SREM Trigger Result */
static int hf_srem_trigger_event_result = -1;
static int hf_srem_trigger_event_result_code = -1;

/* ITSUT SREM Update Event */
static int hf_srem_update_event = -1;

/* ITSUT SREM Update Result */
static int hf_srem_update_event_result = -1;
static int hf_srem_update_event_result_code = -1;

/* ITSUT SREM Event Indication */
static int hf_srem_event_indication = -1;
static int hf_srem_event_indication_length = -1;
static int hf_srem_event_indication_payload = -1;

/* ITSUT SSEM Event Indication */
static int hf_ssem_event_indication = -1;
static int hf_ssem_event_indication_length = -1;
static int hf_ssem_event_indication_payload = -1;

/* ITSUT PKI Trigger Event */
static int hf_pki_trigger_event_ec = -1;
static int hf_pki_trigger_event_at = -1;

/* ITSUT SREM Trigger Result */
static int hf_pki_trigger_event_result = -1;
static int hf_pki_trigger_event_result_code = -1;

/* CAM Parameters */
static int hf_curvature = -1;
static int hf_delta_latitude = -1;
static int hf_delta_longitude = -1;
static int hf_delta_elevation = -1;
static int hf_speed_variation = -1;
static int hf_heading_direction = -1;
static int hf_drive_direction = -1;
static int hf_yawrate = -1;
static int hf_station_type = -1;
static int hf_vehicle_role = -1;
static int hf_embarkation_status = -1;
static int hf_dangerous_goods = -1;
static int hf_dangerous_goods_ext = -1;
/* DENM Parameters */
static int hf_station_id = -1;
static int hf_sequence_number = -1;
static int hf_detection_time = -1;
static int hf_validity_duration = -1;
static int hf_repetition_duration = -1;
static int hf_info_quality = -1;
static int hf_cause = -1;
static int hf_subcause = -1;
static int hf_relevance_distance = -1;
static int hf_relevance_traffic_direction = -1;
static int hf_transmission_interval = -1;
static int hf_repetition_interval = -1;
static int hf_alacarte_length = -1;
static int hf_alacarte = -1;
/* GN Parameters */
static int hf_gn_address = -1;
static int hf_shape = -1;
static int hf_lifetime = -1;
static int hf_trafficclass = -1;
static int hf_reservedgeobroadcast = -1;
static int hf_latitude = -1;
static int hf_longitude = -1;
static int hf_distancea = -1;
static int hf_distanceb = -1;
static int hf_angle = -1;
static int hf_payloadlength = -1;
static int hf_payload = -1;
static int hf_nbhops = -1;
static int hf_dstgnaddr = -1;
/* MAPEM/SPATEM Parameters */
static int hf_event = -1;
/* IVIM Parameters */
static int hf_ivi_id = -1;
static int hf_validity_from = -1;
static int hf_validity_to = -1;
static int hf_repetition_interval_ivim = -1;

/* Initialise the subtree pointers */
static gint ett_itsut = -1;
static gint ett_itsut_command = -1;
static gint ett_itsut_flags = -1;
static gint ett_itsut_data = -1;

static const value_string itsut_command_names[] = {
    { ITSUT_INITIALISE,                    "Initialise" },
    { ITSUT_INITIALISE_RESULT,             "Initialise Result" },
    { ITSUT_CHANGEPOSITION,                "Change Position" },
    { ITSUT_CHANGEPOSITION_RESULT,         "Change Position Result" },
    { ITSUT_CHANGEPSEUDONYM,               "Change Pseudonym" },
    { ITSUT_CHANGEPSEUDONYM_RESULT,        "Change Pseudonym Result" },
    { ITSUT_ACTIVATEPOSITIONTIME,          "Activate Position/Time" },
    { ITSUT_ACTIVATEPOSITIONTIMERESULT,    "Activate Position/Time Result" },
    { ITSUT_DEACTIVATEPOSITIONTIME,        "Deactivate Position/Time" },
    { ITSUT_DEACTIVATEPOSITIONTIMERESULT,  "Deactivate Position/Time Result" },
    { ITSUT_CHANGECURVATURE,               "Change Curvature" },
    { ITSUT_CHANGESPEED,                   "Change Speed" },
    { ITSUT_SETACCELERATIONCONTROLSTATUS,  "Set Acceleration Control Status" },
    { ITSUT_SETEXTERIORLIGHTSSTATUS,       "Set Exterior Lights Status" },
    { ITSUT_CHANGEHEADING,                 "Change Heading" },
    { ITSUT_CHANGEYAWRATE,                 "Change YawRate" },
    { ITSUT_SETDRIVEDIRECTION,             "Set Drive Direction" },
    { ITSUT_SETEMBARKATIONSTATUS,          "Set Embarkation Status" },
    { ITSUT_SETPTACTIVATION,               "Set Pt Activation" },
    { ITSUT_CAMEVENTINDICATION,            "Cam Event Indication" },
    { ITSUT_SETSTATIONTYPE,                "Set Station Type" },
    { ITSUT_SETVEHICLEROLE,                "Set Vehicule Role" },
    { ITSUT_SETDANGEROUSGOODS,             "Set Dangerous Goods" },
    { ITSUT_SETDANGEROUSGOODSEXT,          "Set Dangerous Goods Extended" },
    { ITSUT_SETLIGHTBARSIREN,              "Set Light Bar Siren" },
    { ITSUT_CAMTRIGGER_RESULT,             "Cam Trigger Result" },
    { ITSUT_DENMTRIGGER,                   "Denm Trigger" },
    { ITSUT_DENMTRIGGER_RESULT,            "Denm Trigger Result" },
    { ITSUT_DENMUPDATE,                    "Denm Update" },
    { ITSUT_DENMUPDATE_RESULT,             "Denm Update Result" },
    { ITSUT_TERMINATE_DENMEVENT,           "Denm Terminate Event" },
    { ITSUT_TERMINATE_DENMEVENT_RESULT,    "Denm Terminate Event Result" },
    { ITSUT_DENMEVENTINDICATION,           "Denm Event Indication" },
    { ITSUT_GENERATEGEOUNICAST,            "GeoUnicast Trigger" },
    { ITSUT_GENERATEGEOBROADCAST,          "GeoBroadcast Trigger" },
    { ITSUT_GENERATEGEOANYCAST,            "GeoAnycast Trigger" },
    { ITSUT_GENERATEGEOSHB,                "GeoSHB Trigger" },
    { ITSUT_GENERATEGEOTSB,                "GeoTSB Trigger" },
    { ITSUT_GNEVENTINDICATION,             "Geonetworking Event Indication" },
    { ITSUT_GNTRIGGER_RESULT,              "Geonetworking Trigger Result" },
    { ITSUT_MAPEMSPATEM_TRIGGER_EVENT,     "MAPEM/SPATEM Event Trigger" },
    { ITSUT_MAPEMSPATEM_TRIGGER_EVENT_RESULT,  "MAPEM/SPATEM Trigger Result" },
    { ITSUT_MAPEMEVENTINDICATION,          "MAPEM Event Indication" },
    { ITSUT_SPATEMEVENTINDICATION,         "SPATEM Event Indication" },
    { ITSUT_IVIM_TRIGGER_EVENT,            "IVIM Trigger" },
    { ITSUT_IVIM_TRIGGER_EVENT_RESULT,     "IVIM Trigger Result" },
    { ITSUT_IVIM_UPDATE_EVENT,             "IVIM Update" },
    { ITSUT_IVIM_UPDATE_EVENT_RESULT,      "IVIM Update Result" },
    { ITSUT_IVIM_TERMINATE_EVENT,          "IVIM Terminate" },
    { ITSUT_IVIM_TERMINATE_EVENT_RESULT,   "IVIM Terminate Result" },
    { ITSUT_IVIMEVENTINDICATION,           "IVIM Event Indication" },
    { ITSUT_SREM_TRIGGER_EVENT,            "SREM Trigger" },
    { ITSUT_SREM_TRIGGER_EVENT_RESULT,     "SREM Trigger Result" },
    { ITSUT_SREM_UPDATE_EVENT,             "SREM Update" },
    { ITSUT_SREM_UPDATE_EVENT_RESULT,      "SREM Update Result" },
    { ITSUT_SREMEVENTINDICATION,           "SREM Event Indication" },
    { ITSUT_SSEMEVENTINDICATION,           "SSEM Event Indication" },
    { ITSUT_PKI_TRIGGER_EVENT_EC,          "PKI Trigger Enrolment request" },
    { ITSUT_PKI_TRIGGER_EVENT_AT,          "PKI Trigger Authorization request" },
    { ITSUT_PKI_TRIGGER_EVENT_RESULT,      "PKI Trigger Result" },
    { 0, NULL}
};

static const value_string itsut_result_names[] = {
    { IDX_RESULT_OK, "Succeed" },
    { IDX_RESULT_KO, "Failed" },
    { 0, NULL}
};

/* static const value_string itsut_securedmode_names[] = { */
/*     { IDX_SECUREDMODE_DISABLE,  "Disabled" }, */
/*     { IDX_SECUREDMODE_ENABLE,   "Enabled" }, */
/*     { 0, NULL} */
/* }; */

static const value_string itsut_drive_direction_names[] = {
  { 0x00, "Forward" },
  { 0x01, "Backward" },
  { 0x02, "Unavailable" },
  { 0, NULL}
};

static const value_string itsut_station_type_names[] = {
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

static const value_string itsut_vehicle_role_names[] = {
  { 0, "default" },
  { 1, "publicTransport" },
  { 2, "specialTransport" },
  { 3, "dangerousGoods" },
  { 4, "roadWork" },
  { 5, "rescue" },
  { 6, "emergency" },
  { 7, "safetyCar" },
  { 0, NULL}
};

static const value_string itsut_embarkation_status_names[] = {
    { 0x00, "False" },
    { 0xff, "True" },
    { 0, NULL}
};

static const value_string itsut_relevancetrafficdirection_names[] = {
    { 0x00, "all traffic directions" },
    { 0x01, "upstream traffic" },
    { 0x02, "downstream traffic" },
    { 0x03, "opposite traffic" },
    { 0, NULL}
};

static const value_string itsut_relevancedistance_names[] = {
    { 0x00, "less than 50 m" },
    { 0x01, "less than 100 m" },
    { 0x02, "less than 200 m" },
    { 0x03, "less than 500 m" },
    { 0x04, "less than 1 000 m" },
    { 0x05, "less than 5 km" },
    { 0x06, "less than 10 km" },
    { 0x07, "greater than 10 km" },
    { 0, NULL}
};

static const value_string itsut_setdangerousgoods_names[] = {
    { 0, "explosives1" },
    { 1, "explosives2" },
    { 2, "explosives3" },
    { 3, "explosives4" },
    { 4, "explosives5" },
    { 5, "explosives6" },
    { 6, "flammableGases" },
    { 7, "nonFlammableGases" },
    { 8, "toxicGases" },
    { 9, "flammableLiquids" },
    { 10, "flammableSolids" },
    { 11, "substancesLiableToSpontaneousCombustion" },
    { 12, "substancesEmittingFlammableGasesUponContactWithWater" },
    { 13, "oxidizingSubstances" },
    { 14, "organicPeroxides" },
    { 15, "toxicSubstances" },
    { 16, "infectiousSubstances" },
    { 17, "radioactiveMaterial" },
    { 18, "gcorrosiveSubstances" },
    { 19, "miscellaneousDangerousSubstances" },
    { 0, NULL}
};

static const value_string itsut_shape_names[] = {
    { 0x00, "Circle" },
    { 0x01, "Rectangle" },
    { 0x02, "Ellipse" },
    { 0, NULL}
};

static const value_string itsut_mapemspatem_event_names[] = {
    { 0x00, "Start Traffic Lights Manager service" },
    { 0x01, "Stop Traffic Lights Manager service" },
    { 0x02, "Generate a MAPE message with new content" },
    { 0x03, "Generate a MAPE message with hudge content" },
    { 0x04, "Generate a SPATE message" },
    { 0x05, "Force MAPEM repetition < 10s" },
    { 0x06, "Force MAPEM repetition > 10s" },
    { 0, NULL}
};

/*****************************************************************************
    Command messages
*****************************************************************************/
/* Code to build tree for ItsutInitialise command */
static int dissect_itsut_initialise(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* Extract HashedId8 value */
  tvb_get_ntoh64(tvb, offset + 1);
  
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_initialize, tvb, offset, L_ITSUT_INITIALISE, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtInitialize */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtInitialise tree */
  proto_tree_add_item(tree, hf_hashed_id8, tvb, offset, L_HASHEDID8, FALSE);
  offset += L_HASHEDID8; 

  return offset;
} // End of function dissect_itsut_initialise

/* Code to build tree for UtChangePosition command */
static int dissect_itsut_change_position(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_position, tvb, offset, L_ITSUT_CHANGEPOSITION, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangePosition */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtChangePosition tree */
  /* DeltaLatitude */
  proto_tree_add_item(tree, hf_delta_latitude, tvb, offset, L_DELTALATITUDE, FALSE);
  offset += L_DELTALATITUDE;
  /* DeltaLongitude */
  proto_tree_add_item(tree, hf_delta_longitude, tvb, offset, L_DELTALONGITUDE, FALSE);
  offset += L_DELTALONGITUDE;
  /* DeltaElevation */
  proto_tree_add_item(tree, hf_delta_elevation, tvb, offset, L_DELTAELEVATION, FALSE);
  offset += L_DELTAELEVATION;

  return offset;
} // End of function dissect_itsut_change_position

/* Code to build tree for UtChangePseudonym command */
static int dissect_itsut_change_pseudonym(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_pseudonym, tvb, offset, L_ITSUT_CHANGEPSEUDONYM, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangePseudonym */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  return offset;
} // End of function dissect_itsut_change_pseudonym

/* Code to build tree for UtActivatePositionTime command */
static int dissect_itsut_activate_position_Time(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_pseudonym, tvb, offset, L_ITSUT_ACTIVATEPOSITIONTIME, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtActivatePositionTime */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  return offset;
} // End of function dissect_itsut_activate_position_Time

/* Code to build tree for UtDeactivatePositionTime command */
static int dissect_itsut_deactivate_position_Time(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_pseudonym, tvb, offset, L_ITSUT_DEACTIVATEPOSITIONTIME, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtDeactivatePositionTime */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  return offset;
} // End of function dissect_itsut_deactivate_position_Time

/* Code to build tree for UtChangeCurvature command */
static int dissect_itsut_change_curvature(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_curvature, tvb, offset, L_ITSUT_CHANGECURVATURE, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangeCurvature */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtChangeCurvature tree */
  /* Curvature */
  proto_tree_add_item(tree, hf_curvature, tvb, offset, L_CURVATURE, FALSE);
  offset += L_CURVATURE;

  return offset;
} // End of function dissect_itsut_change_curvature

/* Code to build tree for UtChangeSpeed command */
static int dissect_itsut_change_speed(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_speed, tvb, offset, L_ITSUT_CHANGESPEED, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangeSpeed */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtChangeSpeed tree */
  /* SpeedVariation */
  proto_tree_add_item(tree, hf_speed_variation, tvb, offset, L_SPEEDVARIATION, FALSE);
  offset += L_SPEEDVARIATION;

  return offset;
} // End of function dissect_itsut_change_speed

/* Code to build tree for UtSetAccelerationControlStatus command */
static int dissect_itsut_set_acceleration_control_status(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_tree *tree_flags = NULL;
  proto_item *ti = NULL;
  proto_item *ti_flags = NULL;
  guint8 itsut_flags = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_acceleration_control_status, tvb, offset, L_ITSUT_SETACCELERATIONCONTROLSTATUS, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangeSpeed */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* UtSetAccelerationControlStatus tree */
  /* flags */
  ti_flags = proto_tree_add_item(tree, hf_set_acceleration_control_status_flags, tvb, offset, L_ITSUT_FLAGS, FALSE);
  tree_flags = proto_item_add_subtree(ti_flags, ett_itsut_flags);
  itsut_flags = tvb_get_guint8(tvb, offset);
  if ((itsut_flags & 0x80) == 0x80) {
    proto_tree_add_item(tree_flags, hf_set_acceleration_control_status_flags_B_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x40) == 0x40) {
    proto_tree_add_item(tree_flags, hf_set_acceleration_control_status_flags_G_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x20) == 0x20) {
    proto_tree_add_item(tree_flags, hf_set_acceleration_control_status_flags_E_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x10) == 0x10) {
    proto_tree_add_item(tree_flags, hf_set_acceleration_control_status_flags_C_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x08) == 0x08) {
    proto_tree_add_item(tree_flags, hf_set_acceleration_control_status_flags_A_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x04) == 0x04) {
    proto_tree_add_item(tree_flags, hf_set_acceleration_control_status_flags_CC_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x02) == 0x02) {
    proto_tree_add_item(tree_flags, hf_set_acceleration_control_status_flags_L_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  offset += L_ITSUT_FLAGS;
  
  return offset;
} // End of function dissect_itsut_set_acceleration_control_status

/* Code to build tree for UtSetExteriorLightsStatus command */
static int dissect_itsut_set_exterior_lights_status(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_tree *tree_flags = NULL;
  proto_item *ti = NULL;
  proto_item *ti_flags = NULL;
  guint8 itsut_flags = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_exterior_lights_status, tvb, offset, L_ITSUT_SETEXTERIORLIGHTSSTATUS, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangeSpeed */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* UtSetAccelerationControlStatus tree */
  /* flags */
  ti_flags = proto_tree_add_item(tree, hf_set_exterior_lights_status_flags, tvb, offset, L_ITSUT_FLAGS, FALSE);
  tree_flags = proto_item_add_subtree(ti_flags, ett_itsut_flags);
  itsut_flags = tvb_get_guint8(tvb, offset);
  if ((itsut_flags & 0x80) == 0x80) {
    proto_tree_add_item(tree_flags, hf_set_exterior_lights_status_flags_LB_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x40) == 0x40) {
    proto_tree_add_item(tree_flags, hf_set_exterior_lights_status_flags_HB_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x20) == 0x20) {
    proto_tree_add_item(tree_flags, hf_set_exterior_lights_status_flags_LT_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x10) == 0x10) {
    proto_tree_add_item(tree_flags, hf_set_exterior_lights_status_flags_RT_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x08) == 0x08) {
    proto_tree_add_item(tree_flags, hf_set_exterior_lights_status_flags_D_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x04) == 0x04) {
    proto_tree_add_item(tree_flags, hf_set_exterior_lights_status_flags_R_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x02) == 0x02) {
    proto_tree_add_item(tree_flags, hf_set_exterior_lights_status_flags_F_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x01) {
    proto_tree_add_item(tree_flags, hf_set_exterior_lights_status_flags_P_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  offset += L_ITSUT_FLAGS;
  
  return offset;
} // End of function dissect_itsut_set_exterior_lights_status

/* Code to build tree for UtChangeHeading command */
static int dissect_itsut_change_heading(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_heading, tvb, offset, L_ITSUT_CHANGEHEADING, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangeHeading */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtChangeHeading tree */
  /* Direction */
  proto_tree_add_item(tree, hf_heading_direction, tvb, offset, L_HEADING_DIRECTION, FALSE);
  offset += L_HEADING_DIRECTION;

  return offset;
} // End of function dissect_itsut_change_heading

/* Code to build tree for SetDriveDirection command */
static int dissect_itsut_set_drive_direction(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_drive_direction, tvb, offset, L_ITSUT_SETDRIVEDIRECTION, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* SetDriveDirection */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* SetDriveDirection tree */
  /* Direction */
  proto_tree_add_item(tree, hf_drive_direction, tvb, offset, L_DRIVE_DIRECTION, FALSE);
  offset += L_DRIVE_DIRECTION;

  return offset;
} // End of function dissect_itsut_set_drive_direction

/* Code to build tree for ChangeYawRate command */
static int dissect_itsut_change_yawrate(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_yawrate, tvb, offset, L_ITSUT_CHANGEYAWRATE, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangeSpeed */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* ChangeYawRate tree */
  /* YawRate */
  proto_tree_add_item(tree, hf_yawrate, tvb, offset, L_YAWRATE, FALSE);
  offset += L_YAWRATE;

  return offset;
} // End of function dissect_itsut_change_yawrate

/* Code to build tree for CamEventIndication command */
static int dissect_itsut_cam_event_indication(tvbuff_t *tvb, proto_tree *header_tree, packet_info *pinfo, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_cam_event_indication, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* CamEventIndication */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* CamEventIndication tree */
  /* Length */
  length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_cam_event_indication_length, tvb, offset, L_CAMEVENTLENGTH, FALSE);
  offset += L_CAMEVENTLENGTH;
  if (length != 0) {
    dissector_table_t dissector_table;
    tvbuff_t *next_tvb = NULL;
    
    proto_tree_add_item(tree, hf_cam_event_indication_payload, tvb, offset, length, FALSE);
    
    /* call sub-dissector if any */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    dissector_table = find_dissector_table("btp.dport");
    dissector_try_uint(dissector_table, 2001, next_tvb, pinfo, tree); // TODO How to parametrize BTPport for CAM/DENM/MAPEM/SPATEM
    offset += length;
  }

  return offset;
} // End of function dissect_itsut_cam_event_indication

/* Code to build tree for SetStationType command */
static int dissect_itsut_set_station_type(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_station_type, tvb, offset, L_ITSUT_SETSTATIONTYPE, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* SetStationType */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* SetStationType tree */
  /* StationType */
  proto_tree_add_item(tree, hf_station_type, tvb, offset, L_STATIONTYPE, FALSE);
  offset += L_STATIONTYPE;

  return offset;
} // End of function dissect_itsut_set_station_type

/* Code to build tree for SetVehicleRole command */
static int dissect_itsut_set_vehicle_role(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_vehicle_role, tvb, offset, L_ITSUT_SETVEHICLEROLE, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* SetVehicleRole */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* SetVehicleRole tree */
  /* VehicleRole */
  proto_tree_add_item(tree, hf_vehicle_role, tvb, offset, L_VEHICLEROLE, FALSE);
  offset += L_VEHICLEROLE;

  return offset;
} // End of function dissect_itsut_set_vehicle_role

/* Code to build tree for SetEmbarkationStatus command */
static int dissect_itsut_set_embarkation_status(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_embarkation_status, tvb, offset, L_ITSUT_SETEMBARKATIONSTATUS, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* SetEmbarkationStatus */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* SetEmbarkationStatus tree */
  /* EmbarkationStatus */
  proto_tree_add_item(tree, hf_embarkation_status, tvb, offset, L_EMBARKATIONSTATUS, FALSE);
  offset += L_EMBARKATIONSTATUS;

  return offset;
} // End of function dissect_itsut_set_embarkation_status

/* Code to build tree for SetPtActivation command */
static int dissect_itsut_set_pt_activation(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_pt_activation, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* SetPtActivation */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* SetPtActivation tree */
  /* Type */
  proto_tree_add_item(tree, hf_set_pt_activation_type, tvb, offset, L_SETPTACTIVATIONTYPE, FALSE);
  offset += L_SETPTACTIVATIONTYPE;

  /* Length */
  length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_set_pt_activation_length, tvb, offset, L_SETPTACTIVATIONLENGTH, FALSE);
  offset += L_SETPTACTIVATIONLENGTH;
  if (length != 0) {
    proto_tree_add_item(tree, hf_set_pt_activation_payload, tvb, offset, length, FALSE);
    offset += length;
  }

  return offset;
} // End of function dissect_itsut_set_pt_activation

/* Code to build tree for SetDangerousGoods command */
static int dissect_itsut_set_dangerous_goods(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_dangerous_goods, tvb, offset, L_ITSUT_SETDANGEROUSGOODS, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* SetDangerousGoods */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* SetDangerousGoods tree */
  /* DangerousGoods */
  proto_tree_add_item(tree, hf_dangerous_goods, tvb, offset, L_DANGEROUSGOODS, FALSE);
  offset += L_DANGEROUSGOODS;

  return offset;
} // End of function dissect_itsut_set_dangerous_goods

/* Code to build tree for SetDangerousGoodsExtended command */
static int dissect_itsut_set_dangerous_goods_ext(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_dangerous_goods_ext, tvb, offset, L_ITSUT_SETDANGEROUSGOODSEXT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* SetDangerousGoodsExtended */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* SetDangerousGoodsExtended tree */
  /* DangerousGoodsExtended */
  proto_tree_add_item(tree, hf_dangerous_goods_ext, tvb, offset, L_DANGEROUSGOODS, FALSE);
  offset += L_DANGEROUSGOODS;

  return offset;
} // End of function dissect_itsut_set_dangerous_goods_ext

/* Code to build tree for UtSetLightBarSiren command */
static int dissect_itsut_set_light_bar_siren(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_tree *tree_flags = NULL;
  proto_item *ti = NULL;
  proto_item *ti_flags = NULL;
  guint8 itsut_flags = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_set_light_bar_siren, tvb, offset, L_ITSUT_SETLIGHTBARSIREN, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtChangeSpeed */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* SetLightBarSiren tree */
  /* flags */
  ti_flags = proto_tree_add_item(tree, hf_set_light_bar_siren_flags, tvb, offset, L_ITSUT_FLAGS, FALSE);
  tree_flags = proto_item_add_subtree(ti_flags, ett_itsut_flags);
  itsut_flags = tvb_get_guint8(tvb, offset);
  if ((itsut_flags & 0x80) == 0x80) {
    proto_tree_add_item(tree_flags, hf_set_light_bar_siren_flags_LB_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x40) == 0x40) {
    proto_tree_add_item(tree_flags, hf_set_light_bar_siren_flags_S_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  offset += L_ITSUT_FLAGS;
  
  return offset;
} // End of function dissect_itsut_set_light_bar_siren

/* Code to build tree for UtDenmTrigger command */
static int dissect_itsut_denm_trigger(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  proto_tree *tree_flags = NULL;
  proto_item *ti_flags = NULL;
  guint8 itsut_flags = -1;
  guint8 alacarteLength = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_denm_trigger, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtDenmTrigger */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtDenmTrigger tree */
  /* flags */
  ti_flags = proto_tree_add_item(tree, hf_denm_trigger_flags, tvb, offset, L_ITSUT_FLAGS, FALSE);
  tree_flags = proto_item_add_subtree(ti_flags, ett_itsut_flags);
  itsut_flags = tvb_get_guint8(tvb, offset);
  if ((itsut_flags & 0x80) == 0x80) { // V bits: Validity Duration
    proto_tree_add_item(tree_flags, hf_denm_trigger_flags_V_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x40) == 0x40) { // R bits: RepetitionDuration Duration
    proto_tree_add_item(tree_flags, hf_denm_trigger_flags_R_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  // Three reserved bits
  if ((itsut_flags & 0x04) == 0x04) { // K bits: TransmissionInterval Duration
    proto_tree_add_item(tree_flags, hf_denm_trigger_flags_K_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x02) == 0x02) { // I bits: RepetitionInterval Duration
    proto_tree_add_item(tree_flags, hf_denm_trigger_flags_I_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x01) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  offset += L_ITSUT_FLAGS;
  /* DetectionTime */
  proto_tree_add_item(tree, hf_detection_time, tvb, offset, L_DETECTIONTIME, FALSE);
  offset += L_DETECTIONTIME;
  /* ValidityDuration */
  proto_tree_add_item(tree, hf_validity_duration, tvb, offset, L_VALIDITYDURATION, FALSE);
  offset += L_VALIDITYDURATION;
  /* RepetitionDuration */
  proto_tree_add_item(tree, hf_repetition_duration, tvb, offset, L_REPETITIONDURATION, FALSE);
  offset += L_REPETITIONDURATION;
  /* InfoQuality */
  proto_tree_add_item(tree, hf_info_quality, tvb, offset, L_INFOQUALITY, FALSE);
  offset += L_INFOQUALITY;
  /* Cause */
  proto_tree_add_item(tree, hf_cause, tvb, offset, L_CAUSE, FALSE);
  offset += L_CAUSE;
  /* SubCause */
  proto_tree_add_item(tree, hf_subcause, tvb, offset, L_SUBCAUSE, FALSE);
  offset += L_SUBCAUSE;
  /* RelevanceDistance */
  proto_tree_add_item(tree, hf_relevance_distance, tvb, offset, L_RELEVANCEDISTANCE, FALSE);
  offset += L_RELEVANCEDISTANCE;
  /* RelevanceTrafficDirection */
  proto_tree_add_item(tree, hf_relevance_traffic_direction, tvb, offset, L_RELEVANCETRAFFICDIRECTION, FALSE);
  offset += L_RELEVANCETRAFFICDIRECTION;
  /* TransmissionInterval */
  proto_tree_add_item(tree, hf_transmission_interval, tvb, offset, L_TRANSMISSIONINTERVAL, FALSE);
  offset += L_TRANSMISSIONINTERVAL;
  /* RepetitionInterval */
  proto_tree_add_item(tree, hf_repetition_interval, tvb, offset, L_REPETITIONINTERVAL, FALSE);
  offset += L_REPETITIONINTERVAL;
  /* alacarteLength */
  alacarteLength = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_alacarte_length, tvb, offset, L_ALACARTELENGTH, FALSE);
  offset += L_ALACARTELENGTH;
  if (alacarteLength != 0) {
    proto_tree_add_item(tree, hf_alacarte, tvb, offset, alacarteLength, FALSE);
    offset += alacarteLength;
  }
  
  return offset;
} // End of function dissect_itsut_denm_trigger

/* Code to build tree for UtDenmUpdate command */
static int dissect_itsut_denm_update(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  proto_tree *tree_flags = NULL;
  proto_item *ti_flags = NULL;
  guint8 itsut_flags = -1;
  guint8 alacarteLength = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_denm_event, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtDenmTrigger */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtDenmUpdate tree */
  /* flags */
  ti_flags = proto_tree_add_item(tree, hf_denm_event_flags, tvb, offset, L_ITSUT_FLAGS, FALSE);
  tree_flags = proto_item_add_subtree(ti_flags, ett_itsut_flags);
  itsut_flags = tvb_get_guint8(tvb, offset);
  if ((itsut_flags & 0x80) == 0x80) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_V_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x40) == 0x40) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_S_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x20) == 0x20) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_D_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x10) == 0x10) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_T_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x08) == 0x08) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_C_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x04) == 0x04) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_K_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x02) == 0x02) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_I_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x01) {
    proto_tree_add_item(tree_flags, hf_denm_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  offset += L_ITSUT_FLAGS;
  /* StationID */
  proto_tree_add_item(tree, hf_station_id, tvb, offset, L_STATIONID, FALSE);
  offset += L_STATIONID;
  /* SequenceNumber */
  proto_tree_add_item(tree, hf_sequence_number, tvb, offset, L_SEQNUM, FALSE);
  offset += L_SEQNUM;
  /* DetectionTime */
  proto_tree_add_item(tree, hf_detection_time, tvb, offset, L_DETECTIONTIME, FALSE);
  offset += L_DETECTIONTIME;
  /* ValidityDuration */
  proto_tree_add_item(tree, hf_validity_duration, tvb, offset, L_VALIDITYDURATION, FALSE);
  offset += L_VALIDITYDURATION;
  /* InfoQuality */
  proto_tree_add_item(tree, hf_info_quality, tvb, offset, L_INFOQUALITY, FALSE);
  offset += L_INFOQUALITY;
  /* Cause */
  proto_tree_add_item(tree, hf_cause, tvb, offset, L_CAUSE, FALSE);
  offset += L_CAUSE;
  /* SubCause */
  proto_tree_add_item(tree, hf_subcause, tvb, offset, L_SUBCAUSE, FALSE);
  offset += L_SUBCAUSE;
  /* RelevanceDistance */
  proto_tree_add_item(tree, hf_relevance_distance, tvb, offset, L_RELEVANCEDISTANCE, FALSE);
  offset += L_RELEVANCEDISTANCE;
  /* RelevanceTrafficDirection */
  proto_tree_add_item(tree, hf_relevance_traffic_direction, tvb, offset, L_RELEVANCETRAFFICDIRECTION, FALSE);
  offset += L_RELEVANCETRAFFICDIRECTION;
  /* TransmissionInterval */
  proto_tree_add_item(tree, hf_transmission_interval, tvb, offset, L_TRANSMISSIONINTERVAL, FALSE);
  offset += L_TRANSMISSIONINTERVAL;
  /* RepetitionInterval */
  proto_tree_add_item(tree, hf_repetition_interval, tvb, offset, L_REPETITIONINTERVAL, FALSE);
  offset += L_REPETITIONINTERVAL;
  /* alacarteLength */
  alacarteLength = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_alacarte_length, tvb, offset, L_ALACARTELENGTH, FALSE);
  offset += L_ALACARTELENGTH;
  if (alacarteLength != 0) {
    proto_tree_add_item(tree, hf_alacarte, tvb, offset, alacarteLength, FALSE);
    offset += alacarteLength;
  }
  
  return offset;
} // End of function dissect_itsut_denm_update

/* Code to build tree for UtTerminateDenmEvent indication */
static int dissect_itsut_terminate_denm_event(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_terminate_denm_event, tvb, offset, L_ITSUT_INITIALISE_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtTerminateDenmEvent */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* StationID */
  proto_tree_add_item(tree, hf_station_id, tvb, offset, L_STATIONID, FALSE);
  offset += L_STATIONID;

  /* SequenceNumber */
  proto_tree_add_item(tree, hf_sequence_number, tvb, offset, L_SEQNUM, FALSE);
  offset += L_SEQNUM;

  return offset;
} // End of function dissect_itsut_terminate_denm_event

/* Code to build tree for DenmEventIndication command */
static int dissect_itsut_denm_event_indication(tvbuff_t *tvb, proto_tree *header_tree, packet_info *pinfo, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_denm_event_indication, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* DenmEventIndication */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* DenmEventIndication tree */
  /* Length */
  /* length */
  length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_denm_event_indication_length, tvb, offset, L_DENMEVENTLENGTH, FALSE);
  offset += L_DENMEVENTLENGTH;
  if (length != 0) {
    dissector_table_t dissector_table;
    tvbuff_t *next_tvb = NULL;
    
    proto_tree_add_item(tree, hf_denm_event_indication_payload, tvb, offset, length, FALSE);
    
    /* call sub-dissector if any */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    dissector_table = find_dissector_table("btp.dport");
    dissector_try_uint(dissector_table, 2002, next_tvb, pinfo, tree); // TODO How to parametrize BTPport for CAM/DENM/MAPEM/SPATEM
    offset += length;
 }

  return offset;
} // End of function dissect_itsut_denm_event_indication

/* Code to build tree for GnGenerateGeoUnicast command */
static int dissect_itsut_gn_geounicast(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 payload_length = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_gn_geounicast, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* GnGenerateGeoUnicast */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* GnGenerateGeoUnicast tree */
  /* DstGnAddr */
  proto_tree_add_item(tree, hf_gn_address, tvb, offset, L_DSTGNADDR, FALSE);
  offset += L_DSTGNADDR;
  /* Lifetime */
  proto_tree_add_item(tree, hf_lifetime, tvb, offset, L_LIFETIME, FALSE);
  offset += L_LIFETIME;
  /* TrafficClass */
  proto_tree_add_item(tree, hf_trafficclass, tvb, offset, L_TRAFFICCLASS, FALSE);
  offset += L_TRAFFICCLASS;
  /* PayloadLength */
  if (offset < (int)tvb_captured_length(tvb)) {
  payload_length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_payloadlength, tvb, offset, L_PAYLOADLENGTH, FALSE);
  offset += L_PAYLOADLENGTH;
  if (payload_length != 0) {
    proto_tree_add_item(tree, hf_payload, tvb, offset, payload_length, FALSE);
    offset += payload_length;
  }
  }
  
  return offset;
} // End of function dissect_itsut_gn_geounicast

/* Code to build tree for GnGenerateGeoBroadcast command */
static int dissect_itsut_gn_geobroadcast(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 payload_length = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_gn_geobroadcast, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* GnGenerateGeoBroadcast */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* GnGenerateGeoBroadcast tree */
  /* Shape */
  proto_tree_add_item(tree, hf_shape, tvb, offset, L_SHAPE, FALSE);
  offset += L_SHAPE;
  /* Lifetime */
  proto_tree_add_item(tree, hf_lifetime, tvb, offset, L_LIFETIME, FALSE);
  offset += L_LIFETIME;
  /* TrafficClass */
  proto_tree_add_item(tree, hf_trafficclass, tvb, offset, L_TRAFFICCLASS, FALSE);
  offset += L_TRAFFICCLASS;
  /* Reserved */
  proto_tree_add_item(tree, hf_reservedgeobroadcast, tvb, offset, L_RESERVEDGEOBROADCAST, FALSE);
  offset += L_RESERVEDGEOBROADCAST;
  /* Latitude */
  proto_tree_add_item(tree, hf_latitude, tvb, offset, L_LATITUDE, FALSE);
  offset += L_LATITUDE;
  /* Longitude */
  proto_tree_add_item(tree, hf_longitude, tvb, offset, L_LONGITUDE, FALSE);
  offset += L_LONGITUDE;
  /* DistanceA */
  proto_tree_add_item(tree, hf_distancea, tvb, offset, L_DISTANCEA, FALSE);
  offset += L_DISTANCEA;
  /* DistanceB */
  proto_tree_add_item(tree, hf_distanceb, tvb, offset, L_DISTANCEB, FALSE);
  offset += L_DISTANCEB;
  /* Angle */
  proto_tree_add_item(tree, hf_angle, tvb, offset, L_ANGLE, FALSE);
  offset += L_ANGLE;
  /* PayloadLength */
  if (offset < (int)tvb_captured_length(tvb)) {
  payload_length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_payloadlength, tvb, offset, L_PAYLOADLENGTH, FALSE);
  offset += L_PAYLOADLENGTH;
  if (payload_length != 0) {
    proto_tree_add_item(tree, hf_payload, tvb, offset, payload_length, FALSE);
    offset += payload_length;
  }
  }
  return offset;
} // End of function dissect_itsut_gn_geobroadcast

/* Code to build tree for GnGenerateGeoAnycast command */
static int dissect_itsut_gn_geoanycast(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 payload_length = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_gn_geoanycast, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* GnGenerateGeoAnycast */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* GnGenerateGeoAnycast tree */
  /* Shape */
  proto_tree_add_item(tree, hf_station_id, tvb, offset, L_SHAPE, FALSE);
  offset += L_SHAPE;
  /* Lifetime */
  proto_tree_add_item(tree, hf_lifetime, tvb, offset, L_LIFETIME, FALSE);
  offset += L_LIFETIME;
  /* TrafficClass */
  proto_tree_add_item(tree, hf_trafficclass, tvb, offset, L_TRAFFICCLASS, FALSE);
  offset += L_TRAFFICCLASS;
  /* Reserved */
  proto_tree_add_item(tree, hf_reservedgeobroadcast, tvb, offset, L_RESERVEDGEOBROADCAST, FALSE);
  offset += L_RESERVEDGEOBROADCAST;
  /* Latitude */
  proto_tree_add_item(tree, hf_latitude, tvb, offset, L_LATITUDE, FALSE);
  offset += L_LATITUDE;
  /* Longitude */
  proto_tree_add_item(tree, hf_longitude, tvb, offset, L_LONGITUDE, FALSE);
  offset += L_LONGITUDE;
  /* DistanceA */
  proto_tree_add_item(tree, hf_distancea, tvb, offset, L_DISTANCEA, FALSE);
  offset += L_DISTANCEA;
  /* DistanceB */
  proto_tree_add_item(tree, hf_distanceb, tvb, offset, L_DISTANCEB, FALSE);
  offset += L_DISTANCEB;
  /* Angle */
  proto_tree_add_item(tree, hf_angle, tvb, offset, L_ANGLE, FALSE);
  offset += L_ANGLE;
  /* PayloadLength */
  if (offset < (int)tvb_captured_length(tvb)) {
      payload_length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
      proto_tree_add_item(tree, hf_payloadlength, tvb, offset, L_PAYLOADLENGTH, FALSE);
      offset += L_PAYLOADLENGTH;
      if (payload_length != 0) {
        proto_tree_add_item(tree, hf_payload, tvb, offset, payload_length, FALSE);
        offset += payload_length;
      }
  }
  
  return offset;
} // End of function dissect_itsut_gn_geobroadcast

/* Code to build tree for GnGenerateGeoShb command */
static int dissect_itsut_gn_geoshb(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 payload_length = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_gn_geoshb, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* GnGenerateGeoShb */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* GnGenerateGeoShb tree */
  /* TrafficClass */
  proto_tree_add_item(tree, hf_trafficclass, tvb, offset, L_TRAFFICCLASS, FALSE);
  offset += L_TRAFFICCLASS;
  /* PayloadLength */
  payload_length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_payloadlength, tvb, offset, L_PAYLOADLENGTH, FALSE);
  offset += L_PAYLOADLENGTH;
  if (payload_length != 0) {
    proto_tree_add_item(tree, hf_payload, tvb, offset, payload_length, FALSE);
    offset += payload_length;
  }
  
  return offset;
} // End of function dissect_itsut_gn_geoshb

/* Code to build tree for GnGenerateGeoTsb command */
static int dissect_itsut_gn_geotsb(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 payload_length = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_gn_geotsb, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* GnGenerateGeoTsb */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* GnGenerateGeoTsb tree */
  /* NbHops */
  proto_tree_add_item(tree, hf_nbhops, tvb, offset, L_NBHOPS, FALSE);
  offset += L_NBHOPS;
  /* Lifetime */
  proto_tree_add_item(tree, hf_lifetime, tvb, offset, L_LIFETIME, FALSE);
  offset += L_LIFETIME;
  /* TrafficClass */
  proto_tree_add_item(tree, hf_trafficclass, tvb, offset, L_TRAFFICCLASS, FALSE);
  offset += L_TRAFFICCLASS;
  /* PayloadLength */
  if (offset < (int)tvb_captured_length(tvb)) {
      payload_length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
      proto_tree_add_item(tree, hf_payloadlength, tvb, offset, L_PAYLOADLENGTH, FALSE);
      offset += L_PAYLOADLENGTH;
      if (payload_length != 0) {
        proto_tree_add_item(tree, hf_payload, tvb, offset, payload_length, FALSE);
        offset += payload_length;
      }
  }
  
  return offset;
} // End of function dissect_itsut_gn_geotsb

/* Code to build tree for GnEventIndication command */
static int dissect_itsut_gn_event_indication(tvbuff_t *tvb, proto_tree *header_tree, packet_info *pinfo _U_, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_gn_event_indication, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* GnEventIndication */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* GnEventIndication tree */
  /* Length */
  length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_gn_event_indication_length, tvb, offset, L_PAYLOADLENGTH, FALSE);
  offset += L_PAYLOADLENGTH;
  if (length != 0) {
    proto_tree_add_item(tree, hf_gn_event_indication_payload, tvb, offset, length, FALSE);
    offset += length;
  }

  return offset;
} // End of function dissect_itsut_gn_event_indication

/* Code to build tree for UtMapemSpatemTrigger command */
static int dissect_itsut_mapemspatem_trigger_event(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_mapemspatem_trigger_event, tvb, offset, L_ITSUT_MAPEMSPATEM_TRIGGER_EVENT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtMapemSpatemTrigger */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtMapemSpatemTrigger tree */
  /* Event */
  proto_tree_add_item(tree, hf_event, tvb, offset, L_MAPEMSPATEM_TRIGGER_EVENT, FALSE);
  offset += L_MAPEMSPATEM_TRIGGER_EVENT;
  // TODO Add details according the byte value
  
  return offset;
} // End of function dissect_itsut_mapemspatem_trigger_event

/* Code to build tree for MapemEventIndication command */
static int dissect_itsut_mapem_event_indication(tvbuff_t *tvb, proto_tree *header_tree, packet_info *pinfo, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_mapem_event_indication, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* MapemEventIndication */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* MapemEventIndication tree */
  /* Length */
  length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_mapem_event_indication_length, tvb, offset, L_PAYLOADLENGTH, FALSE);
  offset += L_PAYLOADLENGTH;
  if (length != 0) {
    dissector_table_t dissector_table;
    tvbuff_t *next_tvb = NULL;
    
    proto_tree_add_item(tree, hf_mapem_event_indication_payload, tvb, offset, length, FALSE);
    
    /* call sub-dissector if any */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    dissector_table = find_dissector_table("btp.dport");
    dissector_try_uint(dissector_table, 2005, next_tvb, pinfo, tree); // TODO How to parametrize BTPport for CAM/DENM/MAPEM/SPATEM
    offset += length;
  }

  return offset;
} // End of function dissect_itsut_mapem_event_indication

/* Code to build tree for UtSpatemEventInd command */
static int dissect_itsut_spatem_event_indication(tvbuff_t *tvb, proto_tree *header_tree, packet_info *pinfo, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_spatem_event_indication, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtSpatemEventInd */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtSpatemEventInd tree */
  /* Length */
  length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_spatem_event_indication_length, tvb, offset, L_PAYLOADLENGTH, FALSE);
  offset += L_PAYLOADLENGTH;
  if (length != 0) {
    dissector_table_t dissector_table;
    tvbuff_t *next_tvb = NULL;
    
    proto_tree_add_item(tree, hf_spatem_event_indication_payload, tvb, offset, length, FALSE);
    
    /* call sub-dissector if any */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    dissector_table = find_dissector_table("btp.dport");
    dissector_try_uint(dissector_table, 2004, next_tvb, pinfo, tree); // TODO How to parametrize BTPport for CAM/DENM/MAPEM/SPATEM
    offset += length;
  }

  return offset;
} // End of function dissect_itsut_spatem_event_indication

/* Code to build tree for UtIvimTrigger command */
static int dissect_itsut_ivim_trigger_event(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  proto_tree *tree_flags = NULL;
  proto_item *ti_flags = NULL;
  guint8 itsut_flags = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_ivim_trigger_event, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtIvimTrigger */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtIvimTrigger tree */
  /* flags */
  ti_flags = proto_tree_add_item(tree, hf_ivim_trigger_event_flags, tvb, offset, L_ITSUT_FLAGS, FALSE);
  tree_flags = proto_item_add_subtree(ti_flags, ett_itsut_flags);
  itsut_flags = tvb_get_guint8(tvb, offset);
  if ((itsut_flags & 0x80) == 0x80) { // F bits: Validity From
    proto_tree_add_item(tree_flags, hf_ivim_trigger_event_flags_F_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x40) == 0x40) { // T bits: Validity To
    proto_tree_add_item(tree_flags, hf_ivim_trigger_event_flags_T_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x04) == 0x20) { // R bits: Repetition Interval
    proto_tree_add_item(tree_flags, hf_ivim_trigger_event_flags_R_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x10) {
    proto_tree_add_item(tree_flags, hf_ivim_trigger_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x08) {
    proto_tree_add_item(tree_flags, hf_ivim_trigger_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x04) {
    proto_tree_add_item(tree_flags, hf_ivim_trigger_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x02) {
    proto_tree_add_item(tree_flags, hf_ivim_trigger_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x01) {
    proto_tree_add_item(tree_flags, hf_ivim_trigger_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  offset += L_ITSUT_FLAGS;
  /* ValidityFrom */
  proto_tree_add_item(tree, hf_validity_from, tvb, offset, L_VALIDITYFROM, FALSE);
  offset += L_VALIDITYFROM;
  /* ValidityTo */
  proto_tree_add_item(tree, hf_validity_to, tvb, offset, L_VALIDITYTO, FALSE);
  offset += L_VALIDITYTO;
  /* RepetitionInterval */
  proto_tree_add_item(tree, hf_repetition_interval_ivim, tvb, offset, L_REPETITIONINTERVAL_IVIM, FALSE);
  offset += L_REPETITIONINTERVAL_IVIM;
  
  return offset;
} // End of function dissect_itsut_ivim_trigger_event

/* Code to build tree for UtIvimUpdate command */
static int dissect_itsut_ivim_update_event(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  proto_tree *tree_flags = NULL;
  proto_item *ti_flags = NULL;
  guint8 itsut_flags = -1;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_ivim_update_event, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtIvimTrigger */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtIvimUpdate tree */
  /* flags */
  ti_flags = proto_tree_add_item(tree, hf_ivim_update_event, tvb, offset, L_ITSUT_FLAGS, FALSE);
  tree_flags = proto_item_add_subtree(ti_flags, ett_itsut_flags);
  itsut_flags = tvb_get_guint8(tvb, offset);
  if ((itsut_flags & 0x80) == 0x80) { // F bits: Validity From
    proto_tree_add_item(tree_flags, hf_ivim_update_event_flags_F_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x40) == 0x40) { // T bits: Validity To
    proto_tree_add_item(tree_flags, hf_ivim_update_event_flags_T_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x04) == 0x20) { // R bits: Repetition Interval
    proto_tree_add_item(tree_flags, hf_ivim_update_event_flags_R_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x10) {
    proto_tree_add_item(tree_flags, hf_ivim_update_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x08) {
    proto_tree_add_item(tree_flags, hf_ivim_update_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x04) {
    proto_tree_add_item(tree_flags, hf_ivim_update_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x02) {
    proto_tree_add_item(tree_flags, hf_ivim_update_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  if ((itsut_flags & 0x01) == 0x01) {
    proto_tree_add_item(tree_flags, hf_ivim_update_event_flags_X_bit, tvb, offset, L_ITSUT_FLAGS, FALSE);
  }
  offset += L_ITSUT_FLAGS;
  /* IVI Identification Number */
  proto_tree_add_item(tree, hf_ivi_id, tvb, offset, L_IVIIDENTIFICATIONNUMBER, FALSE);
  offset += L_IVIIDENTIFICATIONNUMBER;
  /* ValidityFrom */
  proto_tree_add_item(tree, hf_validity_from, tvb, offset, L_VALIDITYFROM, FALSE);
  offset += L_VALIDITYFROM;
  /* ValidityTo */
  proto_tree_add_item(tree, hf_validity_to, tvb, offset, L_VALIDITYTO, FALSE);
  offset += L_VALIDITYTO;
  /* RepetitionInterval */
  proto_tree_add_item(tree, hf_repetition_interval_ivim, tvb, offset, L_REPETITIONINTERVAL_IVIM, FALSE);
  offset += L_REPETITIONINTERVAL_IVIM;
  
  return offset;
} // End of function dissect_itsut_ivim_update_event

/* Code to build tree for UtTerminateIvimEvent indication */
static int dissect_itsut_ivim_terminate_event(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_ivim_terminate_event, tvb, offset, L_ITSUT_INITIALISE_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtTerminateIvimEvent */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* IVI Identification Number */
  proto_tree_add_item(tree, hf_ivi_id, tvb, offset, L_IVIIDENTIFICATIONNUMBER, FALSE);
  offset += L_IVIIDENTIFICATIONNUMBER;

  return offset;
} // End of function dissect_itsut_ivim_terminate_event

/* Code to build tree for IvimEventIndication command */
static int dissect_itsut_ivim_event_indication(tvbuff_t *tvb, proto_tree *header_tree, packet_info *pinfo, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_ivim_event_indication, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* IvimEventIndication */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* IvimEventIndication tree */
  /* Length */
  /* length */
  length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_ivim_event_indication_length, tvb, offset, L_DENMEVENTLENGTH, FALSE);
  offset += L_DENMEVENTLENGTH;
  if (length != 0) {
    dissector_table_t dissector_table;
    tvbuff_t *next_tvb = NULL;
    
    proto_tree_add_item(tree, hf_ivim_event_indication_payload, tvb, offset, length, FALSE);
    
    /* call sub-dissector if any */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    dissector_table = find_dissector_table("btp.dport");
    dissector_try_uint(dissector_table, 2006, next_tvb, pinfo, tree); // TODO How to parametrize BTPport for CAM/DENM/MAPEM/SPATEM
    offset += length;
 }

  return offset;
} // End of function dissect_itsut_ivim_event_indication

/* Code to build tree for UtSremTrigger command */
static int dissect_itsut_srem_trigger_event(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_srem_trigger_event, tvb, offset, L_ITSUT_SREM_TRIGGER_EVENT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtSremTrigger */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtSremTrigger tree */
  /* Event */
  proto_tree_add_item(tree, hf_event, tvb, offset, L_SREM_TRIGGER_EVENT, FALSE);
  offset += L_SREM_TRIGGER_EVENT;
  // TODO Add details according the byte value
  
  return offset;
} // End of function dissect_itsut_srem_trigger_event

/* Code to build tree for UtSremUpdate command */
static int dissect_itsut_srem_update_event(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_srem_update_event, tvb, offset, L_ITSUT_SREM_UPDATE_EVENT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtSremUpdate */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtSremUpdate tree */
  /* Event */
  proto_tree_add_item(tree, hf_event, tvb, offset, L_SREM_UPDATE_EVENT, FALSE);
  offset += L_SREM_UPDATE_EVENT;
  // TODO Add details according the byte value
  
  return offset;
} // End of function dissect_itsut_srem_update_event

/* Code to build tree for SremEventIndication command */
static int dissect_itsut_srem_event_indication(tvbuff_t *tvb, proto_tree *header_tree, packet_info *pinfo, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_srem_event_indication, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* SremEventIndication */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* SremEventIndication tree */
  /* Length */
  length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_srem_event_indication_length, tvb, offset, L_PAYLOADLENGTH, FALSE);
  offset += L_PAYLOADLENGTH;
  if (length != 0) {
    dissector_table_t dissector_table;
    tvbuff_t *next_tvb = NULL;
    
    proto_tree_add_item(tree, hf_srem_event_indication_payload, tvb, offset, length, FALSE);
    
    /* call sub-dissector if any */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    dissector_table = find_dissector_table("btp.dport");
    dissector_try_uint(dissector_table, 2005, next_tvb, pinfo, tree); // TODO How to parametrize BTPport for CAM/DENM/MAPEM/SPATEM
    offset += length;
  }

  return offset;
} // End of function dissect_itsut_srem_event_indication

/* Code to build tree for UtSsemEventInd command */
static int dissect_itsut_ssem_event_indication(tvbuff_t *tvb, proto_tree *header_tree, packet_info *pinfo, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  guint16 length = -1;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_ssem_event_indication, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtSsemEventInd */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  /* UtSsemEventInd tree */
  /* Length */
  length = (guint16)((tvb_get_guint8(tvb, offset) << 8) & 0xff00) | (guint16)(tvb_get_guint8(tvb, offset + 1) & 0x00ff);
  proto_tree_add_item(tree, hf_ssem_event_indication, tvb, offset, L_PAYLOADLENGTH, FALSE);
  offset += L_PAYLOADLENGTH;
  if (length != 0) {
    dissector_table_t dissector_table;
    tvbuff_t *next_tvb = NULL;
    
    proto_tree_add_item(tree, hf_ssem_event_indication, tvb, offset, length, FALSE);
    
    /* call sub-dissector if any */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    dissector_table = find_dissector_table("btp.dport");
    dissector_try_uint(dissector_table, 2004, next_tvb, pinfo, tree); // TODO How to parametrize BTPport for CAM/DENM/MAPEM/SPATEM
    offset += length;
  }

  return offset;
} // End of function dissect_itsut_ssem_event_indication

/* Code to build tree for UtPkiTrigger command */
static int dissect_itsut_pki_trigger_event_ec(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_pki_trigger_event_ec, tvb, offset, L_ITSUT_PKI_TRIGGER_EVENT_EC, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtPkiTrigger */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  return offset;
} // End of function dissect_itsut_pki_trigger_event_ec

static int dissect_itsut_pki_trigger_event_at(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
   
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_pki_trigger_event_at, tvb, offset, L_ITSUT_PKI_TRIGGER_EVENT_AT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtPkiTrigger */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;

  return offset;
} // End of function dissect_itsut_pki_trigger_event_at

/*****************************************************************************
    Result messages
*****************************************************************************/
/* Code to build tree for UtInitialiseResult indication */
static int dissect_itsut_initialise_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_initialize_result, tvb, offset, L_ITSUT_INITIALISE_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtInitialiseResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_initialize_result_code, tvb, offset, L_ITSUT_INITIALISE_RESULT_CODE, FALSE);
  offset += L_ITSUT_INITIALISE_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_initialise_result

/* Code to build tree for ItsutChangePositionResult indication */
static int dissect_itsut_change_position_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_position_result, tvb, offset, L_ITSUT_CHANGEPOSITION_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtInitialiseResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_change_position_result_code, tvb, offset, L_ITSUT_CHANGEPOSITION_RESULT_CODE, FALSE);
  offset += L_ITSUT_CHANGEPOSITION_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_change_position_result

/* Code to build tree for UtChangePseudonymResult indication */
static int dissect_itsut_change_pseudonym_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_pseudonym_result, tvb, offset, L_ITSUT_CHANGEPSEUDONYM_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtInitialiseResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_change_pseudonym_result_code, tvb, offset, L_ITSUT_CHANGEPSEUDONYM_RESULT_CODE, FALSE);
  offset += L_ITSUT_CHANGEPSEUDONYM_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_change_pseudonym_result

/* Code to build tree for UtActivatePositionTimeResult indication */
static int dissect_itsut_activate_position_Time_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_pseudonym_result, tvb, offset, L_ITSUT_ACTIVATEPOSITIONTIME_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtInitialiseResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_change_pseudonym_result_code, tvb, offset, L_ITSUT_ACTIVATEPOSITIONTIME_RESULT_CODE, FALSE);
  offset += L_ITSUT_ACTIVATEPOSITIONTIME_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_activate_position_Time_result

/* Code to build tree for UtDeactivatePositionTimeResult indication */
static int dissect_itsut_deactivate_position_Time_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_change_pseudonym_result, tvb, offset, L_ITSUT_DEACTIVATEPOSITIONTIME_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtInitialiseResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_change_pseudonym_result_code, tvb, offset, L_ITSUT_DEACTIVATEPOSITIONTIME_RESULT_CODE, FALSE);
  offset += L_ITSUT_DEACTIVATEPOSITIONTIME_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_deactivate_position_Time_result

/* Code to build tree for UtCamTriggerResult indication */
static int dissect_itsut_cam_trigger_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_cam_trigger_result, tvb, offset, L_ITSUT_CAM_TRIGGER_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtCamTriggerResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_cam_trigger_result_code, tvb, offset, L_ITSUT_CAM_TRIGGER_RESULT_CODE, FALSE);
  offset += L_ITSUT_CAM_TRIGGER_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_cam_trigger_result

/* Code to build tree for ItsutDenmTriggerResult indication */
static int dissect_itsut_denm_trigger_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_denm_trigger_result, tvb, offset, L_ITSUT_DENMM_TRIGGER_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtInitialiseResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_denm_trigger_result_code, tvb, offset, L_ITSUT_DENMM_TRIGGER_RESULT_CODE, FALSE);
  offset += L_ITSUT_DENMM_TRIGGER_RESULT_CODE;

  /* StationID */
  proto_tree_add_item(tree, hf_station_id, tvb, offset, L_STATIONID, FALSE);
  offset += L_STATIONID;

  /* SequenceNumber */
  proto_tree_add_item(tree, hf_sequence_number, tvb, offset, L_SEQNUM, FALSE);
  offset += L_SEQNUM;

  return offset;
} // End of function dissect_itsut_denm_trigger_result

/* Code to build tree for UtDenmUpdateResult indication */
static int dissect_itsut_denm_update_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_denm_event_result, tvb, offset, L_ITSUT_DENMM_EVENT_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtDenmUpdateResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_denm_event_result_code, tvb, offset, L_ITSUT_DENMM_EVENT_RESULT_CODE, FALSE);
  offset += L_ITSUT_DENMM_EVENT_RESULT_CODE;

  /* StationID */
  proto_tree_add_item(tree, hf_station_id, tvb, offset, L_STATIONID, FALSE);
  offset += L_STATIONID;

  /* SequenceNumber */
  proto_tree_add_item(tree, hf_sequence_number, tvb, offset, L_SEQNUM, FALSE);
  offset += L_SEQNUM;

  return offset;
} // End of function dissect_itsut_denm_update_result

/* Code to build tree for UtTerminateDenmEventResult indication */
static int dissect_itsut_terminate_denm_event_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_terminate_denm_event_result, tvb, offset, L_ITSUT_INITIALISE_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtTerminateDenmEventResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_denm_terminate_event_result_code, tvb, offset, L_ITSUT_INITIALISE_RESULT_CODE, FALSE);
  offset += L_ITSUT_INITIALISE_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_terminate_denm_event_result

/* Code to build tree for UtGnTriggerResult indication */
static int dissect_itsut_gn_trigger_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;
  
  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_gntrigger_result, tvb, offset, L_ITSUT_GNTRIGGER_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtGnTriggerResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_gntrigger_result_code, tvb, offset, L_ITSUT_INITIALISE_RESULT_CODE, FALSE);
  offset += L_ITSUT_INITIALISE_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_gn_trigger_result

/* Code to build tree for UtMapemSpatemTriggerResult  indication */
static int dissect_itsut_mapemspatem_trigger_event_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_mapemspatem_trigger_event_result, tvb, offset, L_ITSUT_MAPEMSPATEM_TRIGGER_EVENT_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtMapemSpatemTriggerResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  proto_tree_add_item(tree, hf_mapemspatem_trigger_event_result_code, tvb, offset, L_ITSUT_MAPEMSPATEM_TRIGGER_EVENT_RESULT_CODE, FALSE);
  offset += L_ITSUT_MAPEMSPATEM_TRIGGER_EVENT_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_mapemspatem_trigger_event_result

/* Code to build tree for UtIvimTriggerResult  indication */
static int dissect_itsut_ivim_trigger_event_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_ivim_trigger_event_result, tvb, offset, L_ITSUT_IVIM_TRIGGER_EVENT_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtIvimTriggerResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  proto_tree_add_item(tree, hf_ivim_trigger_event_result_code, tvb, offset, L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_CODE, FALSE);
  offset += L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_CODE;

  /* IviIdentification number */
  proto_tree_add_item(tree, hf_ivim_trigger_event_result_id, tvb, offset, L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_ID, FALSE);
  offset += L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_ID;

  return offset;
} // End of function dissect_itsut_ivim_trigger_event_result

/* Code to build tree for UtIvimUpdateResult  indication */
static int dissect_itsut_ivim_update_event_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_ivim_update_event_result, tvb, offset, L_ITSUT_IVIM_UPDATE_EVENT_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtIvimUpdateResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  proto_tree_add_item(tree, hf_ivim_update_event_result_code, tvb, offset, L_ITSUT_IVIM_UPDATE_EVENT_RESULT_CODE, FALSE);
  offset += L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_CODE;

  /* IviIdentification number */
  proto_tree_add_item(tree, hf_ivim_update_event_result_id, tvb, offset, L_ITSUT_IVIM_UPDATE_EVENT_RESULT_ID, FALSE);
  offset += L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_ID;

  return offset;
} // End of function dissect_itsut_ivim_update_event_result

/* Code to build tree for UtIvimTerminateResult  indication */
static int dissect_itsut_ivim_terminate_event_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_ivim_terminate_event_result, tvb, offset, L_ITSUT_IVIM_TERMINATE_EVENT_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtIvimTerminateResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  proto_tree_add_item(tree, hf_ivim_terminate_event_result_code, tvb, offset, L_ITSUT_IVIM_TERMINATE_EVENT_RESULT_CODE, FALSE);
  offset += L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_CODE;

  /* IviIdentification number */
  proto_tree_add_item(tree, hf_ivim_terminate_event_result_id, tvb, offset, L_ITSUT_IVIM_TERMINATE_EVENT_RESULT_ID, FALSE);
  offset += L_ITSUT_IVIM_TRIGGER_EVENT_RESULT_ID;

  return offset;
} // End of function dissect_itsut_ivim_terminate_event_result

/* Code to build tree for UtSremTriggerResult  indication */
static int dissect_itsut_srem_trigger_event_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_srem_trigger_event_result, tvb, offset, L_ITSUT_SREM_TRIGGER_EVENT_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtSremTriggerResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  proto_tree_add_item(tree, hf_srem_trigger_event_result_code, tvb, offset, L_ITSUT_SREM_TRIGGER_EVENT_RESULT_CODE, FALSE);
  offset += L_ITSUT_SREM_TRIGGER_EVENT_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_srem_trigger_event_result

/* Code to build tree for UtSremUpdateResult  indication */
static int dissect_itsut_srem_update_event_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_srem_update_event_result, tvb, offset, L_ITSUT_SREM_UPDATE_EVENT_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtSremUpdateResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  proto_tree_add_item(tree, hf_srem_update_event_result_code, tvb, offset, L_ITSUT_SREM_UPDATE_EVENT_RESULT_CODE, FALSE);
  offset += L_ITSUT_SREM_UPDATE_EVENT_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_srem_update_event_result

/* Code to build tree for UtPkiTriggerResult  indication */
static int dissect_itsut_pki_trigger_event_result(tvbuff_t *tvb, proto_tree *header_tree, int offset)
{
  proto_tree *tree = NULL;
  proto_item *ti = NULL;

  /* ITSUT command tree */
  ti = proto_tree_add_item(header_tree, hf_pki_trigger_event_result, tvb, offset, L_PKI_TRIGGER_EVENT_RESULT, FALSE);
  tree = proto_item_add_subtree(ti, ett_itsut_command);

  /* UtPkiTriggerResult */
  proto_tree_add_item(tree, hf_command, tvb, offset, L_ITSUT_COMMAND, FALSE);
  offset += L_ITSUT_COMMAND;
  
  /* Result */
  proto_tree_add_item(tree, hf_pki_trigger_event_result_code, tvb, offset, L_PKI_TRIGGER_EVENT_RESULT_CODE, FALSE);
  offset += L_PKI_TRIGGER_EVENT_RESULT_CODE;

  return offset;
} // End of function dissect_itsut_pki_trigger_event_result

/* Code to actually dissect the ITSUT packets */
static int dissect_itsut_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint32 offset = 0;
  guint8 itsut_command = -1;
  
  /* Check that there's enough data */
  if(tvb_captured_length(tvb) < MIN_PDU_SIZE)
    return 0;

  /* Update COL_PROTOCOL */ 
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "UpperTester Protocol");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  /* Extract the command */
  itsut_command = tvb_get_guint8(tvb, offset);
    
  if (tree) { /* we are being asked for details */
    proto_item *ti = NULL;
    proto_tree *itsut_tree = NULL;
    
    /* Main UT tree */
    ti = proto_tree_add_item(tree, proto_itsut, tvb, offset, -1, FALSE);
    proto_item_append_text(ti, ": %s", val_to_str(itsut_command, itsut_command_names, "Unknown (0x%02x)"));
//    proto_item_append_text(ti, ": %s - Secured mode: %s", val_to_str(itsut_command, itsut_command_names, "Unknown (0x%02x)"), val_to_str(SecuredMode, itsut_securedmode_names, "Unknown (0x%02x)"));
    itsut_tree = proto_item_add_subtree(ti, ett_itsut);

    /* Dissect */
    switch (itsut_command) {
        case (guint8)ITSUT_INITIALISE:
            offset = dissect_itsut_initialise(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_INITIALISE_RESULT:
            offset = dissect_itsut_initialise_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CHANGEPOSITION:
            offset = dissect_itsut_change_position(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CHANGEPOSITION_RESULT:
            offset = dissect_itsut_change_position_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CHANGEPSEUDONYM:
            offset = dissect_itsut_change_pseudonym(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CHANGEPSEUDONYM_RESULT:
            offset = dissect_itsut_change_pseudonym_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_ACTIVATEPOSITIONTIME:
            offset = dissect_itsut_activate_position_Time(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_ACTIVATEPOSITIONTIMERESULT:
            offset = dissect_itsut_activate_position_Time_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_DEACTIVATEPOSITIONTIME:
            offset = dissect_itsut_deactivate_position_Time(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_DEACTIVATEPOSITIONTIMERESULT:
            offset = dissect_itsut_deactivate_position_Time_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CHANGECURVATURE:
            offset = dissect_itsut_change_curvature(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CHANGESPEED:
            offset = dissect_itsut_change_speed(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SETACCELERATIONCONTROLSTATUS:
            offset = dissect_itsut_set_acceleration_control_status(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SETEXTERIORLIGHTSSTATUS:
            offset = dissect_itsut_set_exterior_lights_status(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CHANGEHEADING:
            offset = dissect_itsut_change_heading(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SETDRIVEDIRECTION:
            offset = dissect_itsut_set_drive_direction(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CHANGEYAWRATE:
            offset = dissect_itsut_change_yawrate(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SETSTATIONTYPE:
            offset = dissect_itsut_set_station_type(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SETVEHICLEROLE:
            offset = dissect_itsut_set_vehicle_role(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SETEMBARKATIONSTATUS:
            offset = dissect_itsut_set_embarkation_status(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SETPTACTIVATION:
            offset = dissect_itsut_set_pt_activation(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CAMEVENTINDICATION:
            offset = dissect_itsut_cam_event_indication(tvb, itsut_tree, pinfo, offset);
            break;
        case (guint8)ITSUT_SETDANGEROUSGOODS:
            offset = dissect_itsut_set_dangerous_goods(tvb, itsut_tree, offset);
            break;
            break;
        case (guint8)ITSUT_SETDANGEROUSGOODSEXT:
            offset = dissect_itsut_set_dangerous_goods_ext(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SETLIGHTBARSIREN:
            offset = dissect_itsut_set_light_bar_siren(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_CAMTRIGGER_RESULT:
            offset = dissect_itsut_cam_trigger_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_DENMTRIGGER:
            offset = dissect_itsut_denm_trigger(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_DENMTRIGGER_RESULT:
            offset = dissect_itsut_denm_trigger_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_DENMUPDATE:
            offset = dissect_itsut_denm_update(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_DENMUPDATE_RESULT:
            offset = dissect_itsut_denm_update_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_TERMINATE_DENMEVENT:
            offset = dissect_itsut_terminate_denm_event(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_DENMEVENTINDICATION:
            offset = dissect_itsut_denm_event_indication(tvb, itsut_tree, pinfo, offset);
            break;
        case (guint8)ITSUT_TERMINATE_DENMEVENT_RESULT:
            offset = dissect_itsut_terminate_denm_event_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_GENERATEGEOUNICAST:
            offset = dissect_itsut_gn_geounicast(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_GENERATEGEOBROADCAST:
            offset = dissect_itsut_gn_geobroadcast(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_GENERATEGEOANYCAST:
            offset = dissect_itsut_gn_geoanycast(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_GENERATEGEOSHB:
            offset = dissect_itsut_gn_geoshb(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_GENERATEGEOTSB:
            offset = dissect_itsut_gn_geotsb(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_GNEVENTINDICATION:
            offset = dissect_itsut_gn_event_indication(tvb, itsut_tree, pinfo, offset);
            break;
        case (guint8)ITSUT_GNTRIGGER_RESULT:
            offset = dissect_itsut_gn_trigger_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_MAPEMSPATEM_TRIGGER_EVENT:
            offset = dissect_itsut_mapemspatem_trigger_event(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_MAPEMSPATEM_TRIGGER_EVENT_RESULT:
            offset = dissect_itsut_mapemspatem_trigger_event_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_MAPEMEVENTINDICATION:
            offset = dissect_itsut_mapem_event_indication(tvb, itsut_tree, pinfo, offset);
            break;
        case (guint8)ITSUT_SPATEMEVENTINDICATION:
            offset = dissect_itsut_spatem_event_indication(tvb, itsut_tree, pinfo, offset);
            break;
        case (guint8)ITSUT_IVIM_TRIGGER_EVENT:
            offset = dissect_itsut_ivim_trigger_event(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_IVIM_TRIGGER_EVENT_RESULT:
            offset = dissect_itsut_ivim_trigger_event_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_IVIM_UPDATE_EVENT:
            offset = dissect_itsut_ivim_update_event(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_IVIM_UPDATE_EVENT_RESULT:
            offset = dissect_itsut_ivim_update_event_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_IVIM_TERMINATE_EVENT:
            offset = dissect_itsut_ivim_terminate_event(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_IVIM_TERMINATE_EVENT_RESULT:
            offset = dissect_itsut_ivim_terminate_event_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_IVIMEVENTINDICATION:
            offset = dissect_itsut_ivim_event_indication(tvb, itsut_tree, pinfo, offset);
            break;
        case (guint8)ITSUT_SREM_TRIGGER_EVENT:
            offset = dissect_itsut_srem_trigger_event(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SREM_TRIGGER_EVENT_RESULT:
            offset = dissect_itsut_srem_trigger_event_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SREM_UPDATE_EVENT:
            offset = dissect_itsut_srem_update_event(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SREM_UPDATE_EVENT_RESULT:
            offset = dissect_itsut_srem_update_event_result(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_SREMEVENTINDICATION:
            offset = dissect_itsut_srem_event_indication(tvb, itsut_tree, pinfo, offset);
            break;
        case (guint8)ITSUT_SSEMEVENTINDICATION:
            offset = dissect_itsut_ssem_event_indication(tvb, itsut_tree, pinfo, offset);
            break;
        case (guint8)ITSUT_PKI_TRIGGER_EVENT_EC:
            offset = dissect_itsut_pki_trigger_event_ec(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_PKI_TRIGGER_EVENT_AT:
            offset = dissect_itsut_pki_trigger_event_at(tvb, itsut_tree, offset);
            break;
        case (guint8)ITSUT_PKI_TRIGGER_EVENT_RESULT:
            offset = dissect_itsut_pki_trigger_event_result(tvb, itsut_tree, offset);
            break;
        default:
            return 0;
    } /* End of 'swith' statement */
    
    return offset;
  }
  
  return 0;
} // End of function dissect_itsut_packet

/* Register the protocol with Wireshark */
void
proto_register_itsut(void)
{
  module_t *itsut_module;


  /* Setup list of fields 
   * NOTE Error 'Expert Info (Warn/Malformed): Trying to fetch an unsigned integer with length 8' means that hf_xxx shall be set up with 'FT_NONE, BASE_NONE' 
   */
  static hf_register_info hf[] = {
    /* ITSUT Command */
    { &hf_command,
      {"Command", "itsut", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Initialise */
    { &hf_initialize,
      {"UtInitialise", "itsut.Initialise", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },  
    { &hf_initialize_result,
      {"UtInitialiseResult", "itsut.Initialise.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT ChangePosition */
    { &hf_change_position,
      {"UtChangePosition", "itsut.change_position", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },  
    { &hf_change_position_result,
      {"UtChangePositionResult", "itsut.change_position.result", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT ChangePseudonym */
    { &hf_change_pseudonym,
      {"UtChangePseudonym", "itsut.change_pseudonym", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },  
    { &hf_change_pseudonym_result,
      {"UtChangePseudonymResult", "itsut.change_pseudonym.result", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },

    /* UT Change Curvature */
    { &hf_change_curvature ,
      {"UtChangeCurvature", "itsut.change_curvature", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* ITSUT Change Speed */
    { &hf_change_speed,
      {"UtChangeSpeed", "itsut.change_speed", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT SetAccelerationControlStatus */
    { &hf_set_acceleration_control_status,
      {"SetAccelerationControlStatus", "itsut.set_acceleration_control_status", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_set_acceleration_control_status_flags,
      {"Flags", "itsut.set_acceleration_control_status.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_set_acceleration_control_status_flags_B_bit,
      {"B bit", "itsut.set_acceleration_control_status.flags.bbit", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
    },
    { &hf_set_acceleration_control_status_flags_G_bit,
      {"G bit", "itsut.set_acceleration_control_status.flags.gbit", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
    },
    { &hf_set_acceleration_control_status_flags_E_bit,
      {"E bit", "itsut.set_acceleration_control_status.flags.ebit", FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL}
    },
    { &hf_set_acceleration_control_status_flags_C_bit,
      {"C bit", "itsut.set_acceleration_control_status.flags.cbit", FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
    },
    { &hf_set_acceleration_control_status_flags_A_bit,
      {"A bit", "itsut.set_acceleration_control_status.flags.abit", FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL}
    },
    { &hf_set_acceleration_control_status_flags_CC_bit,
      {"CC bit", "itsut.set_acceleration_control_status.flags.ccbit", FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}
    },
    { &hf_set_acceleration_control_status_flags_L_bit,
      {"L bit", "itsut.set_acceleration_control_status.flags.lbit", FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL}
    },
    
    /* ITSUT SetExteriorLightsStatus */
    { &hf_set_exterior_lights_status,
      {"SetExteriorLightsStatus", "itsut.hf_set_exterior_lights_status", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags,
      {"Flags", "itsut.set_exterior_lights_status.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags_LB_bit,
      {"LB bit", "itsut.set_exterior_lights_status.flags.lbit", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags_HB_bit,
      {"HB bit", "itsut.set_exterior_lights_status.flags.hbbit", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags_LT_bit,
      {"LT bit", "itsut.set_exterior_lights_status.flags.ltbit", FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags_RT_bit,
      {"RT bit", "itsut.set_exterior_lights_status.flags.rtbit", FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags_D_bit,
      {"D bit", "itsut.set_exterior_lights_status.flags.dbit", FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags_R_bit,
      {"R bit", "itsut.set_exterior_lights_status.flags.rbit", FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags_F_bit,
      {"LFbit", "itsut.set_exterior_lights_status.flags.fbit", FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL}
    },
    { &hf_set_exterior_lights_status_flags_P_bit,
      {"P bit", "itsut.set_exterior_lights_status.flags.pbit", FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL}
    },
    
    /* ITSUT Change Heading */
    { &hf_change_heading,
      {"UtChangeHeading", "itsut.change_heading", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Set Drive Direction */
    { &hf_set_drive_direction,
      {"SetDriveDirection", "itsut.set_drive_direction", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Change YawRate */
    { &hf_change_yawrate,
      {"ChangeYawRate", "itsut.change_yawrate", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Set Dangerous Goods */
    { &hf_set_dangerous_goods,
      {"SetDangerousGoods", "itsut.set_dangerous_goods", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Set Dangerous Goods Extended */
    { &hf_set_dangerous_goods_ext,
      {"SetDangerousGoodsExtended", "itsut.set_dangerous_goods_ext", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Set Light Bar Siren */
    { &hf_set_light_bar_siren,
      {"SetLightBarSiren", "itsut.hf_set_light_bar_siren", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_set_light_bar_siren_flags,
      {"Flags", "itsut.hf_set_light_bar_siren.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_set_light_bar_siren_flags_LB_bit,
      {"LB bit", "itsut.hf_set_light_bar_siren.flags.lbbit", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
    },
    { &hf_set_light_bar_siren_flags_S_bit,
      {"S bit", "itsut.hf_set_light_bar_siren.flags.sbit", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
    },
    
    /* ITSUT CAM Event Indication */
    { &hf_cam_event_indication,
      {"CAMEventIndication", "itsut.cam_event_indication", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_cam_event_indication_length,
      {"Length", "itsut.cam_event_indication_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_cam_event_indication_payload,
      {"Payload", "itsut.cam_event_indication_payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT SetStationType */
    { &hf_set_station_type,
      {"SetStationType", "itsut.set_station_type", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT SetVehicleRole */
    { &hf_set_vehicle_role,
      {"SetVehicleRole", "itsut.set_vehicle_role", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT SetEmbarkationStatus */
    { &hf_set_embarkation_status,
      {"SetEmbarkationStatus", "itsut.set_embarkation_status", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT SetPtActivation */
    { &hf_set_pt_activation,
      {"SetPtActivation", "itsut.set_pt_activation", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_set_pt_activation_type,
      {"Type", "itsut.set_pt_activation_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_set_pt_activation_length,
      {"Length", "itsut.set_pt_activation_length", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_set_pt_activation_payload,
      {"Payload", "itsut.set_pt_activation_payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT CAM Trigger */
    { &hf_cam_trigger_result,
      {"UtCamTriggerResult", "itsut.cam.trigger.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT DENM Trigger */
    { &hf_denm_trigger,
      {"UtDenmTrigger", "itsut.denm_trigger", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_denm_trigger_result,
      {"UtDenmTriggerResult", "itsut.denm_trigger.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT DENM Event */
    { &hf_denm_event,
      {"UtDenmEvent", "itsut.denm_event", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_denm_event_result,
      {"UtDenmEventResult", "itsut.denm_event.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Terminate DENM Event */
    { &hf_terminate_denm_event,
      {"UtDenmTerminateEvent", "itsut.terminate_denm_event", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_terminate_denm_event_result,
      {"UtDenmTerminateEventResult", "itsut.terminate_denm_event.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Initialise */
    { &hf_hashed_id8,
      {"HashedId8", "itsut.Initialise.hashedid8", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT DENM Trigger */
    { &hf_denm_trigger_flags,
      {"Flags", "itsut.denm_trigger.flags", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_denm_trigger_flags_V_bit,
      {"V bit", "itsut.denm_trigger.flags.vbit", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
    },
    { &hf_denm_trigger_flags_R_bit,
      {"R bit", "itsut.denm_trigger.flags.rbit", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
    },
    { &hf_denm_trigger_flags_K_bit,
      {"K bit", "itsut.denm_trigger.flags.kbit", FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}
    },
    { &hf_denm_trigger_flags_I_bit,
      {"K bit", "itsut.denm_trigger.flags.ibit", FT_UINT8, BASE_HEX, NULL, 0x022, NULL, HFILL}
    },
    
    /* ITSUT DENM Event */
    { &hf_denm_event_flags,
      {"Flags", "itsut.denm_event.flags", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_denm_event_flags_V_bit,
      {"V bit", "itsut.denm_event.flags.vbit", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
    },
    { &hf_denm_event_flags_S_bit,
      {"S bit", "itsut.denm_event.flags.sbit", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
    },
    { &hf_denm_event_flags_D_bit,
      {"D bit", "itsut.denm_event.flags.dbit", FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL}
    },
    { &hf_denm_event_flags_T_bit,
      {"T bit", "itsut.denm_event.flags.tbit", FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
    },
    { &hf_denm_event_flags_C_bit,
      {"C bit", "itsut.denm_event.flags.cbit", FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL}
    },
    { &hf_denm_event_flags_K_bit,
      {"K bit", "itsut.denm_event.flags.kbit", FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}
    },
    { &hf_denm_event_flags_I_bit,
      {"I bit", "itsut.denm_event.flags.ibit", FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL}
    },
    { &hf_denm_event_flags_X_bit,
      {"K bit", "itsut.denm_event.flags.xbit", FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL}
    },

    /* ITSUT DENM Event Indication */
    { &hf_denm_event_indication,
      {"DENMEventIndication", "itsut.denm_event_indication", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_denm_event_indication_length,
      {"Length", "itsut.denm_event_indication_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_denm_event_indication_payload,
      {"Payload", "itsut.denm_event_indication_payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT GN Unicast */
    { &hf_gn_geounicast,
      {"GenerateGeoUnicast", "itsut.gn.geounicast", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT GN Geobroadcast */
    { &hf_gn_geobroadcast,
      {"GenerateGeoBroadcast", "itsut.gn.geobroadcast", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT GN Anycast */
    { &hf_gn_geoanycast,
      {"GenerateGeoAnycast", "itsut.gn.geoanycast", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT GN Shb */
    { &hf_gn_geoshb,
      {"GenerateGeoShb", "itsut.gn.geoshb", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT GN Shb */
    { &hf_gn_geotsb,
      {"GenerateGeoTsb", "itsut.gn.geotsb", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT GN Event Indication */
    { &hf_gn_event_indication,
      {"GNEventIndication", "itsut.gn_event_indication", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_gn_event_indication_length,
      {"Length", "itsut.gn_event_indication.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_event_indication_payload,
      {"Payload", "itsut.gn_event_indication.payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT GN Trigger Result */
    { &hf_gntrigger_result,
      {"UtGnTriggerResult", "itsut.gntrigger_result.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT MAPEM/SPATEM Trigger Event */
    { &hf_mapemspatem_trigger_event,
      {"UtMapemSpatemTrigger ", "itsut.mapemspatem.trigger", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* ITSUT MAPEM/SPATEM Trigger Result */
    { &hf_mapemspatem_trigger_event_result,
      {"UtMapemSpatemTriggerResult", "itsut.mapemspatem.trigger_result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT IVIM Trigger Event */
    { &hf_ivim_trigger_event,
      {"UtIvimTrigger ", "itsut.ivim.trigger", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* ITSUT IVIM Trigger Result */
    { &hf_ivim_trigger_event_result,
      {"UtIvimTriggerResult", "itsut.ivim.trigger_result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT IVIM Update Event */
    { &hf_ivim_update_event,
      {"UtIvimEvent", "itsut.ivim_event", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_ivim_update_event_result,
      {"UtIvimEventResult", "itsut.ivim_event.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT Terminate IVIM Event */
    { &hf_ivim_terminate_event,
      {"UtIvimTerminateEvent", "itsut.terminate_ivim_event", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_ivim_terminate_event_result,
      {"UtIvimTerminateEventResult", "itsut.terminate_ivim_event.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT SREM Trigger Event */
    { &hf_srem_trigger_event,
      {"UtSremTrigger ", "itsut.srem.trigger", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* ITSUT SREM Trigger Result */
    { &hf_srem_trigger_event_result,
      {"UtSremTriggerResult", "itsut.srem.trigger_result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* ITSUT SREM Update Event */
    { &hf_srem_update_event,
      {"UtSremUpdate ", "itsut.srem.update", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* ITSUT SREM Update Result */
    { &hf_srem_update_event_result,
      {"UtSremUpdateResult", "itsut.srem.update_result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    
    /* Parameters */
    { &hf_delta_latitude,
      {"Delta Latitude", "itsut.change_position.delta_latitude", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_delta_longitude,
      {"Delta Longitude", "itsut.change_position.delta_longitude", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_delta_elevation,
      {"Delta Elevation", "itsut.change_position.delta_elevation", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_curvature,
      {"Curvature", "itsut.curvature", FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_speed_variation,
      {"SpeedVariation", "itsut.speed_variation", FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_heading_direction,
      {"Direction", "itsut.change_heading.direction", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_drive_direction,
      {"Direction", "itsut.set_drive_direction.direction", FT_UINT8, BASE_DEC, VALS(itsut_drive_direction_names), 0x0, NULL, HFILL}
    },
    { &hf_yawrate,
      {"Yawrate", "itsut.change_yawrate.yawrate", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_station_type,
      {"StationType", "itsut.set_station_type.station_type", FT_UINT8, BASE_DEC, VALS(itsut_station_type_names), 0x0, NULL, HFILL}
    },
    { &hf_vehicle_role,
      {"VehicleRole", "itsut.set_vehicle_role.vehicle_role", FT_UINT8, BASE_DEC, VALS(itsut_vehicle_role_names), 0x0, NULL, HFILL}
    },
    { &hf_embarkation_status,
      {"EmbarkationStatus", "itsut.set_embarkation_status.embarkation_status", FT_UINT8, BASE_DEC, VALS(itsut_embarkation_status_names), 0x0, NULL, HFILL}
    },
    { &hf_dangerous_goods,
      {"DangerousGoods", "itsut.set_dangerous_goods.dangerous_goods", FT_UINT8, BASE_DEC, VALS(itsut_setdangerousgoods_names), 0x0, NULL, HFILL}
    },
    { &hf_dangerous_goods_ext,
      {"DangerousGoodsExtended", "itsut.set_dangerous_goods_ext.dangerousgoods_ext", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },   
    { &hf_station_id,
      {"StationID", "itsut.denm.station_id", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_sequence_number,
      {"SequenceNumber", "itsut.denm.sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &hf_detection_time,
      {"DetctionTime", "itsut.denm.detection_time", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_validity_duration,
      {"ValidityDuration", "itsut.denm.validity_duration", FT_UINT24, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_repetition_duration,
      {"RepetitionDuration", "itsut.denm.flags.repetition_duration", FT_UINT24, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_info_quality,
      {"InfoQuality", "itsut.denm.flags.info_quality", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_cause,
      {"Cause", "itsut.denm.flags.cause", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_subcause,
      {"SubCause", "itsut.denm.flags.subcause", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_relevance_distance,
      {"RelevanceDistance", "itsut.denm.flags.relevance_distance", FT_UINT8, BASE_DEC, VALS(itsut_relevancedistance_names), 0x00, NULL, HFILL}
    },
    { &hf_relevance_traffic_direction,
      {"RelevanceTrafficDirection", "itsut.denm.flags.relevance_traffic_direction", FT_UINT8, BASE_DEC, VALS(itsut_relevancetrafficdirection_names), 0x00, NULL, HFILL}
    },
    { &hf_transmission_interval,
      {"TransmissionInterval", "itsut.denm.flags.transmission_interval", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_repetition_interval,
      {"RepetitionInterval", "itsut.denm.flags.repetition_interval", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_alacarte_length,
      {"alacarteLength", "itsut.denm.flags.alacarte_length", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_alacarte,
      {"alacarte", "itsut.denm.flags.alacarte", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_gn_address,
      {"GnAddress", "itsut.gn.geoxxxcast.gnaddress", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_shape,
      {"Shape", "itsut.gn.geoxxxcast.shape", FT_UINT8, BASE_DEC, VALS(itsut_shape_names), 0x00, NULL, HFILL}
    },
    { &hf_lifetime,
      {"Lifetime", "itsut.gn.geoxxxcast.lifetime", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_trafficclass,
      {"TrafficClass", "itsut.gn.geoxxxcast.trafficclass", FT_UINT8, BASE_DEC,NULL, 0x00, NULL, HFILL}
    },
    { &hf_reservedgeobroadcast,
      {"Reserved", "itsut.gn.geoxxxcast.reservedgeobroadcast", FT_UINT24, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_latitude,
      {"Latitude", "itsut.gn.geoxxxcast.latitude", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_longitude,
      {"Longitude", "itsut.gn.geoxxxcast.longitude", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_distancea,
      {"DistanceA", "itsut.gn.geoxxxcast.distanceA", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_distanceb,
      {"DistanceB", "itsut.gn.geoxxxcast.distanceB", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_angle,
      {"Angle", "itsut.gn.geoxxxcast.angle", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_payloadlength,
      {"PayloadLength", "itsut.gn.geoxxxcast.payloadlength", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_payload,
      {"Payload", "itsut.gn.geoxxxcast.payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    { &hf_nbhops,
      {"NbHops", "itsut.gn.geotsb.nbhops", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_dstgnaddr,
      {"DstGnAddr", "itsut.gn.geounicast.dstgnaddr", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_event,
      {"Event", "itsut.mapspat.trigger.event", FT_UINT8, BASE_DEC, VALS(itsut_mapemspatem_event_names), 0x00, NULL, HFILL}
    },
    
    /* ITSUT Initialise Result code */
    { &hf_initialize_result_code,
      {"Code", "itsut.Initialise.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },

    /* ITSUT CAM Trigger Result code */
    { &hf_cam_trigger_result_code,
      {"Code", "itsut.cam.trigger.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    
    /* ITSUT Change Position Result code */
    { &hf_change_position_result_code,
      {"Code", "itsut.change_position.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    
    /* ITSUT Change Pseudonym Result code */
    { &hf_change_pseudonym_result_code,
      {"Code", "itsut.change_pseudonym.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    
    /* ITSUT DENM Trigger Result code */
    { &hf_denm_trigger_result_code,
      {"Code", "itsut.denm_trigger.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x0, NULL, HFILL}
    },
    
    /* ITSUT DENM Event Result code */
    { &hf_denm_event_result_code,
      {"Code", "itsut.denm_event.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x0, NULL, HFILL}
    },
    
    /* ITSUT Terminate Denm Event Result code */
    { &hf_denm_terminate_event_result_code,
      {"Code", "itsut.terminate_denm_event.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    
    /* ITSUT GN Trigger Result code */
    { &hf_gntrigger_result_code,
      {"Code", "itsut.gntrigger_result.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },

    /* ITSUT MAPEM/SPATEM Trigger Result code */
    { &hf_mapemspatem_trigger_event_result_code,
      {"Code", "itsut.mapemspatem_result.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    
    /* ITSUT MAPEM Event Indication */
    { &hf_mapem_event_indication,
      {"MAPEventIndication", "itsut.mapem_event_indication", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_mapem_event_indication_length,
      {"Length", "itsut.mapem_event_indication_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_mapem_event_indication_payload,
      {"Payload", "itsut.mapem_event_indication_payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT SPATEM Event Indication */
    { &hf_spatem_event_indication,
      {"UtSpatemEventInd", "itsut.spatem_event_indication", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_spatem_event_indication_length,
      {"Length", "itsut.spatem_event_indication_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_spatem_event_indication_payload,
      {"Payload", "itsut.spatem_event_indication_payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT IVIM Trigger */
    { &hf_ivim_trigger_event_flags,
      {"Flags", "itsut.ivim_trigger.flags", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_ivim_trigger_event_flags_F_bit,
      {"V bit", "itsut.ivim_trigger.flags.fbit", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
    },
    { &hf_ivim_trigger_event_flags_T_bit,
      {"R bit", "itsut.ivim_trigger.flags.tbit", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
    },
    { &hf_ivim_trigger_event_flags_R_bit,
      {"K bit", "itsut.ivim_trigger.flags.rbit", FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL}
    },
    
    /* ITSUT IVIM Event */
    { &hf_ivim_update_event_flags,
      {"Flags", "itsut.ivim_update_event.flags", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    { &hf_ivim_update_event_flags_F_bit,
      {"V bit", "itsut.ivim_update_event.flags.fbit", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
    },
    { &hf_ivim_update_event_flags_T_bit,
      {"S bit", "itsut.ivim_update_event.flags.tbit", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
    },
    { &hf_ivim_update_event_flags_R_bit,
      {"D bit", "itsut.ivim_update_event.flags.rbit", FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL}
    },
    { &hf_ivim_update_event_flags_X_bit,
      {"K bit", "itsut.ivim_update_event.flags.xbit", FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
    },
    
    /* ITSUT Trigger IVIM Event Result code */
    { &hf_ivim_trigger_event_result_code,
      {"Code", "itsut.ivim_trigger_event.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    { &hf_ivim_trigger_event_result_id,
      {"Code", "itsut.ivim_trigger_event.result.id", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    /* ITSUT Update IVIM Event Result code */
    { &hf_ivim_update_event_result_code,
      {"Code", "itsut.ivim_update_event.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    { &hf_ivim_update_event_result_id,
      {"Code", "itsut.ivim_update_event.result.id", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    /* ITSUT Terminate IVIM Event Result code */
    { &hf_ivim_terminate_event_result_code,
      {"Code", "itsut.ivim_terminate_event.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    { &hf_ivim_terminate_event_result_id,
      {"Code", "itsut.ivim_terminate_event.result.id", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT IVIM Event Indication */
    { &hf_ivim_event_indication,
      {"MAPEventIndication", "itsut.ivim_event_indication", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_ivim_event_indication_length,
      {"Length", "itsut.ivim_event_indication_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_ivim_event_indication_payload,
      {"Payload", "itsut.ivim_event_indication_payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    { &hf_ivi_id,
      {"IviIdentifierNumber", "itsut.ivim.id_number", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_validity_from,
      {"ValidFrom", "itsut.ivim.flags.valid_from", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_validity_to,
      {"ValidTo", "itsut.ivim.flags.valid_to", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_repetition_interval_ivim,
      {"RepetitionInterval", "itsut.ivim.flags.repetition_interval", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT SREM/SSEM Trigger Result code */
    { &hf_srem_trigger_event_result_code,
      {"Code", "itsut.sremssem_result.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    
    /* ITSUT SREM Event Indication */
    { &hf_srem_event_indication,
      {"MAPEventIndication", "itsut.srem_event_indication", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_srem_event_indication_length,
      {"Length", "itsut.srem_event_indication_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_srem_event_indication_payload,
      {"Payload", "itsut.srem_event_indication_payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT SSEM Event Indication */
    { &hf_ssem_event_indication,
      {"UtSpatemEventInd", "itsut.ssem_event_indication", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_ssem_event_indication_length,
      {"Length", "itsut.ssem_event_indication_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    { &hf_ssem_event_indication_payload,
      {"Payload", "itsut.ssem_event_indication_payload", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL}
    },
    
    /* ITSUT PKI Trigger Event */
    { &hf_pki_trigger_event_ec,
      {"UtPkiTrigger EC", "itsut.pki.trigger.ec", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &hf_pki_trigger_event_at,
      {"UtPkiTrigger AT", "itsut.pki.trigger.at", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },

    /* ITSUT PKI/SSEM Trigger Result code */
    { &hf_pki_trigger_event_result_code,
      {"Code", "itsut.pki_result.result.code", FT_UINT8, BASE_HEX, VALS(itsut_result_names), 0x00, NULL, HFILL}
    },
    
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_itsut,
    &ett_itsut_command,
    &ett_itsut_flags,
    &ett_itsut_data
  };

  /* Register the protocol name and description */
  proto_itsut = proto_register_protocol (
                       "ETSI ITS Upper Tester protocol",/* name       */
                       "ITSUT",                            /* short name */
                       "itsut"                             /* abbrev     */
                       );
//  new_register_dissector("itsut", dissect_itsut_packet, proto_itsut);
  register_dissector("itsut", dissect_itsut_packet, proto_itsut);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_itsut, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector_table("itsut.command", "ITS UT command", proto_itsut, FT_UINT8, BASE_DEC);
  
  /* Register preferences module */
  itsut_module = prefs_register_protocol(proto_itsut, proto_reg_handoff_itsut);

  /* Register a sample port preference   */
  prefs_register_uint_preference(itsut_module, "port", "ITS Upper Tester UDP port",
                 "ITS Upper Tester UDP port",
                 10, &gPORT_PREF);

}

void
proto_reg_handoff_itsut(void)
{
  dissector_handle_t itsut_handle;
  itsut_handle = create_dissector_handle(dissect_itsut_packet, proto_itsut);
  dissector_add_uint("udp.port", gPORT_PREF, itsut_handle);
}
