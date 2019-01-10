/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cam.c                                                               */
/* asn2wrs.py -p cam -c ./cam.cnf -s ./packet-cam-template -D . -O ../.. ITS-Container.asn CAM.asn */

/* Input file: packet-cam-template.c */

#line 1 "./asn1/cam/packet-cam-template.c"
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


/*--- Included file: packet-cam-hf.c ---*/
#line 1 "./asn1/cam/packet-cam-hf.c"
static int hf_cam_CAM_PDU = -1;                   /* CAM */
static int hf_cam_protocolVersion = -1;           /* INTEGER_0_255 */
static int hf_cam_messageID = -1;                 /* T_messageID */
static int hf_cam_stationID = -1;                 /* StationID */
static int hf_cam_latitude = -1;                  /* Latitude */
static int hf_cam_longitude = -1;                 /* Longitude */
static int hf_cam_positionConfidenceEllipse = -1;  /* PosConfidenceEllipse */
static int hf_cam_altitude = -1;                  /* Altitude */
static int hf_cam_deltaLatitude = -1;             /* DeltaLatitude */
static int hf_cam_deltaLongitude = -1;            /* DeltaLongitude */
static int hf_cam_deltaAltitude = -1;             /* DeltaAltitude */
static int hf_cam_altitudeValue = -1;             /* AltitudeValue */
static int hf_cam_altitudeConfidence = -1;        /* AltitudeConfidence */
static int hf_cam_semiMajorConfidence = -1;       /* SemiAxisLength */
static int hf_cam_semiMinorConfidence = -1;       /* SemiAxisLength */
static int hf_cam_semiMajorOrientation = -1;      /* HeadingValue */
static int hf_cam_pathPosition = -1;              /* DeltaReferencePosition */
static int hf_cam_pathDeltaTime = -1;             /* PathDeltaTime */
static int hf_cam_ptActivationType = -1;          /* PtActivationType */
static int hf_cam_ptActivationData = -1;          /* PtActivationData */
static int hf_cam_causeCode = -1;                 /* CauseCodeType */
static int hf_cam_subCauseCode = -1;              /* SubCauseCodeType */
static int hf_cam_curvatureValue = -1;            /* CurvatureValue */
static int hf_cam_curvatureConfidence = -1;       /* CurvatureConfidence */
static int hf_cam_headingValue = -1;              /* HeadingValue */
static int hf_cam_headingConfidence = -1;         /* HeadingConfidence */
static int hf_cam_innerhardShoulderStatus = -1;   /* HardShoulderStatus */
static int hf_cam_outerhardShoulderStatus = -1;   /* HardShoulderStatus */
static int hf_cam_drivingLaneStatus = -1;         /* DrivingLaneStatus */
static int hf_cam_speedValue = -1;                /* SpeedValue */
static int hf_cam_speedConfidence = -1;           /* SpeedConfidence */
static int hf_cam_longitudinalAccelerationValue = -1;  /* LongitudinalAccelerationValue */
static int hf_cam_longitudinalAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_cam_lateralAccelerationValue = -1;  /* LateralAccelerationValue */
static int hf_cam_lateralAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_cam_verticalAccelerationValue = -1;  /* VerticalAccelerationValue */
static int hf_cam_verticalAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_cam_dangerousGoodsType = -1;        /* DangerousGoodsBasic */
static int hf_cam_unNumber = -1;                  /* INTEGER_0_9999 */
static int hf_cam_elevatedTemperature = -1;       /* BOOLEAN */
static int hf_cam_tunnelsRestricted = -1;         /* BOOLEAN */
static int hf_cam_limitedQuantity = -1;           /* BOOLEAN */
static int hf_cam_emergencyActionCode = -1;       /* IA5String_SIZE_1_24 */
static int hf_cam_phoneNumber = -1;               /* PhoneNumber */
static int hf_cam_companyName = -1;               /* T_companyName */
static int hf_cam_wMInumber = -1;                 /* WMInumber */
static int hf_cam_vDS = -1;                       /* VDS */
static int hf_cam_vehicleLengthValue = -1;        /* VehicleLengthValue */
static int hf_cam_vehicleLengthConfidenceIndication = -1;  /* VehicleLengthConfidenceIndication */
static int hf_cam_PathHistory_item = -1;          /* PathPoint */
static int hf_cam_steeringWheelAngleValue = -1;   /* SteeringWheelAngleValue */
static int hf_cam_steeringWheelAngleConfidence = -1;  /* SteeringWheelAngleConfidence */
static int hf_cam_yawRateValue = -1;              /* YawRateValue */
static int hf_cam_yawRateConfidence = -1;         /* YawRateConfidence */
static int hf_cam_originatingStationID = -1;      /* StationID */
static int hf_cam_sequenceNumber = -1;            /* SequenceNumber */
static int hf_cam_ItineraryPath_item = -1;        /* ReferencePosition */
static int hf_cam_protectedZoneType = -1;         /* ProtectedZoneType */
static int hf_cam_expiryTime = -1;                /* TimestampIts */
static int hf_cam_protectedZoneLatitude = -1;     /* Latitude */
static int hf_cam_protectedZoneLongitude = -1;    /* Longitude */
static int hf_cam_protectedZoneRadius = -1;       /* ProtectedZoneRadius */
static int hf_cam_protectedZoneID = -1;           /* ProtectedZoneID */
static int hf_cam_Traces_item = -1;               /* PathHistory */
static int hf_cam_PositionOfPillars_item = -1;    /* PosPillar */
static int hf_cam_RestrictedTypes_item = -1;      /* StationType */
static int hf_cam_EventHistory_item = -1;         /* EventPoint */
static int hf_cam_eventPosition = -1;             /* DeltaReferencePosition */
static int hf_cam_eventDeltaTime = -1;            /* PathDeltaTime */
static int hf_cam_informationQuality = -1;        /* InformationQuality */
static int hf_cam_ProtectedCommunicationZonesRSU_item = -1;  /* ProtectedCommunicationZone */
static int hf_cam_cenDsrcTollingZoneID = -1;      /* CenDsrcTollingZoneID */
static int hf_cam_DigitalMap_item = -1;           /* ReferencePosition */
static int hf_cam_header = -1;                    /* ItsPduHeader */
static int hf_cam_cam = -1;                       /* CoopAwareness */
static int hf_cam_generationDeltaTime = -1;       /* GenerationDeltaTime */
static int hf_cam_camParameters = -1;             /* CamParameters */
static int hf_cam_basicContainer = -1;            /* BasicContainer */
static int hf_cam_highFrequencyContainer = -1;    /* HighFrequencyContainer */
static int hf_cam_lowFrequencyContainer = -1;     /* LowFrequencyContainer */
static int hf_cam_specialVehicleContainer = -1;   /* SpecialVehicleContainer */
static int hf_cam_basicVehicleContainerHighFrequency = -1;  /* BasicVehicleContainerHighFrequency */
static int hf_cam_rsuContainerHighFrequency = -1;  /* RSUContainerHighFrequency */
static int hf_cam_basicVehicleContainerLowFrequency = -1;  /* BasicVehicleContainerLowFrequency */
static int hf_cam_publicTransportContainer = -1;  /* PublicTransportContainer */
static int hf_cam_specialTransportContainer = -1;  /* SpecialTransportContainer */
static int hf_cam_dangerousGoodsContainer = -1;   /* DangerousGoodsContainer */
static int hf_cam_roadWorksContainerBasic = -1;   /* RoadWorksContainerBasic */
static int hf_cam_rescueContainer = -1;           /* RescueContainer */
static int hf_cam_emergencyContainer = -1;        /* EmergencyContainer */
static int hf_cam_safetyCarContainer = -1;        /* SafetyCarContainer */
static int hf_cam_stationType = -1;               /* StationType */
static int hf_cam_referencePosition = -1;         /* ReferencePosition */
static int hf_cam_heading = -1;                   /* Heading */
static int hf_cam_speed = -1;                     /* Speed */
static int hf_cam_driveDirection = -1;            /* DriveDirection */
static int hf_cam_vehicleLength = -1;             /* VehicleLength */
static int hf_cam_vehicleWidth = -1;              /* VehicleWidth */
static int hf_cam_longitudinalAcceleration = -1;  /* LongitudinalAcceleration */
static int hf_cam_curvature = -1;                 /* Curvature */
static int hf_cam_curvatureCalculationMode = -1;  /* CurvatureCalculationMode */
static int hf_cam_yawRate = -1;                   /* YawRate */
static int hf_cam_accelerationControl = -1;       /* AccelerationControl */
static int hf_cam_lanePosition = -1;              /* LanePosition */
static int hf_cam_steeringWheelAngle = -1;        /* SteeringWheelAngle */
static int hf_cam_lateralAcceleration = -1;       /* LateralAcceleration */
static int hf_cam_verticalAcceleration = -1;      /* VerticalAcceleration */
static int hf_cam_performanceClass = -1;          /* PerformanceClass */
static int hf_cam_cenDsrcTollingZone = -1;        /* CenDsrcTollingZone */
static int hf_cam_vehicleRole = -1;               /* VehicleRole */
static int hf_cam_exteriorLights = -1;            /* ExteriorLights */
static int hf_cam_pathHistory = -1;               /* PathHistory */
static int hf_cam_embarkationStatus = -1;         /* EmbarkationStatus */
static int hf_cam_ptActivation = -1;              /* PtActivation */
static int hf_cam_specialTransportType = -1;      /* SpecialTransportType */
static int hf_cam_lightBarSirenInUse = -1;        /* LightBarSirenInUse */
static int hf_cam_dangerousGoodsBasic = -1;       /* DangerousGoodsBasic */
static int hf_cam_roadworksSubCauseCode = -1;     /* RoadworksSubCauseCode */
static int hf_cam_closedLanes = -1;               /* ClosedLanes */
static int hf_cam_incidentIndication = -1;        /* CauseCode */
static int hf_cam_emergencyPriority = -1;         /* EmergencyPriority */
static int hf_cam_trafficRule = -1;               /* TrafficRule */
static int hf_cam_speedLimit = -1;                /* SpeedLimit */
static int hf_cam_protectedCommunicationZonesRSU = -1;  /* ProtectedCommunicationZonesRSU */
/* named bits */
static int hf_cam_AccelerationControl_brakePedalEngaged = -1;
static int hf_cam_AccelerationControl_gasPedalEngaged = -1;
static int hf_cam_AccelerationControl_emergencyBrakeEngaged = -1;
static int hf_cam_AccelerationControl_collisionWarningEngaged = -1;
static int hf_cam_AccelerationControl_accEngaged = -1;
static int hf_cam_AccelerationControl_cruiseControlEngaged = -1;
static int hf_cam_AccelerationControl_speedLimiterEngaged = -1;
static int hf_cam_ExteriorLights_lowBeamHeadlightsOn = -1;
static int hf_cam_ExteriorLights_highBeamHeadlightsOn = -1;
static int hf_cam_ExteriorLights_leftTurnSignalOn = -1;
static int hf_cam_ExteriorLights_rightTurnSignalOn = -1;
static int hf_cam_ExteriorLights_daytimeRunningLightsOn = -1;
static int hf_cam_ExteriorLights_reverseLightOn = -1;
static int hf_cam_ExteriorLights_fogLightOn = -1;
static int hf_cam_ExteriorLights_parkingLightsOn = -1;
static int hf_cam_SpecialTransportType_heavyLoad = -1;
static int hf_cam_SpecialTransportType_excessWidth = -1;
static int hf_cam_SpecialTransportType_excessLength = -1;
static int hf_cam_SpecialTransportType_excessHeight = -1;
static int hf_cam_LightBarSirenInUse_lightBarActivated = -1;
static int hf_cam_LightBarSirenInUse_sirenActivated = -1;
static int hf_cam_PositionOfOccupants_row1LeftOccupied = -1;
static int hf_cam_PositionOfOccupants_row1RightOccupied = -1;
static int hf_cam_PositionOfOccupants_row1MidOccupied = -1;
static int hf_cam_PositionOfOccupants_row1NotDetectable = -1;
static int hf_cam_PositionOfOccupants_row1NotPresent = -1;
static int hf_cam_PositionOfOccupants_row2LeftOccupied = -1;
static int hf_cam_PositionOfOccupants_row2RightOccupied = -1;
static int hf_cam_PositionOfOccupants_row2MidOccupied = -1;
static int hf_cam_PositionOfOccupants_row2NotDetectable = -1;
static int hf_cam_PositionOfOccupants_row2NotPresent = -1;
static int hf_cam_PositionOfOccupants_row3LeftOccupied = -1;
static int hf_cam_PositionOfOccupants_row3RightOccupied = -1;
static int hf_cam_PositionOfOccupants_row3MidOccupied = -1;
static int hf_cam_PositionOfOccupants_row3NotDetectable = -1;
static int hf_cam_PositionOfOccupants_row3NotPresent = -1;
static int hf_cam_PositionOfOccupants_row4LeftOccupied = -1;
static int hf_cam_PositionOfOccupants_row4RightOccupied = -1;
static int hf_cam_PositionOfOccupants_row4MidOccupied = -1;
static int hf_cam_PositionOfOccupants_row4NotDetectable = -1;
static int hf_cam_PositionOfOccupants_row4NotPresent = -1;
static int hf_cam_EnergyStorageType_hydrogenStorage = -1;
static int hf_cam_EnergyStorageType_electricEnergyStorage = -1;
static int hf_cam_EnergyStorageType_liquidPropaneGas = -1;
static int hf_cam_EnergyStorageType_compressedNaturalGas = -1;
static int hf_cam_EnergyStorageType_diesel = -1;
static int hf_cam_EnergyStorageType_gasoline = -1;
static int hf_cam_EnergyStorageType_ammonia = -1;
static int hf_cam_EmergencyPriority_requestForRightOfWay = -1;
static int hf_cam_EmergencyPriority_requestForFreeCrossingAtATrafficLight = -1;

/*--- End of included file: packet-cam-hf.c ---*/
#line 53 "./asn1/cam/packet-cam-template.c"

/* Initialize the subtree pointers */
static int ett_cam = -1;


/*--- Included file: packet-cam-ett.c ---*/
#line 1 "./asn1/cam/packet-cam-ett.c"
static gint ett_cam_ItsPduHeader = -1;
static gint ett_cam_ReferencePosition = -1;
static gint ett_cam_DeltaReferencePosition = -1;
static gint ett_cam_Altitude = -1;
static gint ett_cam_PosConfidenceEllipse = -1;
static gint ett_cam_PathPoint = -1;
static gint ett_cam_PtActivation = -1;
static gint ett_cam_AccelerationControl = -1;
static gint ett_cam_CauseCode = -1;
static gint ett_cam_Curvature = -1;
static gint ett_cam_Heading = -1;
static gint ett_cam_ClosedLanes = -1;
static gint ett_cam_Speed = -1;
static gint ett_cam_LongitudinalAcceleration = -1;
static gint ett_cam_LateralAcceleration = -1;
static gint ett_cam_VerticalAcceleration = -1;
static gint ett_cam_ExteriorLights = -1;
static gint ett_cam_DangerousGoodsExtended = -1;
static gint ett_cam_SpecialTransportType = -1;
static gint ett_cam_LightBarSirenInUse = -1;
static gint ett_cam_PositionOfOccupants = -1;
static gint ett_cam_VehicleIdentification = -1;
static gint ett_cam_EnergyStorageType = -1;
static gint ett_cam_VehicleLength = -1;
static gint ett_cam_PathHistory = -1;
static gint ett_cam_EmergencyPriority = -1;
static gint ett_cam_SteeringWheelAngle = -1;
static gint ett_cam_YawRate = -1;
static gint ett_cam_ActionID = -1;
static gint ett_cam_ItineraryPath = -1;
static gint ett_cam_ProtectedCommunicationZone = -1;
static gint ett_cam_Traces = -1;
static gint ett_cam_PositionOfPillars = -1;
static gint ett_cam_RestrictedTypes = -1;
static gint ett_cam_EventHistory = -1;
static gint ett_cam_EventPoint = -1;
static gint ett_cam_ProtectedCommunicationZonesRSU = -1;
static gint ett_cam_CenDsrcTollingZone = -1;
static gint ett_cam_DigitalMap = -1;
static gint ett_cam_CAM = -1;
static gint ett_cam_CoopAwareness = -1;
static gint ett_cam_CamParameters = -1;
static gint ett_cam_HighFrequencyContainer = -1;
static gint ett_cam_LowFrequencyContainer = -1;
static gint ett_cam_SpecialVehicleContainer = -1;
static gint ett_cam_BasicContainer = -1;
static gint ett_cam_BasicVehicleContainerHighFrequency = -1;
static gint ett_cam_BasicVehicleContainerLowFrequency = -1;
static gint ett_cam_PublicTransportContainer = -1;
static gint ett_cam_SpecialTransportContainer = -1;
static gint ett_cam_DangerousGoodsContainer = -1;
static gint ett_cam_RoadWorksContainerBasic = -1;
static gint ett_cam_RescueContainer = -1;
static gint ett_cam_EmergencyContainer = -1;
static gint ett_cam_SafetyCarContainer = -1;
static gint ett_cam_RSUContainerHighFrequency = -1;

/*--- End of included file: packet-cam-ett.c ---*/
#line 58 "./asn1/cam/packet-cam-template.c"


/*--- Included file: packet-cam-fn.c ---*/
#line 1 "./asn1/cam/packet-cam-fn.c"


static int
dissect_cam_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_T_messageID_vals[] = {
  {   1, "denm" },
  {   2, "cam" },
  {   3, "poi" },
  {   4, "spatem" },
  {   5, "mapem" },
  {   6, "ivim" },
  {   7, "ev-rsr" },
  {   8, "tistpgtransaction" },
  {   9, "srem" },
  {  10, "ssem" },
  {  11, "evcsn" },
  {  12, "saem" },
  {  13, "rtcmem" },
  { 0, NULL }
};


static int
dissect_cam_T_messageID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_cam_StationID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ItsPduHeader_sequence[] = {
  { &hf_cam_protocolVersion , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_INTEGER_0_255 },
  { &hf_cam_messageID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_T_messageID },
  { &hf_cam_stationID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_StationID },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_ItsPduHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_ItsPduHeader, ItsPduHeader_sequence);

  return offset;
}


static const value_string cam_Latitude_vals[] = {
  {  10, "oneMicrodegreeNorth" },
  { -10, "oneMicrodegreeSouth" },
  { 900000001, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_Latitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -900000000, 900000001U, NULL, FALSE);

  return offset;
}


static const value_string cam_Longitude_vals[] = {
  {  10, "oneMicrodegreeEast" },
  { -10, "oneMicrodegreeWest" },
  { 1800000001, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_Longitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1800000000, 1800000001U, NULL, FALSE);

  return offset;
}


static const value_string cam_SemiAxisLength_vals[] = {
  {   1, "oneCentimeter" },
  { 4094, "outOfRange" },
  { 4095, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_SemiAxisLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const value_string cam_HeadingValue_vals[] = {
  {   0, "wgs84North" },
  { 900, "wgs84East" },
  { 1800, "wgs84South" },
  { 2700, "wgs84West" },
  { 3601, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_HeadingValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3601U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PosConfidenceEllipse_sequence[] = {
  { &hf_cam_semiMajorConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_SemiAxisLength },
  { &hf_cam_semiMinorConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_SemiAxisLength },
  { &hf_cam_semiMajorOrientation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_HeadingValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_PosConfidenceEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_PosConfidenceEllipse, PosConfidenceEllipse_sequence);

  return offset;
}


static const value_string cam_AltitudeValue_vals[] = {
  {   0, "referenceEllipsoidSurface" },
  {   1, "oneCentimeter" },
  { 800001, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_AltitudeValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -100000, 800001U, NULL, FALSE);

  return offset;
}


static const value_string cam_AltitudeConfidence_vals[] = {
  {   0, "alt-000-01" },
  {   1, "alt-000-02" },
  {   2, "alt-000-05" },
  {   3, "alt-000-10" },
  {   4, "alt-000-20" },
  {   5, "alt-000-50" },
  {   6, "alt-001-00" },
  {   7, "alt-002-00" },
  {   8, "alt-005-00" },
  {   9, "alt-010-00" },
  {  10, "alt-020-00" },
  {  11, "alt-050-00" },
  {  12, "alt-100-00" },
  {  13, "alt-200-00" },
  {  14, "outOfRange" },
  {  15, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_AltitudeConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Altitude_sequence[] = {
  { &hf_cam_altitudeValue   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_AltitudeValue },
  { &hf_cam_altitudeConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_AltitudeConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_Altitude, Altitude_sequence);

  return offset;
}


static const per_sequence_t ReferencePosition_sequence[] = {
  { &hf_cam_latitude        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_Latitude },
  { &hf_cam_longitude       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_Longitude },
  { &hf_cam_positionConfidenceEllipse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_PosConfidenceEllipse },
  { &hf_cam_altitude        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_Altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_ReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_ReferencePosition, ReferencePosition_sequence);

  return offset;
}


static const value_string cam_DeltaLatitude_vals[] = {
  {  10, "oneMicrodegreeNorth" },
  { -10, "oneMicrodegreeSouth" },
  { 131072, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_DeltaLatitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131071, 131072U, NULL, FALSE);

  return offset;
}


static const value_string cam_DeltaLongitude_vals[] = {
  {  10, "oneMicrodegreeEast" },
  { -10, "oneMicrodegreeWest" },
  { 131072, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_DeltaLongitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131071, 131072U, NULL, FALSE);

  return offset;
}


static const value_string cam_DeltaAltitude_vals[] = {
  {   1, "oneCentimeterUp" },
  {  -1, "oneCentimeterDown" },
  { 12800, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_DeltaAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -12700, 12800U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DeltaReferencePosition_sequence[] = {
  { &hf_cam_deltaLatitude   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_DeltaLatitude },
  { &hf_cam_deltaLongitude  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_DeltaLongitude },
  { &hf_cam_deltaAltitude   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_DeltaAltitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_DeltaReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_DeltaReferencePosition, DeltaReferencePosition_sequence);

  return offset;
}


static const value_string cam_PathDeltaTime_vals[] = {
  {   1, "tenMilliSecondsInPast" },
  { 0, NULL }
};


static int
dissect_cam_PathDeltaTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PathPoint_sequence[] = {
  { &hf_cam_pathPosition    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_DeltaReferencePosition },
  { &hf_cam_pathDeltaTime   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_PathDeltaTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_PathPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_PathPoint, PathPoint_sequence);

  return offset;
}


static const value_string cam_PtActivationType_vals[] = {
  {   0, "undefinedCodingType" },
  {   1, "r09-16CodingType" },
  {   2, "vdv-50149CodingType" },
  { 0, NULL }
};


static int
dissect_cam_PtActivationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_cam_PtActivationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}


static const per_sequence_t PtActivation_sequence[] = {
  { &hf_cam_ptActivationType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_PtActivationType },
  { &hf_cam_ptActivationData, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_PtActivationData },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_PtActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_PtActivation, PtActivation_sequence);

  return offset;
}



static int
dissect_cam_AccelerationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, NULL);

  return offset;
}


static const value_string cam_CauseCodeType_vals[] = {
  {   0, "reserved" },
  {   1, "trafficCondition" },
  {   2, "accident" },
  {   3, "roadworks" },
  {   5, "impassability" },
  {   6, "adverseWeatherCondition-Adhesion" },
  {   7, "aquaplannning" },
  {   9, "hazardousLocation-SurfaceCondition" },
  {  10, "hazardousLocation-ObstacleOnTheRoad" },
  {  11, "hazardousLocation-AnimalOnTheRoad" },
  {  12, "humanPresenceOnTheRoad" },
  {  14, "wrongWayDriving" },
  {  15, "rescueAndRecoveryWorkInProgress" },
  {  17, "adverseWeatherCondition-ExtremeWeatherCondition" },
  {  18, "adverseWeatherCondition-Visibility" },
  {  19, "adverseWeatherCondition-Precipitation" },
  {  26, "slowVehicle" },
  {  27, "dangerousEndOfQueue" },
  {  91, "vehicleBreakdown" },
  {  92, "postCrash" },
  {  93, "humanProblem" },
  {  94, "stationaryVehicle" },
  {  95, "emergencyVehicleApproaching" },
  {  96, "hazardousLocation-DangerousCurve" },
  {  97, "collisionRisk" },
  {  98, "signalViolation" },
  {  99, "dangerousSituation" },
  { 0, NULL }
};


static int
dissect_cam_CauseCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_cam_SubCauseCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CauseCode_sequence[] = {
  { &hf_cam_causeCode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_CauseCodeType },
  { &hf_cam_subCauseCode    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_SubCauseCodeType },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_CauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_CauseCode, CauseCode_sequence);

  return offset;
}


static const value_string cam_TrafficConditionSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "increasedVolumeOfTraffic" },
  {   2, "trafficJamSlowlyIncreasing" },
  {   3, "trafficJamIncreasing" },
  {   4, "trafficJamStronglyIncreasing" },
  {   5, "trafficStationary" },
  {   6, "trafficJamSlightlyDecreasing" },
  {   7, "trafficJamDecreasing" },
  {   8, "trafficJamStronglyDecreasing" },
  { 0, NULL }
};


static int
dissect_cam_TrafficConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_AccidentSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "multiVehicleAccident" },
  {   2, "heavyAccident" },
  {   3, "accidentInvolvingLorry" },
  {   4, "accidentInvolvingBus" },
  {   5, "accidentInvolvingHazardousMaterials" },
  {   6, "accidentOnOppositeLane" },
  {   7, "unsecuredAccident" },
  {   8, "assistanceRequested" },
  { 0, NULL }
};


static int
dissect_cam_AccidentSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_RoadworksSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "majorRoadworks" },
  {   2, "roadMarkingWork" },
  {   3, "slowMovingRoadMaintenance" },
  {   4, "shortTermStationaryRoadworks" },
  {   5, "streetCleaning" },
  {   6, "winterService" },
  { 0, NULL }
};


static int
dissect_cam_RoadworksSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_HumanPresenceOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "childrenOnRoadway" },
  {   2, "cyclistOnRoadway" },
  {   3, "motorcyclistOnRoadway" },
  { 0, NULL }
};


static int
dissect_cam_HumanPresenceOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_WrongWayDrivingSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "wrongLane" },
  {   2, "wrongDirection" },
  { 0, NULL }
};


static int
dissect_cam_WrongWayDrivingSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_AdverseWeatherCondition_ExtremeWeatherConditionSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "strongWinds" },
  {   2, "damagingHail" },
  {   3, "hurricane" },
  {   4, "thunderstorm" },
  {   5, "tornado" },
  {   6, "blizzard" },
  { 0, NULL }
};


static int
dissect_cam_AdverseWeatherCondition_ExtremeWeatherConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_AdverseWeatherCondition_AdhesionSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "heavyFrostOnRoad" },
  {   2, "fuelOnRoad" },
  {   3, "mudOnRoad" },
  {   4, "snowOnRoad" },
  {   5, "iceOnRoad" },
  {   6, "blackIceOnRoad" },
  {   7, "oilOnRoad" },
  {   8, "looseChippings" },
  {   9, "instantBlackIce" },
  {  10, "roadsSalted" },
  { 0, NULL }
};


static int
dissect_cam_AdverseWeatherCondition_AdhesionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_AdverseWeatherCondition_VisibilitySubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "fog" },
  {   2, "smoke" },
  {   3, "heavySnowfall" },
  {   4, "heavyRain" },
  {   5, "heavyHail" },
  {   6, "lowSunGlare" },
  {   7, "sandstorms" },
  {   8, "swarmsOfInsects" },
  { 0, NULL }
};


static int
dissect_cam_AdverseWeatherCondition_VisibilitySubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_AdverseWeatherCondition_PrecipitationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "heavyRain" },
  {   2, "heavySnowfall" },
  {   3, "softHail" },
  { 0, NULL }
};


static int
dissect_cam_AdverseWeatherCondition_PrecipitationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_SlowVehicleSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "maintenanceVehicle" },
  {   2, "vehiclesSlowingToLookAtAccident" },
  {   3, "abnormalLoad" },
  {   4, "abnormalWideLoad" },
  {   5, "convoy" },
  {   6, "snowplough" },
  {   7, "deicing" },
  {   8, "saltingVehicles" },
  { 0, NULL }
};


static int
dissect_cam_SlowVehicleSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_StationaryVehicleSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "humanProblem" },
  {   2, "vehicleBreakdown" },
  {   3, "postCrash" },
  {   4, "publicTransportStop" },
  {   5, "carryingDangerousGoods" },
  { 0, NULL }
};


static int
dissect_cam_StationaryVehicleSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_HumanProblemSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "glycemiaProblem" },
  {   2, "heartProblem" },
  { 0, NULL }
};


static int
dissect_cam_HumanProblemSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_EmergencyVehicleApproachingSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyVehicleApproaching" },
  {   2, "prioritizedVehicleApproaching" },
  { 0, NULL }
};


static int
dissect_cam_EmergencyVehicleApproachingSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_HazardousLocation_DangerousCurveSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "dangerousLeftTurnCurve" },
  {   2, "dangerousRightTurnCurve" },
  {   3, "multipleCurvesStartingWithUnknownTurningDirection" },
  {   4, "multipleCurvesStartingWithLeftTurn" },
  {   5, "multipleCurvesStartingWithRightTurn" },
  { 0, NULL }
};


static int
dissect_cam_HazardousLocation_DangerousCurveSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_HazardousLocation_SurfaceConditionSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "rockfalls" },
  {   2, "earthquakeDamage" },
  {   3, "sewerCollapse" },
  {   4, "subsidence" },
  {   5, "snowDrifts" },
  {   6, "stormDamage" },
  {   7, "burstPipe" },
  {   8, "volcanoEruption" },
  {   9, "fallingIce" },
  { 0, NULL }
};


static int
dissect_cam_HazardousLocation_SurfaceConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_HazardousLocation_ObstacleOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "shedLoad" },
  {   2, "partsOfVehicles" },
  {   3, "partsOfTyres" },
  {   4, "bigObjects" },
  {   5, "fallenTrees" },
  {   6, "hubCaps" },
  {   7, "waitingVehicles" },
  { 0, NULL }
};


static int
dissect_cam_HazardousLocation_ObstacleOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_HazardousLocation_AnimalOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "wildAnimals" },
  {   2, "herdOfAnimals" },
  {   3, "smallAnimals" },
  {   4, "largeAnimals" },
  { 0, NULL }
};


static int
dissect_cam_HazardousLocation_AnimalOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_CollisionRiskSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "longitudinalCollisionRisk" },
  {   2, "crossingCollisionRisk" },
  {   3, "lateralCollisionRisk" },
  {   4, "vulnerableRoadUser" },
  { 0, NULL }
};


static int
dissect_cam_CollisionRiskSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_SignalViolationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "stopSignViolation" },
  {   2, "trafficLightViolation" },
  {   3, "turningRegulationViolation" },
  { 0, NULL }
};


static int
dissect_cam_SignalViolationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_RescueAndRecoveryWorkInProgressSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyVehicles" },
  {   2, "rescueHelicopterLanding" },
  {   3, "policeActivityOngoing" },
  {   4, "medicalEmergencyOngoing" },
  {   5, "childAbductionInProgress" },
  { 0, NULL }
};


static int
dissect_cam_RescueAndRecoveryWorkInProgressSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_DangerousEndOfQueueSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "suddenEndOfQueue" },
  {   2, "queueOverHill" },
  {   3, "queueAroundBend" },
  {   4, "queueInTunnel" },
  { 0, NULL }
};


static int
dissect_cam_DangerousEndOfQueueSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_DangerousSituationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyElectronicBrakeEngaged" },
  {   2, "preCrashSystemEngaged" },
  {   3, "espEngaged" },
  {   4, "absEngaged" },
  {   5, "aebEngaged" },
  {   6, "brakeWarningEngaged" },
  {   7, "collisionRiskWarningEngaged" },
  { 0, NULL }
};


static int
dissect_cam_DangerousSituationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_VehicleBreakdownSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "lackOfFuel" },
  {   2, "lackOfBatteryPower" },
  {   3, "engineProblem" },
  {   4, "transmissionProblem" },
  {   5, "engineCoolingProblem" },
  {   6, "brakingSystemProblem" },
  {   7, "steeringProblem" },
  {   8, "tyrePuncture" },
  {   9, "tyrePressureProblem" },
  { 0, NULL }
};


static int
dissect_cam_VehicleBreakdownSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_PostCrashSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "accidentWithoutECallTriggered" },
  {   2, "accidentWithECallManuallyTriggered" },
  {   3, "accidentWithECallAutomaticallyTriggered" },
  {   4, "accidentWithECallTriggeredWithoutAccessToCellularNetwork" },
  { 0, NULL }
};


static int
dissect_cam_PostCrashSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_CurvatureValue_vals[] = {
  {   0, "straight" },
  { 1023, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_CurvatureValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1023, 1023U, NULL, FALSE);

  return offset;
}


static const value_string cam_CurvatureConfidence_vals[] = {
  {   0, "onePerMeter-0-00002" },
  {   1, "onePerMeter-0-0001" },
  {   2, "onePerMeter-0-0005" },
  {   3, "onePerMeter-0-002" },
  {   4, "onePerMeter-0-01" },
  {   5, "onePerMeter-0-1" },
  {   6, "outOfRange" },
  {   7, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_CurvatureConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Curvature_sequence[] = {
  { &hf_cam_curvatureValue  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_CurvatureValue },
  { &hf_cam_curvatureConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_CurvatureConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_Curvature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_Curvature, Curvature_sequence);

  return offset;
}


static const value_string cam_CurvatureCalculationMode_vals[] = {
  {   0, "yawRateUsed" },
  {   1, "yawRateNotUsed" },
  {   2, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_CurvatureCalculationMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string cam_HeadingConfidence_vals[] = {
  {   1, "equalOrWithinZeroPointOneDegree" },
  {  10, "equalOrWithinOneDegree" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_HeadingConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Heading_sequence[] = {
  { &hf_cam_headingValue    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_HeadingValue },
  { &hf_cam_headingConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_HeadingConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_Heading(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_Heading, Heading_sequence);

  return offset;
}


static const value_string cam_LanePosition_vals[] = {
  {  -1, "offTheRoad" },
  {   0, "hardShoulder" },
  {   1, "outermostDrivingLane" },
  {   2, "secondLaneFromOutside" },
  { 0, NULL }
};


static int
dissect_cam_LanePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1, 14U, NULL, FALSE);

  return offset;
}


static const value_string cam_HardShoulderStatus_vals[] = {
  {   0, "availableForStopping" },
  {   1, "closed" },
  {   2, "availableForDriving" },
  { 0, NULL }
};


static int
dissect_cam_HardShoulderStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_cam_DrivingLaneStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 13, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t ClosedLanes_sequence[] = {
  { &hf_cam_innerhardShoulderStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_HardShoulderStatus },
  { &hf_cam_outerhardShoulderStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_HardShoulderStatus },
  { &hf_cam_drivingLaneStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_DrivingLaneStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_ClosedLanes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_ClosedLanes, ClosedLanes_sequence);

  return offset;
}


static const value_string cam_PerformanceClass_vals[] = {
  {   0, "unavailable" },
  {   1, "performanceClassA" },
  {   2, "performanceClassB" },
  { 0, NULL }
};


static int
dissect_cam_PerformanceClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string cam_SpeedValue_vals[] = {
  {   0, "standstill" },
  {   1, "oneCentimeterPerSec" },
  { 16383, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_SpeedValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const value_string cam_SpeedConfidence_vals[] = {
  {   1, "equalOrWithinOneCentimeterPerSec" },
  { 100, "equalOrWithinOneMeterPerSec" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_SpeedConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string cam_VehicleMass_vals[] = {
  {   1, "hundredKg" },
  { 1024, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_VehicleMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Speed_sequence[] = {
  { &hf_cam_speedValue      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_SpeedValue },
  { &hf_cam_speedConfidence , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_SpeedConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_Speed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_Speed, Speed_sequence);

  return offset;
}


static const value_string cam_DriveDirection_vals[] = {
  {   0, "forward" },
  {   1, "backward" },
  {   2, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_DriveDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_cam_EmbarkationStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string cam_LongitudinalAccelerationValue_vals[] = {
  {   1, "pointOneMeterPerSecSquaredForward" },
  {  -1, "pointOneMeterPerSecSquaredBackward" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_LongitudinalAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const value_string cam_AccelerationConfidence_vals[] = {
  {   1, "pointOneMeterPerSecSquared" },
  { 101, "outOfRange" },
  { 102, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_AccelerationConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 102U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LongitudinalAcceleration_sequence[] = {
  { &hf_cam_longitudinalAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_LongitudinalAccelerationValue },
  { &hf_cam_longitudinalAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_LongitudinalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_LongitudinalAcceleration, LongitudinalAcceleration_sequence);

  return offset;
}


static const value_string cam_LateralAccelerationValue_vals[] = {
  {  -1, "pointOneMeterPerSecSquaredToRight" },
  {   1, "pointOneMeterPerSecSquaredToLeft" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_LateralAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LateralAcceleration_sequence[] = {
  { &hf_cam_lateralAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_LateralAccelerationValue },
  { &hf_cam_lateralAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_LateralAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_LateralAcceleration, LateralAcceleration_sequence);

  return offset;
}


static const value_string cam_VerticalAccelerationValue_vals[] = {
  {   1, "pointOneMeterPerSecSquaredUp" },
  {  -1, "pointOneMeterPerSecSquaredDown" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_VerticalAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VerticalAcceleration_sequence[] = {
  { &hf_cam_verticalAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_VerticalAccelerationValue },
  { &hf_cam_verticalAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_VerticalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_VerticalAcceleration, VerticalAcceleration_sequence);

  return offset;
}


static const value_string cam_StationType_vals[] = {
  {   0, "unknown" },
  {   1, "pedestrian" },
  {   2, "cyclist" },
  {   3, "moped" },
  {   4, "motorcycle" },
  {   5, "passengerCar" },
  {   6, "bus" },
  {   7, "lightTruck" },
  {   8, "heavyTruck" },
  {   9, "trailer" },
  {  10, "specialVehicles" },
  {  11, "tram" },
  {  15, "roadSideUnit" },
  { 0, NULL }
};


static int
dissect_cam_StationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_cam_ExteriorLights(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}


static const value_string cam_DangerousGoodsBasic_vals[] = {
  {   0, "explosives1" },
  {   1, "explosives2" },
  {   2, "explosives3" },
  {   3, "explosives4" },
  {   4, "explosives5" },
  {   5, "explosives6" },
  {   6, "flammableGases" },
  {   7, "nonFlammableGases" },
  {   8, "toxicGases" },
  {   9, "flammableLiquids" },
  {  10, "flammableSolids" },
  {  11, "substancesLiableToSpontaneousCombustion" },
  {  12, "substancesEmittingFlammableGasesUponContactWithWater" },
  {  13, "oxidizingSubstances" },
  {  14, "organicPeroxides" },
  {  15, "toxicSubstances" },
  {  16, "infectiousSubstances" },
  {  17, "radioactiveMaterial" },
  {  18, "corrosiveSubstances" },
  {  19, "miscellaneousDangerousSubstances" },
  { 0, NULL }
};


static int
dissect_cam_DangerousGoodsBasic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_cam_INTEGER_0_9999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9999U, NULL, FALSE);

  return offset;
}



static int
dissect_cam_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_cam_IA5String_SIZE_1_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 24, FALSE);

  return offset;
}



static int
dissect_cam_PhoneNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          1, 16, FALSE);

  return offset;
}



static int
dissect_cam_T_companyName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 21 "./asn1/cam/cam.cnf"
  offset=dissect_per_octet_string(tvb, offset, actx, tree, hf_index, NO_BOUND, NO_BOUND, FALSE, NULL);


  return offset;
}


static const per_sequence_t DangerousGoodsExtended_sequence[] = {
  { &hf_cam_dangerousGoodsType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_DangerousGoodsBasic },
  { &hf_cam_unNumber        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_INTEGER_0_9999 },
  { &hf_cam_elevatedTemperature, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_BOOLEAN },
  { &hf_cam_tunnelsRestricted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_BOOLEAN },
  { &hf_cam_limitedQuantity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_BOOLEAN },
  { &hf_cam_emergencyActionCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_IA5String_SIZE_1_24 },
  { &hf_cam_phoneNumber     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_PhoneNumber },
  { &hf_cam_companyName     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_T_companyName },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_DangerousGoodsExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_DangerousGoodsExtended, DangerousGoodsExtended_sequence);

  return offset;
}



static int
dissect_cam_SpecialTransportType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_cam_LightBarSirenInUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string cam_HeightLonCarr_vals[] = {
  {   1, "oneCentimeter" },
  { 100, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_HeightLonCarr(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, FALSE);

  return offset;
}


static const value_string cam_PosLonCarr_vals[] = {
  {   1, "oneCentimeter" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_PosLonCarr(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string cam_PosPillar_vals[] = {
  {   1, "tenCentimeters" },
  {  30, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_PosPillar(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 30U, NULL, FALSE);

  return offset;
}


static const value_string cam_PosCentMass_vals[] = {
  {   1, "tenCentimeters" },
  {  63, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_PosCentMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 63U, NULL, FALSE);

  return offset;
}


static const value_string cam_RequestResponseIndication_vals[] = {
  {   0, "request" },
  {   1, "response" },
  { 0, NULL }
};


static int
dissect_cam_RequestResponseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string cam_SpeedLimit_vals[] = {
  {   1, "oneKmPerHour" },
  { 0, NULL }
};


static int
dissect_cam_SpeedLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_StationarySince_vals[] = {
  {   0, "lessThan1Minute" },
  {   1, "lessThan2Minutes" },
  {   2, "lessThan15Minutes" },
  {   3, "equalOrGreater15Minutes" },
  { 0, NULL }
};


static int
dissect_cam_StationarySince(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string cam_Temperature_vals[] = {
  { -60, "equalOrSmallerThanMinus60Deg" },
  {   1, "oneDegreeCelsius" },
  {  67, "equalOrGreaterThan67Deg" },
  { 0, NULL }
};


static int
dissect_cam_Temperature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -60, 67U, NULL, FALSE);

  return offset;
}


static const value_string cam_TrafficRule_vals[] = {
  {   0, "noPassing" },
  {   1, "noPassingForTrucks" },
  {   2, "passToRight" },
  {   3, "passToLeft" },
  { 0, NULL }
};


static int
dissect_cam_TrafficRule(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string cam_WheelBaseVehicle_vals[] = {
  {   1, "tenCentimeters" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_WheelBaseVehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string cam_TurningRadius_vals[] = {
  {   1, "point4Meters" },
  { 255, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_TurningRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string cam_PosFrontAx_vals[] = {
  {   1, "tenCentimeters" },
  {  20, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_PosFrontAx(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 20U, NULL, FALSE);

  return offset;
}



static int
dissect_cam_PositionOfOccupants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, NULL);

  return offset;
}


static const value_string cam_PositioningSolutionType_vals[] = {
  {   0, "noPositioningSolution" },
  {   1, "sGNSS" },
  {   2, "dGNSS" },
  {   3, "sGNSSplusDR" },
  {   4, "dGNSSplusDR" },
  {   5, "dR" },
  { 0, NULL }
};


static int
dissect_cam_PositioningSolutionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_cam_WMInumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 3, FALSE);

  return offset;
}



static int
dissect_cam_VDS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          6, 6, FALSE);

  return offset;
}


static const per_sequence_t VehicleIdentification_sequence[] = {
  { &hf_cam_wMInumber       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_WMInumber },
  { &hf_cam_vDS             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_VDS },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_VehicleIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_VehicleIdentification, VehicleIdentification_sequence);

  return offset;
}



static int
dissect_cam_EnergyStorageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, NULL);

  return offset;
}


static const value_string cam_VehicleLengthValue_vals[] = {
  {   1, "tenCentimeters" },
  { 1022, "outOfRange" },
  { 1023, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_VehicleLengthValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1023U, NULL, FALSE);

  return offset;
}


static const value_string cam_VehicleLengthConfidenceIndication_vals[] = {
  {   0, "noTrailerPresent" },
  {   1, "trailerPresentWithKnownLength" },
  {   2, "trailerPresentWithUnknownLength" },
  {   3, "trailerPresenceIsUnknown" },
  {   4, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_VehicleLengthConfidenceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t VehicleLength_sequence[] = {
  { &hf_cam_vehicleLengthValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_VehicleLengthValue },
  { &hf_cam_vehicleLengthConfidenceIndication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_VehicleLengthConfidenceIndication },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_VehicleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_VehicleLength, VehicleLength_sequence);

  return offset;
}


static const value_string cam_VehicleWidth_vals[] = {
  {   1, "tenCentimeters" },
  {  61, "outOfRange" },
  {  62, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_VehicleWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 62U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PathHistory_sequence_of[1] = {
  { &hf_cam_PathHistory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_PathPoint },
};

static int
dissect_cam_PathHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_cam_PathHistory, PathHistory_sequence_of,
                                                  0, 40, FALSE);

  return offset;
}



static int
dissect_cam_EmergencyPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string cam_InformationQuality_vals[] = {
  {   0, "unavailable" },
  {   1, "lowest" },
  {   7, "highest" },
  { 0, NULL }
};


static int
dissect_cam_InformationQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string cam_RoadType_vals[] = {
  {   0, "urban-NoStructuralSeparationToOppositeLanes" },
  {   1, "urban-WithStructuralSeparationToOppositeLanes" },
  {   2, "nonUrban-NoStructuralSeparationToOppositeLanes" },
  {   3, "nonUrban-WithStructuralSeparationToOppositeLanes" },
  { 0, NULL }
};


static int
dissect_cam_RoadType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string cam_SteeringWheelAngleValue_vals[] = {
  {   0, "straight" },
  {  -1, "onePointFiveDegreesToRight" },
  {   1, "onePointFiveDegreesToLeft" },
  { 512, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_SteeringWheelAngleValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -511, 512U, NULL, FALSE);

  return offset;
}


static const value_string cam_SteeringWheelAngleConfidence_vals[] = {
  {   1, "equalOrWithinOnePointFiveDegree" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_SteeringWheelAngleConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SteeringWheelAngle_sequence[] = {
  { &hf_cam_steeringWheelAngleValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_SteeringWheelAngleValue },
  { &hf_cam_steeringWheelAngleConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_SteeringWheelAngleConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_SteeringWheelAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_SteeringWheelAngle, SteeringWheelAngle_sequence);

  return offset;
}


static const value_string cam_TimestampIts_vals[] = {
  {   0, "utcStartOf2004" },
  {   1, "oneMillisecAfterUTCStartOf2004" },
  { 0, NULL }
};


static int
dissect_cam_TimestampIts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 17 "./asn1/cam/cam.cnf"
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index, 0U, G_GUINT64_CONSTANT(4398046511103), NULL, FALSE);


  return offset;
}


static const value_string cam_VehicleRole_vals[] = {
  {   0, "default" },
  {   1, "publicTransport" },
  {   2, "specialTransport" },
  {   3, "dangerousGoods" },
  {   4, "roadWork" },
  {   5, "rescue" },
  {   6, "emergency" },
  {   7, "safetyCar" },
  {   8, "agriculture" },
  {   9, "commercial" },
  {  10, "military" },
  {  11, "roadOperator" },
  {  12, "taxi" },
  {  13, "reserved1" },
  {  14, "reserved2" },
  {  15, "reserved3" },
  { 0, NULL }
};


static int
dissect_cam_VehicleRole(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string cam_YawRateValue_vals[] = {
  {   0, "straight" },
  {  -1, "degSec-000-01ToRight" },
  {   1, "degSec-000-01ToLeft" },
  { 32767, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_YawRateValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32766, 32767U, NULL, FALSE);

  return offset;
}


static const value_string cam_YawRateConfidence_vals[] = {
  {   0, "degSec-000-01" },
  {   1, "degSec-000-05" },
  {   2, "degSec-000-10" },
  {   3, "degSec-001-00" },
  {   4, "degSec-005-00" },
  {   5, "degSec-010-00" },
  {   6, "degSec-100-00" },
  {   7, "outOfRange" },
  {   8, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_YawRateConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t YawRate_sequence[] = {
  { &hf_cam_yawRateValue    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_YawRateValue },
  { &hf_cam_yawRateConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_YawRateConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_YawRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_YawRate, YawRate_sequence);

  return offset;
}


static const value_string cam_ProtectedZoneType_vals[] = {
  {   0, "permanentCenDsrcTolling" },
  {   1, "temporaryCenDsrcTolling" },
  { 0, NULL }
};


static int
dissect_cam_ProtectedZoneType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}


static const value_string cam_RelevanceDistance_vals[] = {
  {   0, "lessThan50m" },
  {   1, "lessThan100m" },
  {   2, "lessThan200m" },
  {   3, "lessThan500m" },
  {   4, "lessThan1000m" },
  {   5, "lessThan5km" },
  {   6, "lessThan10km" },
  {   7, "over10km" },
  { 0, NULL }
};


static int
dissect_cam_RelevanceDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string cam_RelevanceTrafficDirection_vals[] = {
  {   0, "allTrafficDirections" },
  {   1, "upstreamTraffic" },
  {   2, "downstreamTraffic" },
  {   3, "oppositeTraffic" },
  { 0, NULL }
};


static int
dissect_cam_RelevanceTrafficDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string cam_TransmissionInterval_vals[] = {
  {   1, "oneMilliSecond" },
  { 10000, "tenSeconds" },
  { 0, NULL }
};


static int
dissect_cam_TransmissionInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 10000U, NULL, FALSE);

  return offset;
}


static const value_string cam_ValidityDuration_vals[] = {
  {   0, "timeOfDetection" },
  {   1, "oneSecondAfterDetection" },
  { 0, NULL }
};


static int
dissect_cam_ValidityDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86400U, NULL, FALSE);

  return offset;
}



static int
dissect_cam_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ActionID_sequence[] = {
  { &hf_cam_originatingStationID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_StationID },
  { &hf_cam_sequenceNumber  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_SequenceNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_ActionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_ActionID, ActionID_sequence);

  return offset;
}


static const per_sequence_t ItineraryPath_sequence_of[1] = {
  { &hf_cam_ItineraryPath_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_ReferencePosition },
};

static int
dissect_cam_ItineraryPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_cam_ItineraryPath, ItineraryPath_sequence_of,
                                                  1, 40, FALSE);

  return offset;
}


static const value_string cam_ProtectedZoneRadius_vals[] = {
  {   1, "oneMeter" },
  { 0, NULL }
};


static int
dissect_cam_ProtectedZoneRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_cam_ProtectedZoneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 134217727U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ProtectedCommunicationZone_sequence[] = {
  { &hf_cam_protectedZoneType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_ProtectedZoneType },
  { &hf_cam_expiryTime      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_TimestampIts },
  { &hf_cam_protectedZoneLatitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_Latitude },
  { &hf_cam_protectedZoneLongitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_Longitude },
  { &hf_cam_protectedZoneRadius, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_ProtectedZoneRadius },
  { &hf_cam_protectedZoneID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_ProtectedZoneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_ProtectedCommunicationZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_ProtectedCommunicationZone, ProtectedCommunicationZone_sequence);

  return offset;
}


static const per_sequence_t Traces_sequence_of[1] = {
  { &hf_cam_Traces_item     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_PathHistory },
};

static int
dissect_cam_Traces(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_cam_Traces, Traces_sequence_of,
                                                  1, 7, FALSE);

  return offset;
}


static const value_string cam_NumberOfOccupants_vals[] = {
  {   1, "oneOccupant" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_cam_NumberOfOccupants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PositionOfPillars_sequence_of[1] = {
  { &hf_cam_PositionOfPillars_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_PosPillar },
};

static int
dissect_cam_PositionOfPillars(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_cam_PositionOfPillars, PositionOfPillars_sequence_of,
                                                  1, 3, TRUE);

  return offset;
}


static const per_sequence_t RestrictedTypes_sequence_of[1] = {
  { &hf_cam_RestrictedTypes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_StationType },
};

static int
dissect_cam_RestrictedTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_cam_RestrictedTypes, RestrictedTypes_sequence_of,
                                                  1, 3, TRUE);

  return offset;
}


static const per_sequence_t EventPoint_sequence[] = {
  { &hf_cam_eventPosition   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_DeltaReferencePosition },
  { &hf_cam_eventDeltaTime  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_PathDeltaTime },
  { &hf_cam_informationQuality, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_InformationQuality },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_EventPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_EventPoint, EventPoint_sequence);

  return offset;
}


static const per_sequence_t EventHistory_sequence_of[1] = {
  { &hf_cam_EventHistory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_EventPoint },
};

static int
dissect_cam_EventHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_cam_EventHistory, EventHistory_sequence_of,
                                                  1, 23, FALSE);

  return offset;
}


static const per_sequence_t ProtectedCommunicationZonesRSU_sequence_of[1] = {
  { &hf_cam_ProtectedCommunicationZonesRSU_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_ProtectedCommunicationZone },
};

static int
dissect_cam_ProtectedCommunicationZonesRSU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_cam_ProtectedCommunicationZonesRSU, ProtectedCommunicationZonesRSU_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_cam_CenDsrcTollingZoneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cam_ProtectedZoneID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CenDsrcTollingZone_sequence[] = {
  { &hf_cam_protectedZoneLatitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_Latitude },
  { &hf_cam_protectedZoneLongitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_Longitude },
  { &hf_cam_cenDsrcTollingZoneID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_CenDsrcTollingZoneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_CenDsrcTollingZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_CenDsrcTollingZone, CenDsrcTollingZone_sequence);

  return offset;
}


static const per_sequence_t DigitalMap_sequence_of[1] = {
  { &hf_cam_DigitalMap_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_ReferencePosition },
};

static int
dissect_cam_DigitalMap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_cam_DigitalMap, DigitalMap_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}



static int
dissect_cam_OpeningDaysHours(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_UTF8String(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, FALSE);

  return offset;
}


static const value_string cam_GenerationDeltaTime_vals[] = {
  {   1, "oneMilliSec" },
  { 0, NULL }
};


static int
dissect_cam_GenerationDeltaTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t BasicContainer_sequence[] = {
  { &hf_cam_stationType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_StationType },
  { &hf_cam_referencePosition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_ReferencePosition },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_BasicContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_BasicContainer, BasicContainer_sequence);

  return offset;
}


static const per_sequence_t BasicVehicleContainerHighFrequency_sequence[] = {
  { &hf_cam_heading         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_Heading },
  { &hf_cam_speed           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_Speed },
  { &hf_cam_driveDirection  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_DriveDirection },
  { &hf_cam_vehicleLength   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_VehicleLength },
  { &hf_cam_vehicleWidth    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_VehicleWidth },
  { &hf_cam_longitudinalAcceleration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_LongitudinalAcceleration },
  { &hf_cam_curvature       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_Curvature },
  { &hf_cam_curvatureCalculationMode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_CurvatureCalculationMode },
  { &hf_cam_yawRate         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_YawRate },
  { &hf_cam_accelerationControl, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_AccelerationControl },
  { &hf_cam_lanePosition    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_LanePosition },
  { &hf_cam_steeringWheelAngle, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_SteeringWheelAngle },
  { &hf_cam_lateralAcceleration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_LateralAcceleration },
  { &hf_cam_verticalAcceleration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_VerticalAcceleration },
  { &hf_cam_performanceClass, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_PerformanceClass },
  { &hf_cam_cenDsrcTollingZone, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_CenDsrcTollingZone },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_BasicVehicleContainerHighFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_BasicVehicleContainerHighFrequency, BasicVehicleContainerHighFrequency_sequence);

  return offset;
}


static const per_sequence_t RSUContainerHighFrequency_sequence[] = {
  { &hf_cam_protectedCommunicationZonesRSU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_ProtectedCommunicationZonesRSU },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_RSUContainerHighFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_RSUContainerHighFrequency, RSUContainerHighFrequency_sequence);

  return offset;
}


static const value_string cam_HighFrequencyContainer_vals[] = {
  {   0, "basicVehicleContainerHighFrequency" },
  {   1, "rsuContainerHighFrequency" },
  { 0, NULL }
};

static const per_choice_t HighFrequencyContainer_choice[] = {
  {   0, &hf_cam_basicVehicleContainerHighFrequency, ASN1_EXTENSION_ROOT    , dissect_cam_BasicVehicleContainerHighFrequency },
  {   1, &hf_cam_rsuContainerHighFrequency, ASN1_EXTENSION_ROOT    , dissect_cam_RSUContainerHighFrequency },
  { 0, NULL, 0, NULL }
};

static int
dissect_cam_HighFrequencyContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_cam_HighFrequencyContainer, HighFrequencyContainer_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BasicVehicleContainerLowFrequency_sequence[] = {
  { &hf_cam_vehicleRole     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_VehicleRole },
  { &hf_cam_exteriorLights  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_ExteriorLights },
  { &hf_cam_pathHistory     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_PathHistory },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_BasicVehicleContainerLowFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_BasicVehicleContainerLowFrequency, BasicVehicleContainerLowFrequency_sequence);

  return offset;
}


static const value_string cam_LowFrequencyContainer_vals[] = {
  {   0, "basicVehicleContainerLowFrequency" },
  { 0, NULL }
};

static const per_choice_t LowFrequencyContainer_choice[] = {
  {   0, &hf_cam_basicVehicleContainerLowFrequency, ASN1_EXTENSION_ROOT    , dissect_cam_BasicVehicleContainerLowFrequency },
  { 0, NULL, 0, NULL }
};

static int
dissect_cam_LowFrequencyContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_cam_LowFrequencyContainer, LowFrequencyContainer_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PublicTransportContainer_sequence[] = {
  { &hf_cam_embarkationStatus, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_EmbarkationStatus },
  { &hf_cam_ptActivation    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_PtActivation },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_PublicTransportContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_PublicTransportContainer, PublicTransportContainer_sequence);

  return offset;
}


static const per_sequence_t SpecialTransportContainer_sequence[] = {
  { &hf_cam_specialTransportType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_SpecialTransportType },
  { &hf_cam_lightBarSirenInUse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_LightBarSirenInUse },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_SpecialTransportContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_SpecialTransportContainer, SpecialTransportContainer_sequence);

  return offset;
}


static const per_sequence_t DangerousGoodsContainer_sequence[] = {
  { &hf_cam_dangerousGoodsBasic, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_DangerousGoodsBasic },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_DangerousGoodsContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_DangerousGoodsContainer, DangerousGoodsContainer_sequence);

  return offset;
}


static const per_sequence_t RoadWorksContainerBasic_sequence[] = {
  { &hf_cam_roadworksSubCauseCode, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_RoadworksSubCauseCode },
  { &hf_cam_lightBarSirenInUse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_LightBarSirenInUse },
  { &hf_cam_closedLanes     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_ClosedLanes },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_RoadWorksContainerBasic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_RoadWorksContainerBasic, RoadWorksContainerBasic_sequence);

  return offset;
}


static const per_sequence_t RescueContainer_sequence[] = {
  { &hf_cam_lightBarSirenInUse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_LightBarSirenInUse },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_RescueContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_RescueContainer, RescueContainer_sequence);

  return offset;
}


static const per_sequence_t EmergencyContainer_sequence[] = {
  { &hf_cam_lightBarSirenInUse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_LightBarSirenInUse },
  { &hf_cam_incidentIndication, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_CauseCode },
  { &hf_cam_emergencyPriority, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_EmergencyPriority },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_EmergencyContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_EmergencyContainer, EmergencyContainer_sequence);

  return offset;
}


static const per_sequence_t SafetyCarContainer_sequence[] = {
  { &hf_cam_lightBarSirenInUse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_LightBarSirenInUse },
  { &hf_cam_incidentIndication, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_CauseCode },
  { &hf_cam_trafficRule     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_TrafficRule },
  { &hf_cam_speedLimit      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cam_SpeedLimit },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_SafetyCarContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_SafetyCarContainer, SafetyCarContainer_sequence);

  return offset;
}


static const value_string cam_SpecialVehicleContainer_vals[] = {
  {   0, "publicTransportContainer" },
  {   1, "specialTransportContainer" },
  {   2, "dangerousGoodsContainer" },
  {   3, "roadWorksContainerBasic" },
  {   4, "rescueContainer" },
  {   5, "emergencyContainer" },
  {   6, "safetyCarContainer" },
  { 0, NULL }
};

static const per_choice_t SpecialVehicleContainer_choice[] = {
  {   0, &hf_cam_publicTransportContainer, ASN1_EXTENSION_ROOT    , dissect_cam_PublicTransportContainer },
  {   1, &hf_cam_specialTransportContainer, ASN1_EXTENSION_ROOT    , dissect_cam_SpecialTransportContainer },
  {   2, &hf_cam_dangerousGoodsContainer, ASN1_EXTENSION_ROOT    , dissect_cam_DangerousGoodsContainer },
  {   3, &hf_cam_roadWorksContainerBasic, ASN1_EXTENSION_ROOT    , dissect_cam_RoadWorksContainerBasic },
  {   4, &hf_cam_rescueContainer , ASN1_EXTENSION_ROOT    , dissect_cam_RescueContainer },
  {   5, &hf_cam_emergencyContainer, ASN1_EXTENSION_ROOT    , dissect_cam_EmergencyContainer },
  {   6, &hf_cam_safetyCarContainer, ASN1_EXTENSION_ROOT    , dissect_cam_SafetyCarContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_cam_SpecialVehicleContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_cam_SpecialVehicleContainer, SpecialVehicleContainer_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CamParameters_sequence[] = {
  { &hf_cam_basicContainer  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_BasicContainer },
  { &hf_cam_highFrequencyContainer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cam_HighFrequencyContainer },
  { &hf_cam_lowFrequencyContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_LowFrequencyContainer },
  { &hf_cam_specialVehicleContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cam_SpecialVehicleContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_CamParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_CamParameters, CamParameters_sequence);

  return offset;
}


static const per_sequence_t CoopAwareness_sequence[] = {
  { &hf_cam_generationDeltaTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_GenerationDeltaTime },
  { &hf_cam_camParameters   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_CamParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_CoopAwareness(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_CoopAwareness, CoopAwareness_sequence);

  return offset;
}


static const per_sequence_t CAM_sequence[] = {
  { &hf_cam_header          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_ItsPduHeader },
  { &hf_cam_cam             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cam_CoopAwareness },
  { NULL, 0, 0, NULL }
};

static int
dissect_cam_CAM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_cam_CAM, CAM_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_CAM_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_cam_CAM(tvb, offset, &asn1_ctx, tree, hf_cam_CAM_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-cam-fn.c ---*/
#line 60 "./asn1/cam/packet-cam-template.c"

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


/*--- Included file: packet-cam-hfarr.c ---*/
#line 1 "./asn1/cam/packet-cam-hfarr.c"
    { &hf_cam_CAM_PDU,
      { "CAM", "cam.CAM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_protocolVersion,
      { "protocolVersion", "cam.protocolVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_cam_messageID,
      { "messageID", "cam.messageID",
        FT_UINT32, BASE_DEC, VALS(cam_T_messageID_vals), 0,
        NULL, HFILL }},
    { &hf_cam_stationID,
      { "stationID", "cam.stationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_latitude,
      { "latitude", "cam.latitude",
        FT_INT32, BASE_DEC, VALS(cam_Latitude_vals), 0,
        NULL, HFILL }},
    { &hf_cam_longitude,
      { "longitude", "cam.longitude",
        FT_INT32, BASE_DEC, VALS(cam_Longitude_vals), 0,
        NULL, HFILL }},
    { &hf_cam_positionConfidenceEllipse,
      { "positionConfidenceEllipse", "cam.positionConfidenceEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosConfidenceEllipse", HFILL }},
    { &hf_cam_altitude,
      { "altitude", "cam.altitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_deltaLatitude,
      { "deltaLatitude", "cam.deltaLatitude",
        FT_INT32, BASE_DEC, VALS(cam_DeltaLatitude_vals), 0,
        NULL, HFILL }},
    { &hf_cam_deltaLongitude,
      { "deltaLongitude", "cam.deltaLongitude",
        FT_INT32, BASE_DEC, VALS(cam_DeltaLongitude_vals), 0,
        NULL, HFILL }},
    { &hf_cam_deltaAltitude,
      { "deltaAltitude", "cam.deltaAltitude",
        FT_INT32, BASE_DEC, VALS(cam_DeltaAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_cam_altitudeValue,
      { "altitudeValue", "cam.altitudeValue",
        FT_INT32, BASE_DEC, VALS(cam_AltitudeValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_altitudeConfidence,
      { "altitudeConfidence", "cam.altitudeConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_AltitudeConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_cam_semiMajorConfidence,
      { "semiMajorConfidence", "cam.semiMajorConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_SemiAxisLength_vals), 0,
        "SemiAxisLength", HFILL }},
    { &hf_cam_semiMinorConfidence,
      { "semiMinorConfidence", "cam.semiMinorConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_SemiAxisLength_vals), 0,
        "SemiAxisLength", HFILL }},
    { &hf_cam_semiMajorOrientation,
      { "semiMajorOrientation", "cam.semiMajorOrientation",
        FT_UINT32, BASE_DEC, VALS(cam_HeadingValue_vals), 0,
        "HeadingValue", HFILL }},
    { &hf_cam_pathPosition,
      { "pathPosition", "cam.pathPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_cam_pathDeltaTime,
      { "pathDeltaTime", "cam.pathDeltaTime",
        FT_UINT32, BASE_DEC, VALS(cam_PathDeltaTime_vals), 0,
        NULL, HFILL }},
    { &hf_cam_ptActivationType,
      { "ptActivationType", "cam.ptActivationType",
        FT_UINT32, BASE_DEC, VALS(cam_PtActivationType_vals), 0,
        NULL, HFILL }},
    { &hf_cam_ptActivationData,
      { "ptActivationData", "cam.ptActivationData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_causeCode,
      { "causeCode", "cam.causeCode",
        FT_UINT32, BASE_DEC, VALS(cam_CauseCodeType_vals), 0,
        "CauseCodeType", HFILL }},
    { &hf_cam_subCauseCode,
      { "subCauseCode", "cam.subCauseCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubCauseCodeType", HFILL }},
    { &hf_cam_curvatureValue,
      { "curvatureValue", "cam.curvatureValue",
        FT_INT32, BASE_DEC, VALS(cam_CurvatureValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_curvatureConfidence,
      { "curvatureConfidence", "cam.curvatureConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_CurvatureConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_cam_headingValue,
      { "headingValue", "cam.headingValue",
        FT_UINT32, BASE_DEC, VALS(cam_HeadingValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_headingConfidence,
      { "headingConfidence", "cam.headingConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_HeadingConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_cam_innerhardShoulderStatus,
      { "innerhardShoulderStatus", "cam.innerhardShoulderStatus",
        FT_UINT32, BASE_DEC, VALS(cam_HardShoulderStatus_vals), 0,
        "HardShoulderStatus", HFILL }},
    { &hf_cam_outerhardShoulderStatus,
      { "outerhardShoulderStatus", "cam.outerhardShoulderStatus",
        FT_UINT32, BASE_DEC, VALS(cam_HardShoulderStatus_vals), 0,
        "HardShoulderStatus", HFILL }},
    { &hf_cam_drivingLaneStatus,
      { "drivingLaneStatus", "cam.drivingLaneStatus",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_speedValue,
      { "speedValue", "cam.speedValue",
        FT_UINT32, BASE_DEC, VALS(cam_SpeedValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_speedConfidence,
      { "speedConfidence", "cam.speedConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_SpeedConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_cam_longitudinalAccelerationValue,
      { "longitudinalAccelerationValue", "cam.longitudinalAccelerationValue",
        FT_INT32, BASE_DEC, VALS(cam_LongitudinalAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_longitudinalAccelerationConfidence,
      { "longitudinalAccelerationConfidence", "cam.longitudinalAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_cam_lateralAccelerationValue,
      { "lateralAccelerationValue", "cam.lateralAccelerationValue",
        FT_INT32, BASE_DEC, VALS(cam_LateralAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_lateralAccelerationConfidence,
      { "lateralAccelerationConfidence", "cam.lateralAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_cam_verticalAccelerationValue,
      { "verticalAccelerationValue", "cam.verticalAccelerationValue",
        FT_INT32, BASE_DEC, VALS(cam_VerticalAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_verticalAccelerationConfidence,
      { "verticalAccelerationConfidence", "cam.verticalAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_cam_dangerousGoodsType,
      { "dangerousGoodsType", "cam.dangerousGoodsType",
        FT_UINT32, BASE_DEC, VALS(cam_DangerousGoodsBasic_vals), 0,
        "DangerousGoodsBasic", HFILL }},
    { &hf_cam_unNumber,
      { "unNumber", "cam.unNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9999", HFILL }},
    { &hf_cam_elevatedTemperature,
      { "elevatedTemperature", "cam.elevatedTemperature",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_cam_tunnelsRestricted,
      { "tunnelsRestricted", "cam.tunnelsRestricted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_cam_limitedQuantity,
      { "limitedQuantity", "cam.limitedQuantity",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_cam_emergencyActionCode,
      { "emergencyActionCode", "cam.emergencyActionCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_24", HFILL }},
    { &hf_cam_phoneNumber,
      { "phoneNumber", "cam.phoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_companyName,
      { "companyName", "cam.companyName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_wMInumber,
      { "wMInumber", "cam.wMInumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_vDS,
      { "vDS", "cam.vDS",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_vehicleLengthValue,
      { "vehicleLengthValue", "cam.vehicleLengthValue",
        FT_UINT32, BASE_DEC, VALS(cam_VehicleLengthValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_vehicleLengthConfidenceIndication,
      { "vehicleLengthConfidenceIndication", "cam.vehicleLengthConfidenceIndication",
        FT_UINT32, BASE_DEC, VALS(cam_VehicleLengthConfidenceIndication_vals), 0,
        NULL, HFILL }},
    { &hf_cam_PathHistory_item,
      { "PathPoint", "cam.PathPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_steeringWheelAngleValue,
      { "steeringWheelAngleValue", "cam.steeringWheelAngleValue",
        FT_INT32, BASE_DEC, VALS(cam_SteeringWheelAngleValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_steeringWheelAngleConfidence,
      { "steeringWheelAngleConfidence", "cam.steeringWheelAngleConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_SteeringWheelAngleConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_cam_yawRateValue,
      { "yawRateValue", "cam.yawRateValue",
        FT_INT32, BASE_DEC, VALS(cam_YawRateValue_vals), 0,
        NULL, HFILL }},
    { &hf_cam_yawRateConfidence,
      { "yawRateConfidence", "cam.yawRateConfidence",
        FT_UINT32, BASE_DEC, VALS(cam_YawRateConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_cam_originatingStationID,
      { "originatingStationID", "cam.originatingStationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StationID", HFILL }},
    { &hf_cam_sequenceNumber,
      { "sequenceNumber", "cam.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_ItineraryPath_item,
      { "ReferencePosition", "cam.ReferencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_protectedZoneType,
      { "protectedZoneType", "cam.protectedZoneType",
        FT_UINT32, BASE_DEC, VALS(cam_ProtectedZoneType_vals), 0,
        NULL, HFILL }},
    { &hf_cam_expiryTime,
      { "expiryTime", "cam.expiryTime",
        FT_UINT64, BASE_DEC, VALS(cam_TimestampIts_vals), 0,
        "TimestampIts", HFILL }},
    { &hf_cam_protectedZoneLatitude,
      { "protectedZoneLatitude", "cam.protectedZoneLatitude",
        FT_INT32, BASE_DEC, VALS(cam_Latitude_vals), 0,
        "Latitude", HFILL }},
    { &hf_cam_protectedZoneLongitude,
      { "protectedZoneLongitude", "cam.protectedZoneLongitude",
        FT_INT32, BASE_DEC, VALS(cam_Longitude_vals), 0,
        "Longitude", HFILL }},
    { &hf_cam_protectedZoneRadius,
      { "protectedZoneRadius", "cam.protectedZoneRadius",
        FT_UINT32, BASE_DEC, VALS(cam_ProtectedZoneRadius_vals), 0,
        NULL, HFILL }},
    { &hf_cam_protectedZoneID,
      { "protectedZoneID", "cam.protectedZoneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_Traces_item,
      { "PathHistory", "cam.PathHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_PositionOfPillars_item,
      { "PosPillar", "cam.PosPillar",
        FT_UINT32, BASE_DEC, VALS(cam_PosPillar_vals), 0,
        NULL, HFILL }},
    { &hf_cam_RestrictedTypes_item,
      { "StationType", "cam.StationType",
        FT_UINT32, BASE_DEC, VALS(cam_StationType_vals), 0,
        NULL, HFILL }},
    { &hf_cam_EventHistory_item,
      { "EventPoint", "cam.EventPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_eventPosition,
      { "eventPosition", "cam.eventPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_cam_eventDeltaTime,
      { "eventDeltaTime", "cam.eventDeltaTime",
        FT_UINT32, BASE_DEC, VALS(cam_PathDeltaTime_vals), 0,
        "PathDeltaTime", HFILL }},
    { &hf_cam_informationQuality,
      { "informationQuality", "cam.informationQuality",
        FT_UINT32, BASE_DEC, VALS(cam_InformationQuality_vals), 0,
        NULL, HFILL }},
    { &hf_cam_ProtectedCommunicationZonesRSU_item,
      { "ProtectedCommunicationZone", "cam.ProtectedCommunicationZone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_cenDsrcTollingZoneID,
      { "cenDsrcTollingZoneID", "cam.cenDsrcTollingZoneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_DigitalMap_item,
      { "ReferencePosition", "cam.ReferencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_header,
      { "header", "cam.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ItsPduHeader", HFILL }},
    { &hf_cam_cam,
      { "cam", "cam.cam_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CoopAwareness", HFILL }},
    { &hf_cam_generationDeltaTime,
      { "generationDeltaTime", "cam.generationDeltaTime",
        FT_UINT32, BASE_DEC, VALS(cam_GenerationDeltaTime_vals), 0,
        NULL, HFILL }},
    { &hf_cam_camParameters,
      { "camParameters", "cam.camParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_basicContainer,
      { "basicContainer", "cam.basicContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_highFrequencyContainer,
      { "highFrequencyContainer", "cam.highFrequencyContainer",
        FT_UINT32, BASE_DEC, VALS(cam_HighFrequencyContainer_vals), 0,
        NULL, HFILL }},
    { &hf_cam_lowFrequencyContainer,
      { "lowFrequencyContainer", "cam.lowFrequencyContainer",
        FT_UINT32, BASE_DEC, VALS(cam_LowFrequencyContainer_vals), 0,
        NULL, HFILL }},
    { &hf_cam_specialVehicleContainer,
      { "specialVehicleContainer", "cam.specialVehicleContainer",
        FT_UINT32, BASE_DEC, VALS(cam_SpecialVehicleContainer_vals), 0,
        NULL, HFILL }},
    { &hf_cam_basicVehicleContainerHighFrequency,
      { "basicVehicleContainerHighFrequency", "cam.basicVehicleContainerHighFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_rsuContainerHighFrequency,
      { "rsuContainerHighFrequency", "cam.rsuContainerHighFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_basicVehicleContainerLowFrequency,
      { "basicVehicleContainerLowFrequency", "cam.basicVehicleContainerLowFrequency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_publicTransportContainer,
      { "publicTransportContainer", "cam.publicTransportContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_specialTransportContainer,
      { "specialTransportContainer", "cam.specialTransportContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_dangerousGoodsContainer,
      { "dangerousGoodsContainer", "cam.dangerousGoodsContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_roadWorksContainerBasic,
      { "roadWorksContainerBasic", "cam.roadWorksContainerBasic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_rescueContainer,
      { "rescueContainer", "cam.rescueContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_emergencyContainer,
      { "emergencyContainer", "cam.emergencyContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_safetyCarContainer,
      { "safetyCarContainer", "cam.safetyCarContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_stationType,
      { "stationType", "cam.stationType",
        FT_UINT32, BASE_DEC, VALS(cam_StationType_vals), 0,
        NULL, HFILL }},
    { &hf_cam_referencePosition,
      { "referencePosition", "cam.referencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_heading,
      { "heading", "cam.heading_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_speed,
      { "speed", "cam.speed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_driveDirection,
      { "driveDirection", "cam.driveDirection",
        FT_UINT32, BASE_DEC, VALS(cam_DriveDirection_vals), 0,
        NULL, HFILL }},
    { &hf_cam_vehicleLength,
      { "vehicleLength", "cam.vehicleLength_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_vehicleWidth,
      { "vehicleWidth", "cam.vehicleWidth",
        FT_UINT32, BASE_DEC, VALS(cam_VehicleWidth_vals), 0,
        NULL, HFILL }},
    { &hf_cam_longitudinalAcceleration,
      { "longitudinalAcceleration", "cam.longitudinalAcceleration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_curvature,
      { "curvature", "cam.curvature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_curvatureCalculationMode,
      { "curvatureCalculationMode", "cam.curvatureCalculationMode",
        FT_UINT32, BASE_DEC, VALS(cam_CurvatureCalculationMode_vals), 0,
        NULL, HFILL }},
    { &hf_cam_yawRate,
      { "yawRate", "cam.yawRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_accelerationControl,
      { "accelerationControl", "cam.accelerationControl",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_lanePosition,
      { "lanePosition", "cam.lanePosition",
        FT_INT32, BASE_DEC, VALS(cam_LanePosition_vals), 0,
        NULL, HFILL }},
    { &hf_cam_steeringWheelAngle,
      { "steeringWheelAngle", "cam.steeringWheelAngle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_lateralAcceleration,
      { "lateralAcceleration", "cam.lateralAcceleration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_verticalAcceleration,
      { "verticalAcceleration", "cam.verticalAcceleration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_performanceClass,
      { "performanceClass", "cam.performanceClass",
        FT_UINT32, BASE_DEC, VALS(cam_PerformanceClass_vals), 0,
        NULL, HFILL }},
    { &hf_cam_cenDsrcTollingZone,
      { "cenDsrcTollingZone", "cam.cenDsrcTollingZone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_vehicleRole,
      { "vehicleRole", "cam.vehicleRole",
        FT_UINT32, BASE_DEC, VALS(cam_VehicleRole_vals), 0,
        NULL, HFILL }},
    { &hf_cam_exteriorLights,
      { "exteriorLights", "cam.exteriorLights",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_pathHistory,
      { "pathHistory", "cam.pathHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_embarkationStatus,
      { "embarkationStatus", "cam.embarkationStatus",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_ptActivation,
      { "ptActivation", "cam.ptActivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_specialTransportType,
      { "specialTransportType", "cam.specialTransportType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_lightBarSirenInUse,
      { "lightBarSirenInUse", "cam.lightBarSirenInUse",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_dangerousGoodsBasic,
      { "dangerousGoodsBasic", "cam.dangerousGoodsBasic",
        FT_UINT32, BASE_DEC, VALS(cam_DangerousGoodsBasic_vals), 0,
        NULL, HFILL }},
    { &hf_cam_roadworksSubCauseCode,
      { "roadworksSubCauseCode", "cam.roadworksSubCauseCode",
        FT_UINT32, BASE_DEC, VALS(cam_RoadworksSubCauseCode_vals), 0,
        NULL, HFILL }},
    { &hf_cam_closedLanes,
      { "closedLanes", "cam.closedLanes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_incidentIndication,
      { "incidentIndication", "cam.incidentIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CauseCode", HFILL }},
    { &hf_cam_emergencyPriority,
      { "emergencyPriority", "cam.emergencyPriority",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_trafficRule,
      { "trafficRule", "cam.trafficRule",
        FT_UINT32, BASE_DEC, VALS(cam_TrafficRule_vals), 0,
        NULL, HFILL }},
    { &hf_cam_speedLimit,
      { "speedLimit", "cam.speedLimit",
        FT_UINT32, BASE_DEC, VALS(cam_SpeedLimit_vals), 0,
        NULL, HFILL }},
    { &hf_cam_protectedCommunicationZonesRSU,
      { "protectedCommunicationZonesRSU", "cam.protectedCommunicationZonesRSU",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cam_AccelerationControl_brakePedalEngaged,
      { "brakePedalEngaged", "cam.brakePedalEngaged",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_AccelerationControl_gasPedalEngaged,
      { "gasPedalEngaged", "cam.gasPedalEngaged",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cam_AccelerationControl_emergencyBrakeEngaged,
      { "emergencyBrakeEngaged", "cam.emergencyBrakeEngaged",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cam_AccelerationControl_collisionWarningEngaged,
      { "collisionWarningEngaged", "cam.collisionWarningEngaged",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cam_AccelerationControl_accEngaged,
      { "accEngaged", "cam.accEngaged",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cam_AccelerationControl_cruiseControlEngaged,
      { "cruiseControlEngaged", "cam.cruiseControlEngaged",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cam_AccelerationControl_speedLimiterEngaged,
      { "speedLimiterEngaged", "cam.speedLimiterEngaged",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cam_ExteriorLights_lowBeamHeadlightsOn,
      { "lowBeamHeadlightsOn", "cam.lowBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_ExteriorLights_highBeamHeadlightsOn,
      { "highBeamHeadlightsOn", "cam.highBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cam_ExteriorLights_leftTurnSignalOn,
      { "leftTurnSignalOn", "cam.leftTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cam_ExteriorLights_rightTurnSignalOn,
      { "rightTurnSignalOn", "cam.rightTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cam_ExteriorLights_daytimeRunningLightsOn,
      { "daytimeRunningLightsOn", "cam.daytimeRunningLightsOn",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cam_ExteriorLights_reverseLightOn,
      { "reverseLightOn", "cam.reverseLightOn",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cam_ExteriorLights_fogLightOn,
      { "fogLightOn", "cam.fogLightOn",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cam_ExteriorLights_parkingLightsOn,
      { "parkingLightsOn", "cam.parkingLightsOn",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cam_SpecialTransportType_heavyLoad,
      { "heavyLoad", "cam.heavyLoad",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_SpecialTransportType_excessWidth,
      { "excessWidth", "cam.excessWidth",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cam_SpecialTransportType_excessLength,
      { "excessLength", "cam.excessLength",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cam_SpecialTransportType_excessHeight,
      { "excessHeight", "cam.excessHeight",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cam_LightBarSirenInUse_lightBarActivated,
      { "lightBarActivated", "cam.lightBarActivated",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_LightBarSirenInUse_sirenActivated,
      { "sirenActivated", "cam.sirenActivated",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row1LeftOccupied,
      { "row1LeftOccupied", "cam.row1LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row1RightOccupied,
      { "row1RightOccupied", "cam.row1RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row1MidOccupied,
      { "row1MidOccupied", "cam.row1MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row1NotDetectable,
      { "row1NotDetectable", "cam.row1NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row1NotPresent,
      { "row1NotPresent", "cam.row1NotPresent",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row2LeftOccupied,
      { "row2LeftOccupied", "cam.row2LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row2RightOccupied,
      { "row2RightOccupied", "cam.row2RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row2MidOccupied,
      { "row2MidOccupied", "cam.row2MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row2NotDetectable,
      { "row2NotDetectable", "cam.row2NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row2NotPresent,
      { "row2NotPresent", "cam.row2NotPresent",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row3LeftOccupied,
      { "row3LeftOccupied", "cam.row3LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row3RightOccupied,
      { "row3RightOccupied", "cam.row3RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row3MidOccupied,
      { "row3MidOccupied", "cam.row3MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row3NotDetectable,
      { "row3NotDetectable", "cam.row3NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row3NotPresent,
      { "row3NotPresent", "cam.row3NotPresent",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row4LeftOccupied,
      { "row4LeftOccupied", "cam.row4LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row4RightOccupied,
      { "row4RightOccupied", "cam.row4RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row4MidOccupied,
      { "row4MidOccupied", "cam.row4MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row4NotDetectable,
      { "row4NotDetectable", "cam.row4NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cam_PositionOfOccupants_row4NotPresent,
      { "row4NotPresent", "cam.row4NotPresent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cam_EnergyStorageType_hydrogenStorage,
      { "hydrogenStorage", "cam.hydrogenStorage",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_EnergyStorageType_electricEnergyStorage,
      { "electricEnergyStorage", "cam.electricEnergyStorage",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cam_EnergyStorageType_liquidPropaneGas,
      { "liquidPropaneGas", "cam.liquidPropaneGas",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cam_EnergyStorageType_compressedNaturalGas,
      { "compressedNaturalGas", "cam.compressedNaturalGas",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cam_EnergyStorageType_diesel,
      { "diesel", "cam.diesel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cam_EnergyStorageType_gasoline,
      { "gasoline", "cam.gasoline",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cam_EnergyStorageType_ammonia,
      { "ammonia", "cam.ammonia",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cam_EmergencyPriority_requestForRightOfWay,
      { "requestForRightOfWay", "cam.requestForRightOfWay",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cam_EmergencyPriority_requestForFreeCrossingAtATrafficLight,
      { "requestForFreeCrossingAtATrafficLight", "cam.requestForFreeCrossingAtATrafficLight",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

/*--- End of included file: packet-cam-hfarr.c ---*/
#line 101 "./asn1/cam/packet-cam-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_cam,

/*--- Included file: packet-cam-ettarr.c ---*/
#line 1 "./asn1/cam/packet-cam-ettarr.c"
    &ett_cam_ItsPduHeader,
    &ett_cam_ReferencePosition,
    &ett_cam_DeltaReferencePosition,
    &ett_cam_Altitude,
    &ett_cam_PosConfidenceEllipse,
    &ett_cam_PathPoint,
    &ett_cam_PtActivation,
    &ett_cam_AccelerationControl,
    &ett_cam_CauseCode,
    &ett_cam_Curvature,
    &ett_cam_Heading,
    &ett_cam_ClosedLanes,
    &ett_cam_Speed,
    &ett_cam_LongitudinalAcceleration,
    &ett_cam_LateralAcceleration,
    &ett_cam_VerticalAcceleration,
    &ett_cam_ExteriorLights,
    &ett_cam_DangerousGoodsExtended,
    &ett_cam_SpecialTransportType,
    &ett_cam_LightBarSirenInUse,
    &ett_cam_PositionOfOccupants,
    &ett_cam_VehicleIdentification,
    &ett_cam_EnergyStorageType,
    &ett_cam_VehicleLength,
    &ett_cam_PathHistory,
    &ett_cam_EmergencyPriority,
    &ett_cam_SteeringWheelAngle,
    &ett_cam_YawRate,
    &ett_cam_ActionID,
    &ett_cam_ItineraryPath,
    &ett_cam_ProtectedCommunicationZone,
    &ett_cam_Traces,
    &ett_cam_PositionOfPillars,
    &ett_cam_RestrictedTypes,
    &ett_cam_EventHistory,
    &ett_cam_EventPoint,
    &ett_cam_ProtectedCommunicationZonesRSU,
    &ett_cam_CenDsrcTollingZone,
    &ett_cam_DigitalMap,
    &ett_cam_CAM,
    &ett_cam_CoopAwareness,
    &ett_cam_CamParameters,
    &ett_cam_HighFrequencyContainer,
    &ett_cam_LowFrequencyContainer,
    &ett_cam_SpecialVehicleContainer,
    &ett_cam_BasicContainer,
    &ett_cam_BasicVehicleContainerHighFrequency,
    &ett_cam_BasicVehicleContainerLowFrequency,
    &ett_cam_PublicTransportContainer,
    &ett_cam_SpecialTransportContainer,
    &ett_cam_DangerousGoodsContainer,
    &ett_cam_RoadWorksContainerBasic,
    &ett_cam_RescueContainer,
    &ett_cam_EmergencyContainer,
    &ett_cam_SafetyCarContainer,
    &ett_cam_RSUContainerHighFrequency,

/*--- End of included file: packet-cam-ettarr.c ---*/
#line 107 "./asn1/cam/packet-cam-template.c"
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
