/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-denm.c                                                              */
/* asn2wrs.py -p denm -c ./denm.cnf -s ./packet-denm-template -D . -O ../.. ITS-Container.asn DENM.asn */

/* Input file: packet-denm-template.c */

#line 1 "./asn1/denm/packet-denm-template.c"
/* packet-denm.c
 * Routines for DENM packet dissection
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

#include "packet-denm.h"

void proto_register_denm(void);
void proto_reg_handoff_denm(void);

/*ETSI EN 302 637-3 Intelligent Transport Systems (ITS); Vehicular Communications; Basic Set of Applications; Part 2: Specification of Dangerous Event Notification Service */
#define PNAME  "DENM"
#define PSNAME "DENM"
#define PFNAME "denm"
#define DENM_PORT 2002    /* BTP port */

/* Initialize the protocol and registered fields */
static int proto_denm = -1;
static int global_denm_port = DENM_PORT;


/*--- Included file: packet-denm-hf.c ---*/
#line 1 "./asn1/denm/packet-denm-hf.c"
static int hf_denm_DENM_PDU = -1;                 /* DENM */
static int hf_denm_protocolVersion = -1;          /* INTEGER_0_255 */
static int hf_denm_messageID = -1;                /* T_messageID */
static int hf_denm_stationID = -1;                /* StationID */
static int hf_denm_latitude = -1;                 /* Latitude */
static int hf_denm_longitude = -1;                /* Longitude */
static int hf_denm_positionConfidenceEllipse = -1;  /* PosConfidenceEllipse */
static int hf_denm_altitude = -1;                 /* Altitude */
static int hf_denm_deltaLatitude = -1;            /* DeltaLatitude */
static int hf_denm_deltaLongitude = -1;           /* DeltaLongitude */
static int hf_denm_deltaAltitude = -1;            /* DeltaAltitude */
static int hf_denm_altitudeValue = -1;            /* AltitudeValue */
static int hf_denm_altitudeConfidence = -1;       /* AltitudeConfidence */
static int hf_denm_semiMajorConfidence = -1;      /* SemiAxisLength */
static int hf_denm_semiMinorConfidence = -1;      /* SemiAxisLength */
static int hf_denm_semiMajorOrientation = -1;     /* HeadingValue */
static int hf_denm_pathPosition = -1;             /* DeltaReferencePosition */
static int hf_denm_pathDeltaTime = -1;            /* PathDeltaTime */
static int hf_denm_ptActivationType = -1;         /* PtActivationType */
static int hf_denm_ptActivationData = -1;         /* PtActivationData */
static int hf_denm_causeCode = -1;                /* CauseCodeType */
static int hf_denm_subCauseCode = -1;             /* SubCauseCodeType */
static int hf_denm_curvatureValue = -1;           /* CurvatureValue */
static int hf_denm_curvatureConfidence = -1;      /* CurvatureConfidence */
static int hf_denm_headingValue = -1;             /* HeadingValue */
static int hf_denm_headingConfidence = -1;        /* HeadingConfidence */
static int hf_denm_innerhardShoulderStatus = -1;  /* HardShoulderStatus */
static int hf_denm_outerhardShoulderStatus = -1;  /* HardShoulderStatus */
static int hf_denm_drivingLaneStatus = -1;        /* DrivingLaneStatus */
static int hf_denm_speedValue = -1;               /* SpeedValue */
static int hf_denm_speedConfidence = -1;          /* SpeedConfidence */
static int hf_denm_longitudinalAccelerationValue = -1;  /* LongitudinalAccelerationValue */
static int hf_denm_longitudinalAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_denm_lateralAccelerationValue = -1;  /* LateralAccelerationValue */
static int hf_denm_lateralAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_denm_verticalAccelerationValue = -1;  /* VerticalAccelerationValue */
static int hf_denm_verticalAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_denm_dangerousGoodsType = -1;       /* DangerousGoodsBasic */
static int hf_denm_unNumber = -1;                 /* INTEGER_0_9999 */
static int hf_denm_elevatedTemperature = -1;      /* BOOLEAN */
static int hf_denm_tunnelsRestricted = -1;        /* BOOLEAN */
static int hf_denm_limitedQuantity = -1;          /* BOOLEAN */
static int hf_denm_emergencyActionCode = -1;      /* IA5String_SIZE_1_24 */
static int hf_denm_phoneNumber = -1;              /* PhoneNumber */
static int hf_denm_companyName = -1;              /* T_companyName */
static int hf_denm_wMInumber = -1;                /* WMInumber */
static int hf_denm_vDS = -1;                      /* VDS */
static int hf_denm_vehicleLengthValue = -1;       /* VehicleLengthValue */
static int hf_denm_vehicleLengthConfidenceIndication = -1;  /* VehicleLengthConfidenceIndication */
static int hf_denm_PathHistory_item = -1;         /* PathPoint */
static int hf_denm_steeringWheelAngleValue = -1;  /* SteeringWheelAngleValue */
static int hf_denm_steeringWheelAngleConfidence = -1;  /* SteeringWheelAngleConfidence */
static int hf_denm_yawRateValue = -1;             /* YawRateValue */
static int hf_denm_yawRateConfidence = -1;        /* YawRateConfidence */
static int hf_denm_originatingStationID = -1;     /* StationID */
static int hf_denm_sequenceNumber = -1;           /* SequenceNumber */
static int hf_denm_ItineraryPath_item = -1;       /* ReferencePosition */
static int hf_denm_protectedZoneType = -1;        /* ProtectedZoneType */
static int hf_denm_expiryTime = -1;               /* TimestampIts */
static int hf_denm_protectedZoneLatitude = -1;    /* Latitude */
static int hf_denm_protectedZoneLongitude = -1;   /* Longitude */
static int hf_denm_protectedZoneRadius = -1;      /* ProtectedZoneRadius */
static int hf_denm_protectedZoneID = -1;          /* ProtectedZoneID */
static int hf_denm_Traces_item = -1;              /* PathHistory */
static int hf_denm_PositionOfPillars_item = -1;   /* PosPillar */
static int hf_denm_RestrictedTypes_item = -1;     /* StationType */
static int hf_denm_EventHistory_item = -1;        /* EventPoint */
static int hf_denm_eventPosition = -1;            /* DeltaReferencePosition */
static int hf_denm_eventDeltaTime = -1;           /* PathDeltaTime */
static int hf_denm_informationQuality = -1;       /* InformationQuality */
static int hf_denm_ProtectedCommunicationZonesRSU_item = -1;  /* ProtectedCommunicationZone */
static int hf_denm_cenDsrcTollingZoneID = -1;     /* CenDsrcTollingZoneID */
static int hf_denm_DigitalMap_item = -1;          /* ReferencePosition */
static int hf_denm_header = -1;                   /* ItsPduHeader */
static int hf_denm_denm = -1;                     /* DecentralizedEnvironmentalNotificationMessage */
static int hf_denm_management = -1;               /* ManagementContainer */
static int hf_denm_situation = -1;                /* SituationContainer */
static int hf_denm_location = -1;                 /* LocationContainer */
static int hf_denm_alacarte = -1;                 /* AlacarteContainer */
static int hf_denm_actionID = -1;                 /* ActionID */
static int hf_denm_detectionTime = -1;            /* TimestampIts */
static int hf_denm_referenceTime = -1;            /* TimestampIts */
static int hf_denm_termination = -1;              /* Termination */
static int hf_denm_eventPosition_01 = -1;         /* ReferencePosition */
static int hf_denm_relevanceDistance = -1;        /* RelevanceDistance */
static int hf_denm_relevanceTrafficDirection = -1;  /* RelevanceTrafficDirection */
static int hf_denm_validityDuration = -1;         /* ValidityDuration */
static int hf_denm_transmissionInterval = -1;     /* TransmissionInterval */
static int hf_denm_stationType = -1;              /* StationType */
static int hf_denm_eventType = -1;                /* CauseCode */
static int hf_denm_linkedCause = -1;              /* CauseCode */
static int hf_denm_eventHistory = -1;             /* EventHistory */
static int hf_denm_eventSpeed = -1;               /* Speed */
static int hf_denm_eventPositionHeading = -1;     /* Heading */
static int hf_denm_traces = -1;                   /* Traces */
static int hf_denm_roadType = -1;                 /* RoadType */
static int hf_denm_heightLonCarrLeft = -1;        /* HeightLonCarr */
static int hf_denm_heightLonCarrRight = -1;       /* HeightLonCarr */
static int hf_denm_posLonCarrLeft = -1;           /* PosLonCarr */
static int hf_denm_posLonCarrRight = -1;          /* PosLonCarr */
static int hf_denm_positionOfPillars = -1;        /* PositionOfPillars */
static int hf_denm_posCentMass = -1;              /* PosCentMass */
static int hf_denm_wheelBaseVehicle = -1;         /* WheelBaseVehicle */
static int hf_denm_turningRadius = -1;            /* TurningRadius */
static int hf_denm_posFrontAx = -1;               /* PosFrontAx */
static int hf_denm_positionOfOccupants = -1;      /* PositionOfOccupants */
static int hf_denm_vehicleMass = -1;              /* VehicleMass */
static int hf_denm_requestResponseIndication = -1;  /* RequestResponseIndication */
static int hf_denm_lightBarSirenInUse = -1;       /* LightBarSirenInUse */
static int hf_denm_closedLanes = -1;              /* ClosedLanes */
static int hf_denm_restriction = -1;              /* RestrictedTypes */
static int hf_denm_speedLimit = -1;               /* SpeedLimit */
static int hf_denm_incidentIndication = -1;       /* CauseCode */
static int hf_denm_recommendedPath = -1;          /* ItineraryPath */
static int hf_denm_startingPointSpeedLimit = -1;  /* DeltaReferencePosition */
static int hf_denm_trafficFlowRule = -1;          /* TrafficRule */
static int hf_denm_referenceDenms = -1;           /* ReferenceDenms */
static int hf_denm_stationarySince = -1;          /* StationarySince */
static int hf_denm_stationaryCause = -1;          /* CauseCode */
static int hf_denm_carryingDangerousGoods = -1;   /* DangerousGoodsExtended */
static int hf_denm_numberOfOccupants = -1;        /* NumberOfOccupants */
static int hf_denm_vehicleIdentification = -1;    /* VehicleIdentification */
static int hf_denm_energyStorageType = -1;        /* EnergyStorageType */
static int hf_denm_lanePosition = -1;             /* LanePosition */
static int hf_denm_impactReduction = -1;          /* ImpactReductionContainer */
static int hf_denm_externalTemperature = -1;      /* Temperature */
static int hf_denm_roadWorks = -1;                /* RoadWorksContainerExtended */
static int hf_denm_positioningSolution = -1;      /* PositioningSolutionType */
static int hf_denm_stationaryVehicle = -1;        /* StationaryVehicleContainer */
static int hf_denm_ReferenceDenms_item = -1;      /* ActionID */
/* named bits */
static int hf_denm_AccelerationControl_brakePedalEngaged = -1;
static int hf_denm_AccelerationControl_gasPedalEngaged = -1;
static int hf_denm_AccelerationControl_emergencyBrakeEngaged = -1;
static int hf_denm_AccelerationControl_collisionWarningEngaged = -1;
static int hf_denm_AccelerationControl_accEngaged = -1;
static int hf_denm_AccelerationControl_cruiseControlEngaged = -1;
static int hf_denm_AccelerationControl_speedLimiterEngaged = -1;
static int hf_denm_ExteriorLights_lowBeamHeadlightsOn = -1;
static int hf_denm_ExteriorLights_highBeamHeadlightsOn = -1;
static int hf_denm_ExteriorLights_leftTurnSignalOn = -1;
static int hf_denm_ExteriorLights_rightTurnSignalOn = -1;
static int hf_denm_ExteriorLights_daytimeRunningLightsOn = -1;
static int hf_denm_ExteriorLights_reverseLightOn = -1;
static int hf_denm_ExteriorLights_fogLightOn = -1;
static int hf_denm_ExteriorLights_parkingLightsOn = -1;
static int hf_denm_SpecialTransportType_heavyLoad = -1;
static int hf_denm_SpecialTransportType_excessWidth = -1;
static int hf_denm_SpecialTransportType_excessLength = -1;
static int hf_denm_SpecialTransportType_excessHeight = -1;
static int hf_denm_LightBarSirenInUse_lightBarActivated = -1;
static int hf_denm_LightBarSirenInUse_sirenActivated = -1;
static int hf_denm_PositionOfOccupants_row1LeftOccupied = -1;
static int hf_denm_PositionOfOccupants_row1RightOccupied = -1;
static int hf_denm_PositionOfOccupants_row1MidOccupied = -1;
static int hf_denm_PositionOfOccupants_row1NotDetectable = -1;
static int hf_denm_PositionOfOccupants_row1NotPresent = -1;
static int hf_denm_PositionOfOccupants_row2LeftOccupied = -1;
static int hf_denm_PositionOfOccupants_row2RightOccupied = -1;
static int hf_denm_PositionOfOccupants_row2MidOccupied = -1;
static int hf_denm_PositionOfOccupants_row2NotDetectable = -1;
static int hf_denm_PositionOfOccupants_row2NotPresent = -1;
static int hf_denm_PositionOfOccupants_row3LeftOccupied = -1;
static int hf_denm_PositionOfOccupants_row3RightOccupied = -1;
static int hf_denm_PositionOfOccupants_row3MidOccupied = -1;
static int hf_denm_PositionOfOccupants_row3NotDetectable = -1;
static int hf_denm_PositionOfOccupants_row3NotPresent = -1;
static int hf_denm_PositionOfOccupants_row4LeftOccupied = -1;
static int hf_denm_PositionOfOccupants_row4RightOccupied = -1;
static int hf_denm_PositionOfOccupants_row4MidOccupied = -1;
static int hf_denm_PositionOfOccupants_row4NotDetectable = -1;
static int hf_denm_PositionOfOccupants_row4NotPresent = -1;
static int hf_denm_EnergyStorageType_hydrogenStorage = -1;
static int hf_denm_EnergyStorageType_electricEnergyStorage = -1;
static int hf_denm_EnergyStorageType_liquidPropaneGas = -1;
static int hf_denm_EnergyStorageType_compressedNaturalGas = -1;
static int hf_denm_EnergyStorageType_diesel = -1;
static int hf_denm_EnergyStorageType_gasoline = -1;
static int hf_denm_EnergyStorageType_ammonia = -1;
static int hf_denm_EmergencyPriority_requestForRightOfWay = -1;
static int hf_denm_EmergencyPriority_requestForFreeCrossingAtATrafficLight = -1;

/*--- End of included file: packet-denm-hf.c ---*/
#line 53 "./asn1/denm/packet-denm-template.c"

/* Initialize the subtree pointers */
static int ett_denm = -1;


/*--- Included file: packet-denm-ett.c ---*/
#line 1 "./asn1/denm/packet-denm-ett.c"
static gint ett_denm_ItsPduHeader = -1;
static gint ett_denm_ReferencePosition = -1;
static gint ett_denm_DeltaReferencePosition = -1;
static gint ett_denm_Altitude = -1;
static gint ett_denm_PosConfidenceEllipse = -1;
static gint ett_denm_PathPoint = -1;
static gint ett_denm_PtActivation = -1;
static gint ett_denm_AccelerationControl = -1;
static gint ett_denm_CauseCode = -1;
static gint ett_denm_Curvature = -1;
static gint ett_denm_Heading = -1;
static gint ett_denm_ClosedLanes = -1;
static gint ett_denm_Speed = -1;
static gint ett_denm_LongitudinalAcceleration = -1;
static gint ett_denm_LateralAcceleration = -1;
static gint ett_denm_VerticalAcceleration = -1;
static gint ett_denm_ExteriorLights = -1;
static gint ett_denm_DangerousGoodsExtended = -1;
static gint ett_denm_SpecialTransportType = -1;
static gint ett_denm_LightBarSirenInUse = -1;
static gint ett_denm_PositionOfOccupants = -1;
static gint ett_denm_VehicleIdentification = -1;
static gint ett_denm_EnergyStorageType = -1;
static gint ett_denm_VehicleLength = -1;
static gint ett_denm_PathHistory = -1;
static gint ett_denm_EmergencyPriority = -1;
static gint ett_denm_SteeringWheelAngle = -1;
static gint ett_denm_YawRate = -1;
static gint ett_denm_ActionID = -1;
static gint ett_denm_ItineraryPath = -1;
static gint ett_denm_ProtectedCommunicationZone = -1;
static gint ett_denm_Traces = -1;
static gint ett_denm_PositionOfPillars = -1;
static gint ett_denm_RestrictedTypes = -1;
static gint ett_denm_EventHistory = -1;
static gint ett_denm_EventPoint = -1;
static gint ett_denm_ProtectedCommunicationZonesRSU = -1;
static gint ett_denm_CenDsrcTollingZone = -1;
static gint ett_denm_DigitalMap = -1;
static gint ett_denm_DENM = -1;
static gint ett_denm_DecentralizedEnvironmentalNotificationMessage = -1;
static gint ett_denm_ManagementContainer = -1;
static gint ett_denm_SituationContainer = -1;
static gint ett_denm_LocationContainer = -1;
static gint ett_denm_ImpactReductionContainer = -1;
static gint ett_denm_RoadWorksContainerExtended = -1;
static gint ett_denm_StationaryVehicleContainer = -1;
static gint ett_denm_AlacarteContainer = -1;
static gint ett_denm_ReferenceDenms = -1;

/*--- End of included file: packet-denm-ett.c ---*/
#line 58 "./asn1/denm/packet-denm-template.c"


/*--- Included file: packet-denm-fn.c ---*/
#line 1 "./asn1/denm/packet-denm-fn.c"


static int
dissect_denm_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_T_messageID_vals[] = {
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
dissect_denm_T_messageID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_denm_StationID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ItsPduHeader_sequence[] = {
  { &hf_denm_protocolVersion, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_INTEGER_0_255 },
  { &hf_denm_messageID      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_T_messageID },
  { &hf_denm_stationID      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_StationID },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_ItsPduHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_ItsPduHeader, ItsPduHeader_sequence);

  return offset;
}


static const value_string denm_Latitude_vals[] = {
  {  10, "oneMicrodegreeNorth" },
  { -10, "oneMicrodegreeSouth" },
  { 900000001, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_Latitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -900000000, 900000001U, NULL, FALSE);

  return offset;
}


static const value_string denm_Longitude_vals[] = {
  {  10, "oneMicrodegreeEast" },
  { -10, "oneMicrodegreeWest" },
  { 1800000001, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_Longitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1800000000, 1800000001U, NULL, FALSE);

  return offset;
}


static const value_string denm_SemiAxisLength_vals[] = {
  {   1, "oneCentimeter" },
  { 4094, "outOfRange" },
  { 4095, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_SemiAxisLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const value_string denm_HeadingValue_vals[] = {
  {   0, "wgs84North" },
  { 900, "wgs84East" },
  { 1800, "wgs84South" },
  { 2700, "wgs84West" },
  { 3601, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_HeadingValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3601U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PosConfidenceEllipse_sequence[] = {
  { &hf_denm_semiMajorConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_SemiAxisLength },
  { &hf_denm_semiMinorConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_SemiAxisLength },
  { &hf_denm_semiMajorOrientation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_HeadingValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_PosConfidenceEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_PosConfidenceEllipse, PosConfidenceEllipse_sequence);

  return offset;
}


static const value_string denm_AltitudeValue_vals[] = {
  {   0, "referenceEllipsoidSurface" },
  {   1, "oneCentimeter" },
  { 800001, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_AltitudeValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -100000, 800001U, NULL, FALSE);

  return offset;
}


static const value_string denm_AltitudeConfidence_vals[] = {
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
dissect_denm_AltitudeConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Altitude_sequence[] = {
  { &hf_denm_altitudeValue  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_AltitudeValue },
  { &hf_denm_altitudeConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_AltitudeConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_Altitude, Altitude_sequence);

  return offset;
}


static const per_sequence_t ReferencePosition_sequence[] = {
  { &hf_denm_latitude       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_Latitude },
  { &hf_denm_longitude      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_Longitude },
  { &hf_denm_positionConfidenceEllipse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PosConfidenceEllipse },
  { &hf_denm_altitude       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_Altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_ReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_ReferencePosition, ReferencePosition_sequence);

  return offset;
}


static const value_string denm_DeltaLatitude_vals[] = {
  {  10, "oneMicrodegreeNorth" },
  { -10, "oneMicrodegreeSouth" },
  { 131072, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_DeltaLatitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131071, 131072U, NULL, FALSE);

  return offset;
}


static const value_string denm_DeltaLongitude_vals[] = {
  {  10, "oneMicrodegreeEast" },
  { -10, "oneMicrodegreeWest" },
  { 131072, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_DeltaLongitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131071, 131072U, NULL, FALSE);

  return offset;
}


static const value_string denm_DeltaAltitude_vals[] = {
  {   1, "oneCentimeterUp" },
  {  -1, "oneCentimeterDown" },
  { 12800, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_DeltaAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -12700, 12800U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DeltaReferencePosition_sequence[] = {
  { &hf_denm_deltaLatitude  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_DeltaLatitude },
  { &hf_denm_deltaLongitude , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_DeltaLongitude },
  { &hf_denm_deltaAltitude  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_DeltaAltitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_DeltaReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_DeltaReferencePosition, DeltaReferencePosition_sequence);

  return offset;
}


static const value_string denm_PathDeltaTime_vals[] = {
  {   1, "tenMilliSecondsInPast" },
  { 0, NULL }
};


static int
dissect_denm_PathDeltaTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PathPoint_sequence[] = {
  { &hf_denm_pathPosition   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_DeltaReferencePosition },
  { &hf_denm_pathDeltaTime  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_PathDeltaTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_PathPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_PathPoint, PathPoint_sequence);

  return offset;
}


static const value_string denm_PtActivationType_vals[] = {
  {   0, "undefinedCodingType" },
  {   1, "r09-16CodingType" },
  {   2, "vdv-50149CodingType" },
  { 0, NULL }
};


static int
dissect_denm_PtActivationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_denm_PtActivationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}


static const per_sequence_t PtActivation_sequence[] = {
  { &hf_denm_ptActivationType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PtActivationType },
  { &hf_denm_ptActivationData, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PtActivationData },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_PtActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_PtActivation, PtActivation_sequence);

  return offset;
}



static int
dissect_denm_AccelerationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, NULL);

  return offset;
}


static const value_string denm_CauseCodeType_vals[] = {
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
dissect_denm_CauseCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_denm_SubCauseCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CauseCode_sequence[] = {
  { &hf_denm_causeCode      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_CauseCodeType },
  { &hf_denm_subCauseCode   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_SubCauseCodeType },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_CauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_CauseCode, CauseCode_sequence);

  return offset;
}


static const value_string denm_TrafficConditionSubCauseCode_vals[] = {
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
dissect_denm_TrafficConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_AccidentSubCauseCode_vals[] = {
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
dissect_denm_AccidentSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_RoadworksSubCauseCode_vals[] = {
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
dissect_denm_RoadworksSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_HumanPresenceOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "childrenOnRoadway" },
  {   2, "cyclistOnRoadway" },
  {   3, "motorcyclistOnRoadway" },
  { 0, NULL }
};


static int
dissect_denm_HumanPresenceOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_WrongWayDrivingSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "wrongLane" },
  {   2, "wrongDirection" },
  { 0, NULL }
};


static int
dissect_denm_WrongWayDrivingSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_AdverseWeatherCondition_ExtremeWeatherConditionSubCauseCode_vals[] = {
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
dissect_denm_AdverseWeatherCondition_ExtremeWeatherConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_AdverseWeatherCondition_AdhesionSubCauseCode_vals[] = {
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
dissect_denm_AdverseWeatherCondition_AdhesionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_AdverseWeatherCondition_VisibilitySubCauseCode_vals[] = {
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
dissect_denm_AdverseWeatherCondition_VisibilitySubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_AdverseWeatherCondition_PrecipitationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "heavyRain" },
  {   2, "heavySnowfall" },
  {   3, "softHail" },
  { 0, NULL }
};


static int
dissect_denm_AdverseWeatherCondition_PrecipitationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_SlowVehicleSubCauseCode_vals[] = {
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
dissect_denm_SlowVehicleSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_StationaryVehicleSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "humanProblem" },
  {   2, "vehicleBreakdown" },
  {   3, "postCrash" },
  {   4, "publicTransportStop" },
  {   5, "carryingDangerousGoods" },
  { 0, NULL }
};


static int
dissect_denm_StationaryVehicleSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_HumanProblemSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "glycemiaProblem" },
  {   2, "heartProblem" },
  { 0, NULL }
};


static int
dissect_denm_HumanProblemSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_EmergencyVehicleApproachingSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyVehicleApproaching" },
  {   2, "prioritizedVehicleApproaching" },
  { 0, NULL }
};


static int
dissect_denm_EmergencyVehicleApproachingSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_HazardousLocation_DangerousCurveSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "dangerousLeftTurnCurve" },
  {   2, "dangerousRightTurnCurve" },
  {   3, "multipleCurvesStartingWithUnknownTurningDirection" },
  {   4, "multipleCurvesStartingWithLeftTurn" },
  {   5, "multipleCurvesStartingWithRightTurn" },
  { 0, NULL }
};


static int
dissect_denm_HazardousLocation_DangerousCurveSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_HazardousLocation_SurfaceConditionSubCauseCode_vals[] = {
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
dissect_denm_HazardousLocation_SurfaceConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_HazardousLocation_ObstacleOnTheRoadSubCauseCode_vals[] = {
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
dissect_denm_HazardousLocation_ObstacleOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_HazardousLocation_AnimalOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "wildAnimals" },
  {   2, "herdOfAnimals" },
  {   3, "smallAnimals" },
  {   4, "largeAnimals" },
  { 0, NULL }
};


static int
dissect_denm_HazardousLocation_AnimalOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_CollisionRiskSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "longitudinalCollisionRisk" },
  {   2, "crossingCollisionRisk" },
  {   3, "lateralCollisionRisk" },
  {   4, "vulnerableRoadUser" },
  { 0, NULL }
};


static int
dissect_denm_CollisionRiskSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_SignalViolationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "stopSignViolation" },
  {   2, "trafficLightViolation" },
  {   3, "turningRegulationViolation" },
  { 0, NULL }
};


static int
dissect_denm_SignalViolationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_RescueAndRecoveryWorkInProgressSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyVehicles" },
  {   2, "rescueHelicopterLanding" },
  {   3, "policeActivityOngoing" },
  {   4, "medicalEmergencyOngoing" },
  {   5, "childAbductionInProgress" },
  { 0, NULL }
};


static int
dissect_denm_RescueAndRecoveryWorkInProgressSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_DangerousEndOfQueueSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "suddenEndOfQueue" },
  {   2, "queueOverHill" },
  {   3, "queueAroundBend" },
  {   4, "queueInTunnel" },
  { 0, NULL }
};


static int
dissect_denm_DangerousEndOfQueueSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_DangerousSituationSubCauseCode_vals[] = {
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
dissect_denm_DangerousSituationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_VehicleBreakdownSubCauseCode_vals[] = {
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
dissect_denm_VehicleBreakdownSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_PostCrashSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "accidentWithoutECallTriggered" },
  {   2, "accidentWithECallManuallyTriggered" },
  {   3, "accidentWithECallAutomaticallyTriggered" },
  {   4, "accidentWithECallTriggeredWithoutAccessToCellularNetwork" },
  { 0, NULL }
};


static int
dissect_denm_PostCrashSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_CurvatureValue_vals[] = {
  {   0, "straight" },
  { 1023, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_CurvatureValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1023, 1023U, NULL, FALSE);

  return offset;
}


static const value_string denm_CurvatureConfidence_vals[] = {
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
dissect_denm_CurvatureConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Curvature_sequence[] = {
  { &hf_denm_curvatureValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_CurvatureValue },
  { &hf_denm_curvatureConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_CurvatureConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_Curvature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_Curvature, Curvature_sequence);

  return offset;
}


static const value_string denm_CurvatureCalculationMode_vals[] = {
  {   0, "yawRateUsed" },
  {   1, "yawRateNotUsed" },
  {   2, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_CurvatureCalculationMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string denm_HeadingConfidence_vals[] = {
  {   1, "equalOrWithinZeroPointOneDegree" },
  {  10, "equalOrWithinOneDegree" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_HeadingConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Heading_sequence[] = {
  { &hf_denm_headingValue   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_HeadingValue },
  { &hf_denm_headingConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_HeadingConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_Heading(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_Heading, Heading_sequence);

  return offset;
}


static const value_string denm_LanePosition_vals[] = {
  {  -1, "offTheRoad" },
  {   0, "hardShoulder" },
  {   1, "outermostDrivingLane" },
  {   2, "secondLaneFromOutside" },
  { 0, NULL }
};


static int
dissect_denm_LanePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1, 14U, NULL, FALSE);

  return offset;
}


static const value_string denm_HardShoulderStatus_vals[] = {
  {   0, "availableForStopping" },
  {   1, "closed" },
  {   2, "availableForDriving" },
  { 0, NULL }
};


static int
dissect_denm_HardShoulderStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_denm_DrivingLaneStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 13, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t ClosedLanes_sequence[] = {
  { &hf_denm_innerhardShoulderStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_HardShoulderStatus },
  { &hf_denm_outerhardShoulderStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_HardShoulderStatus },
  { &hf_denm_drivingLaneStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_DrivingLaneStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_ClosedLanes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_ClosedLanes, ClosedLanes_sequence);

  return offset;
}


static const value_string denm_PerformanceClass_vals[] = {
  {   0, "unavailable" },
  {   1, "performanceClassA" },
  {   2, "performanceClassB" },
  { 0, NULL }
};


static int
dissect_denm_PerformanceClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string denm_SpeedValue_vals[] = {
  {   0, "standstill" },
  {   1, "oneCentimeterPerSec" },
  { 16383, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_SpeedValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const value_string denm_SpeedConfidence_vals[] = {
  {   1, "equalOrWithinOneCentimeterPerSec" },
  { 100, "equalOrWithinOneMeterPerSec" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_SpeedConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string denm_VehicleMass_vals[] = {
  {   1, "hundredKg" },
  { 1024, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_VehicleMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Speed_sequence[] = {
  { &hf_denm_speedValue     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_SpeedValue },
  { &hf_denm_speedConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_SpeedConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_Speed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_Speed, Speed_sequence);

  return offset;
}


static const value_string denm_DriveDirection_vals[] = {
  {   0, "forward" },
  {   1, "backward" },
  {   2, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_DriveDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_denm_EmbarkationStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string denm_LongitudinalAccelerationValue_vals[] = {
  {   1, "pointOneMeterPerSecSquaredForward" },
  {  -1, "pointOneMeterPerSecSquaredBackward" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_LongitudinalAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const value_string denm_AccelerationConfidence_vals[] = {
  {   1, "pointOneMeterPerSecSquared" },
  { 101, "outOfRange" },
  { 102, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_AccelerationConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 102U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LongitudinalAcceleration_sequence[] = {
  { &hf_denm_longitudinalAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_LongitudinalAccelerationValue },
  { &hf_denm_longitudinalAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_LongitudinalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_LongitudinalAcceleration, LongitudinalAcceleration_sequence);

  return offset;
}


static const value_string denm_LateralAccelerationValue_vals[] = {
  {  -1, "pointOneMeterPerSecSquaredToRight" },
  {   1, "pointOneMeterPerSecSquaredToLeft" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_LateralAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LateralAcceleration_sequence[] = {
  { &hf_denm_lateralAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_LateralAccelerationValue },
  { &hf_denm_lateralAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_LateralAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_LateralAcceleration, LateralAcceleration_sequence);

  return offset;
}


static const value_string denm_VerticalAccelerationValue_vals[] = {
  {   1, "pointOneMeterPerSecSquaredUp" },
  {  -1, "pointOneMeterPerSecSquaredDown" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_VerticalAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VerticalAcceleration_sequence[] = {
  { &hf_denm_verticalAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_VerticalAccelerationValue },
  { &hf_denm_verticalAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_VerticalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_VerticalAcceleration, VerticalAcceleration_sequence);

  return offset;
}


static const value_string denm_StationType_vals[] = {
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
dissect_denm_StationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_denm_ExteriorLights(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}


static const value_string denm_DangerousGoodsBasic_vals[] = {
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
dissect_denm_DangerousGoodsBasic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_denm_INTEGER_0_9999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9999U, NULL, FALSE);

  return offset;
}



static int
dissect_denm_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_denm_IA5String_SIZE_1_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 24, FALSE);

  return offset;
}



static int
dissect_denm_PhoneNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          1, 16, FALSE);

  return offset;
}



static int
dissect_denm_T_companyName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 21 "./asn1/denm/denm.cnf"
  offset=dissect_per_octet_string(tvb, offset, actx, tree, hf_index, NO_BOUND, NO_BOUND, FALSE, NULL);


  return offset;
}


static const per_sequence_t DangerousGoodsExtended_sequence[] = {
  { &hf_denm_dangerousGoodsType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_DangerousGoodsBasic },
  { &hf_denm_unNumber       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_INTEGER_0_9999 },
  { &hf_denm_elevatedTemperature, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_BOOLEAN },
  { &hf_denm_tunnelsRestricted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_BOOLEAN },
  { &hf_denm_limitedQuantity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_BOOLEAN },
  { &hf_denm_emergencyActionCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_IA5String_SIZE_1_24 },
  { &hf_denm_phoneNumber    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_PhoneNumber },
  { &hf_denm_companyName    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_T_companyName },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_DangerousGoodsExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_DangerousGoodsExtended, DangerousGoodsExtended_sequence);

  return offset;
}



static int
dissect_denm_SpecialTransportType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_denm_LightBarSirenInUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string denm_HeightLonCarr_vals[] = {
  {   1, "oneCentimeter" },
  { 100, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_HeightLonCarr(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, FALSE);

  return offset;
}


static const value_string denm_PosLonCarr_vals[] = {
  {   1, "oneCentimeter" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_PosLonCarr(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string denm_PosPillar_vals[] = {
  {   1, "tenCentimeters" },
  {  30, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_PosPillar(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 30U, NULL, FALSE);

  return offset;
}


static const value_string denm_PosCentMass_vals[] = {
  {   1, "tenCentimeters" },
  {  63, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_PosCentMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 63U, NULL, FALSE);

  return offset;
}


static const value_string denm_RequestResponseIndication_vals[] = {
  {   0, "request" },
  {   1, "response" },
  { 0, NULL }
};


static int
dissect_denm_RequestResponseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string denm_SpeedLimit_vals[] = {
  {   1, "oneKmPerHour" },
  { 0, NULL }
};


static int
dissect_denm_SpeedLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_StationarySince_vals[] = {
  {   0, "lessThan1Minute" },
  {   1, "lessThan2Minutes" },
  {   2, "lessThan15Minutes" },
  {   3, "equalOrGreater15Minutes" },
  { 0, NULL }
};


static int
dissect_denm_StationarySince(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string denm_Temperature_vals[] = {
  { -60, "equalOrSmallerThanMinus60Deg" },
  {   1, "oneDegreeCelsius" },
  {  67, "equalOrGreaterThan67Deg" },
  { 0, NULL }
};


static int
dissect_denm_Temperature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -60, 67U, NULL, FALSE);

  return offset;
}


static const value_string denm_TrafficRule_vals[] = {
  {   0, "noPassing" },
  {   1, "noPassingForTrucks" },
  {   2, "passToRight" },
  {   3, "passToLeft" },
  { 0, NULL }
};


static int
dissect_denm_TrafficRule(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string denm_WheelBaseVehicle_vals[] = {
  {   1, "tenCentimeters" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_WheelBaseVehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string denm_TurningRadius_vals[] = {
  {   1, "point4Meters" },
  { 255, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_TurningRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string denm_PosFrontAx_vals[] = {
  {   1, "tenCentimeters" },
  {  20, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_PosFrontAx(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 20U, NULL, FALSE);

  return offset;
}



static int
dissect_denm_PositionOfOccupants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, NULL);

  return offset;
}


static const value_string denm_PositioningSolutionType_vals[] = {
  {   0, "noPositioningSolution" },
  {   1, "sGNSS" },
  {   2, "dGNSS" },
  {   3, "sGNSSplusDR" },
  {   4, "dGNSSplusDR" },
  {   5, "dR" },
  { 0, NULL }
};


static int
dissect_denm_PositioningSolutionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_denm_WMInumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 3, FALSE);

  return offset;
}



static int
dissect_denm_VDS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          6, 6, FALSE);

  return offset;
}


static const per_sequence_t VehicleIdentification_sequence[] = {
  { &hf_denm_wMInumber      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_WMInumber },
  { &hf_denm_vDS            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_VDS },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_VehicleIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_VehicleIdentification, VehicleIdentification_sequence);

  return offset;
}



static int
dissect_denm_EnergyStorageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, NULL);

  return offset;
}


static const value_string denm_VehicleLengthValue_vals[] = {
  {   1, "tenCentimeters" },
  { 1022, "outOfRange" },
  { 1023, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_VehicleLengthValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1023U, NULL, FALSE);

  return offset;
}


static const value_string denm_VehicleLengthConfidenceIndication_vals[] = {
  {   0, "noTrailerPresent" },
  {   1, "trailerPresentWithKnownLength" },
  {   2, "trailerPresentWithUnknownLength" },
  {   3, "trailerPresenceIsUnknown" },
  {   4, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_VehicleLengthConfidenceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t VehicleLength_sequence[] = {
  { &hf_denm_vehicleLengthValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_VehicleLengthValue },
  { &hf_denm_vehicleLengthConfidenceIndication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_VehicleLengthConfidenceIndication },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_VehicleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_VehicleLength, VehicleLength_sequence);

  return offset;
}


static const value_string denm_VehicleWidth_vals[] = {
  {   1, "tenCentimeters" },
  {  61, "outOfRange" },
  {  62, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_VehicleWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 62U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PathHistory_sequence_of[1] = {
  { &hf_denm_PathHistory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PathPoint },
};

static int
dissect_denm_PathHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_PathHistory, PathHistory_sequence_of,
                                                  0, 40, FALSE);

  return offset;
}



static int
dissect_denm_EmergencyPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string denm_InformationQuality_vals[] = {
  {   0, "unavailable" },
  {   1, "lowest" },
  {   7, "highest" },
  { 0, NULL }
};


static int
dissect_denm_InformationQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string denm_RoadType_vals[] = {
  {   0, "urban-NoStructuralSeparationToOppositeLanes" },
  {   1, "urban-WithStructuralSeparationToOppositeLanes" },
  {   2, "nonUrban-NoStructuralSeparationToOppositeLanes" },
  {   3, "nonUrban-WithStructuralSeparationToOppositeLanes" },
  { 0, NULL }
};


static int
dissect_denm_RoadType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string denm_SteeringWheelAngleValue_vals[] = {
  {   0, "straight" },
  {  -1, "onePointFiveDegreesToRight" },
  {   1, "onePointFiveDegreesToLeft" },
  { 512, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_SteeringWheelAngleValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -511, 512U, NULL, FALSE);

  return offset;
}


static const value_string denm_SteeringWheelAngleConfidence_vals[] = {
  {   1, "equalOrWithinOnePointFiveDegree" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_SteeringWheelAngleConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SteeringWheelAngle_sequence[] = {
  { &hf_denm_steeringWheelAngleValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_SteeringWheelAngleValue },
  { &hf_denm_steeringWheelAngleConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_SteeringWheelAngleConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_SteeringWheelAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_SteeringWheelAngle, SteeringWheelAngle_sequence);

  return offset;
}


static const value_string denm_TimestampIts_vals[] = {
  {   0, "utcStartOf2004" },
  {   1, "oneMillisecAfterUTCStartOf2004" },
  { 0, NULL }
};


static int
dissect_denm_TimestampIts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 17 "./asn1/denm/denm.cnf"
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index, 0U, G_GUINT64_CONSTANT(4398046511103), NULL, FALSE);


  return offset;
}


static const value_string denm_VehicleRole_vals[] = {
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
dissect_denm_VehicleRole(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string denm_YawRateValue_vals[] = {
  {   0, "straight" },
  {  -1, "degSec-000-01ToRight" },
  {   1, "degSec-000-01ToLeft" },
  { 32767, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_YawRateValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32766, 32767U, NULL, FALSE);

  return offset;
}


static const value_string denm_YawRateConfidence_vals[] = {
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
dissect_denm_YawRateConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t YawRate_sequence[] = {
  { &hf_denm_yawRateValue   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_YawRateValue },
  { &hf_denm_yawRateConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_YawRateConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_YawRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_YawRate, YawRate_sequence);

  return offset;
}


static const value_string denm_ProtectedZoneType_vals[] = {
  {   0, "permanentCenDsrcTolling" },
  {   1, "temporaryCenDsrcTolling" },
  { 0, NULL }
};


static int
dissect_denm_ProtectedZoneType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}


static const value_string denm_RelevanceDistance_vals[] = {
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
dissect_denm_RelevanceDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string denm_RelevanceTrafficDirection_vals[] = {
  {   0, "allTrafficDirections" },
  {   1, "upstreamTraffic" },
  {   2, "downstreamTraffic" },
  {   3, "oppositeTraffic" },
  { 0, NULL }
};


static int
dissect_denm_RelevanceTrafficDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string denm_TransmissionInterval_vals[] = {
  {   1, "oneMilliSecond" },
  { 10000, "tenSeconds" },
  { 0, NULL }
};


static int
dissect_denm_TransmissionInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 10000U, NULL, FALSE);

  return offset;
}


static const value_string denm_ValidityDuration_vals[] = {
  {   0, "timeOfDetection" },
  {   1, "oneSecondAfterDetection" },
  { 0, NULL }
};


static int
dissect_denm_ValidityDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86400U, NULL, FALSE);

  return offset;
}



static int
dissect_denm_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ActionID_sequence[] = {
  { &hf_denm_originatingStationID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_StationID },
  { &hf_denm_sequenceNumber , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_SequenceNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_ActionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_ActionID, ActionID_sequence);

  return offset;
}


static const per_sequence_t ItineraryPath_sequence_of[1] = {
  { &hf_denm_ItineraryPath_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_ReferencePosition },
};

static int
dissect_denm_ItineraryPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_ItineraryPath, ItineraryPath_sequence_of,
                                                  1, 40, FALSE);

  return offset;
}


static const value_string denm_ProtectedZoneRadius_vals[] = {
  {   1, "oneMeter" },
  { 0, NULL }
};


static int
dissect_denm_ProtectedZoneRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_denm_ProtectedZoneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 134217727U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ProtectedCommunicationZone_sequence[] = {
  { &hf_denm_protectedZoneType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_ProtectedZoneType },
  { &hf_denm_expiryTime     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_TimestampIts },
  { &hf_denm_protectedZoneLatitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_Latitude },
  { &hf_denm_protectedZoneLongitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_Longitude },
  { &hf_denm_protectedZoneRadius, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_ProtectedZoneRadius },
  { &hf_denm_protectedZoneID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_ProtectedZoneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_ProtectedCommunicationZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_ProtectedCommunicationZone, ProtectedCommunicationZone_sequence);

  return offset;
}


static const per_sequence_t Traces_sequence_of[1] = {
  { &hf_denm_Traces_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PathHistory },
};

static int
dissect_denm_Traces(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_Traces, Traces_sequence_of,
                                                  1, 7, FALSE);

  return offset;
}


static const value_string denm_NumberOfOccupants_vals[] = {
  {   1, "oneOccupant" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_denm_NumberOfOccupants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PositionOfPillars_sequence_of[1] = {
  { &hf_denm_PositionOfPillars_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PosPillar },
};

static int
dissect_denm_PositionOfPillars(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_PositionOfPillars, PositionOfPillars_sequence_of,
                                                  1, 3, TRUE);

  return offset;
}


static const per_sequence_t RestrictedTypes_sequence_of[1] = {
  { &hf_denm_RestrictedTypes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_StationType },
};

static int
dissect_denm_RestrictedTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_RestrictedTypes, RestrictedTypes_sequence_of,
                                                  1, 3, TRUE);

  return offset;
}


static const per_sequence_t EventPoint_sequence[] = {
  { &hf_denm_eventPosition  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_DeltaReferencePosition },
  { &hf_denm_eventDeltaTime , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_PathDeltaTime },
  { &hf_denm_informationQuality, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_InformationQuality },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_EventPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_EventPoint, EventPoint_sequence);

  return offset;
}


static const per_sequence_t EventHistory_sequence_of[1] = {
  { &hf_denm_EventHistory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_EventPoint },
};

static int
dissect_denm_EventHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_EventHistory, EventHistory_sequence_of,
                                                  1, 23, FALSE);

  return offset;
}


static const per_sequence_t ProtectedCommunicationZonesRSU_sequence_of[1] = {
  { &hf_denm_ProtectedCommunicationZonesRSU_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_ProtectedCommunicationZone },
};

static int
dissect_denm_ProtectedCommunicationZonesRSU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_ProtectedCommunicationZonesRSU, ProtectedCommunicationZonesRSU_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_denm_CenDsrcTollingZoneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_denm_ProtectedZoneID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CenDsrcTollingZone_sequence[] = {
  { &hf_denm_protectedZoneLatitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_Latitude },
  { &hf_denm_protectedZoneLongitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_Longitude },
  { &hf_denm_cenDsrcTollingZoneID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_CenDsrcTollingZoneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_CenDsrcTollingZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_CenDsrcTollingZone, CenDsrcTollingZone_sequence);

  return offset;
}


static const per_sequence_t DigitalMap_sequence_of[1] = {
  { &hf_denm_DigitalMap_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_ReferencePosition },
};

static int
dissect_denm_DigitalMap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_DigitalMap, DigitalMap_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}



static int
dissect_denm_OpeningDaysHours(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_UTF8String(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, FALSE);

  return offset;
}


static const value_string denm_Termination_vals[] = {
  {   0, "isCancellation" },
  {   1, "isNegation" },
  { 0, NULL }
};


static int
dissect_denm_Termination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ManagementContainer_sequence[] = {
  { &hf_denm_actionID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_ActionID },
  { &hf_denm_detectionTime  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_TimestampIts },
  { &hf_denm_referenceTime  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_TimestampIts },
  { &hf_denm_termination    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_Termination },
  { &hf_denm_eventPosition_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_ReferencePosition },
  { &hf_denm_relevanceDistance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_RelevanceDistance },
  { &hf_denm_relevanceTrafficDirection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_RelevanceTrafficDirection },
  { &hf_denm_validityDuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_ValidityDuration },
  { &hf_denm_transmissionInterval, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_TransmissionInterval },
  { &hf_denm_stationType    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_StationType },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_ManagementContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_ManagementContainer, ManagementContainer_sequence);

  return offset;
}


static const per_sequence_t SituationContainer_sequence[] = {
  { &hf_denm_informationQuality, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_InformationQuality },
  { &hf_denm_eventType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_CauseCode },
  { &hf_denm_linkedCause    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_CauseCode },
  { &hf_denm_eventHistory   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_EventHistory },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_SituationContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_SituationContainer, SituationContainer_sequence);

  return offset;
}


static const per_sequence_t LocationContainer_sequence[] = {
  { &hf_denm_eventSpeed     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_Speed },
  { &hf_denm_eventPositionHeading, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_Heading },
  { &hf_denm_traces         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_denm_Traces },
  { &hf_denm_roadType       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_RoadType },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_LocationContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_LocationContainer, LocationContainer_sequence);

  return offset;
}


static const per_sequence_t ImpactReductionContainer_sequence[] = {
  { &hf_denm_heightLonCarrLeft, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_HeightLonCarr },
  { &hf_denm_heightLonCarrRight, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_HeightLonCarr },
  { &hf_denm_posLonCarrLeft , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PosLonCarr },
  { &hf_denm_posLonCarrRight, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PosLonCarr },
  { &hf_denm_positionOfPillars, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PositionOfPillars },
  { &hf_denm_posCentMass    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PosCentMass },
  { &hf_denm_wheelBaseVehicle, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_WheelBaseVehicle },
  { &hf_denm_turningRadius  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_TurningRadius },
  { &hf_denm_posFrontAx     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PosFrontAx },
  { &hf_denm_positionOfOccupants, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_PositionOfOccupants },
  { &hf_denm_vehicleMass    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_VehicleMass },
  { &hf_denm_requestResponseIndication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_RequestResponseIndication },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_ImpactReductionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_ImpactReductionContainer, ImpactReductionContainer_sequence);

  return offset;
}


static const per_sequence_t ReferenceDenms_sequence_of[1] = {
  { &hf_denm_ReferenceDenms_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_ActionID },
};

static int
dissect_denm_ReferenceDenms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_denm_ReferenceDenms, ReferenceDenms_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}


static const per_sequence_t RoadWorksContainerExtended_sequence[] = {
  { &hf_denm_lightBarSirenInUse, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_LightBarSirenInUse },
  { &hf_denm_closedLanes    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_ClosedLanes },
  { &hf_denm_restriction    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_RestrictedTypes },
  { &hf_denm_speedLimit     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_SpeedLimit },
  { &hf_denm_incidentIndication, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_CauseCode },
  { &hf_denm_recommendedPath, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_ItineraryPath },
  { &hf_denm_startingPointSpeedLimit, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_DeltaReferencePosition },
  { &hf_denm_trafficFlowRule, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_TrafficRule },
  { &hf_denm_referenceDenms , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_ReferenceDenms },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_RoadWorksContainerExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_RoadWorksContainerExtended, RoadWorksContainerExtended_sequence);

  return offset;
}


static const per_sequence_t StationaryVehicleContainer_sequence[] = {
  { &hf_denm_stationarySince, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_StationarySince },
  { &hf_denm_stationaryCause, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_CauseCode },
  { &hf_denm_carryingDangerousGoods, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_DangerousGoodsExtended },
  { &hf_denm_numberOfOccupants, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_NumberOfOccupants },
  { &hf_denm_vehicleIdentification, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_VehicleIdentification },
  { &hf_denm_energyStorageType, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_EnergyStorageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_StationaryVehicleContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_StationaryVehicleContainer, StationaryVehicleContainer_sequence);

  return offset;
}


static const per_sequence_t AlacarteContainer_sequence[] = {
  { &hf_denm_lanePosition   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_LanePosition },
  { &hf_denm_impactReduction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_ImpactReductionContainer },
  { &hf_denm_externalTemperature, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_Temperature },
  { &hf_denm_roadWorks      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_RoadWorksContainerExtended },
  { &hf_denm_positioningSolution, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_PositioningSolutionType },
  { &hf_denm_stationaryVehicle, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_denm_StationaryVehicleContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_AlacarteContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_AlacarteContainer, AlacarteContainer_sequence);

  return offset;
}


static const per_sequence_t DecentralizedEnvironmentalNotificationMessage_sequence[] = {
  { &hf_denm_management     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_ManagementContainer },
  { &hf_denm_situation      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_SituationContainer },
  { &hf_denm_location       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_LocationContainer },
  { &hf_denm_alacarte       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_denm_AlacarteContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_DecentralizedEnvironmentalNotificationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_DecentralizedEnvironmentalNotificationMessage, DecentralizedEnvironmentalNotificationMessage_sequence);

  return offset;
}


static const per_sequence_t DENM_sequence[] = {
  { &hf_denm_header         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_ItsPduHeader },
  { &hf_denm_denm           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_denm_DecentralizedEnvironmentalNotificationMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_denm_DENM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_denm_DENM, DENM_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_DENM_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_denm_DENM(tvb, offset, &asn1_ctx, tree, hf_denm_DENM_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-denm-fn.c ---*/
#line 60 "./asn1/denm/packet-denm-template.c"

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
dissect_denm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *denm_item = NULL;
    proto_tree      *denm_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* create the denm protocol tree */
    if (tree) {
        denm_item = proto_tree_add_item(tree, proto_denm, tvb, 0, -1, FALSE);
        denm_tree = proto_item_add_subtree(denm_item, ett_denm);
        dissect_DENM_PDU(tvb, pinfo, denm_tree, NULL);
    }

    return tvb_captured_length(tvb);
}
/*--- proto_register_denm -------------------------------------------*/
void proto_register_denm(void) {

  module_t *denm_module;

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-denm-hfarr.c ---*/
#line 1 "./asn1/denm/packet-denm-hfarr.c"
    { &hf_denm_DENM_PDU,
      { "DENM", "denm.DENM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_protocolVersion,
      { "protocolVersion", "denm.protocolVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_denm_messageID,
      { "messageID", "denm.messageID",
        FT_UINT32, BASE_DEC, VALS(denm_T_messageID_vals), 0,
        NULL, HFILL }},
    { &hf_denm_stationID,
      { "stationID", "denm.stationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_latitude,
      { "latitude", "denm.latitude",
        FT_INT32, BASE_DEC, VALS(denm_Latitude_vals), 0,
        NULL, HFILL }},
    { &hf_denm_longitude,
      { "longitude", "denm.longitude",
        FT_INT32, BASE_DEC, VALS(denm_Longitude_vals), 0,
        NULL, HFILL }},
    { &hf_denm_positionConfidenceEllipse,
      { "positionConfidenceEllipse", "denm.positionConfidenceEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosConfidenceEllipse", HFILL }},
    { &hf_denm_altitude,
      { "altitude", "denm.altitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_deltaLatitude,
      { "deltaLatitude", "denm.deltaLatitude",
        FT_INT32, BASE_DEC, VALS(denm_DeltaLatitude_vals), 0,
        NULL, HFILL }},
    { &hf_denm_deltaLongitude,
      { "deltaLongitude", "denm.deltaLongitude",
        FT_INT32, BASE_DEC, VALS(denm_DeltaLongitude_vals), 0,
        NULL, HFILL }},
    { &hf_denm_deltaAltitude,
      { "deltaAltitude", "denm.deltaAltitude",
        FT_INT32, BASE_DEC, VALS(denm_DeltaAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_denm_altitudeValue,
      { "altitudeValue", "denm.altitudeValue",
        FT_INT32, BASE_DEC, VALS(denm_AltitudeValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_altitudeConfidence,
      { "altitudeConfidence", "denm.altitudeConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_AltitudeConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_denm_semiMajorConfidence,
      { "semiMajorConfidence", "denm.semiMajorConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_SemiAxisLength_vals), 0,
        "SemiAxisLength", HFILL }},
    { &hf_denm_semiMinorConfidence,
      { "semiMinorConfidence", "denm.semiMinorConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_SemiAxisLength_vals), 0,
        "SemiAxisLength", HFILL }},
    { &hf_denm_semiMajorOrientation,
      { "semiMajorOrientation", "denm.semiMajorOrientation",
        FT_UINT32, BASE_DEC, VALS(denm_HeadingValue_vals), 0,
        "HeadingValue", HFILL }},
    { &hf_denm_pathPosition,
      { "pathPosition", "denm.pathPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_denm_pathDeltaTime,
      { "pathDeltaTime", "denm.pathDeltaTime",
        FT_UINT32, BASE_DEC, VALS(denm_PathDeltaTime_vals), 0,
        NULL, HFILL }},
    { &hf_denm_ptActivationType,
      { "ptActivationType", "denm.ptActivationType",
        FT_UINT32, BASE_DEC, VALS(denm_PtActivationType_vals), 0,
        NULL, HFILL }},
    { &hf_denm_ptActivationData,
      { "ptActivationData", "denm.ptActivationData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_causeCode,
      { "causeCode", "denm.causeCode",
        FT_UINT32, BASE_DEC, VALS(denm_CauseCodeType_vals), 0,
        "CauseCodeType", HFILL }},
    { &hf_denm_subCauseCode,
      { "subCauseCode", "denm.subCauseCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubCauseCodeType", HFILL }},
    { &hf_denm_curvatureValue,
      { "curvatureValue", "denm.curvatureValue",
        FT_INT32, BASE_DEC, VALS(denm_CurvatureValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_curvatureConfidence,
      { "curvatureConfidence", "denm.curvatureConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_CurvatureConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_denm_headingValue,
      { "headingValue", "denm.headingValue",
        FT_UINT32, BASE_DEC, VALS(denm_HeadingValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_headingConfidence,
      { "headingConfidence", "denm.headingConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_HeadingConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_denm_innerhardShoulderStatus,
      { "innerhardShoulderStatus", "denm.innerhardShoulderStatus",
        FT_UINT32, BASE_DEC, VALS(denm_HardShoulderStatus_vals), 0,
        "HardShoulderStatus", HFILL }},
    { &hf_denm_outerhardShoulderStatus,
      { "outerhardShoulderStatus", "denm.outerhardShoulderStatus",
        FT_UINT32, BASE_DEC, VALS(denm_HardShoulderStatus_vals), 0,
        "HardShoulderStatus", HFILL }},
    { &hf_denm_drivingLaneStatus,
      { "drivingLaneStatus", "denm.drivingLaneStatus",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_speedValue,
      { "speedValue", "denm.speedValue",
        FT_UINT32, BASE_DEC, VALS(denm_SpeedValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_speedConfidence,
      { "speedConfidence", "denm.speedConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_SpeedConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_denm_longitudinalAccelerationValue,
      { "longitudinalAccelerationValue", "denm.longitudinalAccelerationValue",
        FT_INT32, BASE_DEC, VALS(denm_LongitudinalAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_longitudinalAccelerationConfidence,
      { "longitudinalAccelerationConfidence", "denm.longitudinalAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_denm_lateralAccelerationValue,
      { "lateralAccelerationValue", "denm.lateralAccelerationValue",
        FT_INT32, BASE_DEC, VALS(denm_LateralAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_lateralAccelerationConfidence,
      { "lateralAccelerationConfidence", "denm.lateralAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_denm_verticalAccelerationValue,
      { "verticalAccelerationValue", "denm.verticalAccelerationValue",
        FT_INT32, BASE_DEC, VALS(denm_VerticalAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_verticalAccelerationConfidence,
      { "verticalAccelerationConfidence", "denm.verticalAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_denm_dangerousGoodsType,
      { "dangerousGoodsType", "denm.dangerousGoodsType",
        FT_UINT32, BASE_DEC, VALS(denm_DangerousGoodsBasic_vals), 0,
        "DangerousGoodsBasic", HFILL }},
    { &hf_denm_unNumber,
      { "unNumber", "denm.unNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9999", HFILL }},
    { &hf_denm_elevatedTemperature,
      { "elevatedTemperature", "denm.elevatedTemperature",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_denm_tunnelsRestricted,
      { "tunnelsRestricted", "denm.tunnelsRestricted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_denm_limitedQuantity,
      { "limitedQuantity", "denm.limitedQuantity",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_denm_emergencyActionCode,
      { "emergencyActionCode", "denm.emergencyActionCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_24", HFILL }},
    { &hf_denm_phoneNumber,
      { "phoneNumber", "denm.phoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_companyName,
      { "companyName", "denm.companyName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_wMInumber,
      { "wMInumber", "denm.wMInumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_vDS,
      { "vDS", "denm.vDS",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_vehicleLengthValue,
      { "vehicleLengthValue", "denm.vehicleLengthValue",
        FT_UINT32, BASE_DEC, VALS(denm_VehicleLengthValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_vehicleLengthConfidenceIndication,
      { "vehicleLengthConfidenceIndication", "denm.vehicleLengthConfidenceIndication",
        FT_UINT32, BASE_DEC, VALS(denm_VehicleLengthConfidenceIndication_vals), 0,
        NULL, HFILL }},
    { &hf_denm_PathHistory_item,
      { "PathPoint", "denm.PathPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_steeringWheelAngleValue,
      { "steeringWheelAngleValue", "denm.steeringWheelAngleValue",
        FT_INT32, BASE_DEC, VALS(denm_SteeringWheelAngleValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_steeringWheelAngleConfidence,
      { "steeringWheelAngleConfidence", "denm.steeringWheelAngleConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_SteeringWheelAngleConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_denm_yawRateValue,
      { "yawRateValue", "denm.yawRateValue",
        FT_INT32, BASE_DEC, VALS(denm_YawRateValue_vals), 0,
        NULL, HFILL }},
    { &hf_denm_yawRateConfidence,
      { "yawRateConfidence", "denm.yawRateConfidence",
        FT_UINT32, BASE_DEC, VALS(denm_YawRateConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_denm_originatingStationID,
      { "originatingStationID", "denm.originatingStationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StationID", HFILL }},
    { &hf_denm_sequenceNumber,
      { "sequenceNumber", "denm.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_ItineraryPath_item,
      { "ReferencePosition", "denm.ReferencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_protectedZoneType,
      { "protectedZoneType", "denm.protectedZoneType",
        FT_UINT32, BASE_DEC, VALS(denm_ProtectedZoneType_vals), 0,
        NULL, HFILL }},
    { &hf_denm_expiryTime,
      { "expiryTime", "denm.expiryTime",
        FT_UINT64, BASE_DEC, VALS(denm_TimestampIts_vals), 0,
        "TimestampIts", HFILL }},
    { &hf_denm_protectedZoneLatitude,
      { "protectedZoneLatitude", "denm.protectedZoneLatitude",
        FT_INT32, BASE_DEC, VALS(denm_Latitude_vals), 0,
        "Latitude", HFILL }},
    { &hf_denm_protectedZoneLongitude,
      { "protectedZoneLongitude", "denm.protectedZoneLongitude",
        FT_INT32, BASE_DEC, VALS(denm_Longitude_vals), 0,
        "Longitude", HFILL }},
    { &hf_denm_protectedZoneRadius,
      { "protectedZoneRadius", "denm.protectedZoneRadius",
        FT_UINT32, BASE_DEC, VALS(denm_ProtectedZoneRadius_vals), 0,
        NULL, HFILL }},
    { &hf_denm_protectedZoneID,
      { "protectedZoneID", "denm.protectedZoneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_Traces_item,
      { "PathHistory", "denm.PathHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_PositionOfPillars_item,
      { "PosPillar", "denm.PosPillar",
        FT_UINT32, BASE_DEC, VALS(denm_PosPillar_vals), 0,
        NULL, HFILL }},
    { &hf_denm_RestrictedTypes_item,
      { "StationType", "denm.StationType",
        FT_UINT32, BASE_DEC, VALS(denm_StationType_vals), 0,
        NULL, HFILL }},
    { &hf_denm_EventHistory_item,
      { "EventPoint", "denm.EventPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_eventPosition,
      { "eventPosition", "denm.eventPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_denm_eventDeltaTime,
      { "eventDeltaTime", "denm.eventDeltaTime",
        FT_UINT32, BASE_DEC, VALS(denm_PathDeltaTime_vals), 0,
        "PathDeltaTime", HFILL }},
    { &hf_denm_informationQuality,
      { "informationQuality", "denm.informationQuality",
        FT_UINT32, BASE_DEC, VALS(denm_InformationQuality_vals), 0,
        NULL, HFILL }},
    { &hf_denm_ProtectedCommunicationZonesRSU_item,
      { "ProtectedCommunicationZone", "denm.ProtectedCommunicationZone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_cenDsrcTollingZoneID,
      { "cenDsrcTollingZoneID", "denm.cenDsrcTollingZoneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_DigitalMap_item,
      { "ReferencePosition", "denm.ReferencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_header,
      { "header", "denm.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ItsPduHeader", HFILL }},
    { &hf_denm_denm,
      { "denm", "denm.denm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DecentralizedEnvironmentalNotificationMessage", HFILL }},
    { &hf_denm_management,
      { "management", "denm.management_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ManagementContainer", HFILL }},
    { &hf_denm_situation,
      { "situation", "denm.situation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SituationContainer", HFILL }},
    { &hf_denm_location,
      { "location", "denm.location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocationContainer", HFILL }},
    { &hf_denm_alacarte,
      { "alacarte", "denm.alacarte_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlacarteContainer", HFILL }},
    { &hf_denm_actionID,
      { "actionID", "denm.actionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_detectionTime,
      { "detectionTime", "denm.detectionTime",
        FT_UINT64, BASE_DEC, VALS(denm_TimestampIts_vals), 0,
        "TimestampIts", HFILL }},
    { &hf_denm_referenceTime,
      { "referenceTime", "denm.referenceTime",
        FT_UINT64, BASE_DEC, VALS(denm_TimestampIts_vals), 0,
        "TimestampIts", HFILL }},
    { &hf_denm_termination,
      { "termination", "denm.termination",
        FT_UINT32, BASE_DEC, VALS(denm_Termination_vals), 0,
        NULL, HFILL }},
    { &hf_denm_eventPosition_01,
      { "eventPosition", "denm.eventPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferencePosition", HFILL }},
    { &hf_denm_relevanceDistance,
      { "relevanceDistance", "denm.relevanceDistance",
        FT_UINT32, BASE_DEC, VALS(denm_RelevanceDistance_vals), 0,
        NULL, HFILL }},
    { &hf_denm_relevanceTrafficDirection,
      { "relevanceTrafficDirection", "denm.relevanceTrafficDirection",
        FT_UINT32, BASE_DEC, VALS(denm_RelevanceTrafficDirection_vals), 0,
        NULL, HFILL }},
    { &hf_denm_validityDuration,
      { "validityDuration", "denm.validityDuration",
        FT_UINT32, BASE_DEC, VALS(denm_ValidityDuration_vals), 0,
        NULL, HFILL }},
    { &hf_denm_transmissionInterval,
      { "transmissionInterval", "denm.transmissionInterval",
        FT_UINT32, BASE_DEC, VALS(denm_TransmissionInterval_vals), 0,
        NULL, HFILL }},
    { &hf_denm_stationType,
      { "stationType", "denm.stationType",
        FT_UINT32, BASE_DEC, VALS(denm_StationType_vals), 0,
        NULL, HFILL }},
    { &hf_denm_eventType,
      { "eventType", "denm.eventType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CauseCode", HFILL }},
    { &hf_denm_linkedCause,
      { "linkedCause", "denm.linkedCause_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CauseCode", HFILL }},
    { &hf_denm_eventHistory,
      { "eventHistory", "denm.eventHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_eventSpeed,
      { "eventSpeed", "denm.eventSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Speed", HFILL }},
    { &hf_denm_eventPositionHeading,
      { "eventPositionHeading", "denm.eventPositionHeading_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Heading", HFILL }},
    { &hf_denm_traces,
      { "traces", "denm.traces",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_roadType,
      { "roadType", "denm.roadType",
        FT_UINT32, BASE_DEC, VALS(denm_RoadType_vals), 0,
        NULL, HFILL }},
    { &hf_denm_heightLonCarrLeft,
      { "heightLonCarrLeft", "denm.heightLonCarrLeft",
        FT_UINT32, BASE_DEC, VALS(denm_HeightLonCarr_vals), 0,
        "HeightLonCarr", HFILL }},
    { &hf_denm_heightLonCarrRight,
      { "heightLonCarrRight", "denm.heightLonCarrRight",
        FT_UINT32, BASE_DEC, VALS(denm_HeightLonCarr_vals), 0,
        "HeightLonCarr", HFILL }},
    { &hf_denm_posLonCarrLeft,
      { "posLonCarrLeft", "denm.posLonCarrLeft",
        FT_UINT32, BASE_DEC, VALS(denm_PosLonCarr_vals), 0,
        "PosLonCarr", HFILL }},
    { &hf_denm_posLonCarrRight,
      { "posLonCarrRight", "denm.posLonCarrRight",
        FT_UINT32, BASE_DEC, VALS(denm_PosLonCarr_vals), 0,
        "PosLonCarr", HFILL }},
    { &hf_denm_positionOfPillars,
      { "positionOfPillars", "denm.positionOfPillars",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_posCentMass,
      { "posCentMass", "denm.posCentMass",
        FT_UINT32, BASE_DEC, VALS(denm_PosCentMass_vals), 0,
        NULL, HFILL }},
    { &hf_denm_wheelBaseVehicle,
      { "wheelBaseVehicle", "denm.wheelBaseVehicle",
        FT_UINT32, BASE_DEC, VALS(denm_WheelBaseVehicle_vals), 0,
        NULL, HFILL }},
    { &hf_denm_turningRadius,
      { "turningRadius", "denm.turningRadius",
        FT_UINT32, BASE_DEC, VALS(denm_TurningRadius_vals), 0,
        NULL, HFILL }},
    { &hf_denm_posFrontAx,
      { "posFrontAx", "denm.posFrontAx",
        FT_UINT32, BASE_DEC, VALS(denm_PosFrontAx_vals), 0,
        NULL, HFILL }},
    { &hf_denm_positionOfOccupants,
      { "positionOfOccupants", "denm.positionOfOccupants",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_vehicleMass,
      { "vehicleMass", "denm.vehicleMass",
        FT_UINT32, BASE_DEC, VALS(denm_VehicleMass_vals), 0,
        NULL, HFILL }},
    { &hf_denm_requestResponseIndication,
      { "requestResponseIndication", "denm.requestResponseIndication",
        FT_UINT32, BASE_DEC, VALS(denm_RequestResponseIndication_vals), 0,
        NULL, HFILL }},
    { &hf_denm_lightBarSirenInUse,
      { "lightBarSirenInUse", "denm.lightBarSirenInUse",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_closedLanes,
      { "closedLanes", "denm.closedLanes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_restriction,
      { "restriction", "denm.restriction",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictedTypes", HFILL }},
    { &hf_denm_speedLimit,
      { "speedLimit", "denm.speedLimit",
        FT_UINT32, BASE_DEC, VALS(denm_SpeedLimit_vals), 0,
        NULL, HFILL }},
    { &hf_denm_incidentIndication,
      { "incidentIndication", "denm.incidentIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CauseCode", HFILL }},
    { &hf_denm_recommendedPath,
      { "recommendedPath", "denm.recommendedPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ItineraryPath", HFILL }},
    { &hf_denm_startingPointSpeedLimit,
      { "startingPointSpeedLimit", "denm.startingPointSpeedLimit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_denm_trafficFlowRule,
      { "trafficFlowRule", "denm.trafficFlowRule",
        FT_UINT32, BASE_DEC, VALS(denm_TrafficRule_vals), 0,
        "TrafficRule", HFILL }},
    { &hf_denm_referenceDenms,
      { "referenceDenms", "denm.referenceDenms",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_stationarySince,
      { "stationarySince", "denm.stationarySince",
        FT_UINT32, BASE_DEC, VALS(denm_StationarySince_vals), 0,
        NULL, HFILL }},
    { &hf_denm_stationaryCause,
      { "stationaryCause", "denm.stationaryCause_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CauseCode", HFILL }},
    { &hf_denm_carryingDangerousGoods,
      { "carryingDangerousGoods", "denm.carryingDangerousGoods_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DangerousGoodsExtended", HFILL }},
    { &hf_denm_numberOfOccupants,
      { "numberOfOccupants", "denm.numberOfOccupants",
        FT_UINT32, BASE_DEC, VALS(denm_NumberOfOccupants_vals), 0,
        NULL, HFILL }},
    { &hf_denm_vehicleIdentification,
      { "vehicleIdentification", "denm.vehicleIdentification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_energyStorageType,
      { "energyStorageType", "denm.energyStorageType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_lanePosition,
      { "lanePosition", "denm.lanePosition",
        FT_INT32, BASE_DEC, VALS(denm_LanePosition_vals), 0,
        NULL, HFILL }},
    { &hf_denm_impactReduction,
      { "impactReduction", "denm.impactReduction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ImpactReductionContainer", HFILL }},
    { &hf_denm_externalTemperature,
      { "externalTemperature", "denm.externalTemperature",
        FT_INT32, BASE_DEC, VALS(denm_Temperature_vals), 0,
        "Temperature", HFILL }},
    { &hf_denm_roadWorks,
      { "roadWorks", "denm.roadWorks_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RoadWorksContainerExtended", HFILL }},
    { &hf_denm_positioningSolution,
      { "positioningSolution", "denm.positioningSolution",
        FT_UINT32, BASE_DEC, VALS(denm_PositioningSolutionType_vals), 0,
        "PositioningSolutionType", HFILL }},
    { &hf_denm_stationaryVehicle,
      { "stationaryVehicle", "denm.stationaryVehicle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StationaryVehicleContainer", HFILL }},
    { &hf_denm_ReferenceDenms_item,
      { "ActionID", "denm.ActionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_denm_AccelerationControl_brakePedalEngaged,
      { "brakePedalEngaged", "denm.brakePedalEngaged",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_AccelerationControl_gasPedalEngaged,
      { "gasPedalEngaged", "denm.gasPedalEngaged",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_denm_AccelerationControl_emergencyBrakeEngaged,
      { "emergencyBrakeEngaged", "denm.emergencyBrakeEngaged",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_denm_AccelerationControl_collisionWarningEngaged,
      { "collisionWarningEngaged", "denm.collisionWarningEngaged",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_denm_AccelerationControl_accEngaged,
      { "accEngaged", "denm.accEngaged",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_denm_AccelerationControl_cruiseControlEngaged,
      { "cruiseControlEngaged", "denm.cruiseControlEngaged",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_denm_AccelerationControl_speedLimiterEngaged,
      { "speedLimiterEngaged", "denm.speedLimiterEngaged",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_denm_ExteriorLights_lowBeamHeadlightsOn,
      { "lowBeamHeadlightsOn", "denm.lowBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_ExteriorLights_highBeamHeadlightsOn,
      { "highBeamHeadlightsOn", "denm.highBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_denm_ExteriorLights_leftTurnSignalOn,
      { "leftTurnSignalOn", "denm.leftTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_denm_ExteriorLights_rightTurnSignalOn,
      { "rightTurnSignalOn", "denm.rightTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_denm_ExteriorLights_daytimeRunningLightsOn,
      { "daytimeRunningLightsOn", "denm.daytimeRunningLightsOn",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_denm_ExteriorLights_reverseLightOn,
      { "reverseLightOn", "denm.reverseLightOn",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_denm_ExteriorLights_fogLightOn,
      { "fogLightOn", "denm.fogLightOn",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_denm_ExteriorLights_parkingLightsOn,
      { "parkingLightsOn", "denm.parkingLightsOn",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_denm_SpecialTransportType_heavyLoad,
      { "heavyLoad", "denm.heavyLoad",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_SpecialTransportType_excessWidth,
      { "excessWidth", "denm.excessWidth",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_denm_SpecialTransportType_excessLength,
      { "excessLength", "denm.excessLength",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_denm_SpecialTransportType_excessHeight,
      { "excessHeight", "denm.excessHeight",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_denm_LightBarSirenInUse_lightBarActivated,
      { "lightBarActivated", "denm.lightBarActivated",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_LightBarSirenInUse_sirenActivated,
      { "sirenActivated", "denm.sirenActivated",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row1LeftOccupied,
      { "row1LeftOccupied", "denm.row1LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row1RightOccupied,
      { "row1RightOccupied", "denm.row1RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row1MidOccupied,
      { "row1MidOccupied", "denm.row1MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row1NotDetectable,
      { "row1NotDetectable", "denm.row1NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row1NotPresent,
      { "row1NotPresent", "denm.row1NotPresent",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row2LeftOccupied,
      { "row2LeftOccupied", "denm.row2LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row2RightOccupied,
      { "row2RightOccupied", "denm.row2RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row2MidOccupied,
      { "row2MidOccupied", "denm.row2MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row2NotDetectable,
      { "row2NotDetectable", "denm.row2NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row2NotPresent,
      { "row2NotPresent", "denm.row2NotPresent",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row3LeftOccupied,
      { "row3LeftOccupied", "denm.row3LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row3RightOccupied,
      { "row3RightOccupied", "denm.row3RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row3MidOccupied,
      { "row3MidOccupied", "denm.row3MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row3NotDetectable,
      { "row3NotDetectable", "denm.row3NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row3NotPresent,
      { "row3NotPresent", "denm.row3NotPresent",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row4LeftOccupied,
      { "row4LeftOccupied", "denm.row4LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row4RightOccupied,
      { "row4RightOccupied", "denm.row4RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row4MidOccupied,
      { "row4MidOccupied", "denm.row4MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row4NotDetectable,
      { "row4NotDetectable", "denm.row4NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_denm_PositionOfOccupants_row4NotPresent,
      { "row4NotPresent", "denm.row4NotPresent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_denm_EnergyStorageType_hydrogenStorage,
      { "hydrogenStorage", "denm.hydrogenStorage",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_EnergyStorageType_electricEnergyStorage,
      { "electricEnergyStorage", "denm.electricEnergyStorage",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_denm_EnergyStorageType_liquidPropaneGas,
      { "liquidPropaneGas", "denm.liquidPropaneGas",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_denm_EnergyStorageType_compressedNaturalGas,
      { "compressedNaturalGas", "denm.compressedNaturalGas",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_denm_EnergyStorageType_diesel,
      { "diesel", "denm.diesel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_denm_EnergyStorageType_gasoline,
      { "gasoline", "denm.gasoline",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_denm_EnergyStorageType_ammonia,
      { "ammonia", "denm.ammonia",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_denm_EmergencyPriority_requestForRightOfWay,
      { "requestForRightOfWay", "denm.requestForRightOfWay",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_denm_EmergencyPriority_requestForFreeCrossingAtATrafficLight,
      { "requestForFreeCrossingAtATrafficLight", "denm.requestForFreeCrossingAtATrafficLight",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

/*--- End of included file: packet-denm-hfarr.c ---*/
#line 101 "./asn1/denm/packet-denm-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_denm,

/*--- Included file: packet-denm-ettarr.c ---*/
#line 1 "./asn1/denm/packet-denm-ettarr.c"
    &ett_denm_ItsPduHeader,
    &ett_denm_ReferencePosition,
    &ett_denm_DeltaReferencePosition,
    &ett_denm_Altitude,
    &ett_denm_PosConfidenceEllipse,
    &ett_denm_PathPoint,
    &ett_denm_PtActivation,
    &ett_denm_AccelerationControl,
    &ett_denm_CauseCode,
    &ett_denm_Curvature,
    &ett_denm_Heading,
    &ett_denm_ClosedLanes,
    &ett_denm_Speed,
    &ett_denm_LongitudinalAcceleration,
    &ett_denm_LateralAcceleration,
    &ett_denm_VerticalAcceleration,
    &ett_denm_ExteriorLights,
    &ett_denm_DangerousGoodsExtended,
    &ett_denm_SpecialTransportType,
    &ett_denm_LightBarSirenInUse,
    &ett_denm_PositionOfOccupants,
    &ett_denm_VehicleIdentification,
    &ett_denm_EnergyStorageType,
    &ett_denm_VehicleLength,
    &ett_denm_PathHistory,
    &ett_denm_EmergencyPriority,
    &ett_denm_SteeringWheelAngle,
    &ett_denm_YawRate,
    &ett_denm_ActionID,
    &ett_denm_ItineraryPath,
    &ett_denm_ProtectedCommunicationZone,
    &ett_denm_Traces,
    &ett_denm_PositionOfPillars,
    &ett_denm_RestrictedTypes,
    &ett_denm_EventHistory,
    &ett_denm_EventPoint,
    &ett_denm_ProtectedCommunicationZonesRSU,
    &ett_denm_CenDsrcTollingZone,
    &ett_denm_DigitalMap,
    &ett_denm_DENM,
    &ett_denm_DecentralizedEnvironmentalNotificationMessage,
    &ett_denm_ManagementContainer,
    &ett_denm_SituationContainer,
    &ett_denm_LocationContainer,
    &ett_denm_ImpactReductionContainer,
    &ett_denm_RoadWorksContainerExtended,
    &ett_denm_StationaryVehicleContainer,
    &ett_denm_AlacarteContainer,
    &ett_denm_ReferenceDenms,

/*--- End of included file: packet-denm-ettarr.c ---*/
#line 107 "./asn1/denm/packet-denm-template.c"
  };


  /* Register protocol */
  proto_denm = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("denm", dissect_denm, proto_denm);

  /* Register fields and subtrees */
  proto_register_field_array(proto_denm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register preferences module */
  denm_module = prefs_register_protocol(proto_denm, proto_reg_handoff_denm);

  /* Register a sample port preference   */
  prefs_register_uint_preference(denm_module, "btp.dport", "BTP destination port",
				 "BTP destination port",
				 10, &global_denm_port);

}


/*--- proto_reg_handoff_denm ---------------------------------------*/
void
proto_reg_handoff_denm(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t denm_handle;
  static guint16 denm_port;

  if (!initialized) {
    denm_handle = create_dissector_handle(dissect_denm, proto_denm);
    dissector_add_for_decode_as("btp.dport", denm_handle);
    initialized = TRUE;
  } else {
    if (denm_port != 0) {
      dissector_delete_uint("btp.dport", denm_port, denm_handle);
    }
  }
  if (global_denm_port != 0) {
    dissector_add_uint("btp.dport", global_denm_port, denm_handle);
  }
  denm_port = global_denm_port;
}
