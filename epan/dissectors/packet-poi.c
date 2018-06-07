/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-poi.c                                                               */
/* asn2wrs.py -p poi -c ./poi.cnf -s ./packet-poi-template -D . -O ../.. ITS-Container.asn EVCSN-PDU-Descriptions.asn */

/* Input file: packet-poi-template.c */

#line 1 "./asn1/poi/packet-poi-template.c"
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


/*--- Included file: packet-poi-hf.c ---*/
#line 1 "./asn1/poi/packet-poi-hf.c"
static int hf_poi_EvcsnPdu_PDU = -1;              /* EvcsnPdu */
static int hf_poi_protocolVersion = -1;           /* T_protocolVersion */
static int hf_poi_messageID = -1;                 /* T_messageID */
static int hf_poi_stationID = -1;                 /* StationID */
static int hf_poi_latitude = -1;                  /* Latitude */
static int hf_poi_longitude = -1;                 /* Longitude */
static int hf_poi_positionConfidenceEllipse = -1;  /* PosConfidenceEllipse */
static int hf_poi_altitude = -1;                  /* Altitude */
static int hf_poi_deltaLatitude = -1;             /* DeltaLatitude */
static int hf_poi_deltaLongitude = -1;            /* DeltaLongitude */
static int hf_poi_deltaAltitude = -1;             /* DeltaAltitude */
static int hf_poi_altitudeValue = -1;             /* AltitudeValue */
static int hf_poi_altitudeConfidence = -1;        /* AltitudeConfidence */
static int hf_poi_semiMajorConfidence = -1;       /* SemiAxisLength */
static int hf_poi_semiMinorConfidence = -1;       /* SemiAxisLength */
static int hf_poi_semiMajorOrientation = -1;      /* HeadingValue */
static int hf_poi_pathPosition = -1;              /* DeltaReferencePosition */
static int hf_poi_pathDeltaTime = -1;             /* PathDeltaTime */
static int hf_poi_ptActivationType = -1;          /* PtActivationType */
static int hf_poi_ptActivationData = -1;          /* PtActivationData */
static int hf_poi_causeCode = -1;                 /* CauseCodeType */
static int hf_poi_subCauseCode = -1;              /* SubCauseCodeType */
static int hf_poi_curvatureValue = -1;            /* CurvatureValue */
static int hf_poi_curvatureConfidence = -1;       /* CurvatureConfidence */
static int hf_poi_headingValue = -1;              /* HeadingValue */
static int hf_poi_headingConfidence = -1;         /* HeadingConfidence */
static int hf_poi_hardShoulderStatus = -1;        /* HardShoulderStatus */
static int hf_poi_drivingLaneStatus = -1;         /* DrivingLaneStatus */
static int hf_poi_speedValue = -1;                /* SpeedValue */
static int hf_poi_speedConfidence = -1;           /* SpeedConfidence */
static int hf_poi_longitudinalAccelerationValue = -1;  /* LongitudinalAccelerationValue */
static int hf_poi_longitudinalAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_poi_lateralAccelerationValue = -1;  /* LateralAccelerationValue */
static int hf_poi_lateralAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_poi_verticalAccelerationValue = -1;  /* VerticalAccelerationValue */
static int hf_poi_verticalAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_poi_dangerousGoodsType = -1;        /* DangerousGoodsBasic */
static int hf_poi_unNumber = -1;                  /* INTEGER_0_9999 */
static int hf_poi_elevatedTemperature = -1;       /* BOOLEAN */
static int hf_poi_tunnelsRestricted = -1;         /* BOOLEAN */
static int hf_poi_limitedQuantity = -1;           /* BOOLEAN */
static int hf_poi_emergencyActionCode = -1;       /* IA5String_SIZE_1_24 */
static int hf_poi_phoneNumber = -1;               /* IA5String_SIZE_1_24 */
static int hf_poi_companyName = -1;               /* T_companyName */
static int hf_poi_wMInumber = -1;                 /* WMInumber */
static int hf_poi_vDS = -1;                       /* VDS */
static int hf_poi_vehicleLengthValue = -1;        /* VehicleLengthValue */
static int hf_poi_vehicleLengthConfidenceIndication = -1;  /* VehicleLengthConfidenceIndication */
static int hf_poi_PathHistory_item = -1;          /* PathPoint */
static int hf_poi_steeringWheelAngleValue = -1;   /* SteeringWheelAngleValue */
static int hf_poi_steeringWheelAngleConfidence = -1;  /* SteeringWheelAngleConfidence */
static int hf_poi_yawRateValue = -1;              /* YawRateValue */
static int hf_poi_yawRateConfidence = -1;         /* YawRateConfidence */
static int hf_poi_originatingStationID = -1;      /* StationID */
static int hf_poi_sequenceNumber = -1;            /* SequenceNumber */
static int hf_poi_ItineraryPath_item = -1;        /* ReferencePosition */
static int hf_poi_protectedZoneType = -1;         /* ProtectedZoneType */
static int hf_poi_expiryTime = -1;                /* TimestampIts */
static int hf_poi_protectedZoneLatitude = -1;     /* Latitude */
static int hf_poi_protectedZoneLongitude = -1;    /* Longitude */
static int hf_poi_protectedZoneRadius = -1;       /* ProtectedZoneRadius */
static int hf_poi_protectedZoneID = -1;           /* ProtectedZoneID */
static int hf_poi_Traces_item = -1;               /* PathHistory */
static int hf_poi_PositionOfPillars_item = -1;    /* PosPillar */
static int hf_poi_RestrictedTypes_item = -1;      /* StationType */
static int hf_poi_EventHistory_item = -1;         /* EventPoint */
static int hf_poi_eventPosition = -1;             /* DeltaReferencePosition */
static int hf_poi_eventDeltaTime = -1;            /* PathDeltaTime */
static int hf_poi_informationQuality = -1;        /* InformationQuality */
static int hf_poi_ProtectedCommunicationZonesRSU_item = -1;  /* ProtectedCommunicationZone */
static int hf_poi_cenDsrcTollingZoneID = -1;      /* CenDsrcTollingZoneID */
static int hf_poi_header = -1;                    /* ItsPduHeader */
static int hf_poi_evcsn = -1;                     /* EVChargingSpotNotificationPOIMessage */
static int hf_poi_poiHeader = -1;                 /* ItsPOIHeader */
static int hf_poi_evcsnData = -1;                 /* ItsEVCSNData */
static int hf_poi_poiType = -1;                   /* POIType */
static int hf_poi_timeStamp = -1;                 /* TimestampIts */
static int hf_poi_relayCapable = -1;              /* BOOLEAN */
static int hf_poi_totalNumberOfStations = -1;     /* NumberStations */
static int hf_poi_chargingStationsData = -1;      /* SEQUENCE_SIZE_1_256_OF_ItsChargingStationData */
static int hf_poi_chargingStationsData_item = -1;  /* ItsChargingStationData */
static int hf_poi_chargingStationID = -1;         /* StationID */
static int hf_poi_utilityDistributorId = -1;      /* UTF8String_SIZE_1_32 */
static int hf_poi_providerID = -1;                /* UTF8String_SIZE_1_32 */
static int hf_poi_chargingStationLocation = -1;   /* ReferencePosition */
static int hf_poi_address = -1;                   /* UTF8String */
static int hf_poi_phoneNumber_01 = -1;            /* NumericString_SIZE_1_16 */
static int hf_poi_accessibility = -1;             /* UTF8String_SIZE_1_32 */
static int hf_poi_digitalMap = -1;                /* DigitalMap */
static int hf_poi_openingDaysHours = -1;          /* UTF8String */
static int hf_poi_pricing = -1;                   /* UTF8String */
static int hf_poi_bookingContactInfo = -1;        /* UTF8String */
static int hf_poi_payment = -1;                   /* UTF8String */
static int hf_poi_chargingSpotsAvailable = -1;    /* ItsChargingSpots */
static int hf_poi_ItsChargingSpots_item = -1;     /* ItsChargingSpotDataElements */
static int hf_poi_type = -1;                      /* ChargingSpotType */
static int hf_poi_evEquipmentID = -1;             /* UTF8String */
static int hf_poi_typeOfReceptacle = -1;          /* TypeOfReceptacle */
static int hf_poi_energyAvailability = -1;        /* UTF8String */
static int hf_poi_parkingPlacesData = -1;         /* ParkingPlacesData */
static int hf_poi_DigitalMap_item = -1;           /* ReferencePosition */
static int hf_poi_ParkingPlacesData_item = -1;    /* SpotAvailability */
static int hf_poi_maxWaitingTimeMinutes = -1;     /* INTEGER_0_1400 */
static int hf_poi_blocking = -1;                  /* BOOLEAN */
/* named bits */
static int hf_poi_AccelerationControl_brakePedalEngaged = -1;
static int hf_poi_AccelerationControl_gasPedalEngaged = -1;
static int hf_poi_AccelerationControl_emergencyBrakeEngaged = -1;
static int hf_poi_AccelerationControl_collisionWarningEngaged = -1;
static int hf_poi_AccelerationControl_accEngaged = -1;
static int hf_poi_AccelerationControl_cruiseControlEngaged = -1;
static int hf_poi_AccelerationControl_speedLimiterEngaged = -1;
static int hf_poi_ExteriorLights_lowBeamHeadlightsOn = -1;
static int hf_poi_ExteriorLights_highBeamHeadlightsOn = -1;
static int hf_poi_ExteriorLights_leftTurnSignalOn = -1;
static int hf_poi_ExteriorLights_rightTurnSignalOn = -1;
static int hf_poi_ExteriorLights_daytimeRunningLightsOn = -1;
static int hf_poi_ExteriorLights_reverseLightOn = -1;
static int hf_poi_ExteriorLights_fogLightOn = -1;
static int hf_poi_ExteriorLights_parkingLightsOn = -1;
static int hf_poi_SpecialTransportType_heavyLoad = -1;
static int hf_poi_SpecialTransportType_excessWidth = -1;
static int hf_poi_SpecialTransportType_excessLength = -1;
static int hf_poi_SpecialTransportType_excessHeight = -1;
static int hf_poi_LightBarSirenInUse_lightBarActivated = -1;
static int hf_poi_LightBarSirenInUse_sirenActivated = -1;
static int hf_poi_PositionOfOccupants_row1LeftOccupied = -1;
static int hf_poi_PositionOfOccupants_row1RightOccupied = -1;
static int hf_poi_PositionOfOccupants_row1MidOccupied = -1;
static int hf_poi_PositionOfOccupants_row1NotDetectable = -1;
static int hf_poi_PositionOfOccupants_row1NotPresent = -1;
static int hf_poi_PositionOfOccupants_row2LeftOccupied = -1;
static int hf_poi_PositionOfOccupants_row2RightOccupied = -1;
static int hf_poi_PositionOfOccupants_row2MidOccupied = -1;
static int hf_poi_PositionOfOccupants_row2NotDetectable = -1;
static int hf_poi_PositionOfOccupants_row2NotPresent = -1;
static int hf_poi_PositionOfOccupants_row3LeftOccupied = -1;
static int hf_poi_PositionOfOccupants_row3RightOccupied = -1;
static int hf_poi_PositionOfOccupants_row3MidOccupied = -1;
static int hf_poi_PositionOfOccupants_row3NotDetectable = -1;
static int hf_poi_PositionOfOccupants_row3NotPresent = -1;
static int hf_poi_PositionOfOccupants_row4LeftOccupied = -1;
static int hf_poi_PositionOfOccupants_row4RightOccupied = -1;
static int hf_poi_PositionOfOccupants_row4MidOccupied = -1;
static int hf_poi_PositionOfOccupants_row4NotDetectable = -1;
static int hf_poi_PositionOfOccupants_row4NotPresent = -1;
static int hf_poi_EnergyStorageType_hydrogenStorage = -1;
static int hf_poi_EnergyStorageType_electricEnergyStorage = -1;
static int hf_poi_EnergyStorageType_liquidPropaneGas = -1;
static int hf_poi_EnergyStorageType_compressedNaturalGas = -1;
static int hf_poi_EnergyStorageType_diesel = -1;
static int hf_poi_EnergyStorageType_gasoline = -1;
static int hf_poi_EnergyStorageType_ammonia = -1;
static int hf_poi_EmergencyPriority_requestForRightOfWay = -1;
static int hf_poi_EmergencyPriority_requestForFreeCrossingAtATrafficLight = -1;
static int hf_poi_ChargingSpotType_standardChargeMode1 = -1;
static int hf_poi_ChargingSpotType_standardChargeMode2 = -1;
static int hf_poi_ChargingSpotType_standardOrFastChargeMode3 = -1;
static int hf_poi_ChargingSpotType_fastChargeWithExternalCharger = -1;
static int hf_poi_ChargingSpotType_quickDrop = -1;
static int hf_poi_ChargingSpotType_inductiveChargeWhileStationary = -1;
static int hf_poi_ChargingSpotType_inductiveChargeWhileDriving = -1;

/*--- End of included file: packet-poi-hf.c ---*/
#line 50 "./asn1/poi/packet-poi-template.c"

/* Initialize the subtree pointers */
static int ett_poi = -1;


/*--- Included file: packet-poi-ett.c ---*/
#line 1 "./asn1/poi/packet-poi-ett.c"
static gint ett_poi_ItsPduHeader = -1;
static gint ett_poi_ReferencePosition = -1;
static gint ett_poi_DeltaReferencePosition = -1;
static gint ett_poi_Altitude = -1;
static gint ett_poi_PosConfidenceEllipse = -1;
static gint ett_poi_PathPoint = -1;
static gint ett_poi_PtActivation = -1;
static gint ett_poi_AccelerationControl = -1;
static gint ett_poi_CauseCode = -1;
static gint ett_poi_Curvature = -1;
static gint ett_poi_Heading = -1;
static gint ett_poi_ClosedLanes = -1;
static gint ett_poi_Speed = -1;
static gint ett_poi_LongitudinalAcceleration = -1;
static gint ett_poi_LateralAcceleration = -1;
static gint ett_poi_VerticalAcceleration = -1;
static gint ett_poi_ExteriorLights = -1;
static gint ett_poi_DangerousGoodsExtended = -1;
static gint ett_poi_SpecialTransportType = -1;
static gint ett_poi_LightBarSirenInUse = -1;
static gint ett_poi_PositionOfOccupants = -1;
static gint ett_poi_VehicleIdentification = -1;
static gint ett_poi_EnergyStorageType = -1;
static gint ett_poi_VehicleLength = -1;
static gint ett_poi_PathHistory = -1;
static gint ett_poi_EmergencyPriority = -1;
static gint ett_poi_SteeringWheelAngle = -1;
static gint ett_poi_YawRate = -1;
static gint ett_poi_ActionID = -1;
static gint ett_poi_ItineraryPath = -1;
static gint ett_poi_ProtectedCommunicationZone = -1;
static gint ett_poi_Traces = -1;
static gint ett_poi_PositionOfPillars = -1;
static gint ett_poi_RestrictedTypes = -1;
static gint ett_poi_EventHistory = -1;
static gint ett_poi_EventPoint = -1;
static gint ett_poi_ProtectedCommunicationZonesRSU = -1;
static gint ett_poi_CenDsrcTollingZone = -1;
static gint ett_poi_EvcsnPdu = -1;
static gint ett_poi_EVChargingSpotNotificationPOIMessage = -1;
static gint ett_poi_ItsPOIHeader = -1;
static gint ett_poi_ItsEVCSNData = -1;
static gint ett_poi_SEQUENCE_SIZE_1_256_OF_ItsChargingStationData = -1;
static gint ett_poi_ItsChargingStationData = -1;
static gint ett_poi_ItsChargingSpots = -1;
static gint ett_poi_ItsChargingSpotDataElements = -1;
static gint ett_poi_DigitalMap = -1;
static gint ett_poi_ChargingSpotType = -1;
static gint ett_poi_ParkingPlacesData = -1;
static gint ett_poi_SpotAvailability = -1;

/*--- End of included file: packet-poi-ett.c ---*/
#line 55 "./asn1/poi/packet-poi-template.c"


/*--- Included file: packet-poi-fn.c ---*/
#line 1 "./asn1/poi/packet-poi-fn.c"

static const value_string poi_T_protocolVersion_vals[] = {
  {   1, "currentVersion" },
  { 0, NULL }
};


static int
dissect_poi_T_protocolVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_T_messageID_vals[] = {
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
  { 0, NULL }
};


static int
dissect_poi_T_messageID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_poi_StationID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ItsPduHeader_sequence[] = {
  { &hf_poi_protocolVersion , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_T_protocolVersion },
  { &hf_poi_messageID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_T_messageID },
  { &hf_poi_stationID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_StationID },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ItsPduHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ItsPduHeader, ItsPduHeader_sequence);

  return offset;
}


static const value_string poi_Latitude_vals[] = {
  {  10, "oneMicrodegreeNorth" },
  { -10, "oneMicrodegreeSouth" },
  { 900000001, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_Latitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -900000000, 900000001U, NULL, FALSE);

  return offset;
}


static const value_string poi_Longitude_vals[] = {
  {  10, "oneMicrodegreeEast" },
  { -10, "oneMicrodegreeWest" },
  { 1800000001, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_Longitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1800000000, 1800000001U, NULL, FALSE);

  return offset;
}


static const value_string poi_SemiAxisLength_vals[] = {
  {   1, "oneCentimeter" },
  { 4094, "outOfRange" },
  { 4095, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_SemiAxisLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const value_string poi_HeadingValue_vals[] = {
  {   0, "wgs84North" },
  { 900, "wgs84East" },
  { 1800, "wgs84South" },
  { 2700, "wgs84West" },
  { 3601, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_HeadingValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3601U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PosConfidenceEllipse_sequence[] = {
  { &hf_poi_semiMajorConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SemiAxisLength },
  { &hf_poi_semiMinorConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SemiAxisLength },
  { &hf_poi_semiMajorOrientation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_HeadingValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_PosConfidenceEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_PosConfidenceEllipse, PosConfidenceEllipse_sequence);

  return offset;
}


static const value_string poi_AltitudeValue_vals[] = {
  {   0, "referenceEllipsoidSurface" },
  {   1, "oneCentimeter" },
  { 800001, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_AltitudeValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -100000, 800001U, NULL, FALSE);

  return offset;
}


static const value_string poi_AltitudeConfidence_vals[] = {
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
dissect_poi_AltitudeConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Altitude_sequence[] = {
  { &hf_poi_altitudeValue   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_AltitudeValue },
  { &hf_poi_altitudeConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_AltitudeConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_Altitude, Altitude_sequence);

  return offset;
}


static const per_sequence_t ReferencePosition_sequence[] = {
  { &hf_poi_latitude        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_Latitude },
  { &hf_poi_longitude       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_Longitude },
  { &hf_poi_positionConfidenceEllipse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_PosConfidenceEllipse },
  { &hf_poi_altitude        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_Altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ReferencePosition, ReferencePosition_sequence);

  return offset;
}


static const value_string poi_DeltaLatitude_vals[] = {
  {  10, "oneMicrodegreeNorth" },
  { -10, "oneMicrodegreeSouth" },
  { 131072, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_DeltaLatitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131071, 131072U, NULL, FALSE);

  return offset;
}


static const value_string poi_DeltaLongitude_vals[] = {
  {  10, "oneMicrodegreeEast" },
  { -10, "oneMicrodegreeWest" },
  { 131072, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_DeltaLongitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131071, 131072U, NULL, FALSE);

  return offset;
}


static const value_string poi_DeltaAltitude_vals[] = {
  {   1, "oneCentimeterUp" },
  {  -1, "oneCentimeterDown" },
  { 12800, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_DeltaAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -12700, 12800U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DeltaReferencePosition_sequence[] = {
  { &hf_poi_deltaLatitude   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_DeltaLatitude },
  { &hf_poi_deltaLongitude  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_DeltaLongitude },
  { &hf_poi_deltaAltitude   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_DeltaAltitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_DeltaReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_DeltaReferencePosition, DeltaReferencePosition_sequence);

  return offset;
}


static const value_string poi_PathDeltaTime_vals[] = {
  {   1, "tenMilliSecondsInPast" },
  { 0, NULL }
};


static int
dissect_poi_PathDeltaTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PathPoint_sequence[] = {
  { &hf_poi_pathPosition    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_DeltaReferencePosition },
  { &hf_poi_pathDeltaTime   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_PathDeltaTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_PathPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_PathPoint, PathPoint_sequence);

  return offset;
}


static const value_string poi_PtActivationType_vals[] = {
  {   0, "undefinedCodingType" },
  {   1, "r09-16CodingType" },
  {   2, "vdv-50149CodingType" },
  { 0, NULL }
};


static int
dissect_poi_PtActivationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_poi_PtActivationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}


static const per_sequence_t PtActivation_sequence[] = {
  { &hf_poi_ptActivationType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_PtActivationType },
  { &hf_poi_ptActivationData, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_PtActivationData },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_PtActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_PtActivation, PtActivation_sequence);

  return offset;
}



static int
dissect_poi_AccelerationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, NULL);

  return offset;
}


static const value_string poi_CauseCodeType_vals[] = {
  {   0, "reserved" },
  {   1, "trafficCondition" },
  {   2, "accident" },
  {   3, "roadworks" },
  {   6, "adverseWeatherCondition-Adhesion" },
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
dissect_poi_CauseCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_poi_SubCauseCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CauseCode_sequence[] = {
  { &hf_poi_causeCode       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_CauseCodeType },
  { &hf_poi_subCauseCode    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SubCauseCodeType },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_CauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_CauseCode, CauseCode_sequence);

  return offset;
}


static const value_string poi_TrafficConditionSubCauseCode_vals[] = {
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
dissect_poi_TrafficConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_AccidentSubCauseCode_vals[] = {
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
dissect_poi_AccidentSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_RoadworksSubCauseCode_vals[] = {
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
dissect_poi_RoadworksSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_HumanPresenceOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "childrenOnRoadway" },
  {   2, "cyclistOnRoadway" },
  {   3, "motorcyclistOnRoadway" },
  { 0, NULL }
};


static int
dissect_poi_HumanPresenceOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_WrongWayDrivingSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "wrongLane" },
  {   2, "wrongDirection" },
  { 0, NULL }
};


static int
dissect_poi_WrongWayDrivingSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_AdverseWeatherCondition_ExtremeWeatherConditionSubCauseCode_vals[] = {
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
dissect_poi_AdverseWeatherCondition_ExtremeWeatherConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_AdverseWeatherCondition_AdhesionSubCauseCode_vals[] = {
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
dissect_poi_AdverseWeatherCondition_AdhesionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_AdverseWeatherCondition_VisibilitySubCauseCode_vals[] = {
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
dissect_poi_AdverseWeatherCondition_VisibilitySubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_AdverseWeatherCondition_PrecipitationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "heavyRain" },
  {   2, "heavySnowfall" },
  {   3, "softHail" },
  { 0, NULL }
};


static int
dissect_poi_AdverseWeatherCondition_PrecipitationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_SlowVehicleSubCauseCode_vals[] = {
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
dissect_poi_SlowVehicleSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_StationaryVehicleSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "humanProblem" },
  {   2, "vehicleBreakdown" },
  {   3, "postCrash" },
  {   4, "publicTransportStop" },
  {   5, "carryingDangerousGoods" },
  { 0, NULL }
};


static int
dissect_poi_StationaryVehicleSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_HumanProblemSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "glycemiaProblem" },
  {   2, "heartProblem" },
  { 0, NULL }
};


static int
dissect_poi_HumanProblemSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_EmergencyVehicleApproachingSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyVehicleApproaching" },
  {   2, "prioritizedVehicleApproaching" },
  { 0, NULL }
};


static int
dissect_poi_EmergencyVehicleApproachingSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_HazardousLocation_DangerousCurveSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "dangerousLeftTurnCurve" },
  {   2, "dangerousRightTurnCurve" },
  {   3, "multipleCurvesStartingWithUnknownTurningDirection" },
  {   4, "multipleCurvesStartingWithLeftTurn" },
  {   5, "multipleCurvesStartingWithRightTurn" },
  { 0, NULL }
};


static int
dissect_poi_HazardousLocation_DangerousCurveSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_HazardousLocation_SurfaceConditionSubCauseCode_vals[] = {
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
dissect_poi_HazardousLocation_SurfaceConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_HazardousLocation_ObstacleOnTheRoadSubCauseCode_vals[] = {
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
dissect_poi_HazardousLocation_ObstacleOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_HazardousLocation_AnimalOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "wildAnimals" },
  {   2, "herdOfAnimals" },
  {   3, "smallAnimals" },
  {   4, "largeAnimals" },
  { 0, NULL }
};


static int
dissect_poi_HazardousLocation_AnimalOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_CollisionRiskSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "longitudinalCollisionRisk" },
  {   2, "crossingCollisionRisk" },
  {   3, "lateralCollisionRisk" },
  {   4, "vulnerableRoadUser" },
  { 0, NULL }
};


static int
dissect_poi_CollisionRiskSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_SignalViolationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "stopSignViolation" },
  {   2, "trafficLightViolation" },
  {   3, "turningRegulationViolation" },
  { 0, NULL }
};


static int
dissect_poi_SignalViolationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_RescueAndRecoveryWorkInProgressSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyVehicles" },
  {   2, "rescueHelicopterLanding" },
  {   3, "policeActivityOngoing" },
  {   4, "medicalEmergencyOngoing" },
  {   5, "childAbductionInProgress" },
  { 0, NULL }
};


static int
dissect_poi_RescueAndRecoveryWorkInProgressSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_DangerousEndOfQueueSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "suddenEndOfQueue" },
  {   2, "queueOverHill" },
  {   3, "queueAroundBend" },
  {   4, "queueInTunnel" },
  { 0, NULL }
};


static int
dissect_poi_DangerousEndOfQueueSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_DangerousSituationSubCauseCode_vals[] = {
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
dissect_poi_DangerousSituationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_VehicleBreakdownSubCauseCode_vals[] = {
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
dissect_poi_VehicleBreakdownSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_PostCrashSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "accidentWithoutECallTriggered" },
  {   2, "accidentWithECallManuallyTriggered" },
  {   3, "accidentWithECallAutomaticallyTriggered" },
  {   4, "accidentWithECallTriggeredWithoutAccessToCellularNetwork" },
  { 0, NULL }
};


static int
dissect_poi_PostCrashSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_CurvatureValue_vals[] = {
  {   0, "straight" },
  { -30000, "reciprocalOf1MeterRadiusToRight" },
  { 30000, "reciprocalOf1MeterRadiusToLeft" },
  { 30001, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_CurvatureValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30000, 30001U, NULL, FALSE);

  return offset;
}


static const value_string poi_CurvatureConfidence_vals[] = {
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
dissect_poi_CurvatureConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Curvature_sequence[] = {
  { &hf_poi_curvatureValue  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_CurvatureValue },
  { &hf_poi_curvatureConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_CurvatureConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_Curvature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_Curvature, Curvature_sequence);

  return offset;
}


static const value_string poi_CurvatureCalculationMode_vals[] = {
  {   0, "yawRateUsed" },
  {   1, "yawRateNotUsed" },
  {   2, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_CurvatureCalculationMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string poi_HeadingConfidence_vals[] = {
  {   1, "equalOrWithinZeroPointOneDegree" },
  {  10, "equalOrWithinOneDegree" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_HeadingConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Heading_sequence[] = {
  { &hf_poi_headingValue    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_HeadingValue },
  { &hf_poi_headingConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_HeadingConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_Heading(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_Heading, Heading_sequence);

  return offset;
}


static const value_string poi_LanePosition_vals[] = {
  {  -1, "offTheRoad" },
  {   0, "hardShoulder" },
  {   1, "outermostDrivingLane" },
  {   2, "secondLaneFromOutside" },
  { 0, NULL }
};


static int
dissect_poi_LanePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1, 14U, NULL, FALSE);

  return offset;
}


static const value_string poi_HardShoulderStatus_vals[] = {
  {   0, "availableForStopping" },
  {   1, "closed" },
  {   2, "availableForDriving" },
  { 0, NULL }
};


static int
dissect_poi_HardShoulderStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_poi_DrivingLaneStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 15, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t ClosedLanes_sequence[] = {
  { &hf_poi_hardShoulderStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_HardShoulderStatus },
  { &hf_poi_drivingLaneStatus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_poi_DrivingLaneStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ClosedLanes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ClosedLanes, ClosedLanes_sequence);

  return offset;
}


static const value_string poi_PerformanceClass_vals[] = {
  {   0, "unavailable" },
  {   1, "performanceClassA" },
  {   2, "performanceClassB" },
  { 0, NULL }
};


static int
dissect_poi_PerformanceClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string poi_SpeedValue_vals[] = {
  {   0, "standstill" },
  {   1, "oneCentimeterPerSec" },
  { 16383, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_SpeedValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const value_string poi_SpeedConfidence_vals[] = {
  {   1, "equalOrWithinOneCentimeterPerSec" },
  { 100, "equalOrWithinOneMeterPerSec" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_SpeedConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string poi_VehicleMass_vals[] = {
  {   1, "hundredKg" },
  { 1024, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_VehicleMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Speed_sequence[] = {
  { &hf_poi_speedValue      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SpeedValue },
  { &hf_poi_speedConfidence , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SpeedConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_Speed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_Speed, Speed_sequence);

  return offset;
}


static const value_string poi_DriveDirection_vals[] = {
  {   0, "forward" },
  {   1, "backward" },
  {   2, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_DriveDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_poi_EmbarkationStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string poi_LongitudinalAccelerationValue_vals[] = {
  {   1, "pointOneMeterPerSecSquaredForward" },
  {  -1, "pointOneMeterPerSecSquaredBackward" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_LongitudinalAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const value_string poi_AccelerationConfidence_vals[] = {
  {   1, "pointOneMeterPerSecSquared" },
  { 101, "outOfRange" },
  { 102, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_AccelerationConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 102U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LongitudinalAcceleration_sequence[] = {
  { &hf_poi_longitudinalAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_LongitudinalAccelerationValue },
  { &hf_poi_longitudinalAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_LongitudinalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_LongitudinalAcceleration, LongitudinalAcceleration_sequence);

  return offset;
}


static const value_string poi_LateralAccelerationValue_vals[] = {
  {  -1, "pointOneMeterPerSecSquaredToRight" },
  {   1, "pointOneMeterPerSecSquaredToLeft" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_LateralAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LateralAcceleration_sequence[] = {
  { &hf_poi_lateralAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_LateralAccelerationValue },
  { &hf_poi_lateralAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_LateralAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_LateralAcceleration, LateralAcceleration_sequence);

  return offset;
}


static const value_string poi_VerticalAccelerationValue_vals[] = {
  {   1, "pointOneMeterPerSecSquaredUp" },
  {  -1, "pointOneMeterPerSecSquaredDown" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_VerticalAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VerticalAcceleration_sequence[] = {
  { &hf_poi_verticalAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_VerticalAccelerationValue },
  { &hf_poi_verticalAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_VerticalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_VerticalAcceleration, VerticalAcceleration_sequence);

  return offset;
}


static const value_string poi_StationType_vals[] = {
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
dissect_poi_StationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_poi_ExteriorLights(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}


static const value_string poi_DangerousGoodsBasic_vals[] = {
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
dissect_poi_DangerousGoodsBasic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_poi_INTEGER_0_9999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9999U, NULL, FALSE);

  return offset;
}



static int
dissect_poi_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_poi_IA5String_SIZE_1_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 24, FALSE);

  return offset;
}



static int
dissect_poi_T_companyName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 21 "./asn1/poi/poi.cnf"
  offset=dissect_per_octet_string(tvb, offset, actx, tree, hf_index, NO_BOUND, NO_BOUND, FALSE, NULL);


  return offset;
}


static const per_sequence_t DangerousGoodsExtended_sequence[] = {
  { &hf_poi_dangerousGoodsType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_DangerousGoodsBasic },
  { &hf_poi_unNumber        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_INTEGER_0_9999 },
  { &hf_poi_elevatedTemperature, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_BOOLEAN },
  { &hf_poi_tunnelsRestricted, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_BOOLEAN },
  { &hf_poi_limitedQuantity , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_BOOLEAN },
  { &hf_poi_emergencyActionCode, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_IA5String_SIZE_1_24 },
  { &hf_poi_phoneNumber     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_IA5String_SIZE_1_24 },
  { &hf_poi_companyName     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_T_companyName },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_DangerousGoodsExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_DangerousGoodsExtended, DangerousGoodsExtended_sequence);

  return offset;
}



static int
dissect_poi_SpecialTransportType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_poi_LightBarSirenInUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string poi_HeightLonCarr_vals[] = {
  {   1, "oneCentimeter" },
  { 100, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_HeightLonCarr(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, FALSE);

  return offset;
}


static const value_string poi_PosLonCarr_vals[] = {
  {   1, "oneCentimeter" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_PosLonCarr(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string poi_PosPillar_vals[] = {
  {   1, "tenCentimeters" },
  {  30, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_PosPillar(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 30U, NULL, FALSE);

  return offset;
}


static const value_string poi_PosCentMass_vals[] = {
  {   1, "tenCentimeters" },
  {  63, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_PosCentMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 63U, NULL, FALSE);

  return offset;
}


static const value_string poi_RequestResponseIndication_vals[] = {
  {   0, "request" },
  {   1, "response" },
  { 0, NULL }
};


static int
dissect_poi_RequestResponseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string poi_SpeedLimit_vals[] = {
  {   1, "oneKmPerHour" },
  { 0, NULL }
};


static int
dissect_poi_SpeedLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_StationarySince_vals[] = {
  {   0, "lessThan1Minute" },
  {   1, "lessThan2Minutes" },
  {   2, "lessThan15Minutes" },
  {   3, "equalOrGreater15Minutes" },
  { 0, NULL }
};


static int
dissect_poi_StationarySince(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string poi_Temperature_vals[] = {
  { -60, "equalOrSmallerThanMinus60Deg" },
  {   1, "oneDegreeCelsius" },
  {  67, "equalOrGreaterThan67Deg" },
  { 0, NULL }
};


static int
dissect_poi_Temperature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -60, 67U, NULL, FALSE);

  return offset;
}


static const value_string poi_TrafficRule_vals[] = {
  {   0, "noPassing" },
  {   1, "noPassingForTrucks" },
  {   2, "passToRight" },
  {   3, "passToLeft" },
  { 0, NULL }
};


static int
dissect_poi_TrafficRule(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string poi_WheelBaseVehicle_vals[] = {
  {   1, "tenCentimeters" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_WheelBaseVehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string poi_TurningRadius_vals[] = {
  {   1, "point4Meters" },
  { 255, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_TurningRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string poi_PosFrontAx_vals[] = {
  {   1, "tenCentimeters" },
  {  20, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_PosFrontAx(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 20U, NULL, FALSE);

  return offset;
}



static int
dissect_poi_PositionOfOccupants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, NULL);

  return offset;
}


static const value_string poi_PositioningSolutionType_vals[] = {
  {   0, "noPositioningSolution" },
  {   1, "sGNSS" },
  {   2, "dGNSS" },
  {   3, "sGNSSplusDR" },
  {   4, "dGNSSplusDR" },
  {   5, "dR" },
  { 0, NULL }
};


static int
dissect_poi_PositioningSolutionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_poi_WMInumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 3, FALSE);

  return offset;
}



static int
dissect_poi_VDS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          6, 6, FALSE);

  return offset;
}


static const per_sequence_t VehicleIdentification_sequence[] = {
  { &hf_poi_wMInumber       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_WMInumber },
  { &hf_poi_vDS             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_VDS },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_VehicleIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_VehicleIdentification, VehicleIdentification_sequence);

  return offset;
}



static int
dissect_poi_EnergyStorageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, NULL);

  return offset;
}


static const value_string poi_VehicleLengthValue_vals[] = {
  {   1, "tenCentimeters" },
  { 1022, "outOfRange" },
  { 1023, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_VehicleLengthValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1023U, NULL, FALSE);

  return offset;
}


static const value_string poi_VehicleLengthConfidenceIndication_vals[] = {
  {   0, "noTrailerPresent" },
  {   1, "trailerPresentWithKnownLength" },
  {   2, "trailerPresentWithUnknownLength" },
  {   3, "trailerPresenceIsUnknown" },
  {   4, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_VehicleLengthConfidenceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t VehicleLength_sequence[] = {
  { &hf_poi_vehicleLengthValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_VehicleLengthValue },
  { &hf_poi_vehicleLengthConfidenceIndication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_VehicleLengthConfidenceIndication },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_VehicleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_VehicleLength, VehicleLength_sequence);

  return offset;
}


static const value_string poi_VehicleWidth_vals[] = {
  {   1, "tenCentimeters" },
  {  61, "outOfRange" },
  {  62, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_VehicleWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 62U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PathHistory_sequence_of[1] = {
  { &hf_poi_PathHistory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_PathPoint },
};

static int
dissect_poi_PathHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_PathHistory, PathHistory_sequence_of,
                                                  0, 40, FALSE);

  return offset;
}



static int
dissect_poi_EmergencyPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string poi_InformationQuality_vals[] = {
  {   0, "unavailable" },
  {   1, "lowest" },
  {   7, "highest" },
  { 0, NULL }
};


static int
dissect_poi_InformationQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string poi_RoadType_vals[] = {
  {   0, "urban-NoStructuralSeparationToOppositeLanes" },
  {   1, "urban-WithStructuralSeparationToOppositeLanes" },
  {   2, "nonUrban-NoStructuralSeparationToOppositeLanes" },
  {   3, "nonUrban-WithStructuralSeparationToOppositeLanes" },
  { 0, NULL }
};


static int
dissect_poi_RoadType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string poi_SteeringWheelAngleValue_vals[] = {
  {   0, "straight" },
  {  -1, "onePointFiveDegreesToRight" },
  {   1, "onePointFiveDegreesToLeft" },
  { 512, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_SteeringWheelAngleValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -511, 512U, NULL, FALSE);

  return offset;
}


static const value_string poi_SteeringWheelAngleConfidence_vals[] = {
  {   1, "equalOrWithinOnePointFiveDegree" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_SteeringWheelAngleConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SteeringWheelAngle_sequence[] = {
  { &hf_poi_steeringWheelAngleValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SteeringWheelAngleValue },
  { &hf_poi_steeringWheelAngleConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SteeringWheelAngleConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_SteeringWheelAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_SteeringWheelAngle, SteeringWheelAngle_sequence);

  return offset;
}



static int
dissect_poi_TimestampIts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 17 "./asn1/poi/poi.cnf"
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index, 0U, G_GUINT64_CONSTANT(4398046511103), NULL, FALSE);


  return offset;
}


static const value_string poi_VehicleRole_vals[] = {
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
dissect_poi_VehicleRole(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string poi_YawRateValue_vals[] = {
  {   0, "straight" },
  {  -1, "degSec-000-01ToRight" },
  {   1, "degSec-000-01ToLeft" },
  { 32767, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_YawRateValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32766, 32767U, NULL, FALSE);

  return offset;
}


static const value_string poi_YawRateConfidence_vals[] = {
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
dissect_poi_YawRateConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t YawRate_sequence[] = {
  { &hf_poi_yawRateValue    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_YawRateValue },
  { &hf_poi_yawRateConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_YawRateConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_YawRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_YawRate, YawRate_sequence);

  return offset;
}


static const value_string poi_ProtectedZoneType_vals[] = {
  {   0, "permanentCenDsrcTolling" },
  {   1, "temporaryCenDsrcTolling" },
  { 0, NULL }
};


static int
dissect_poi_ProtectedZoneType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}


static const value_string poi_RelevanceDistance_vals[] = {
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
dissect_poi_RelevanceDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string poi_RelevanceTrafficDirection_vals[] = {
  {   0, "allTrafficDirections" },
  {   1, "upstreamTraffic" },
  {   2, "downstreamTraffic" },
  {   3, "oppositeTraffic" },
  { 0, NULL }
};


static int
dissect_poi_RelevanceTrafficDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string poi_TransmissionInterval_vals[] = {
  {   1, "oneMilliSecond" },
  { 10000, "tenSeconds" },
  { 0, NULL }
};


static int
dissect_poi_TransmissionInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 10000U, NULL, FALSE);

  return offset;
}


static const value_string poi_ValidityDuration_vals[] = {
  {   0, "timeOfDetection" },
  {   1, "oneSecondAfterDetection" },
  { 0, NULL }
};


static int
dissect_poi_ValidityDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86400U, NULL, FALSE);

  return offset;
}



static int
dissect_poi_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ActionID_sequence[] = {
  { &hf_poi_originatingStationID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_StationID },
  { &hf_poi_sequenceNumber  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SequenceNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ActionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ActionID, ActionID_sequence);

  return offset;
}


static const per_sequence_t ItineraryPath_sequence_of[1] = {
  { &hf_poi_ItineraryPath_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ReferencePosition },
};

static int
dissect_poi_ItineraryPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_ItineraryPath, ItineraryPath_sequence_of,
                                                  1, 40, FALSE);

  return offset;
}


static const value_string poi_ProtectedZoneRadius_vals[] = {
  {   1, "oneMeter" },
  { 0, NULL }
};


static int
dissect_poi_ProtectedZoneRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_poi_ProtectedZoneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 134217727U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ProtectedCommunicationZone_sequence[] = {
  { &hf_poi_protectedZoneType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ProtectedZoneType },
  { &hf_poi_expiryTime      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_TimestampIts },
  { &hf_poi_protectedZoneLatitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_Latitude },
  { &hf_poi_protectedZoneLongitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_Longitude },
  { &hf_poi_protectedZoneRadius, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_ProtectedZoneRadius },
  { &hf_poi_protectedZoneID , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_ProtectedZoneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ProtectedCommunicationZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ProtectedCommunicationZone, ProtectedCommunicationZone_sequence);

  return offset;
}


static const per_sequence_t Traces_sequence_of[1] = {
  { &hf_poi_Traces_item     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_PathHistory },
};

static int
dissect_poi_Traces(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_Traces, Traces_sequence_of,
                                                  1, 7, FALSE);

  return offset;
}


static const value_string poi_NumberOfOccupants_vals[] = {
  {   1, "oneOccupant" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_poi_NumberOfOccupants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PositionOfPillars_sequence_of[1] = {
  { &hf_poi_PositionOfPillars_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_PosPillar },
};

static int
dissect_poi_PositionOfPillars(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_PositionOfPillars, PositionOfPillars_sequence_of,
                                                  1, 3, TRUE);

  return offset;
}


static const per_sequence_t RestrictedTypes_sequence_of[1] = {
  { &hf_poi_RestrictedTypes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_StationType },
};

static int
dissect_poi_RestrictedTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_RestrictedTypes, RestrictedTypes_sequence_of,
                                                  1, 3, TRUE);

  return offset;
}


static const per_sequence_t EventPoint_sequence[] = {
  { &hf_poi_eventPosition   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_DeltaReferencePosition },
  { &hf_poi_eventDeltaTime  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_PathDeltaTime },
  { &hf_poi_informationQuality, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_InformationQuality },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_EventPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_EventPoint, EventPoint_sequence);

  return offset;
}


static const per_sequence_t EventHistory_sequence_of[1] = {
  { &hf_poi_EventHistory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_EventPoint },
};

static int
dissect_poi_EventHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_EventHistory, EventHistory_sequence_of,
                                                  1, 23, FALSE);

  return offset;
}


static const per_sequence_t ProtectedCommunicationZonesRSU_sequence_of[1] = {
  { &hf_poi_ProtectedCommunicationZonesRSU_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ProtectedCommunicationZone },
};

static int
dissect_poi_ProtectedCommunicationZonesRSU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_ProtectedCommunicationZonesRSU, ProtectedCommunicationZonesRSU_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_poi_CenDsrcTollingZoneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_poi_ProtectedZoneID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CenDsrcTollingZone_sequence[] = {
  { &hf_poi_protectedZoneLatitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_Latitude },
  { &hf_poi_protectedZoneLongitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_Longitude },
  { &hf_poi_cenDsrcTollingZoneID, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_CenDsrcTollingZoneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_CenDsrcTollingZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_CenDsrcTollingZone, CenDsrcTollingZone_sequence);

  return offset;
}



static int
dissect_poi_POIType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ItsPOIHeader_sequence[] = {
  { &hf_poi_poiType         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_POIType },
  { &hf_poi_timeStamp       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_TimestampIts },
  { &hf_poi_relayCapable    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ItsPOIHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ItsPOIHeader, ItsPOIHeader_sequence);

  return offset;
}



static int
dissect_poi_NumberStations(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}



static int
dissect_poi_UTF8String_SIZE_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_UTF8String(tvb, offset, actx, tree, hf_index,
                                          1, 32, FALSE);

  return offset;
}



static int
dissect_poi_UTF8String(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_UTF8String(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, FALSE);

  return offset;
}



static int
dissect_poi_NumericString_SIZE_1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          1, 16, FALSE);

  return offset;
}


static const per_sequence_t DigitalMap_sequence_of[1] = {
  { &hf_poi_DigitalMap_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ReferencePosition },
};

static int
dissect_poi_DigitalMap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_DigitalMap, DigitalMap_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}



static int
dissect_poi_ChargingSpotType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_poi_TypeOfReceptacle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_poi_INTEGER_0_1400(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1400U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SpotAvailability_sequence[] = {
  { &hf_poi_maxWaitingTimeMinutes, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_INTEGER_0_1400 },
  { &hf_poi_blocking        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_SpotAvailability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_SpotAvailability, SpotAvailability_sequence);

  return offset;
}


static const per_sequence_t ParkingPlacesData_sequence_of[1] = {
  { &hf_poi_ParkingPlacesData_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SpotAvailability },
};

static int
dissect_poi_ParkingPlacesData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_ParkingPlacesData, ParkingPlacesData_sequence_of,
                                                  1, 4, FALSE);

  return offset;
}


static const per_sequence_t ItsChargingSpotDataElements_sequence[] = {
  { &hf_poi_type            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ChargingSpotType },
  { &hf_poi_evEquipmentID   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_UTF8String },
  { &hf_poi_typeOfReceptacle, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_TypeOfReceptacle },
  { &hf_poi_energyAvailability, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_UTF8String },
  { &hf_poi_parkingPlacesData, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_poi_ParkingPlacesData },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ItsChargingSpotDataElements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ItsChargingSpotDataElements, ItsChargingSpotDataElements_sequence);

  return offset;
}


static const per_sequence_t ItsChargingSpots_sequence_of[1] = {
  { &hf_poi_ItsChargingSpots_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ItsChargingSpotDataElements },
};

static int
dissect_poi_ItsChargingSpots(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_ItsChargingSpots, ItsChargingSpots_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t ItsChargingStationData_sequence[] = {
  { &hf_poi_chargingStationID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_poi_StationID },
  { &hf_poi_utilityDistributorId, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_UTF8String_SIZE_1_32 },
  { &hf_poi_providerID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_UTF8String_SIZE_1_32 },
  { &hf_poi_chargingStationLocation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_poi_ReferencePosition },
  { &hf_poi_address         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_UTF8String },
  { &hf_poi_phoneNumber_01  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_NumericString_SIZE_1_16 },
  { &hf_poi_accessibility   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_poi_UTF8String_SIZE_1_32 },
  { &hf_poi_digitalMap      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_DigitalMap },
  { &hf_poi_openingDaysHours, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_poi_UTF8String },
  { &hf_poi_pricing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_poi_UTF8String },
  { &hf_poi_bookingContactInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_UTF8String },
  { &hf_poi_payment         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_poi_UTF8String },
  { &hf_poi_chargingSpotsAvailable, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_poi_ItsChargingSpots },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ItsChargingStationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ItsChargingStationData, ItsChargingStationData_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_ItsChargingStationData_sequence_of[1] = {
  { &hf_poi_chargingStationsData_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ItsChargingStationData },
};

static int
dissect_poi_SEQUENCE_SIZE_1_256_OF_ItsChargingStationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_poi_SEQUENCE_SIZE_1_256_OF_ItsChargingStationData, SEQUENCE_SIZE_1_256_OF_ItsChargingStationData_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t ItsEVCSNData_sequence[] = {
  { &hf_poi_totalNumberOfStations, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_NumberStations },
  { &hf_poi_chargingStationsData, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_SEQUENCE_SIZE_1_256_OF_ItsChargingStationData },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_ItsEVCSNData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_ItsEVCSNData, ItsEVCSNData_sequence);

  return offset;
}


static const per_sequence_t EVChargingSpotNotificationPOIMessage_sequence[] = {
  { &hf_poi_poiHeader       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ItsPOIHeader },
  { &hf_poi_evcsnData       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ItsEVCSNData },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_EVChargingSpotNotificationPOIMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_EVChargingSpotNotificationPOIMessage, EVChargingSpotNotificationPOIMessage_sequence);

  return offset;
}


static const per_sequence_t EvcsnPdu_sequence[] = {
  { &hf_poi_header          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_ItsPduHeader },
  { &hf_poi_evcsn           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_poi_EVChargingSpotNotificationPOIMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_poi_EvcsnPdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_poi_EvcsnPdu, EvcsnPdu_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_EvcsnPdu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_poi_EvcsnPdu(tvb, offset, &asn1_ctx, tree, hf_poi_EvcsnPdu_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-poi-fn.c ---*/
#line 57 "./asn1/poi/packet-poi-template.c"

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


/*--- Included file: packet-poi-hfarr.c ---*/
#line 1 "./asn1/poi/packet-poi-hfarr.c"
    { &hf_poi_EvcsnPdu_PDU,
      { "EvcsnPdu", "poi.EvcsnPdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_protocolVersion,
      { "protocolVersion", "poi.protocolVersion",
        FT_UINT32, BASE_DEC, VALS(poi_T_protocolVersion_vals), 0,
        NULL, HFILL }},
    { &hf_poi_messageID,
      { "messageID", "poi.messageID",
        FT_UINT32, BASE_DEC, VALS(poi_T_messageID_vals), 0,
        NULL, HFILL }},
    { &hf_poi_stationID,
      { "stationID", "poi.stationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_latitude,
      { "latitude", "poi.latitude",
        FT_INT32, BASE_DEC, VALS(poi_Latitude_vals), 0,
        NULL, HFILL }},
    { &hf_poi_longitude,
      { "longitude", "poi.longitude",
        FT_INT32, BASE_DEC, VALS(poi_Longitude_vals), 0,
        NULL, HFILL }},
    { &hf_poi_positionConfidenceEllipse,
      { "positionConfidenceEllipse", "poi.positionConfidenceEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosConfidenceEllipse", HFILL }},
    { &hf_poi_altitude,
      { "altitude", "poi.altitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_deltaLatitude,
      { "deltaLatitude", "poi.deltaLatitude",
        FT_INT32, BASE_DEC, VALS(poi_DeltaLatitude_vals), 0,
        NULL, HFILL }},
    { &hf_poi_deltaLongitude,
      { "deltaLongitude", "poi.deltaLongitude",
        FT_INT32, BASE_DEC, VALS(poi_DeltaLongitude_vals), 0,
        NULL, HFILL }},
    { &hf_poi_deltaAltitude,
      { "deltaAltitude", "poi.deltaAltitude",
        FT_INT32, BASE_DEC, VALS(poi_DeltaAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_poi_altitudeValue,
      { "altitudeValue", "poi.altitudeValue",
        FT_INT32, BASE_DEC, VALS(poi_AltitudeValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_altitudeConfidence,
      { "altitudeConfidence", "poi.altitudeConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_AltitudeConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_poi_semiMajorConfidence,
      { "semiMajorConfidence", "poi.semiMajorConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_SemiAxisLength_vals), 0,
        "SemiAxisLength", HFILL }},
    { &hf_poi_semiMinorConfidence,
      { "semiMinorConfidence", "poi.semiMinorConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_SemiAxisLength_vals), 0,
        "SemiAxisLength", HFILL }},
    { &hf_poi_semiMajorOrientation,
      { "semiMajorOrientation", "poi.semiMajorOrientation",
        FT_UINT32, BASE_DEC, VALS(poi_HeadingValue_vals), 0,
        "HeadingValue", HFILL }},
    { &hf_poi_pathPosition,
      { "pathPosition", "poi.pathPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_poi_pathDeltaTime,
      { "pathDeltaTime", "poi.pathDeltaTime",
        FT_UINT32, BASE_DEC, VALS(poi_PathDeltaTime_vals), 0,
        NULL, HFILL }},
    { &hf_poi_ptActivationType,
      { "ptActivationType", "poi.ptActivationType",
        FT_UINT32, BASE_DEC, VALS(poi_PtActivationType_vals), 0,
        NULL, HFILL }},
    { &hf_poi_ptActivationData,
      { "ptActivationData", "poi.ptActivationData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_causeCode,
      { "causeCode", "poi.causeCode",
        FT_UINT32, BASE_DEC, VALS(poi_CauseCodeType_vals), 0,
        "CauseCodeType", HFILL }},
    { &hf_poi_subCauseCode,
      { "subCauseCode", "poi.subCauseCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubCauseCodeType", HFILL }},
    { &hf_poi_curvatureValue,
      { "curvatureValue", "poi.curvatureValue",
        FT_INT32, BASE_DEC, VALS(poi_CurvatureValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_curvatureConfidence,
      { "curvatureConfidence", "poi.curvatureConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_CurvatureConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_poi_headingValue,
      { "headingValue", "poi.headingValue",
        FT_UINT32, BASE_DEC, VALS(poi_HeadingValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_headingConfidence,
      { "headingConfidence", "poi.headingConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_HeadingConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_poi_hardShoulderStatus,
      { "hardShoulderStatus", "poi.hardShoulderStatus",
        FT_UINT32, BASE_DEC, VALS(poi_HardShoulderStatus_vals), 0,
        NULL, HFILL }},
    { &hf_poi_drivingLaneStatus,
      { "drivingLaneStatus", "poi.drivingLaneStatus",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_speedValue,
      { "speedValue", "poi.speedValue",
        FT_UINT32, BASE_DEC, VALS(poi_SpeedValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_speedConfidence,
      { "speedConfidence", "poi.speedConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_SpeedConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_poi_longitudinalAccelerationValue,
      { "longitudinalAccelerationValue", "poi.longitudinalAccelerationValue",
        FT_INT32, BASE_DEC, VALS(poi_LongitudinalAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_longitudinalAccelerationConfidence,
      { "longitudinalAccelerationConfidence", "poi.longitudinalAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_poi_lateralAccelerationValue,
      { "lateralAccelerationValue", "poi.lateralAccelerationValue",
        FT_INT32, BASE_DEC, VALS(poi_LateralAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_lateralAccelerationConfidence,
      { "lateralAccelerationConfidence", "poi.lateralAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_poi_verticalAccelerationValue,
      { "verticalAccelerationValue", "poi.verticalAccelerationValue",
        FT_INT32, BASE_DEC, VALS(poi_VerticalAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_verticalAccelerationConfidence,
      { "verticalAccelerationConfidence", "poi.verticalAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_poi_dangerousGoodsType,
      { "dangerousGoodsType", "poi.dangerousGoodsType",
        FT_UINT32, BASE_DEC, VALS(poi_DangerousGoodsBasic_vals), 0,
        "DangerousGoodsBasic", HFILL }},
    { &hf_poi_unNumber,
      { "unNumber", "poi.unNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9999", HFILL }},
    { &hf_poi_elevatedTemperature,
      { "elevatedTemperature", "poi.elevatedTemperature",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_poi_tunnelsRestricted,
      { "tunnelsRestricted", "poi.tunnelsRestricted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_poi_limitedQuantity,
      { "limitedQuantity", "poi.limitedQuantity",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_poi_emergencyActionCode,
      { "emergencyActionCode", "poi.emergencyActionCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_24", HFILL }},
    { &hf_poi_phoneNumber,
      { "phoneNumber", "poi.phoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_24", HFILL }},
    { &hf_poi_companyName,
      { "companyName", "poi.companyName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_wMInumber,
      { "wMInumber", "poi.wMInumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_vDS,
      { "vDS", "poi.vDS",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_vehicleLengthValue,
      { "vehicleLengthValue", "poi.vehicleLengthValue",
        FT_UINT32, BASE_DEC, VALS(poi_VehicleLengthValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_vehicleLengthConfidenceIndication,
      { "vehicleLengthConfidenceIndication", "poi.vehicleLengthConfidenceIndication",
        FT_UINT32, BASE_DEC, VALS(poi_VehicleLengthConfidenceIndication_vals), 0,
        NULL, HFILL }},
    { &hf_poi_PathHistory_item,
      { "PathPoint", "poi.PathPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_steeringWheelAngleValue,
      { "steeringWheelAngleValue", "poi.steeringWheelAngleValue",
        FT_INT32, BASE_DEC, VALS(poi_SteeringWheelAngleValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_steeringWheelAngleConfidence,
      { "steeringWheelAngleConfidence", "poi.steeringWheelAngleConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_SteeringWheelAngleConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_poi_yawRateValue,
      { "yawRateValue", "poi.yawRateValue",
        FT_INT32, BASE_DEC, VALS(poi_YawRateValue_vals), 0,
        NULL, HFILL }},
    { &hf_poi_yawRateConfidence,
      { "yawRateConfidence", "poi.yawRateConfidence",
        FT_UINT32, BASE_DEC, VALS(poi_YawRateConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_poi_originatingStationID,
      { "originatingStationID", "poi.originatingStationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StationID", HFILL }},
    { &hf_poi_sequenceNumber,
      { "sequenceNumber", "poi.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_ItineraryPath_item,
      { "ReferencePosition", "poi.ReferencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_protectedZoneType,
      { "protectedZoneType", "poi.protectedZoneType",
        FT_UINT32, BASE_DEC, VALS(poi_ProtectedZoneType_vals), 0,
        NULL, HFILL }},
    { &hf_poi_expiryTime,
      { "expiryTime", "poi.expiryTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimestampIts", HFILL }},
    { &hf_poi_protectedZoneLatitude,
      { "protectedZoneLatitude", "poi.protectedZoneLatitude",
        FT_INT32, BASE_DEC, VALS(poi_Latitude_vals), 0,
        "Latitude", HFILL }},
    { &hf_poi_protectedZoneLongitude,
      { "protectedZoneLongitude", "poi.protectedZoneLongitude",
        FT_INT32, BASE_DEC, VALS(poi_Longitude_vals), 0,
        "Longitude", HFILL }},
    { &hf_poi_protectedZoneRadius,
      { "protectedZoneRadius", "poi.protectedZoneRadius",
        FT_UINT32, BASE_DEC, VALS(poi_ProtectedZoneRadius_vals), 0,
        NULL, HFILL }},
    { &hf_poi_protectedZoneID,
      { "protectedZoneID", "poi.protectedZoneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_Traces_item,
      { "PathHistory", "poi.PathHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_PositionOfPillars_item,
      { "PosPillar", "poi.PosPillar",
        FT_UINT32, BASE_DEC, VALS(poi_PosPillar_vals), 0,
        NULL, HFILL }},
    { &hf_poi_RestrictedTypes_item,
      { "StationType", "poi.StationType",
        FT_UINT32, BASE_DEC, VALS(poi_StationType_vals), 0,
        NULL, HFILL }},
    { &hf_poi_EventHistory_item,
      { "EventPoint", "poi.EventPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_eventPosition,
      { "eventPosition", "poi.eventPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_poi_eventDeltaTime,
      { "eventDeltaTime", "poi.eventDeltaTime",
        FT_UINT32, BASE_DEC, VALS(poi_PathDeltaTime_vals), 0,
        "PathDeltaTime", HFILL }},
    { &hf_poi_informationQuality,
      { "informationQuality", "poi.informationQuality",
        FT_UINT32, BASE_DEC, VALS(poi_InformationQuality_vals), 0,
        NULL, HFILL }},
    { &hf_poi_ProtectedCommunicationZonesRSU_item,
      { "ProtectedCommunicationZone", "poi.ProtectedCommunicationZone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_cenDsrcTollingZoneID,
      { "cenDsrcTollingZoneID", "poi.cenDsrcTollingZoneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_header,
      { "header", "poi.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ItsPduHeader", HFILL }},
    { &hf_poi_evcsn,
      { "evcsn", "poi.evcsn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EVChargingSpotNotificationPOIMessage", HFILL }},
    { &hf_poi_poiHeader,
      { "poiHeader", "poi.poiHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ItsPOIHeader", HFILL }},
    { &hf_poi_evcsnData,
      { "evcsnData", "poi.evcsnData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ItsEVCSNData", HFILL }},
    { &hf_poi_poiType,
      { "poiType", "poi.poiType",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_timeStamp,
      { "timeStamp", "poi.timeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimestampIts", HFILL }},
    { &hf_poi_relayCapable,
      { "relayCapable", "poi.relayCapable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_poi_totalNumberOfStations,
      { "totalNumberOfStations", "poi.totalNumberOfStations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NumberStations", HFILL }},
    { &hf_poi_chargingStationsData,
      { "chargingStationsData", "poi.chargingStationsData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_ItsChargingStationData", HFILL }},
    { &hf_poi_chargingStationsData_item,
      { "ItsChargingStationData", "poi.ItsChargingStationData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_chargingStationID,
      { "chargingStationID", "poi.chargingStationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StationID", HFILL }},
    { &hf_poi_utilityDistributorId,
      { "utilityDistributorId", "poi.utilityDistributorId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_32", HFILL }},
    { &hf_poi_providerID,
      { "providerID", "poi.providerID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_32", HFILL }},
    { &hf_poi_chargingStationLocation,
      { "chargingStationLocation", "poi.chargingStationLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferencePosition", HFILL }},
    { &hf_poi_address,
      { "address", "poi.address",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_poi_phoneNumber_01,
      { "phoneNumber", "poi.phoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_1_16", HFILL }},
    { &hf_poi_accessibility,
      { "accessibility", "poi.accessibility",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_32", HFILL }},
    { &hf_poi_digitalMap,
      { "digitalMap", "poi.digitalMap",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_openingDaysHours,
      { "openingDaysHours", "poi.openingDaysHours",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_poi_pricing,
      { "pricing", "poi.pricing",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_poi_bookingContactInfo,
      { "bookingContactInfo", "poi.bookingContactInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_poi_payment,
      { "payment", "poi.payment",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_poi_chargingSpotsAvailable,
      { "chargingSpotsAvailable", "poi.chargingSpotsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ItsChargingSpots", HFILL }},
    { &hf_poi_ItsChargingSpots_item,
      { "ItsChargingSpotDataElements", "poi.ItsChargingSpotDataElements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_type,
      { "type", "poi.type",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ChargingSpotType", HFILL }},
    { &hf_poi_evEquipmentID,
      { "evEquipmentID", "poi.evEquipmentID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_poi_typeOfReceptacle,
      { "typeOfReceptacle", "poi.typeOfReceptacle",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_energyAvailability,
      { "energyAvailability", "poi.energyAvailability",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_poi_parkingPlacesData,
      { "parkingPlacesData", "poi.parkingPlacesData",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_DigitalMap_item,
      { "ReferencePosition", "poi.ReferencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_ParkingPlacesData_item,
      { "SpotAvailability", "poi.SpotAvailability_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_poi_maxWaitingTimeMinutes,
      { "maxWaitingTimeMinutes", "poi.maxWaitingTimeMinutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1400", HFILL }},
    { &hf_poi_blocking,
      { "blocking", "poi.blocking",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_poi_AccelerationControl_brakePedalEngaged,
      { "brakePedalEngaged", "poi.brakePedalEngaged",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_AccelerationControl_gasPedalEngaged,
      { "gasPedalEngaged", "poi.gasPedalEngaged",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_AccelerationControl_emergencyBrakeEngaged,
      { "emergencyBrakeEngaged", "poi.emergencyBrakeEngaged",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_poi_AccelerationControl_collisionWarningEngaged,
      { "collisionWarningEngaged", "poi.collisionWarningEngaged",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_poi_AccelerationControl_accEngaged,
      { "accEngaged", "poi.accEngaged",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_poi_AccelerationControl_cruiseControlEngaged,
      { "cruiseControlEngaged", "poi.cruiseControlEngaged",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_poi_AccelerationControl_speedLimiterEngaged,
      { "speedLimiterEngaged", "poi.speedLimiterEngaged",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_poi_ExteriorLights_lowBeamHeadlightsOn,
      { "lowBeamHeadlightsOn", "poi.lowBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_ExteriorLights_highBeamHeadlightsOn,
      { "highBeamHeadlightsOn", "poi.highBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_ExteriorLights_leftTurnSignalOn,
      { "leftTurnSignalOn", "poi.leftTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_poi_ExteriorLights_rightTurnSignalOn,
      { "rightTurnSignalOn", "poi.rightTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_poi_ExteriorLights_daytimeRunningLightsOn,
      { "daytimeRunningLightsOn", "poi.daytimeRunningLightsOn",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_poi_ExteriorLights_reverseLightOn,
      { "reverseLightOn", "poi.reverseLightOn",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_poi_ExteriorLights_fogLightOn,
      { "fogLightOn", "poi.fogLightOn",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_poi_ExteriorLights_parkingLightsOn,
      { "parkingLightsOn", "poi.parkingLightsOn",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_poi_SpecialTransportType_heavyLoad,
      { "heavyLoad", "poi.heavyLoad",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_SpecialTransportType_excessWidth,
      { "excessWidth", "poi.excessWidth",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_SpecialTransportType_excessLength,
      { "excessLength", "poi.excessLength",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_poi_SpecialTransportType_excessHeight,
      { "excessHeight", "poi.excessHeight",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_poi_LightBarSirenInUse_lightBarActivated,
      { "lightBarActivated", "poi.lightBarActivated",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_LightBarSirenInUse_sirenActivated,
      { "sirenActivated", "poi.sirenActivated",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row1LeftOccupied,
      { "row1LeftOccupied", "poi.row1LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row1RightOccupied,
      { "row1RightOccupied", "poi.row1RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row1MidOccupied,
      { "row1MidOccupied", "poi.row1MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row1NotDetectable,
      { "row1NotDetectable", "poi.row1NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row1NotPresent,
      { "row1NotPresent", "poi.row1NotPresent",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row2LeftOccupied,
      { "row2LeftOccupied", "poi.row2LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row2RightOccupied,
      { "row2RightOccupied", "poi.row2RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row2MidOccupied,
      { "row2MidOccupied", "poi.row2MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row2NotDetectable,
      { "row2NotDetectable", "poi.row2NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row2NotPresent,
      { "row2NotPresent", "poi.row2NotPresent",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row3LeftOccupied,
      { "row3LeftOccupied", "poi.row3LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row3RightOccupied,
      { "row3RightOccupied", "poi.row3RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row3MidOccupied,
      { "row3MidOccupied", "poi.row3MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row3NotDetectable,
      { "row3NotDetectable", "poi.row3NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row3NotPresent,
      { "row3NotPresent", "poi.row3NotPresent",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row4LeftOccupied,
      { "row4LeftOccupied", "poi.row4LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row4RightOccupied,
      { "row4RightOccupied", "poi.row4RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row4MidOccupied,
      { "row4MidOccupied", "poi.row4MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row4NotDetectable,
      { "row4NotDetectable", "poi.row4NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_poi_PositionOfOccupants_row4NotPresent,
      { "row4NotPresent", "poi.row4NotPresent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_poi_EnergyStorageType_hydrogenStorage,
      { "hydrogenStorage", "poi.hydrogenStorage",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_EnergyStorageType_electricEnergyStorage,
      { "electricEnergyStorage", "poi.electricEnergyStorage",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_EnergyStorageType_liquidPropaneGas,
      { "liquidPropaneGas", "poi.liquidPropaneGas",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_poi_EnergyStorageType_compressedNaturalGas,
      { "compressedNaturalGas", "poi.compressedNaturalGas",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_poi_EnergyStorageType_diesel,
      { "diesel", "poi.diesel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_poi_EnergyStorageType_gasoline,
      { "gasoline", "poi.gasoline",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_poi_EnergyStorageType_ammonia,
      { "ammonia", "poi.ammonia",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_poi_EmergencyPriority_requestForRightOfWay,
      { "requestForRightOfWay", "poi.requestForRightOfWay",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_EmergencyPriority_requestForFreeCrossingAtATrafficLight,
      { "requestForFreeCrossingAtATrafficLight", "poi.requestForFreeCrossingAtATrafficLight",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_ChargingSpotType_standardChargeMode1,
      { "standardChargeMode1", "poi.standardChargeMode1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_ChargingSpotType_standardChargeMode2,
      { "standardChargeMode2", "poi.standardChargeMode2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_poi_ChargingSpotType_standardOrFastChargeMode3,
      { "standardOrFastChargeMode3", "poi.standardOrFastChargeMode3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_poi_ChargingSpotType_fastChargeWithExternalCharger,
      { "fastChargeWithExternalCharger", "poi.fastChargeWithExternalCharger",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_poi_ChargingSpotType_quickDrop,
      { "quickDrop", "poi.quickDrop",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_poi_ChargingSpotType_inductiveChargeWhileStationary,
      { "inductiveChargeWhileStationary", "poi.inductiveChargeWhileStationary",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_poi_ChargingSpotType_inductiveChargeWhileDriving,
      { "inductiveChargeWhileDriving", "poi.inductiveChargeWhileDriving",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

/*--- End of included file: packet-poi-hfarr.c ---*/
#line 90 "./asn1/poi/packet-poi-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_poi,

/*--- Included file: packet-poi-ettarr.c ---*/
#line 1 "./asn1/poi/packet-poi-ettarr.c"
    &ett_poi_ItsPduHeader,
    &ett_poi_ReferencePosition,
    &ett_poi_DeltaReferencePosition,
    &ett_poi_Altitude,
    &ett_poi_PosConfidenceEllipse,
    &ett_poi_PathPoint,
    &ett_poi_PtActivation,
    &ett_poi_AccelerationControl,
    &ett_poi_CauseCode,
    &ett_poi_Curvature,
    &ett_poi_Heading,
    &ett_poi_ClosedLanes,
    &ett_poi_Speed,
    &ett_poi_LongitudinalAcceleration,
    &ett_poi_LateralAcceleration,
    &ett_poi_VerticalAcceleration,
    &ett_poi_ExteriorLights,
    &ett_poi_DangerousGoodsExtended,
    &ett_poi_SpecialTransportType,
    &ett_poi_LightBarSirenInUse,
    &ett_poi_PositionOfOccupants,
    &ett_poi_VehicleIdentification,
    &ett_poi_EnergyStorageType,
    &ett_poi_VehicleLength,
    &ett_poi_PathHistory,
    &ett_poi_EmergencyPriority,
    &ett_poi_SteeringWheelAngle,
    &ett_poi_YawRate,
    &ett_poi_ActionID,
    &ett_poi_ItineraryPath,
    &ett_poi_ProtectedCommunicationZone,
    &ett_poi_Traces,
    &ett_poi_PositionOfPillars,
    &ett_poi_RestrictedTypes,
    &ett_poi_EventHistory,
    &ett_poi_EventPoint,
    &ett_poi_ProtectedCommunicationZonesRSU,
    &ett_poi_CenDsrcTollingZone,
    &ett_poi_EvcsnPdu,
    &ett_poi_EVChargingSpotNotificationPOIMessage,
    &ett_poi_ItsPOIHeader,
    &ett_poi_ItsEVCSNData,
    &ett_poi_SEQUENCE_SIZE_1_256_OF_ItsChargingStationData,
    &ett_poi_ItsChargingStationData,
    &ett_poi_ItsChargingSpots,
    &ett_poi_ItsChargingSpotDataElements,
    &ett_poi_DigitalMap,
    &ett_poi_ChargingSpotType,
    &ett_poi_ParkingPlacesData,
    &ett_poi_SpotAvailability,

/*--- End of included file: packet-poi-ettarr.c ---*/
#line 96 "./asn1/poi/packet-poi-template.c"
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
