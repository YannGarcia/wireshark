/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-itsis.c                                                             */
/* asn2wrs.py -p itsis -c ./itsis.cnf -s ./packet-itsis-template -D . -O ../.. ETSI_TS_103301_IVIM_PDU_Descriptions.asn ETSI_TS_103301_MAPEM_PDU_Descriptions.asn ETSI_TS_103301_SPATEM_PDU_Descriptions.asn ETSI_TS_103301_SREM_PDU_Descriptions.asn ETSI_TS_103301_SSEM_PDU_Descriptions.asn ISO_TS_14816.asn ISO_TS_14906_Application.asn ISO_TS_14906_Generic.asn ISO_TS_17419.asn ISO_TS_19091_AddGrpC.asn ISO_TS_19091_DSRC.asn ISO_TS_19091_REGION.asn ISO_TS_19321.asn ISO_TS_24534-3.asn ITS-Container.asn */

/* Input file: packet-itsis-template.c */

#line 1 "./asn1/itsis/packet-itsis-template.c"
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


/*--- Included file: packet-itsis-hf.c ---*/
#line 1 "./asn1/itsis/packet-itsis-hf.c"
static int hf_itsis_IVIM_PDU = -1;                /* IVIM */
static int hf_itsis_MAPEM_PDU = -1;               /* MAPEM */
static int hf_itsis_SPATEM_PDU = -1;              /* SPATEM */
static int hf_itsis_SREM_PDU = -1;                /* SREM */
static int hf_itsis_SSEM_PDU = -1;                /* SSEM */
static int hf_itsis_header = -1;                  /* ItsPduHeader */
static int hf_itsis_ivi = -1;                     /* IviStructure */
static int hf_itsis_map = -1;                     /* MapData */
static int hf_itsis_spat = -1;                    /* SPAT */
static int hf_itsis_srm = -1;                     /* SignalRequestMessage */
static int hf_itsis_ssm = -1;                     /* SignalStatusMessage */
static int hf_itsis_vin = -1;                     /* VisibleString */
static int hf_itsis_fill = -1;                    /* BIT_STRING_SIZE_9 */
static int hf_itsis_maxLadenweightOnAxle1 = -1;   /* Int2 */
static int hf_itsis_maxLadenweightOnAxle2 = -1;   /* Int2 */
static int hf_itsis_maxLadenweightOnAxle3 = -1;   /* Int2 */
static int hf_itsis_maxLadenweightOnAxle4 = -1;   /* Int2 */
static int hf_itsis_maxLadenweightOnAxle5 = -1;   /* Int2 */
static int hf_itsis_particulate = -1;             /* T_particulate */
static int hf_itsis_unitType = -1;                /* UnitType */
static int hf_itsis_value = -1;                   /* INTEGER_0_32767 */
static int hf_itsis_absorptionCoeff = -1;         /* Int2 */
static int hf_itsis_euroValue = -1;               /* EuroValue */
static int hf_itsis_copValue = -1;                /* CopValue */
static int hf_itsis_emissionCO = -1;              /* INTEGER_0_32767 */
static int hf_itsis_emissionHC = -1;              /* Int2 */
static int hf_itsis_emissionNOX = -1;             /* Int2 */
static int hf_itsis_emissionHCNOX = -1;           /* Int2 */
static int hf_itsis_numberOfSeats = -1;           /* Int1 */
static int hf_itsis_numberOfStandingPlaces = -1;  /* Int1 */
static int hf_itsis_countryCode = -1;             /* CountryCode */
static int hf_itsis_providerIdentifier = -1;      /* IssuerIdentifier */
static int hf_itsis_soundstationary = -1;         /* Int1 */
static int hf_itsis_sounddriveby = -1;            /* Int1 */
static int hf_itsis_vehicleLengthOverall = -1;    /* Int1 */
static int hf_itsis_vehicleHeigthOverall = -1;    /* Int1 */
static int hf_itsis_vehicleWidthOverall = -1;     /* Int1 */
static int hf_itsis_vehicleMaxLadenWeight = -1;   /* Int2 */
static int hf_itsis_vehicleTrainMaximumWeight = -1;  /* Int2 */
static int hf_itsis_vehicleWeightUnladen = -1;    /* Int2 */
static int hf_itsis_AttributeIdList_item = -1;    /* INTEGER_0_127_ */
static int hf_itsis_AttributeList_item = -1;      /* Attributes */
static int hf_itsis_attributeId = -1;             /* INTEGER_0_127_ */
static int hf_itsis_attributeValue = -1;          /* Container */
static int hf_itsis_content = -1;                 /* INTEGER_0_127 */
static int hf_itsis_extension = -1;               /* Ext1 */
static int hf_itsis_content_01 = -1;              /* INTEGER_128_16511 */
static int hf_itsis_extension_01 = -1;            /* Ext2 */
static int hf_itsis_content_02 = -1;              /* INTEGER_16512_2113663 */
static int hf_itsis_extension_02 = -1;            /* Ext3 */
static int hf_itsis_vehicleToLanePositions = -1;  /* VehicleToLanePositionList */
static int hf_itsis_rsuGNSSOffset = -1;           /* NodeOffsetPointXY */
static int hf_itsis_nodes = -1;                   /* NodeSetXY */
static int hf_itsis_ptvRequest = -1;              /* PtvRequestType */
static int hf_itsis_activePrioritizations = -1;   /* PrioritizationResponseList */
static int hf_itsis_signalHeadLocations = -1;     /* SignalHeadLocationList */
static int hf_itsis_altitude = -1;                /* Altitude */
static int hf_itsis_PrioritizationResponseList_item = -1;  /* PrioritizationResponse */
static int hf_itsis_stationed = -1;               /* StationID */
static int hf_itsis_priorState = -1;              /* PrioritizationResponseStatus */
static int hf_itsis_signalGroup = -1;             /* SignalGroupID */
static int hf_itsis_emission = -1;                /* EmissionType */
static int hf_itsis_SignalHeadLocationList_item = -1;  /* SignalHeadLocation */
static int hf_itsis_nodeXY = -1;                  /* NodeOffsetPointXY */
static int hf_itsis_nodeZ = -1;                   /* DeltaAltitude */
static int hf_itsis_signalGroupID = -1;           /* SignalGroupID */
static int hf_itsis_synchToSchedule = -1;         /* DeltaTime */
static int hf_itsis_VehicleToLanePositionList_item = -1;  /* VehicleToLanePosition */
static int hf_itsis_stationID = -1;               /* StationID */
static int hf_itsis_laneID = -1;                  /* LaneID */
static int hf_itsis_timeReference = -1;           /* TimeReference */
static int hf_itsis_messageId = -1;               /* DSRCmsgID */
static int hf_itsis_value_01 = -1;                /* T_value */
static int hf_itsis_regionId = -1;                /* RegionId */
static int hf_itsis_regExtValue = -1;             /* T_regExtValue */
static int hf_itsis_timeStamp = -1;               /* MinuteOfTheYear */
static int hf_itsis_name = -1;                    /* DescriptiveName */
static int hf_itsis_intersections = -1;           /* IntersectionStateList */
static int hf_itsis_regional = -1;                /* SEQUENCE_SIZE_1_4_OF_RegionalExtension */
static int hf_itsis_regional_item = -1;           /* RegionalExtension */
static int hf_itsis_second = -1;                  /* DSecond */
static int hf_itsis_sequenceNumber = -1;          /* MsgCount */
static int hf_itsis_requests = -1;                /* SignalRequestList */
static int hf_itsis_requestor = -1;               /* RequestorDescription */
static int hf_itsis_status = -1;                  /* SignalStatusList */
static int hf_itsis_msgIssueRevision = -1;        /* MsgCount */
static int hf_itsis_layerType = -1;               /* LayerType */
static int hf_itsis_layerID = -1;                 /* LayerID */
static int hf_itsis_intersections_01 = -1;        /* IntersectionGeometryList */
static int hf_itsis_roadSegments = -1;            /* RoadSegmentList */
static int hf_itsis_dataParameters = -1;          /* DataParameters */
static int hf_itsis_restrictionList = -1;         /* RestrictionClassList */
static int hf_itsis_type = -1;                    /* AdvisorySpeedType */
static int hf_itsis_speed = -1;                   /* SpeedAdvice */
static int hf_itsis_confidence = -1;              /* SpeedConfidence */
static int hf_itsis_distance = -1;                /* ZoneLength */
static int hf_itsis_class = -1;                   /* RestrictionClassID */
static int hf_itsis_AdvisorySpeedList_item = -1;  /* AdvisorySpeed */
static int hf_itsis_referenceLaneId = -1;         /* LaneID */
static int hf_itsis_offsetXaxis = -1;             /* T_offsetXaxis */
static int hf_itsis_small = -1;                   /* DrivenLineOffsetSm */
static int hf_itsis_large = -1;                   /* DrivenLineOffsetLg */
static int hf_itsis_offsetYaxis = -1;             /* T_offsetYaxis */
static int hf_itsis_rotateXY = -1;                /* Angle */
static int hf_itsis_scaleXaxis = -1;              /* Scale_B12 */
static int hf_itsis_scaleYaxis = -1;              /* Scale_B12 */
static int hf_itsis_ConnectsToList_item = -1;     /* Connection */
static int hf_itsis_lane = -1;                    /* LaneID */
static int hf_itsis_maneuver = -1;                /* AllowedManeuvers */
static int hf_itsis_connectingLane = -1;          /* ConnectingLane */
static int hf_itsis_remoteIntersection = -1;      /* IntersectionReferenceID */
static int hf_itsis_userClass = -1;               /* RestrictionClassID */
static int hf_itsis_connectionID = -1;            /* LaneConnectionID */
static int hf_itsis_queueLength = -1;             /* ZoneLength */
static int hf_itsis_availableStorageLength = -1;  /* ZoneLength */
static int hf_itsis_waitOnStop = -1;              /* WaitOnStopline */
static int hf_itsis_pedBicycleDetect = -1;        /* PedestrianBicycleDetect */
static int hf_itsis_processMethod = -1;           /* IA5String_SIZE_1_255 */
static int hf_itsis_processAgency = -1;           /* IA5String_SIZE_1_255 */
static int hf_itsis_lastCheckedDate = -1;         /* IA5String_SIZE_1_255 */
static int hf_itsis_geoidUsed = -1;               /* IA5String_SIZE_1_255 */
static int hf_itsis_EnabledLaneList_item = -1;    /* LaneID */
static int hf_itsis_ingressApproach = -1;         /* ApproachID */
static int hf_itsis_egressApproach = -1;          /* ApproachID */
static int hf_itsis_laneAttributes = -1;          /* LaneAttributes */
static int hf_itsis_maneuvers = -1;               /* AllowedManeuvers */
static int hf_itsis_nodeList = -1;                /* NodeListXY */
static int hf_itsis_connectsTo = -1;              /* ConnectsToList */
static int hf_itsis_overlays = -1;                /* OverlayLaneList */
static int hf_itsis_approach = -1;                /* ApproachID */
static int hf_itsis_connection = -1;              /* LaneConnectionID */
static int hf_itsis_id = -1;                      /* IntersectionReferenceID */
static int hf_itsis_revision = -1;                /* MsgCount */
static int hf_itsis_refPoint = -1;                /* Position3D */
static int hf_itsis_laneWidth = -1;               /* LaneWidth */
static int hf_itsis_speedLimits = -1;             /* SpeedLimitList */
static int hf_itsis_laneSet = -1;                 /* LaneList */
static int hf_itsis_preemptPriorityData = -1;     /* PreemptPriorityList */
static int hf_itsis_IntersectionGeometryList_item = -1;  /* IntersectionGeometry */
static int hf_itsis_region = -1;                  /* RoadRegulatorID */
static int hf_itsis_id_01 = -1;                   /* IntersectionID */
static int hf_itsis_status_01 = -1;               /* IntersectionStatusObject */
static int hf_itsis_moy = -1;                     /* MinuteOfTheYear */
static int hf_itsis_timeStamp_01 = -1;            /* DSecond */
static int hf_itsis_enabledLanes = -1;            /* EnabledLaneList */
static int hf_itsis_states = -1;                  /* MovementList */
static int hf_itsis_maneuverAssistList = -1;      /* ManeuverAssistList */
static int hf_itsis_IntersectionStateList_item = -1;  /* IntersectionState */
static int hf_itsis_directionalUse = -1;          /* LaneDirection */
static int hf_itsis_sharedWith = -1;              /* LaneSharing */
static int hf_itsis_laneType = -1;                /* LaneTypeAttributes */
static int hf_itsis_regional_01 = -1;             /* RegionalExtension */
static int hf_itsis_pathEndPointAngle = -1;       /* DeltaAngle */
static int hf_itsis_laneCrownPointCenter = -1;    /* RoadwayCrownAngle */
static int hf_itsis_laneCrownPointLeft = -1;      /* RoadwayCrownAngle */
static int hf_itsis_laneCrownPointRight = -1;     /* RoadwayCrownAngle */
static int hf_itsis_laneAngle = -1;               /* MergeDivergeNodeAngle */
static int hf_itsis_LaneDataAttributeList_item = -1;  /* LaneDataAttribute */
static int hf_itsis_LaneList_item = -1;           /* GenericLane */
static int hf_itsis_vehicle = -1;                 /* LaneAttributes_Vehicle */
static int hf_itsis_crosswalk = -1;               /* LaneAttributes_Crosswalk */
static int hf_itsis_bikeLane = -1;                /* LaneAttributes_Bike */
static int hf_itsis_sidewalk = -1;                /* LaneAttributes_Sidewalk */
static int hf_itsis_median = -1;                  /* LaneAttributes_Barrier */
static int hf_itsis_striping = -1;                /* LaneAttributes_Striping */
static int hf_itsis_trackedVehicle = -1;          /* LaneAttributes_TrackedVehicle */
static int hf_itsis_parking = -1;                 /* LaneAttributes_Parking */
static int hf_itsis_ManeuverAssistList_item = -1;  /* ConnectionManeuverAssist */
static int hf_itsis_MovementEventList_item = -1;  /* MovementEvent */
static int hf_itsis_eventState = -1;              /* MovementPhaseState */
static int hf_itsis_timing = -1;                  /* TimeChangeDetails */
static int hf_itsis_speeds = -1;                  /* AdvisorySpeedList */
static int hf_itsis_MovementList_item = -1;       /* MovementState */
static int hf_itsis_movementName = -1;            /* DescriptiveName */
static int hf_itsis_state_time_speed = -1;        /* MovementEventList */
static int hf_itsis_localNode = -1;               /* NodeAttributeXYList */
static int hf_itsis_disabled = -1;                /* SegmentAttributeXYList */
static int hf_itsis_enabled = -1;                 /* SegmentAttributeXYList */
static int hf_itsis_data = -1;                    /* LaneDataAttributeList */
static int hf_itsis_dWidth = -1;                  /* Offset_B10 */
static int hf_itsis_dElevation = -1;              /* Offset_B10 */
static int hf_itsis_NodeAttributeXYList_item = -1;  /* NodeAttributeXY */
static int hf_itsis_lon = -1;                     /* Longitude */
static int hf_itsis_lat = -1;                     /* Latitude */
static int hf_itsis_x = -1;                       /* Offset_B10 */
static int hf_itsis_y = -1;                       /* Offset_B10 */
static int hf_itsis_x_01 = -1;                    /* Offset_B11 */
static int hf_itsis_y_01 = -1;                    /* Offset_B11 */
static int hf_itsis_x_02 = -1;                    /* Offset_B12 */
static int hf_itsis_y_02 = -1;                    /* Offset_B12 */
static int hf_itsis_x_03 = -1;                    /* Offset_B13 */
static int hf_itsis_y_03 = -1;                    /* Offset_B13 */
static int hf_itsis_x_04 = -1;                    /* Offset_B14 */
static int hf_itsis_y_04 = -1;                    /* Offset_B14 */
static int hf_itsis_x_05 = -1;                    /* Offset_B16 */
static int hf_itsis_y_05 = -1;                    /* Offset_B16 */
static int hf_itsis_computed = -1;                /* ComputedLane */
static int hf_itsis_node_XY1 = -1;                /* Node_XY_20b */
static int hf_itsis_node_XY2 = -1;                /* Node_XY_22b */
static int hf_itsis_node_XY3 = -1;                /* Node_XY_24b */
static int hf_itsis_node_XY4 = -1;                /* Node_XY_26b */
static int hf_itsis_node_XY5 = -1;                /* Node_XY_28b */
static int hf_itsis_node_XY6 = -1;                /* Node_XY_32b */
static int hf_itsis_node_LatLon = -1;             /* Node_LLmD_64b */
static int hf_itsis_NodeSetXY_item = -1;          /* NodeXY */
static int hf_itsis_delta = -1;                   /* NodeOffsetPointXY */
static int hf_itsis_attributes = -1;              /* NodeAttributeSetXY */
static int hf_itsis_OverlayLaneList_item = -1;    /* LaneID */
static int hf_itsis_long = -1;                    /* Longitude */
static int hf_itsis_elevation = -1;               /* Elevation */
static int hf_itsis_PreemptPriorityList_item = -1;  /* SignalControlZone */
static int hf_itsis_type_01 = -1;                 /* SpeedLimitType */
static int hf_itsis_speed_01 = -1;                /* Velocity */
static int hf_itsis_id_02 = -1;                   /* VehicleID */
static int hf_itsis_type_02 = -1;                 /* RequestorType */
static int hf_itsis_position = -1;                /* RequestorPositionVector */
static int hf_itsis_routeName = -1;               /* DescriptiveName */
static int hf_itsis_transitStatus = -1;           /* TransitVehicleStatus */
static int hf_itsis_transitOccupancy = -1;        /* TransitVehicleOccupancy */
static int hf_itsis_transitSchedule = -1;         /* DeltaTime */
static int hf_itsis_position_01 = -1;             /* Position3D */
static int hf_itsis_heading = -1;                 /* Angle */
static int hf_itsis_speed_02 = -1;                /* TransmissionAndSpeed */
static int hf_itsis_role = -1;                    /* BasicVehicleRole */
static int hf_itsis_subrole = -1;                 /* RequestSubRole */
static int hf_itsis_request = -1;                 /* RequestImportanceLevel */
static int hf_itsis_iso3883 = -1;                 /* Iso3833VehicleType */
static int hf_itsis_hpmsType = -1;                /* VehicleType */
static int hf_itsis_id_03 = -1;                   /* RestrictionClassID */
static int hf_itsis_users = -1;                   /* RestrictionUserTypeList */
static int hf_itsis_RestrictionClassList_item = -1;  /* RestrictionClassAssignment */
static int hf_itsis_RestrictionUserTypeList_item = -1;  /* RestrictionUserType */
static int hf_itsis_basicType = -1;               /* RestrictionAppliesTo */
static int hf_itsis_RoadLaneSetList_item = -1;    /* GenericLane */
static int hf_itsis_id_04 = -1;                   /* RoadSegmentID */
static int hf_itsis_id_05 = -1;                   /* RoadSegmentReferenceID */
static int hf_itsis_roadLaneSet = -1;             /* RoadLaneSetList */
static int hf_itsis_RoadSegmentList_item = -1;    /* RoadSegment */
static int hf_itsis_SegmentAttributeXYList_item = -1;  /* SegmentAttributeXY */
static int hf_itsis_zone = -1;                    /* RegionalExtension */
static int hf_itsis_request_01 = -1;              /* RequestID */
static int hf_itsis_typeData = -1;                /* RequestorType */
static int hf_itsis_SignalRequestList_item = -1;  /* SignalRequestPackage */
static int hf_itsis_request_02 = -1;              /* SignalRequest */
static int hf_itsis_minute = -1;                  /* MinuteOfTheYear */
static int hf_itsis_duration = -1;                /* DSecond */
static int hf_itsis_requestID = -1;               /* RequestID */
static int hf_itsis_requestType = -1;             /* PriorityRequestType */
static int hf_itsis_inBoundLane = -1;             /* IntersectionAccessPoint */
static int hf_itsis_outBoundLane = -1;            /* IntersectionAccessPoint */
static int hf_itsis_SignalStatusList_item = -1;   /* SignalStatus */
static int hf_itsis_SignalStatusPackageList_item = -1;  /* SignalStatusPackage */
static int hf_itsis_requester = -1;               /* SignalRequesterInfo */
static int hf_itsis_inboundOn = -1;               /* IntersectionAccessPoint */
static int hf_itsis_outboundOn = -1;              /* IntersectionAccessPoint */
static int hf_itsis_status_02 = -1;               /* PrioritizationResponseStatus */
static int hf_itsis_sigStatus = -1;               /* SignalStatusPackageList */
static int hf_itsis_SpeedLimitList_item = -1;     /* RegulatorySpeedLimit */
static int hf_itsis_startTime = -1;               /* TimeMark */
static int hf_itsis_minEndTime = -1;              /* TimeMark */
static int hf_itsis_maxEndTime = -1;              /* TimeMark */
static int hf_itsis_likelyTime = -1;              /* TimeMark */
static int hf_itsis_confidence_01 = -1;           /* TimeIntervalConfidence */
static int hf_itsis_nextTime = -1;                /* TimeMark */
static int hf_itsis_transmisson = -1;             /* TransmissionState */
static int hf_itsis_entityID = -1;                /* TemporaryID */
static int hf_itsis_mandatory = -1;               /* IVIManagementContainer */
static int hf_itsis_optional = -1;                /* SEQUENCE_SIZE_1_8__OF_IviContainer */
static int hf_itsis_optional_item = -1;           /* IviContainer */
static int hf_itsis_glc = -1;                     /* GeographicLocationContainer */
static int hf_itsis_giv = -1;                     /* GeneralIviContainer */
static int hf_itsis_rcc = -1;                     /* RoadConfigurationContainer */
static int hf_itsis_tc = -1;                      /* TextContainer */
static int hf_itsis_lac = -1;                     /* LayoutContainer */
static int hf_itsis_serviceProviderId = -1;       /* Provider */
static int hf_itsis_iviIdentificationNumber = -1;  /* IviIdentificationNumber */
static int hf_itsis_timeStamp_02 = -1;            /* TimestampIts */
static int hf_itsis_validFrom = -1;               /* TimestampIts */
static int hf_itsis_validTo = -1;                 /* TimestampIts */
static int hf_itsis_connectedIviStructures = -1;  /* SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber */
static int hf_itsis_connectedIviStructures_item = -1;  /* IviIdentificationNumber */
static int hf_itsis_iviStatus = -1;               /* IviStatus */
static int hf_itsis_referencePosition = -1;       /* ReferencePosition */
static int hf_itsis_referencePositionTime = -1;   /* TimestampIts */
static int hf_itsis_referencePositionHeading = -1;  /* Heading */
static int hf_itsis_referencePositionSpeed = -1;  /* Speed */
static int hf_itsis_parts = -1;                   /* SEQUENCE_SIZE_1_16__OF_GlcPart */
static int hf_itsis_parts_item = -1;              /* GlcPart */
static int hf_itsis_zoneId = -1;                  /* Zid */
static int hf_itsis_laneNumber = -1;              /* LanePosition */
static int hf_itsis_zoneExtension = -1;           /* INTEGER_0_255 */
static int hf_itsis_zoneHeading = -1;             /* HeadingValue */
static int hf_itsis_zone_01 = -1;                 /* Zone */
static int hf_itsis_GeneralIviContainer_item = -1;  /* GicPart */
static int hf_itsis_detectionZoneIds = -1;        /* SEQUENCE_SIZE_1_8__OF_Zid */
static int hf_itsis_detectionZoneIds_item = -1;   /* Zid */
static int hf_itsis_its_Rrid = -1;                /* VarLengthNumber */
static int hf_itsis_relevanceZoneIds = -1;        /* SEQUENCE_SIZE_1_8__OF_Zid */
static int hf_itsis_relevanceZoneIds_item = -1;   /* Zid */
static int hf_itsis_direction = -1;               /* Direction */
static int hf_itsis_driverAwarenessZoneIds = -1;  /* SEQUENCE_SIZE_1_8__OF_Zid */
static int hf_itsis_driverAwarenessZoneIds_item = -1;  /* Zid */
static int hf_itsis_minimumAwarenessTime = -1;    /* INTEGER_0_255 */
static int hf_itsis_applicableLanes = -1;         /* SEQUENCE_SIZE_1_8__OF_LanePosition */
static int hf_itsis_applicableLanes_item = -1;    /* LanePosition */
static int hf_itsis_iviType = -1;                 /* IviType */
static int hf_itsis_iviPurpose = -1;              /* IviPurpose */
static int hf_itsis_laneStatus = -1;              /* LaneStatus */
static int hf_itsis_vehicleCharacteristics = -1;  /* SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics */
static int hf_itsis_vehicleCharacteristics_item = -1;  /* CompleteVehicleCharacteristics */
static int hf_itsis_driverCharacteristics = -1;   /* DriverCharacteristics */
static int hf_itsis_layoutId = -1;                /* INTEGER_1_4_ */
static int hf_itsis_preStoredlayoutId = -1;       /* INTEGER_1_64_ */
static int hf_itsis_roadSignCodes = -1;           /* SEQUENCE_SIZE_1_4__OF_RSCode */
static int hf_itsis_roadSignCodes_item = -1;      /* RSCode */
static int hf_itsis_extraText = -1;               /* SEQUENCE_SIZE_1_4__OF_Text */
static int hf_itsis_extraText_item = -1;          /* Text */
static int hf_itsis_RoadConfigurationContainer_item = -1;  /* RccPart */
static int hf_itsis_zoneIds = -1;                 /* SEQUENCE_SIZE_1_8__OF_Zid */
static int hf_itsis_zoneIds_item = -1;            /* Zid */
static int hf_itsis_roadType = -1;                /* RoadType */
static int hf_itsis_laneConfiguration = -1;       /* SEQUENCE_SIZE_1_16__OF_LaneInformation */
static int hf_itsis_laneConfiguration_item = -1;  /* LaneInformation */
static int hf_itsis_TextContainer_item = -1;      /* TcPart */
static int hf_itsis_text = -1;                    /* SEQUENCE_SIZE_1_4__OF_Text */
static int hf_itsis_text_item = -1;               /* Text */
static int hf_itsis_data_01 = -1;                 /* OCTET_STRING */
static int hf_itsis_height = -1;                  /* INTEGER_10_73 */
static int hf_itsis_width = -1;                   /* INTEGER_10_265 */
static int hf_itsis_layoutComponents = -1;        /* SEQUENCE_SIZE_1_4__OF_LayoutComponent */
static int hf_itsis_layoutComponents_item = -1;   /* LayoutComponent */
static int hf_itsis_latitude = -1;                /* Latitude */
static int hf_itsis_longitude = -1;               /* Longitude */
static int hf_itsis_owner = -1;                   /* Provider */
static int hf_itsis_version = -1;                 /* INTEGER_0_255 */
static int hf_itsis_pictogramCode = -1;           /* INTEGER_0_65535 */
static int hf_itsis_value_02 = -1;                /* INTEGER_0_65535 */
static int hf_itsis_unit = -1;                    /* RSCUnit */
static int hf_itsis_attributes_01 = -1;           /* ISO14823Attributes */
static int hf_itsis_tractor = -1;                 /* TractorCharacteristics */
static int hf_itsis_trailer = -1;                 /* SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics */
static int hf_itsis_trailer_item = -1;            /* TrailerCharacteristics */
static int hf_itsis_train = -1;                   /* TrainCharacteristics */
static int hf_itsis_laneWidth_01 = -1;            /* IVILaneWidth */
static int hf_itsis_offsetDistance = -1;          /* INTEGER_M32768_32767 */
static int hf_itsis_offsetPosition = -1;          /* DeltaReferencePosition */
static int hf_itsis_deltaLatitude = -1;           /* DeltaLatitude */
static int hf_itsis_deltaLongitude = -1;          /* DeltaLongitude */
static int hf_itsis_value_03 = -1;                /* INTEGER_1_16384 */
static int hf_itsis_unit_01 = -1;                 /* RSCUnit2468 */
static int hf_itsis_unit_02 = -1;                 /* RSCUnit29 */
static int hf_itsis_ISO14823Attributes_item = -1;  /* ISO14823Attributes_item */
static int hf_itsis_dtm = -1;                     /* DTM */
static int hf_itsis_edt = -1;                     /* EDT */
static int hf_itsis_dfl = -1;                     /* DFL */
static int hf_itsis_ved = -1;                     /* VED */
static int hf_itsis_spe = -1;                     /* SPE */
static int hf_itsis_roi = -1;                     /* ROI */
static int hf_itsis_dbv = -1;                     /* DBV */
static int hf_itsis_ddd = -1;                     /* DDD */
static int hf_itsis_pictogramCode_01 = -1;        /* T_pictogramCode */
static int hf_itsis_countryCode_01 = -1;          /* OCTET_STRING_SIZE_2 */
static int hf_itsis_serviceCategoryCode = -1;     /* T_serviceCategoryCode */
static int hf_itsis_trafficSignPictogram = -1;    /* T_trafficSignPictogram */
static int hf_itsis_publicFacilitiesPictogram = -1;  /* T_publicFacilitiesPictogram */
static int hf_itsis_ambientOrRoadConditionPictogram = -1;  /* T_ambientOrRoadConditionPictogram */
static int hf_itsis_pictogramCategoryCode = -1;   /* T_pictogramCategoryCode */
static int hf_itsis_nature = -1;                  /* INTEGER_1_9 */
static int hf_itsis_serialNumber = -1;            /* INTEGER_0_99 */
static int hf_itsis_validity = -1;                /* DTM */
static int hf_itsis_laneType_01 = -1;             /* LaneType */
static int hf_itsis_laneTypeQualifier = -1;       /* CompleteVehicleCharacteristics */
static int hf_itsis_layoutComponentId = -1;       /* INTEGER_1_8_ */
static int hf_itsis_x_06 = -1;                    /* INTEGER_10_265 */
static int hf_itsis_y_06 = -1;                    /* INTEGER_10_73 */
static int hf_itsis_textScripting = -1;           /* T_textScripting */
static int hf_itsis_goodsType = -1;               /* GoodsType */
static int hf_itsis_dangerousGoodsType = -1;      /* DangerousGoodsBasic */
static int hf_itsis_specialTransportType = -1;    /* SpecialTransportType */
static int hf_itsis_deltaPositions = -1;          /* SEQUENCE_SIZE_1_32__OF_DeltaPosition */
static int hf_itsis_deltaPositions_item = -1;     /* DeltaPosition */
static int hf_itsis_deltaPositionsWithAltitude = -1;  /* SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition */
static int hf_itsis_deltaPositionsWithAltitude_item = -1;  /* DeltaReferencePosition */
static int hf_itsis_absolutePositions = -1;       /* SEQUENCE_SIZE_1_8__OF_AbsolutePosition */
static int hf_itsis_absolutePositions_item = -1;  /* AbsolutePosition */
static int hf_itsis_absolutePositionsWithAltitude = -1;  /* SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude */
static int hf_itsis_absolutePositionsWithAltitude_item = -1;  /* AbsolutePositionWAltitude */
static int hf_itsis_layoutComponentId_01 = -1;    /* INTEGER_1_4_ */
static int hf_itsis_code = -1;                    /* T_code */
static int hf_itsis_viennaConvention = -1;        /* VcCode */
static int hf_itsis_iso14823 = -1;                /* ISO14823Code */
static int hf_itsis_itisCodes = -1;               /* INTEGER_0_65535 */
static int hf_itsis_anyCatalogue = -1;            /* AnyCatalogue */
static int hf_itsis_line = -1;                    /* PolygonalLine */
static int hf_itsis_language = -1;                /* BIT_STRING_SIZE_10 */
static int hf_itsis_textContent = -1;             /* UTF8String */
static int hf_itsis_equalTo = -1;                 /* SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues */
static int hf_itsis_equalTo_item = -1;            /* VehicleCharacteristicsFixValues */
static int hf_itsis_notEqualTo = -1;              /* SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues */
static int hf_itsis_notEqualTo_item = -1;         /* VehicleCharacteristicsFixValues */
static int hf_itsis_ranges = -1;                  /* SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges */
static int hf_itsis_ranges_item = -1;             /* VehicleCharacteristicsRanges */
static int hf_itsis_roadSignClass = -1;           /* VcClass */
static int hf_itsis_roadSignCode = -1;            /* INTEGER_1_64 */
static int hf_itsis_vcOption = -1;                /* VcOption */
static int hf_itsis_validity_01 = -1;             /* SEQUENCE_SIZE_1_8__OF_DTM */
static int hf_itsis_validity_item = -1;           /* DTM */
static int hf_itsis_simpleVehicleType = -1;       /* StationType */
static int hf_itsis_euVehicleCategoryCode = -1;   /* EuVehicleCategoryCode */
static int hf_itsis_iso3833VehicleType = -1;      /* Iso3833VehicleType */
static int hf_itsis_euroAndCo2value = -1;         /* EnvironmentalCharacteristics */
static int hf_itsis_engineCharacteristics = -1;   /* EngineCharacteristics */
static int hf_itsis_loadType = -1;                /* LoadType */
static int hf_itsis_usage = -1;                   /* VehicleRole */
static int hf_itsis_comparisonOperator = -1;      /* ComparisonOperator */
static int hf_itsis_limits = -1;                  /* T_limits */
static int hf_itsis_numberOfAxles = -1;           /* INTEGER_0_7 */
static int hf_itsis_vehicleDimensions = -1;       /* VehicleDimensions */
static int hf_itsis_vehicleWeightLimits = -1;     /* VehicleWeightLimits */
static int hf_itsis_axleWeightLimits = -1;        /* AxleWeightLimits */
static int hf_itsis_passengerCapacity = -1;       /* PassengerCapacity */
static int hf_itsis_exhaustEmissionValues = -1;   /* ExhaustEmissionValues */
static int hf_itsis_dieselEmissionValues = -1;    /* DieselEmissionValues */
static int hf_itsis_soundLevel = -1;              /* SoundLevel */
static int hf_itsis_unit_03 = -1;                 /* RSCUnit1012 */
static int hf_itsis_segment = -1;                 /* Segment */
static int hf_itsis_area = -1;                    /* PolygonalLine */
static int hf_itsis_computedSegment = -1;         /* ComputedSegment */
static int hf_itsis_year = -1;                    /* T_year */
static int hf_itsis_syr = -1;                     /* INTEGER_2000_2127_ */
static int hf_itsis_eyr = -1;                     /* INTEGER_2000_2127_ */
static int hf_itsis_month_day = -1;               /* T_month_day */
static int hf_itsis_smd = -1;                     /* MonthDay */
static int hf_itsis_emd = -1;                     /* MonthDay */
static int hf_itsis_pmd = -1;                     /* PMD */
static int hf_itsis_hourMinutes = -1;             /* T_hourMinutes */
static int hf_itsis_shm = -1;                     /* HoursMinutes */
static int hf_itsis_ehm = -1;                     /* HoursMinutes */
static int hf_itsis_dayOfWeek = -1;               /* DayOfWeek */
static int hf_itsis_period = -1;                  /* HoursMinutes */
static int hf_itsis_month = -1;                   /* INTEGER_1_12 */
static int hf_itsis_day = -1;                     /* INTEGER_1_31 */
static int hf_itsis_hours = -1;                   /* INTEGER_0_23 */
static int hf_itsis_mins = -1;                    /* INTEGER_0_59 */
static int hf_itsis_hei = -1;                     /* Distance */
static int hf_itsis_wid = -1;                     /* Distance */
static int hf_itsis_vln = -1;                     /* Distance */
static int hf_itsis_wei = -1;                     /* Weight */
static int hf_itsis_spm = -1;                     /* INTEGER_0_250 */
static int hf_itsis_mns = -1;                     /* INTEGER_0_250 */
static int hf_itsis_unit_04 = -1;                 /* RSCUnit01 */
static int hf_itsis_dcj = -1;                     /* INTEGER_1_128 */
static int hf_itsis_dcr = -1;                     /* INTEGER_1_128 */
static int hf_itsis_tpl = -1;                     /* INTEGER_1_128 */
static int hf_itsis_ioList = -1;                  /* SEQUENCE_SIZE_1_8__OF_DDD_IO */
static int hf_itsis_ioList_item = -1;             /* DDD_IO */
static int hf_itsis_drn = -1;                     /* INTEGER_0_7 */
static int hf_itsis_dp = -1;                      /* SEQUENCE_SIZE_1_4__OF_DestinationPlace */
static int hf_itsis_dp_item = -1;                 /* DestinationPlace */
static int hf_itsis_dr = -1;                      /* SEQUENCE_SIZE_1_4__OF_DestinationRoad */
static int hf_itsis_dr_item = -1;                 /* DestinationRoad */
static int hf_itsis_rne = -1;                     /* INTEGER_1_999 */
static int hf_itsis_stnId = -1;                   /* INTEGER_1_999 */
static int hf_itsis_stnText = -1;                 /* UTF8String */
static int hf_itsis_dcp = -1;                     /* DistanceOrDuration */
static int hf_itsis_ddp = -1;                     /* DistanceOrDuration */
static int hf_itsis_depType = -1;                 /* DDD_DEP */
static int hf_itsis_depRSCode = -1;               /* ISO14823Code */
static int hf_itsis_depBlob = -1;                 /* OCTET_STRING */
static int hf_itsis_plnId = -1;                   /* INTEGER_1_999 */
static int hf_itsis_plnText = -1;                 /* UTF8String */
static int hf_itsis_derType = -1;                 /* DDD_DER */
static int hf_itsis_ronId = -1;                   /* INTEGER_1_999 */
static int hf_itsis_ronText = -1;                 /* UTF8String */
static int hf_itsis_euVehicleCategoryL = -1;      /* EuVehicleCategoryL */
static int hf_itsis_euVehicleCategoryM = -1;      /* EuVehicleCategoryM */
static int hf_itsis_euVehicleCategoryN = -1;      /* EuVehicleCategoryN */
static int hf_itsis_euVehicleCategoryO = -1;      /* EuVehicleCategoryO */
static int hf_itsis_euVehilcleCategoryT = -1;     /* NULL */
static int hf_itsis_euVehilcleCategoryG = -1;     /* NULL */
static int hf_itsis_protocolVersion = -1;         /* T_protocolVersion */
static int hf_itsis_messageID = -1;               /* T_messageID */
static int hf_itsis_positionConfidenceEllipse = -1;  /* PosConfidenceEllipse */
static int hf_itsis_deltaAltitude = -1;           /* DeltaAltitude */
static int hf_itsis_altitudeValue = -1;           /* AltitudeValue */
static int hf_itsis_altitudeConfidence = -1;      /* AltitudeConfidence */
static int hf_itsis_semiMajorConfidence = -1;     /* SemiAxisLength */
static int hf_itsis_semiMinorConfidence = -1;     /* SemiAxisLength */
static int hf_itsis_semiMajorOrientation = -1;    /* HeadingValue */
static int hf_itsis_pathPosition = -1;            /* DeltaReferencePosition */
static int hf_itsis_pathDeltaTime = -1;           /* PathDeltaTime */
static int hf_itsis_ptActivationType = -1;        /* PtActivationType */
static int hf_itsis_ptActivationData = -1;        /* PtActivationData */
static int hf_itsis_causeCode = -1;               /* CauseCodeType */
static int hf_itsis_subCauseCode = -1;            /* SubCauseCodeType */
static int hf_itsis_curvatureValue = -1;          /* CurvatureValue */
static int hf_itsis_curvatureConfidence = -1;     /* CurvatureConfidence */
static int hf_itsis_headingValue = -1;            /* HeadingValue */
static int hf_itsis_headingConfidence = -1;       /* HeadingConfidence */
static int hf_itsis_hardShoulderStatus = -1;      /* HardShoulderStatus */
static int hf_itsis_drivingLaneStatus = -1;       /* DrivingLaneStatus */
static int hf_itsis_speedValue = -1;              /* SpeedValue */
static int hf_itsis_speedConfidence = -1;         /* SpeedConfidence */
static int hf_itsis_longitudinalAccelerationValue = -1;  /* LongitudinalAccelerationValue */
static int hf_itsis_longitudinalAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_itsis_lateralAccelerationValue = -1;  /* LateralAccelerationValue */
static int hf_itsis_lateralAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_itsis_verticalAccelerationValue = -1;  /* VerticalAccelerationValue */
static int hf_itsis_verticalAccelerationConfidence = -1;  /* AccelerationConfidence */
static int hf_itsis_unNumber = -1;                /* INTEGER_0_9999 */
static int hf_itsis_elevatedTemperature = -1;     /* BOOLEAN */
static int hf_itsis_tunnelsRestricted = -1;       /* BOOLEAN */
static int hf_itsis_limitedQuantity = -1;         /* BOOLEAN */
static int hf_itsis_emergencyActionCode = -1;     /* IA5String_SIZE_1_24 */
static int hf_itsis_phoneNumber = -1;             /* IA5String_SIZE_1_24 */
static int hf_itsis_companyName = -1;             /* T_companyName */
static int hf_itsis_wMInumber = -1;               /* WMInumber */
static int hf_itsis_vDS = -1;                     /* VDS */
static int hf_itsis_vehicleLengthValue = -1;      /* VehicleLengthValue */
static int hf_itsis_vehicleLengthConfidenceIndication = -1;  /* VehicleLengthConfidenceIndication */
static int hf_itsis_PathHistory_item = -1;        /* PathPoint */
static int hf_itsis_steeringWheelAngleValue = -1;  /* SteeringWheelAngleValue */
static int hf_itsis_steeringWheelAngleConfidence = -1;  /* SteeringWheelAngleConfidence */
static int hf_itsis_yawRateValue = -1;            /* YawRateValue */
static int hf_itsis_yawRateConfidence = -1;       /* YawRateConfidence */
static int hf_itsis_originatingStationID = -1;    /* StationID */
static int hf_itsis_sequenceNumber_01 = -1;       /* SequenceNumber */
static int hf_itsis_ItineraryPath_item = -1;      /* ReferencePosition */
static int hf_itsis_protectedZoneType = -1;       /* ProtectedZoneType */
static int hf_itsis_expiryTime = -1;              /* TimestampIts */
static int hf_itsis_protectedZoneLatitude = -1;   /* Latitude */
static int hf_itsis_protectedZoneLongitude = -1;  /* Longitude */
static int hf_itsis_protectedZoneRadius = -1;     /* ProtectedZoneRadius */
static int hf_itsis_protectedZoneID = -1;         /* ProtectedZoneID */
static int hf_itsis_Traces_item = -1;             /* PathHistory */
static int hf_itsis_PositionOfPillars_item = -1;  /* PosPillar */
static int hf_itsis_RestrictedTypes_item = -1;    /* StationType */
static int hf_itsis_EventHistory_item = -1;       /* EventPoint */
static int hf_itsis_eventPosition = -1;           /* DeltaReferencePosition */
static int hf_itsis_eventDeltaTime = -1;          /* PathDeltaTime */
static int hf_itsis_informationQuality = -1;      /* InformationQuality */
static int hf_itsis_ProtectedCommunicationZonesRSU_item = -1;  /* ProtectedCommunicationZone */
static int hf_itsis_cenDsrcTollingZoneID = -1;    /* CenDsrcTollingZoneID */
/* named bits */
static int hf_itsis_LaneSharing_overlappingLaneDescriptionProvided = -1;
static int hf_itsis_LaneSharing_multipleLanesTreatedAsOneLane = -1;
static int hf_itsis_LaneSharing_otherNonMotorizedTrafficTypes = -1;
static int hf_itsis_LaneSharing_individualMotorizedVehicleTraffic = -1;
static int hf_itsis_LaneSharing_busVehicleTraffic = -1;
static int hf_itsis_LaneSharing_taxiVehicleTraffic = -1;
static int hf_itsis_LaneSharing_pedestriansTraffic = -1;
static int hf_itsis_LaneSharing_cyclistVehicleTraffic = -1;
static int hf_itsis_LaneSharing_trackedVehicleTraffic = -1;
static int hf_itsis_LaneSharing_pedestrianTraffic = -1;
static int hf_itsis_AllowedManeuvers_maneuverStraightAllowed = -1;
static int hf_itsis_AllowedManeuvers_maneuverLeftAllowed = -1;
static int hf_itsis_AllowedManeuvers_maneuverRightAllowed = -1;
static int hf_itsis_AllowedManeuvers_maneuverUTurnAllowed = -1;
static int hf_itsis_AllowedManeuvers_maneuverLeftTurnOnRedAllowed = -1;
static int hf_itsis_AllowedManeuvers_maneuverRightTurnOnRedAllowed = -1;
static int hf_itsis_AllowedManeuvers_maneuverLaneChangeAllowed = -1;
static int hf_itsis_AllowedManeuvers_maneuverNoStoppingAllowed = -1;
static int hf_itsis_AllowedManeuvers_yieldAllwaysRequired = -1;
static int hf_itsis_AllowedManeuvers_goWithHalt = -1;
static int hf_itsis_AllowedManeuvers_caution = -1;
static int hf_itsis_AllowedManeuvers_reserved1 = -1;
static int hf_itsis_IntersectionStatusObject_manualControlIsEnabled = -1;
static int hf_itsis_IntersectionStatusObject_stopTimeIsActivated = -1;
static int hf_itsis_IntersectionStatusObject_failureFlash = -1;
static int hf_itsis_IntersectionStatusObject_preemptIsActive = -1;
static int hf_itsis_IntersectionStatusObject_signalPriorityIsActive = -1;
static int hf_itsis_IntersectionStatusObject_fixedTimeOperation = -1;
static int hf_itsis_IntersectionStatusObject_trafficDependentOperation = -1;
static int hf_itsis_IntersectionStatusObject_standbyOperation = -1;
static int hf_itsis_IntersectionStatusObject_failureMode = -1;
static int hf_itsis_IntersectionStatusObject_off = -1;
static int hf_itsis_IntersectionStatusObject_recentMAPmessageUpdate = -1;
static int hf_itsis_IntersectionStatusObject_recentChangeInMAPassignedLanesIDsUsed = -1;
static int hf_itsis_IntersectionStatusObject_noValidMAPisAvailableAtThisTime = -1;
static int hf_itsis_IntersectionStatusObject_noValidSPATisAvailableAtThisTime = -1;
static int hf_itsis_LaneAttributes_Barrier_median_RevocableLane = -1;
static int hf_itsis_LaneAttributes_Barrier_median = -1;
static int hf_itsis_LaneAttributes_Barrier_whiteLineHashing = -1;
static int hf_itsis_LaneAttributes_Barrier_stripedLines = -1;
static int hf_itsis_LaneAttributes_Barrier_doubleStripedLines = -1;
static int hf_itsis_LaneAttributes_Barrier_trafficCones = -1;
static int hf_itsis_LaneAttributes_Barrier_constructionBarrier = -1;
static int hf_itsis_LaneAttributes_Barrier_trafficChannels = -1;
static int hf_itsis_LaneAttributes_Barrier_lowCurbs = -1;
static int hf_itsis_LaneAttributes_Barrier_highCurbs = -1;
static int hf_itsis_LaneAttributes_Bike_bikeRevocableLane = -1;
static int hf_itsis_LaneAttributes_Bike_pedestrianUseAllowed = -1;
static int hf_itsis_LaneAttributes_Bike_isBikeFlyOverLane = -1;
static int hf_itsis_LaneAttributes_Bike_fixedCycleTime = -1;
static int hf_itsis_LaneAttributes_Bike_biDirectionalCycleTimes = -1;
static int hf_itsis_LaneAttributes_Bike_isolatedByBarrier = -1;
static int hf_itsis_LaneAttributes_Bike_unsignalizedSegmentsPresent = -1;
static int hf_itsis_LaneAttributes_Crosswalk_crosswalkRevocableLane = -1;
static int hf_itsis_LaneAttributes_Crosswalk_bicyleUseAllowed = -1;
static int hf_itsis_LaneAttributes_Crosswalk_isXwalkFlyOverLane = -1;
static int hf_itsis_LaneAttributes_Crosswalk_fixedCycleTime = -1;
static int hf_itsis_LaneAttributes_Crosswalk_biDirectionalCycleTimes = -1;
static int hf_itsis_LaneAttributes_Crosswalk_hasPushToWalkButton = -1;
static int hf_itsis_LaneAttributes_Crosswalk_audioSupport = -1;
static int hf_itsis_LaneAttributes_Crosswalk_rfSignalRequestPresent = -1;
static int hf_itsis_LaneAttributes_Crosswalk_unsignalizedSegmentsPresent = -1;
static int hf_itsis_LaneAttributes_Parking_parkingRevocableLane = -1;
static int hf_itsis_LaneAttributes_Parking_parallelParkingInUse = -1;
static int hf_itsis_LaneAttributes_Parking_headInParkingInUse = -1;
static int hf_itsis_LaneAttributes_Parking_doNotParkZone = -1;
static int hf_itsis_LaneAttributes_Parking_parkingForBusUse = -1;
static int hf_itsis_LaneAttributes_Parking_parkingForTaxiUse = -1;
static int hf_itsis_LaneAttributes_Parking_noPublicParkingUse = -1;
static int hf_itsis_LaneAttributes_Sidewalk_sidewalk_RevocableLane = -1;
static int hf_itsis_LaneAttributes_Sidewalk_bicyleUseAllowed = -1;
static int hf_itsis_LaneAttributes_Sidewalk_isSidewalkFlyOverLane = -1;
static int hf_itsis_LaneAttributes_Sidewalk_walkBikes = -1;
static int hf_itsis_LaneAttributes_Striping_stripeToConnectingLanesRevocableLane = -1;
static int hf_itsis_LaneAttributes_Striping_stripeDrawOnLeft = -1;
static int hf_itsis_LaneAttributes_Striping_stripeDrawOnRight = -1;
static int hf_itsis_LaneAttributes_Striping_stripeToConnectingLanesLeft = -1;
static int hf_itsis_LaneAttributes_Striping_stripeToConnectingLanesRight = -1;
static int hf_itsis_LaneAttributes_Striping_stripeToConnectingLanesAhead = -1;
static int hf_itsis_LaneAttributes_TrackedVehicle_spec_RevocableLane = -1;
static int hf_itsis_LaneAttributes_TrackedVehicle_spec_commuterRailRoadTrack = -1;
static int hf_itsis_LaneAttributes_TrackedVehicle_spec_lightRailRoadTrack = -1;
static int hf_itsis_LaneAttributes_TrackedVehicle_spec_heavyRailRoadTrack = -1;
static int hf_itsis_LaneAttributes_TrackedVehicle_spec_otherRailType = -1;
static int hf_itsis_LaneAttributes_Vehicle_isVehicleRevocableLane = -1;
static int hf_itsis_LaneAttributes_Vehicle_isVehicleFlyOverLane = -1;
static int hf_itsis_LaneAttributes_Vehicle_hovLaneUseOnly = -1;
static int hf_itsis_LaneAttributes_Vehicle_restrictedToBusUse = -1;
static int hf_itsis_LaneAttributes_Vehicle_restrictedToTaxiUse = -1;
static int hf_itsis_LaneAttributes_Vehicle_restrictedFromPublicUse = -1;
static int hf_itsis_LaneAttributes_Vehicle_hasIRbeaconCoverage = -1;
static int hf_itsis_LaneAttributes_Vehicle_permissionOnRequest = -1;
static int hf_itsis_LaneDirection_ingressPath = -1;
static int hf_itsis_LaneDirection_egressPath = -1;
static int hf_itsis_TransitVehicleStatus_loading = -1;
static int hf_itsis_TransitVehicleStatus_anADAuse = -1;
static int hf_itsis_TransitVehicleStatus_aBikeLoad = -1;
static int hf_itsis_TransitVehicleStatus_doorOpen = -1;
static int hf_itsis_TransitVehicleStatus_charging = -1;
static int hf_itsis_TransitVehicleStatus_atStopLine = -1;
static int hf_itsis_PMD_national_holiday = -1;
static int hf_itsis_PMD_even_days = -1;
static int hf_itsis_PMD_odd_days = -1;
static int hf_itsis_PMD_market_day = -1;
static int hf_itsis_DayOfWeek_unused = -1;
static int hf_itsis_DayOfWeek_monday = -1;
static int hf_itsis_DayOfWeek_tuesday = -1;
static int hf_itsis_DayOfWeek_wednesday = -1;
static int hf_itsis_DayOfWeek_thursday = -1;
static int hf_itsis_DayOfWeek_friday = -1;
static int hf_itsis_DayOfWeek_saturday = -1;
static int hf_itsis_DayOfWeek_sunday = -1;
static int hf_itsis_AccelerationControl_brakePedalEngaged = -1;
static int hf_itsis_AccelerationControl_gasPedalEngaged = -1;
static int hf_itsis_AccelerationControl_emergencyBrakeEngaged = -1;
static int hf_itsis_AccelerationControl_collisionWarningEngaged = -1;
static int hf_itsis_AccelerationControl_accEngaged = -1;
static int hf_itsis_AccelerationControl_cruiseControlEngaged = -1;
static int hf_itsis_AccelerationControl_speedLimiterEngaged = -1;
static int hf_itsis_ExteriorLights_lowBeamHeadlightsOn = -1;
static int hf_itsis_ExteriorLights_highBeamHeadlightsOn = -1;
static int hf_itsis_ExteriorLights_leftTurnSignalOn = -1;
static int hf_itsis_ExteriorLights_rightTurnSignalOn = -1;
static int hf_itsis_ExteriorLights_daytimeRunningLightsOn = -1;
static int hf_itsis_ExteriorLights_reverseLightOn = -1;
static int hf_itsis_ExteriorLights_fogLightOn = -1;
static int hf_itsis_ExteriorLights_parkingLightsOn = -1;
static int hf_itsis_SpecialTransportType_heavyLoad = -1;
static int hf_itsis_SpecialTransportType_excessWidth = -1;
static int hf_itsis_SpecialTransportType_excessLength = -1;
static int hf_itsis_SpecialTransportType_excessHeight = -1;
static int hf_itsis_LightBarSirenInUse_lightBarActivated = -1;
static int hf_itsis_LightBarSirenInUse_sirenActivated = -1;
static int hf_itsis_PositionOfOccupants_row1LeftOccupied = -1;
static int hf_itsis_PositionOfOccupants_row1RightOccupied = -1;
static int hf_itsis_PositionOfOccupants_row1MidOccupied = -1;
static int hf_itsis_PositionOfOccupants_row1NotDetectable = -1;
static int hf_itsis_PositionOfOccupants_row1NotPresent = -1;
static int hf_itsis_PositionOfOccupants_row2LeftOccupied = -1;
static int hf_itsis_PositionOfOccupants_row2RightOccupied = -1;
static int hf_itsis_PositionOfOccupants_row2MidOccupied = -1;
static int hf_itsis_PositionOfOccupants_row2NotDetectable = -1;
static int hf_itsis_PositionOfOccupants_row2NotPresent = -1;
static int hf_itsis_PositionOfOccupants_row3LeftOccupied = -1;
static int hf_itsis_PositionOfOccupants_row3RightOccupied = -1;
static int hf_itsis_PositionOfOccupants_row3MidOccupied = -1;
static int hf_itsis_PositionOfOccupants_row3NotDetectable = -1;
static int hf_itsis_PositionOfOccupants_row3NotPresent = -1;
static int hf_itsis_PositionOfOccupants_row4LeftOccupied = -1;
static int hf_itsis_PositionOfOccupants_row4RightOccupied = -1;
static int hf_itsis_PositionOfOccupants_row4MidOccupied = -1;
static int hf_itsis_PositionOfOccupants_row4NotDetectable = -1;
static int hf_itsis_PositionOfOccupants_row4NotPresent = -1;
static int hf_itsis_EnergyStorageType_hydrogenStorage = -1;
static int hf_itsis_EnergyStorageType_electricEnergyStorage = -1;
static int hf_itsis_EnergyStorageType_liquidPropaneGas = -1;
static int hf_itsis_EnergyStorageType_compressedNaturalGas = -1;
static int hf_itsis_EnergyStorageType_diesel = -1;
static int hf_itsis_EnergyStorageType_gasoline = -1;
static int hf_itsis_EnergyStorageType_ammonia = -1;
static int hf_itsis_EmergencyPriority_requestForRightOfWay = -1;
static int hf_itsis_EmergencyPriority_requestForFreeCrossingAtATrafficLight = -1;

/*--- End of included file: packet-itsis-hf.c ---*/
#line 78 "./asn1/itsis/packet-itsis-template.c"

/* Initialize the subtree pointers */
static int ett_itsis = -1;

static dissector_table_t dissect_messageframe_pdu_type_table;
static dissector_table_t dissect_regionalextension_pdu_type_table;

static int dissect_messageframe_pdu_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int dissect_regionalextension_pdu_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int dissect_xxx_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);


/*--- Included file: packet-itsis-ett.c ---*/
#line 1 "./asn1/itsis/packet-itsis-ett.c"
static gint ett_itsis_IVIM = -1;
static gint ett_itsis_MAPEM = -1;
static gint ett_itsis_SPATEM = -1;
static gint ett_itsis_SREM = -1;
static gint ett_itsis_SSEM = -1;
static gint ett_itsis_CS5 = -1;
static gint ett_itsis_AxleWeightLimits = -1;
static gint ett_itsis_DieselEmissionValues = -1;
static gint ett_itsis_T_particulate = -1;
static gint ett_itsis_EnvironmentalCharacteristics = -1;
static gint ett_itsis_ExhaustEmissionValues = -1;
static gint ett_itsis_PassengerCapacity = -1;
static gint ett_itsis_Provider = -1;
static gint ett_itsis_SoundLevel = -1;
static gint ett_itsis_VehicleDimensions = -1;
static gint ett_itsis_VehicleWeightLimits = -1;
static gint ett_itsis_AttributeIdList = -1;
static gint ett_itsis_AttributeList = -1;
static gint ett_itsis_Attributes = -1;
static gint ett_itsis_VarLengthNumber = -1;
static gint ett_itsis_Ext1 = -1;
static gint ett_itsis_Ext2 = -1;
static gint ett_itsis_ConnectionManeuverAssist_addGrpC = -1;
static gint ett_itsis_ConnectionTrajectory_addGrpC = -1;
static gint ett_itsis_Control_addGrpC = -1;
static gint ett_itsis_IntersectionState_addGrpC = -1;
static gint ett_itsis_MapData_addGrpC = -1;
static gint ett_itsis_Position3D_addGrpC = -1;
static gint ett_itsis_PrioritizationResponseList = -1;
static gint ett_itsis_PrioritizationResponse = -1;
static gint ett_itsis_RestrictionUserType_addGrpC = -1;
static gint ett_itsis_SignalHeadLocationList = -1;
static gint ett_itsis_SignalHeadLocation = -1;
static gint ett_itsis_SignalStatusPackage_addGrpC = -1;
static gint ett_itsis_VehicleToLanePositionList = -1;
static gint ett_itsis_VehicleToLanePosition = -1;
static gint ett_itsis_MessageFrame = -1;
static gint ett_itsis_RegionalExtension = -1;
static gint ett_itsis_SPAT = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension = -1;
static gint ett_itsis_SignalRequestMessage = -1;
static gint ett_itsis_SignalStatusMessage = -1;
static gint ett_itsis_MapData = -1;
static gint ett_itsis_AdvisorySpeed = -1;
static gint ett_itsis_AdvisorySpeedList = -1;
static gint ett_itsis_ComputedLane = -1;
static gint ett_itsis_T_offsetXaxis = -1;
static gint ett_itsis_T_offsetYaxis = -1;
static gint ett_itsis_ConnectsToList = -1;
static gint ett_itsis_ConnectingLane = -1;
static gint ett_itsis_Connection = -1;
static gint ett_itsis_ConnectionManeuverAssist = -1;
static gint ett_itsis_DataParameters = -1;
static gint ett_itsis_EnabledLaneList = -1;
static gint ett_itsis_GenericLane = -1;
static gint ett_itsis_IntersectionAccessPoint = -1;
static gint ett_itsis_IntersectionGeometry = -1;
static gint ett_itsis_IntersectionGeometryList = -1;
static gint ett_itsis_IntersectionReferenceID = -1;
static gint ett_itsis_IntersectionState = -1;
static gint ett_itsis_IntersectionStateList = -1;
static gint ett_itsis_LaneAttributes = -1;
static gint ett_itsis_LaneDataAttribute = -1;
static gint ett_itsis_LaneDataAttributeList = -1;
static gint ett_itsis_LaneList = -1;
static gint ett_itsis_LaneSharing = -1;
static gint ett_itsis_LaneTypeAttributes = -1;
static gint ett_itsis_ManeuverAssistList = -1;
static gint ett_itsis_MovementEventList = -1;
static gint ett_itsis_MovementEvent = -1;
static gint ett_itsis_MovementList = -1;
static gint ett_itsis_MovementState = -1;
static gint ett_itsis_NodeAttributeSetXY = -1;
static gint ett_itsis_NodeAttributeXYList = -1;
static gint ett_itsis_Node_LLmD_64b = -1;
static gint ett_itsis_Node_XY_20b = -1;
static gint ett_itsis_Node_XY_22b = -1;
static gint ett_itsis_Node_XY_24b = -1;
static gint ett_itsis_Node_XY_26b = -1;
static gint ett_itsis_Node_XY_28b = -1;
static gint ett_itsis_Node_XY_32b = -1;
static gint ett_itsis_NodeListXY = -1;
static gint ett_itsis_NodeOffsetPointXY = -1;
static gint ett_itsis_NodeSetXY = -1;
static gint ett_itsis_NodeXY = -1;
static gint ett_itsis_OverlayLaneList = -1;
static gint ett_itsis_Position3D = -1;
static gint ett_itsis_PreemptPriorityList = -1;
static gint ett_itsis_RegulatorySpeedLimit = -1;
static gint ett_itsis_RequestorDescription = -1;
static gint ett_itsis_RequestorPositionVector = -1;
static gint ett_itsis_RequestorType = -1;
static gint ett_itsis_RestrictionClassAssignment = -1;
static gint ett_itsis_RestrictionClassList = -1;
static gint ett_itsis_RestrictionUserTypeList = -1;
static gint ett_itsis_RestrictionUserType = -1;
static gint ett_itsis_RoadLaneSetList = -1;
static gint ett_itsis_RoadSegmentReferenceID = -1;
static gint ett_itsis_RoadSegment = -1;
static gint ett_itsis_RoadSegmentList = -1;
static gint ett_itsis_SegmentAttributeXYList = -1;
static gint ett_itsis_SignalControlZone = -1;
static gint ett_itsis_SignalRequesterInfo = -1;
static gint ett_itsis_SignalRequestList = -1;
static gint ett_itsis_SignalRequestPackage = -1;
static gint ett_itsis_SignalRequest = -1;
static gint ett_itsis_SignalStatusList = -1;
static gint ett_itsis_SignalStatusPackageList = -1;
static gint ett_itsis_SignalStatusPackage = -1;
static gint ett_itsis_SignalStatus = -1;
static gint ett_itsis_SpeedLimitList = -1;
static gint ett_itsis_TimeChangeDetails = -1;
static gint ett_itsis_TransmissionAndSpeed = -1;
static gint ett_itsis_VehicleID = -1;
static gint ett_itsis_AllowedManeuvers = -1;
static gint ett_itsis_IntersectionStatusObject = -1;
static gint ett_itsis_LaneAttributes_Barrier = -1;
static gint ett_itsis_LaneAttributes_Bike = -1;
static gint ett_itsis_LaneAttributes_Crosswalk = -1;
static gint ett_itsis_LaneAttributes_Parking = -1;
static gint ett_itsis_LaneAttributes_Sidewalk = -1;
static gint ett_itsis_LaneAttributes_Striping = -1;
static gint ett_itsis_LaneAttributes_TrackedVehicle = -1;
static gint ett_itsis_LaneAttributes_Vehicle = -1;
static gint ett_itsis_LaneDirection = -1;
static gint ett_itsis_TransitVehicleStatus = -1;
static gint ett_itsis_IVI = -1;
static gint ett_itsis_IviStructure = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8__OF_IviContainer = -1;
static gint ett_itsis_IviContainer = -1;
static gint ett_itsis_IVIManagementContainer = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber = -1;
static gint ett_itsis_GeographicLocationContainer = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_16__OF_GlcPart = -1;
static gint ett_itsis_GlcPart = -1;
static gint ett_itsis_GeneralIviContainer = -1;
static gint ett_itsis_GicPart = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8__OF_Zid = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8__OF_LanePosition = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_4__OF_RSCode = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_4__OF_Text = -1;
static gint ett_itsis_RoadConfigurationContainer = -1;
static gint ett_itsis_RccPart = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_16__OF_LaneInformation = -1;
static gint ett_itsis_TextContainer = -1;
static gint ett_itsis_TcPart = -1;
static gint ett_itsis_LayoutContainer = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_4__OF_LayoutComponent = -1;
static gint ett_itsis_AbsolutePosition = -1;
static gint ett_itsis_AbsolutePositionWAltitude = -1;
static gint ett_itsis_AnyCatalogue = -1;
static gint ett_itsis_CompleteVehicleCharacteristics = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics = -1;
static gint ett_itsis_ComputedSegment = -1;
static gint ett_itsis_DeltaPosition = -1;
static gint ett_itsis_Distance = -1;
static gint ett_itsis_DistanceOrDuration = -1;
static gint ett_itsis_ISO14823Attributes = -1;
static gint ett_itsis_ISO14823Attributes_item = -1;
static gint ett_itsis_ISO14823Code = -1;
static gint ett_itsis_T_pictogramCode = -1;
static gint ett_itsis_T_serviceCategoryCode = -1;
static gint ett_itsis_T_pictogramCategoryCode = -1;
static gint ett_itsis_LaneInformation = -1;
static gint ett_itsis_LayoutComponent = -1;
static gint ett_itsis_LoadType = -1;
static gint ett_itsis_PolygonalLine = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_32__OF_DeltaPosition = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePosition = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude = -1;
static gint ett_itsis_RSCode = -1;
static gint ett_itsis_T_code = -1;
static gint ett_itsis_Segment = -1;
static gint ett_itsis_Text = -1;
static gint ett_itsis_TractorCharacteristics = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges = -1;
static gint ett_itsis_TrailerCharacteristics = -1;
static gint ett_itsis_VcCode = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8__OF_DTM = -1;
static gint ett_itsis_VehicleCharacteristicsFixValues = -1;
static gint ett_itsis_VehicleCharacteristicsRanges = -1;
static gint ett_itsis_T_limits = -1;
static gint ett_itsis_Weight = -1;
static gint ett_itsis_Zone = -1;
static gint ett_itsis_DTM = -1;
static gint ett_itsis_T_year = -1;
static gint ett_itsis_T_month_day = -1;
static gint ett_itsis_T_hourMinutes = -1;
static gint ett_itsis_MonthDay = -1;
static gint ett_itsis_PMD = -1;
static gint ett_itsis_HoursMinutes = -1;
static gint ett_itsis_DayOfWeek = -1;
static gint ett_itsis_VED = -1;
static gint ett_itsis_SPE = -1;
static gint ett_itsis_DDD = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_8__OF_DDD_IO = -1;
static gint ett_itsis_DDD_IO = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_4__OF_DestinationPlace = -1;
static gint ett_itsis_SEQUENCE_SIZE_1_4__OF_DestinationRoad = -1;
static gint ett_itsis_DestinationPlace = -1;
static gint ett_itsis_DestinationRoad = -1;
static gint ett_itsis_EuVehicleCategoryCode = -1;
static gint ett_itsis_ItsPduHeader = -1;
static gint ett_itsis_ReferencePosition = -1;
static gint ett_itsis_DeltaReferencePosition = -1;
static gint ett_itsis_Altitude = -1;
static gint ett_itsis_PosConfidenceEllipse = -1;
static gint ett_itsis_PathPoint = -1;
static gint ett_itsis_PtActivation = -1;
static gint ett_itsis_AccelerationControl = -1;
static gint ett_itsis_CauseCode = -1;
static gint ett_itsis_Curvature = -1;
static gint ett_itsis_Heading = -1;
static gint ett_itsis_ClosedLanes = -1;
static gint ett_itsis_Speed = -1;
static gint ett_itsis_LongitudinalAcceleration = -1;
static gint ett_itsis_LateralAcceleration = -1;
static gint ett_itsis_VerticalAcceleration = -1;
static gint ett_itsis_ExteriorLights = -1;
static gint ett_itsis_DangerousGoodsExtended = -1;
static gint ett_itsis_SpecialTransportType = -1;
static gint ett_itsis_LightBarSirenInUse = -1;
static gint ett_itsis_PositionOfOccupants = -1;
static gint ett_itsis_VehicleIdentification = -1;
static gint ett_itsis_EnergyStorageType = -1;
static gint ett_itsis_VehicleLength = -1;
static gint ett_itsis_PathHistory = -1;
static gint ett_itsis_EmergencyPriority = -1;
static gint ett_itsis_SteeringWheelAngle = -1;
static gint ett_itsis_YawRate = -1;
static gint ett_itsis_ActionID = -1;
static gint ett_itsis_ItineraryPath = -1;
static gint ett_itsis_ProtectedCommunicationZone = -1;
static gint ett_itsis_Traces = -1;
static gint ett_itsis_PositionOfPillars = -1;
static gint ett_itsis_RestrictedTypes = -1;
static gint ett_itsis_EventHistory = -1;
static gint ett_itsis_EventPoint = -1;
static gint ett_itsis_ProtectedCommunicationZonesRSU = -1;
static gint ett_itsis_CenDsrcTollingZone = -1;

/*--- End of included file: packet-itsis-ett.c ---*/
#line 90 "./asn1/itsis/packet-itsis-template.c"


/*--- Included file: packet-itsis-fn.c ---*/
#line 1 "./asn1/itsis/packet-itsis-fn.c"
/*--- Cyclic dependencies ---*/

/* ISO14823Code -> ISO14823Attributes -> ISO14823Attributes/_item -> DDD -> DDD/ioList -> DDD-IO -> DDD-IO/dp -> DestinationPlace -> ISO14823Code */
static int dissect_itsis_ISO14823Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);



static const value_string itsis_T_protocolVersion_vals[] = {
  {   1, "currentVersion" },
  { 0, NULL }
};


static int
dissect_itsis_T_protocolVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_T_messageID_vals[] = {
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
dissect_itsis_T_messageID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_StationID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ItsPduHeader_sequence[] = {
  { &hf_itsis_protocolVersion, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_protocolVersion },
  { &hf_itsis_messageID     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_messageID },
  { &hf_itsis_stationID     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_StationID },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ItsPduHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ItsPduHeader, ItsPduHeader_sequence);

  return offset;
}



static int
dissect_itsis_CountryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_IssuerIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Provider_sequence[] = {
  { &hf_itsis_countryCode   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_CountryCode },
  { &hf_itsis_providerIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IssuerIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Provider(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Provider, Provider_sequence);

  return offset;
}



static int
dissect_itsis_IviIdentificationNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32767U, NULL, TRUE);

  return offset;
}



static int
dissect_itsis_TimestampIts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     42, 42, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber_sequence_of[1] = {
  { &hf_itsis_connectedIviStructures_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IviIdentificationNumber },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber, SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const value_string itsis_IviStatus_vals[] = {
  {   0, "new" },
  {   1, "update" },
  {   2, "cancellation" },
  {   3, "negation" },
  { 0, NULL }
};


static int
dissect_itsis_IviStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t IVIManagementContainer_sequence[] = {
  { &hf_itsis_serviceProviderId, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Provider },
  { &hf_itsis_iviIdentificationNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IviIdentificationNumber },
  { &hf_itsis_timeStamp_02  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TimestampIts },
  { &hf_itsis_validFrom     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TimestampIts },
  { &hf_itsis_validTo       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TimestampIts },
  { &hf_itsis_connectedIviStructures, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber },
  { &hf_itsis_iviStatus     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IviStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_IVIManagementContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_IVIManagementContainer, IVIManagementContainer_sequence);

  return offset;
}


static const value_string itsis_Latitude_vals[] = {
  {  10, "oneMicrodegreeNorth" },
  { -10, "oneMicrodegreeSouth" },
  { 900000001, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_Latitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -900000000, 900000001U, NULL, FALSE);

  return offset;
}


static const value_string itsis_Longitude_vals[] = {
  {  10, "oneMicrodegreeEast" },
  { -10, "oneMicrodegreeWest" },
  { 1800000001, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_Longitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1800000000, 1800000001U, NULL, FALSE);

  return offset;
}


static const value_string itsis_SemiAxisLength_vals[] = {
  {   1, "oneCentimeter" },
  { 4094, "outOfRange" },
  { 4095, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_SemiAxisLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const value_string itsis_HeadingValue_vals[] = {
  {   0, "wgs84North" },
  { 900, "wgs84East" },
  { 1800, "wgs84South" },
  { 2700, "wgs84West" },
  { 3601, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_HeadingValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3601U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PosConfidenceEllipse_sequence[] = {
  { &hf_itsis_semiMajorConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SemiAxisLength },
  { &hf_itsis_semiMinorConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SemiAxisLength },
  { &hf_itsis_semiMajorOrientation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_HeadingValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_PosConfidenceEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_PosConfidenceEllipse, PosConfidenceEllipse_sequence);

  return offset;
}


static const value_string itsis_AltitudeValue_vals[] = {
  {   0, "referenceEllipsoidSurface" },
  {   1, "oneCentimeter" },
  { 800001, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_AltitudeValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -100000, 800001U, NULL, FALSE);

  return offset;
}


static const value_string itsis_AltitudeConfidence_vals[] = {
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
dissect_itsis_AltitudeConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Altitude_sequence[] = {
  { &hf_itsis_altitudeValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_AltitudeValue },
  { &hf_itsis_altitudeConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_AltitudeConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Altitude, Altitude_sequence);

  return offset;
}


static const per_sequence_t ReferencePosition_sequence[] = {
  { &hf_itsis_latitude      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Latitude },
  { &hf_itsis_longitude     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Longitude },
  { &hf_itsis_positionConfidenceEllipse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_PosConfidenceEllipse },
  { &hf_itsis_altitude      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ReferencePosition, ReferencePosition_sequence);

  return offset;
}


static const value_string itsis_HeadingConfidence_vals[] = {
  {   1, "equalOrWithinZeroPointOneDegree" },
  {  10, "equalOrWithinOneDegree" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_HeadingConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Heading_sequence[] = {
  { &hf_itsis_headingValue  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_HeadingValue },
  { &hf_itsis_headingConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_HeadingConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Heading(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Heading, Heading_sequence);

  return offset;
}


static const value_string itsis_SpeedValue_vals[] = {
  {   0, "standstill" },
  {   1, "oneCentimeterPerSec" },
  { 16383, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_SpeedValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const value_string itsis_SpeedConfidence_vals[] = {
  {   1, "equalOrWithinOneCentimeterPerSec" },
  { 100, "equalOrWithinOneMeterPerSec" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_SpeedConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Speed_sequence[] = {
  { &hf_itsis_speedValue    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SpeedValue },
  { &hf_itsis_speedConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SpeedConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Speed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Speed, Speed_sequence);

  return offset;
}



static int
dissect_itsis_Zid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

  return offset;
}


static const value_string itsis_LanePosition_vals[] = {
  {  -1, "offTheRoad" },
  {   0, "hardShoulder" },
  {   1, "outermostDrivingLane" },
  {   2, "secondLaneFromOutside" },
  { 0, NULL }
};


static int
dissect_itsis_LanePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1, 14U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_DeltaLatitude_vals[] = {
  {  10, "oneMicrodegreeNorth" },
  { -10, "oneMicrodegreeSouth" },
  { 131072, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_DeltaLatitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131071, 131072U, NULL, FALSE);

  return offset;
}


static const value_string itsis_DeltaLongitude_vals[] = {
  {  10, "oneMicrodegreeEast" },
  { -10, "oneMicrodegreeWest" },
  { 131072, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_DeltaLongitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131071, 131072U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DeltaPosition_sequence[] = {
  { &hf_itsis_deltaLatitude , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaLatitude },
  { &hf_itsis_deltaLongitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaLongitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DeltaPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DeltaPosition, DeltaPosition_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_32__OF_DeltaPosition_sequence_of[1] = {
  { &hf_itsis_deltaPositions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaPosition },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_32__OF_DeltaPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_32__OF_DeltaPosition, SEQUENCE_SIZE_1_32__OF_DeltaPosition_sequence_of,
                                                  1, 32, TRUE);

  return offset;
}


static const value_string itsis_DeltaAltitude_vals[] = {
  {   1, "oneCentimeterUp" },
  {  -1, "oneCentimeterDown" },
  { 12800, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_DeltaAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -12700, 12800U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DeltaReferencePosition_sequence[] = {
  { &hf_itsis_deltaLatitude , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaLatitude },
  { &hf_itsis_deltaLongitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaLongitude },
  { &hf_itsis_deltaAltitude , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaAltitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DeltaReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DeltaReferencePosition, DeltaReferencePosition_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition_sequence_of[1] = {
  { &hf_itsis_deltaPositionsWithAltitude_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaReferencePosition },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition, SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition_sequence_of,
                                                  1, 32, TRUE);

  return offset;
}


static const per_sequence_t AbsolutePosition_sequence[] = {
  { &hf_itsis_latitude      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Latitude },
  { &hf_itsis_longitude     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Longitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_AbsolutePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_AbsolutePosition, AbsolutePosition_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8__OF_AbsolutePosition_sequence_of[1] = {
  { &hf_itsis_absolutePositions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_AbsolutePosition },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePosition, SEQUENCE_SIZE_1_8__OF_AbsolutePosition_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}


static const per_sequence_t AbsolutePositionWAltitude_sequence[] = {
  { &hf_itsis_latitude      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Latitude },
  { &hf_itsis_longitude     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Longitude },
  { &hf_itsis_altitude      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_AbsolutePositionWAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_AbsolutePositionWAltitude, AbsolutePositionWAltitude_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude_sequence_of[1] = {
  { &hf_itsis_absolutePositionsWithAltitude_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_AbsolutePositionWAltitude },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude, SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}


static const value_string itsis_PolygonalLine_vals[] = {
  {   0, "deltaPositions" },
  {   1, "deltaPositionsWithAltitude" },
  {   2, "absolutePositions" },
  {   3, "absolutePositionsWithAltitude" },
  { 0, NULL }
};

static const per_choice_t PolygonalLine_choice[] = {
  {   0, &hf_itsis_deltaPositions, ASN1_EXTENSION_ROOT    , dissect_itsis_SEQUENCE_SIZE_1_32__OF_DeltaPosition },
  {   1, &hf_itsis_deltaPositionsWithAltitude, ASN1_EXTENSION_ROOT    , dissect_itsis_SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition },
  {   2, &hf_itsis_absolutePositions, ASN1_EXTENSION_ROOT    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePosition },
  {   3, &hf_itsis_absolutePositionsWithAltitude, ASN1_EXTENSION_ROOT    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_PolygonalLine(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_PolygonalLine, PolygonalLine_choice,
                                 NULL);

  return offset;
}



static int
dissect_itsis_IVILaneWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Segment_sequence[] = {
  { &hf_itsis_line          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_PolygonalLine },
  { &hf_itsis_laneWidth_01  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_IVILaneWidth },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Segment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Segment, Segment_sequence);

  return offset;
}



static int
dissect_itsis_INTEGER_M32768_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ComputedSegment_sequence[] = {
  { &hf_itsis_zoneId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Zid },
  { &hf_itsis_laneNumber    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LanePosition },
  { &hf_itsis_laneWidth_01  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IVILaneWidth },
  { &hf_itsis_offsetDistance, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_M32768_32767 },
  { &hf_itsis_offsetPosition, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_DeltaReferencePosition },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ComputedSegment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ComputedSegment, ComputedSegment_sequence);

  return offset;
}


static const value_string itsis_Zone_vals[] = {
  {   0, "segment" },
  {   1, "area" },
  {   2, "computedSegment" },
  { 0, NULL }
};

static const per_choice_t Zone_choice[] = {
  {   0, &hf_itsis_segment       , ASN1_EXTENSION_ROOT    , dissect_itsis_Segment },
  {   1, &hf_itsis_area          , ASN1_EXTENSION_ROOT    , dissect_itsis_PolygonalLine },
  {   2, &hf_itsis_computedSegment, ASN1_EXTENSION_ROOT    , dissect_itsis_ComputedSegment },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_Zone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_Zone, Zone_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlcPart_sequence[] = {
  { &hf_itsis_zoneId        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Zid },
  { &hf_itsis_laneNumber    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_LanePosition },
  { &hf_itsis_zoneExtension , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_0_255 },
  { &hf_itsis_zoneHeading   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_HeadingValue },
  { &hf_itsis_zone_01       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Zone },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_GlcPart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_GlcPart, GlcPart_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_16__OF_GlcPart_sequence_of[1] = {
  { &hf_itsis_parts_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_GlcPart },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_16__OF_GlcPart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_16__OF_GlcPart, SEQUENCE_SIZE_1_16__OF_GlcPart_sequence_of,
                                                  1, 16, TRUE);

  return offset;
}


static const per_sequence_t GeographicLocationContainer_sequence[] = {
  { &hf_itsis_referencePosition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_ReferencePosition },
  { &hf_itsis_referencePositionTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TimestampIts },
  { &hf_itsis_referencePositionHeading, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Heading },
  { &hf_itsis_referencePositionSpeed, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Speed },
  { &hf_itsis_parts         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SEQUENCE_SIZE_1_16__OF_GlcPart },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_GeographicLocationContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_GeographicLocationContainer, GeographicLocationContainer_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8__OF_Zid_sequence_of[1] = {
  { &hf_itsis_detectionZoneIds_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Zid },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8__OF_Zid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8__OF_Zid, SEQUENCE_SIZE_1_8__OF_Zid_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}



static int
dissect_itsis_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_128_16511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            128U, 16511U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_16512_2113663(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            16512U, 2113663U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_Ext3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2113664U, 270549119U, NULL, TRUE);

  return offset;
}


static const value_string itsis_Ext2_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t Ext2_choice[] = {
  {   0, &hf_itsis_content_02    , ASN1_NO_EXTENSIONS     , dissect_itsis_INTEGER_16512_2113663 },
  {   1, &hf_itsis_extension_02  , ASN1_NO_EXTENSIONS     , dissect_itsis_Ext3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_Ext2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_Ext2, Ext2_choice,
                                 NULL);

  return offset;
}


static const value_string itsis_Ext1_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t Ext1_choice[] = {
  {   0, &hf_itsis_content_01    , ASN1_NO_EXTENSIONS     , dissect_itsis_INTEGER_128_16511 },
  {   1, &hf_itsis_extension_01  , ASN1_NO_EXTENSIONS     , dissect_itsis_Ext2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_Ext1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_Ext1, Ext1_choice,
                                 NULL);

  return offset;
}


static const value_string itsis_VarLengthNumber_vals[] = {
  {   0, "content" },
  {   1, "extension" },
  { 0, NULL }
};

static const per_choice_t VarLengthNumber_choice[] = {
  {   0, &hf_itsis_content       , ASN1_NO_EXTENSIONS     , dissect_itsis_INTEGER_0_127 },
  {   1, &hf_itsis_extension     , ASN1_NO_EXTENSIONS     , dissect_itsis_Ext1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_VarLengthNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_VarLengthNumber, VarLengthNumber_choice,
                                 NULL);

  return offset;
}


static const value_string itsis_Direction_vals[] = {
  {   0, "sameDirection" },
  {   1, "oppositeDirection" },
  {   2, "bothDirections" },
  {   3, "valueNotUsed" },
  { 0, NULL }
};


static int
dissect_itsis_Direction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8__OF_LanePosition_sequence_of[1] = {
  { &hf_itsis_applicableLanes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LanePosition },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8__OF_LanePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8__OF_LanePosition, SEQUENCE_SIZE_1_8__OF_LanePosition_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}


static const value_string itsis_IviType_vals[] = {
  {   0, "immediateDangerWarningMessages" },
  {   1, "regulatoryMessages" },
  {   2, "trafficRelatedInformationMessages" },
  {   3, "pollutionMessages" },
  {   4, "notTrafficRelatedInformationMessages" },
  { 0, NULL }
};


static int
dissect_itsis_IviType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string itsis_IviPurpose_vals[] = {
  {   0, "safety" },
  {   1, "environmental" },
  {   2, "trafficOptimisation" },
  { 0, NULL }
};


static int
dissect_itsis_IviPurpose(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const value_string itsis_LaneStatus_vals[] = {
  {   0, "open" },
  {   1, "closed" },
  {   2, "mergeR" },
  {   3, "mergeL" },
  {   4, "mergeLR" },
  {   5, "provisionallyOpen" },
  {   6, "diverging" },
  { 0, NULL }
};


static int
dissect_itsis_LaneStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, TRUE);

  return offset;
}


static const value_string itsis_StationType_vals[] = {
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
dissect_itsis_StationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_EuVehicleCategoryL_vals[] = {
  {   0, "l1" },
  {   1, "l2" },
  {   2, "l3" },
  {   3, "l4" },
  {   4, "l5" },
  {   5, "l6" },
  {   6, "l7" },
  { 0, NULL }
};


static int
dissect_itsis_EuVehicleCategoryL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_EuVehicleCategoryM_vals[] = {
  {   0, "m1" },
  {   1, "m2" },
  {   2, "m3" },
  { 0, NULL }
};


static int
dissect_itsis_EuVehicleCategoryM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_EuVehicleCategoryN_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n3" },
  { 0, NULL }
};


static int
dissect_itsis_EuVehicleCategoryN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_EuVehicleCategoryO_vals[] = {
  {   0, "o1" },
  {   1, "o2" },
  {   2, "o3" },
  {   3, "o4" },
  { 0, NULL }
};


static int
dissect_itsis_EuVehicleCategoryO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_itsis_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string itsis_EuVehicleCategoryCode_vals[] = {
  {   0, "euVehicleCategoryL" },
  {   1, "euVehicleCategoryM" },
  {   2, "euVehicleCategoryN" },
  {   3, "euVehicleCategoryO" },
  {   4, "euVehilcleCategoryT" },
  {   5, "euVehilcleCategoryG" },
  { 0, NULL }
};

static const per_choice_t EuVehicleCategoryCode_choice[] = {
  {   0, &hf_itsis_euVehicleCategoryL, ASN1_NO_EXTENSIONS     , dissect_itsis_EuVehicleCategoryL },
  {   1, &hf_itsis_euVehicleCategoryM, ASN1_NO_EXTENSIONS     , dissect_itsis_EuVehicleCategoryM },
  {   2, &hf_itsis_euVehicleCategoryN, ASN1_NO_EXTENSIONS     , dissect_itsis_EuVehicleCategoryN },
  {   3, &hf_itsis_euVehicleCategoryO, ASN1_NO_EXTENSIONS     , dissect_itsis_EuVehicleCategoryO },
  {   4, &hf_itsis_euVehilcleCategoryT, ASN1_NO_EXTENSIONS     , dissect_itsis_NULL },
  {   5, &hf_itsis_euVehilcleCategoryG, ASN1_NO_EXTENSIONS     , dissect_itsis_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_EuVehicleCategoryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_EuVehicleCategoryCode, EuVehicleCategoryCode_choice,
                                 NULL);

  return offset;
}


static const value_string itsis_Iso3833VehicleType_vals[] = {
  {   0, "passengerCar" },
  {   1, "saloon" },
  {   2, "convertibleSaloon" },
  {   3, "pullmanSaloon" },
  {   4, "stationWagon" },
  {   5, "truckStationWagon" },
  {   6, "coupe" },
  {   7, "convertible" },
  {   8, "multipurposePassengerCar" },
  {   9, "forwardControlPassengerCar" },
  {  10, "specialPassengerCar" },
  {  11, "bus" },
  {  12, "minibus" },
  {  13, "urbanBus" },
  {  14, "interurbanCoach" },
  {  15, "longDistanceCoach" },
  {  16, "articulatedBus" },
  {  17, "trolleyBus" },
  {  18, "specialBus" },
  {  19, "commercialVehicle" },
  {  20, "specialCommercialVehicle" },
  {  21, "specialVehicle" },
  {  22, "trailingTowingVehicle" },
  {  23, "semiTrailerTowingVehicle" },
  {  24, "trailer" },
  {  25, "busTrailer" },
  {  26, "generalPurposeTrailer" },
  {  27, "caravan" },
  {  28, "specialTrailer" },
  {  29, "semiTrailer" },
  {  30, "busSemiTrailer" },
  {  31, "generalPurposeSemiTrailer" },
  {  32, "specialSemiTrailer" },
  {  33, "roadTrain" },
  {  34, "passengerRoadTrain" },
  {  35, "articulatedRoadTrain" },
  {  36, "doubleRoadTrain" },
  {  37, "compositeRoadTrain" },
  {  38, "specialRoadTrain" },
  {  39, "moped" },
  {  40, "motorCycle" },
  { 0, NULL }
};


static int
dissect_itsis_Iso3833VehicleType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_EuroValue_vals[] = {
  {   0, "noEntry" },
  {   1, "euro-1" },
  {   2, "euro-2" },
  {   3, "euro-3" },
  {   4, "euro-4" },
  {   5, "euro-5" },
  {   6, "euro-6" },
  {   7, "reservedForUse1" },
  {   8, "reservedForUse2" },
  {   9, "reservedForUse3" },
  {  10, "reservedForUse4" },
  {  11, "reservedForUse5" },
  {  12, "reservedForUse6" },
  {  13, "reservedForUse7" },
  {  14, "reservedForUse8" },
  {  15, "eev" },
  { 0, NULL }
};


static int
dissect_itsis_EuroValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_CopValue_vals[] = {
  {   0, "noEntry" },
  {   1, "co2class1" },
  {   2, "co2class2" },
  {   3, "co2class3" },
  {   4, "co2class4" },
  {   5, "co2class5" },
  {   6, "co2class6" },
  {   7, "co2class7" },
  {   8, "reservedforUse" },
  { 0, NULL }
};


static int
dissect_itsis_CopValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t EnvironmentalCharacteristics_sequence[] = {
  { &hf_itsis_euroValue     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_EuroValue },
  { &hf_itsis_copValue      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_CopValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_EnvironmentalCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_EnvironmentalCharacteristics, EnvironmentalCharacteristics_sequence);

  return offset;
}


static const value_string itsis_EngineCharacteristics_vals[] = {
  {   0, "noEntry" },
  {   1, "noEngine" },
  {   2, "petrolUnleaded" },
  {   3, "petrolLeaded" },
  {   4, "diesel" },
  {   5, "lPG" },
  {   6, "battery" },
  {   7, "solar" },
  {   8, "hybrid" },
  {   9, "hydrogen" },
  { 0, NULL }
};


static int
dissect_itsis_EngineCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_GoodsType_vals[] = {
  {   0, "ammunition" },
  {   1, "chemicals" },
  {   2, "empty" },
  {   3, "fuel" },
  {   4, "glass" },
  {   5, "dangerous" },
  {   6, "liquid" },
  {   7, "liveStock" },
  {   8, "dangerousForPeople" },
  {   9, "dangerousForTheEnvironment" },
  {  10, "dangerousForWater" },
  {  11, "perishableProducts" },
  {  12, "pharmaceutical" },
  {  13, "vehicles" },
  { 0, NULL }
};


static int
dissect_itsis_GoodsType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}


static const value_string itsis_DangerousGoodsBasic_vals[] = {
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
dissect_itsis_DangerousGoodsBasic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_itsis_SpecialTransportType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t LoadType_sequence[] = {
  { &hf_itsis_goodsType     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_GoodsType },
  { &hf_itsis_dangerousGoodsType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DangerousGoodsBasic },
  { &hf_itsis_specialTransportType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SpecialTransportType },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_LoadType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_LoadType, LoadType_sequence);

  return offset;
}


static const value_string itsis_VehicleRole_vals[] = {
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
dissect_itsis_VehicleRole(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_VehicleCharacteristicsFixValues_vals[] = {
  {   0, "simpleVehicleType" },
  {   1, "euVehicleCategoryCode" },
  {   2, "iso3833VehicleType" },
  {   3, "euroAndCo2value" },
  {   4, "engineCharacteristics" },
  {   5, "loadType" },
  {   6, "usage" },
  { 0, NULL }
};

static const per_choice_t VehicleCharacteristicsFixValues_choice[] = {
  {   0, &hf_itsis_simpleVehicleType, ASN1_EXTENSION_ROOT    , dissect_itsis_StationType },
  {   1, &hf_itsis_euVehicleCategoryCode, ASN1_EXTENSION_ROOT    , dissect_itsis_EuVehicleCategoryCode },
  {   2, &hf_itsis_iso3833VehicleType, ASN1_EXTENSION_ROOT    , dissect_itsis_Iso3833VehicleType },
  {   3, &hf_itsis_euroAndCo2value, ASN1_EXTENSION_ROOT    , dissect_itsis_EnvironmentalCharacteristics },
  {   4, &hf_itsis_engineCharacteristics, ASN1_EXTENSION_ROOT    , dissect_itsis_EngineCharacteristics },
  {   5, &hf_itsis_loadType      , ASN1_EXTENSION_ROOT    , dissect_itsis_LoadType },
  {   6, &hf_itsis_usage         , ASN1_EXTENSION_ROOT    , dissect_itsis_VehicleRole },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_VehicleCharacteristicsFixValues(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_VehicleCharacteristicsFixValues, VehicleCharacteristicsFixValues_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues_sequence_of[1] = {
  { &hf_itsis_equalTo_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VehicleCharacteristicsFixValues },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues, SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues_sequence_of,
                                                  1, 4, TRUE);

  return offset;
}


static const value_string itsis_ComparisonOperator_vals[] = {
  {   0, "greaterThan" },
  {   1, "greaterThanOrEqualTo" },
  {   2, "lessThan" },
  {   3, "lessThanOrEqualTo" },
  { 0, NULL }
};


static int
dissect_itsis_ComparisonOperator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_Int1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VehicleDimensions_sequence[] = {
  { &hf_itsis_vehicleLengthOverall, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int1 },
  { &hf_itsis_vehicleHeigthOverall, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int1 },
  { &hf_itsis_vehicleWidthOverall, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VehicleDimensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VehicleDimensions, VehicleDimensions_sequence);

  return offset;
}



static int
dissect_itsis_Int2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VehicleWeightLimits_sequence[] = {
  { &hf_itsis_vehicleMaxLadenWeight, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { &hf_itsis_vehicleTrainMaximumWeight, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { &hf_itsis_vehicleWeightUnladen, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VehicleWeightLimits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VehicleWeightLimits, VehicleWeightLimits_sequence);

  return offset;
}


static const per_sequence_t AxleWeightLimits_sequence[] = {
  { &hf_itsis_maxLadenweightOnAxle1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { &hf_itsis_maxLadenweightOnAxle2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { &hf_itsis_maxLadenweightOnAxle3, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { &hf_itsis_maxLadenweightOnAxle4, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { &hf_itsis_maxLadenweightOnAxle5, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_AxleWeightLimits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_AxleWeightLimits, AxleWeightLimits_sequence);

  return offset;
}


static const per_sequence_t PassengerCapacity_sequence[] = {
  { &hf_itsis_numberOfSeats , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int1 },
  { &hf_itsis_numberOfStandingPlaces, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_PassengerCapacity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_PassengerCapacity, PassengerCapacity_sequence);

  return offset;
}


static const value_string itsis_UnitType_vals[] = {
  {   0, "mg-km" },
  {   1, "mg-kWh" },
  { 0, NULL }
};


static int
dissect_itsis_UnitType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_itsis_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ExhaustEmissionValues_sequence[] = {
  { &hf_itsis_unitType      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_UnitType },
  { &hf_itsis_emissionCO    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_32767 },
  { &hf_itsis_emissionHC    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { &hf_itsis_emissionNOX   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { &hf_itsis_emissionHCNOX , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ExhaustEmissionValues(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ExhaustEmissionValues, ExhaustEmissionValues_sequence);

  return offset;
}


static const per_sequence_t T_particulate_sequence[] = {
  { &hf_itsis_unitType      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_UnitType },
  { &hf_itsis_value         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_32767 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_T_particulate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_T_particulate, T_particulate_sequence);

  return offset;
}


static const per_sequence_t DieselEmissionValues_sequence[] = {
  { &hf_itsis_particulate   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_particulate },
  { &hf_itsis_absorptionCoeff, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DieselEmissionValues(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DieselEmissionValues, DieselEmissionValues_sequence);

  return offset;
}


static const per_sequence_t SoundLevel_sequence[] = {
  { &hf_itsis_soundstationary, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int1 },
  { &hf_itsis_sounddriveby  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Int1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SoundLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SoundLevel, SoundLevel_sequence);

  return offset;
}


static const value_string itsis_T_limits_vals[] = {
  {   0, "numberOfAxles" },
  {   1, "vehicleDimensions" },
  {   2, "vehicleWeightLimits" },
  {   3, "axleWeightLimits" },
  {   4, "passengerCapacity" },
  {   5, "exhaustEmissionValues" },
  {   6, "dieselEmissionValues" },
  {   7, "soundLevel" },
  { 0, NULL }
};

static const per_choice_t T_limits_choice[] = {
  {   0, &hf_itsis_numberOfAxles , ASN1_EXTENSION_ROOT    , dissect_itsis_INTEGER_0_7 },
  {   1, &hf_itsis_vehicleDimensions, ASN1_EXTENSION_ROOT    , dissect_itsis_VehicleDimensions },
  {   2, &hf_itsis_vehicleWeightLimits, ASN1_EXTENSION_ROOT    , dissect_itsis_VehicleWeightLimits },
  {   3, &hf_itsis_axleWeightLimits, ASN1_EXTENSION_ROOT    , dissect_itsis_AxleWeightLimits },
  {   4, &hf_itsis_passengerCapacity, ASN1_EXTENSION_ROOT    , dissect_itsis_PassengerCapacity },
  {   5, &hf_itsis_exhaustEmissionValues, ASN1_EXTENSION_ROOT    , dissect_itsis_ExhaustEmissionValues },
  {   6, &hf_itsis_dieselEmissionValues, ASN1_EXTENSION_ROOT    , dissect_itsis_DieselEmissionValues },
  {   7, &hf_itsis_soundLevel    , ASN1_EXTENSION_ROOT    , dissect_itsis_SoundLevel },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_T_limits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_T_limits, T_limits_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t VehicleCharacteristicsRanges_sequence[] = {
  { &hf_itsis_comparisonOperator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ComparisonOperator },
  { &hf_itsis_limits        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_limits },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VehicleCharacteristicsRanges(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VehicleCharacteristicsRanges, VehicleCharacteristicsRanges_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges_sequence_of[1] = {
  { &hf_itsis_ranges_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VehicleCharacteristicsRanges },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges, SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges_sequence_of,
                                                  1, 4, TRUE);

  return offset;
}


static const per_sequence_t TractorCharacteristics_sequence[] = {
  { &hf_itsis_equalTo       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues },
  { &hf_itsis_notEqualTo    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues },
  { &hf_itsis_ranges        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_TractorCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_TractorCharacteristics, TractorCharacteristics_sequence);

  return offset;
}


static const per_sequence_t TrailerCharacteristics_sequence[] = {
  { &hf_itsis_equalTo       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues },
  { &hf_itsis_notEqualTo    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues },
  { &hf_itsis_ranges        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_TrailerCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_TrailerCharacteristics, TrailerCharacteristics_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics_sequence_of[1] = {
  { &hf_itsis_trailer_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_TrailerCharacteristics },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics, SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics_sequence_of,
                                                  1, 3, FALSE);

  return offset;
}



static int
dissect_itsis_TrainCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_itsis_TractorCharacteristics(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CompleteVehicleCharacteristics_sequence[] = {
  { &hf_itsis_tractor       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_TractorCharacteristics },
  { &hf_itsis_trailer       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics },
  { &hf_itsis_train         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_TrainCharacteristics },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_CompleteVehicleCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_CompleteVehicleCharacteristics, CompleteVehicleCharacteristics_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics_sequence_of[1] = {
  { &hf_itsis_vehicleCharacteristics_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_CompleteVehicleCharacteristics },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics, SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}


static const value_string itsis_DriverCharacteristics_vals[] = {
  {   0, "unexperiencedDrivers" },
  {   1, "experiencedDrivers" },
  {   2, "rfu1" },
  {   3, "rfu2" },
  { 0, NULL }
};


static int
dissect_itsis_DriverCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_1_4_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4U, NULL, TRUE);

  return offset;
}



static int
dissect_itsis_INTEGER_1_64_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, TRUE);

  return offset;
}


static const value_string itsis_VcClass_vals[] = {
  {   0, "classA" },
  {   1, "classB" },
  {   2, "classC" },
  {   3, "classD" },
  {   4, "classE" },
  {   5, "classF" },
  {   6, "classG" },
  {   7, "classH" },
  { 0, NULL }
};


static int
dissect_itsis_VcClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_1_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, FALSE);

  return offset;
}


static const value_string itsis_VcOption_vals[] = {
  {   0, "none" },
  {   1, "a" },
  {   2, "b" },
  {   3, "c" },
  {   4, "d" },
  {   5, "e" },
  {   6, "f" },
  {   7, "g" },
  { 0, NULL }
};


static int
dissect_itsis_VcOption(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_2000_2127_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2000U, 2127U, NULL, TRUE);

  return offset;
}


static const per_sequence_t T_year_sequence[] = {
  { &hf_itsis_syr           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_2000_2127_ },
  { &hf_itsis_eyr           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_2000_2127_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_T_year(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_T_year, T_year_sequence);

  return offset;
}



static int
dissect_itsis_INTEGER_1_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 12U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_1_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 31U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MonthDay_sequence[] = {
  { &hf_itsis_month         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_12 },
  { &hf_itsis_day           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_31 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_MonthDay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_MonthDay, MonthDay_sequence);

  return offset;
}


static const per_sequence_t T_month_day_sequence[] = {
  { &hf_itsis_smd           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_MonthDay },
  { &hf_itsis_emd           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_MonthDay },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_T_month_day(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_T_month_day, T_month_day_sequence);

  return offset;
}



static int
dissect_itsis_PMD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_INTEGER_0_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 23U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_0_59(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}


static const per_sequence_t HoursMinutes_sequence[] = {
  { &hf_itsis_hours         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_23 },
  { &hf_itsis_mins          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_59 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_HoursMinutes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_HoursMinutes, HoursMinutes_sequence);

  return offset;
}


static const per_sequence_t T_hourMinutes_sequence[] = {
  { &hf_itsis_shm           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_HoursMinutes },
  { &hf_itsis_ehm           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_HoursMinutes },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_T_hourMinutes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_T_hourMinutes, T_hourMinutes_sequence);

  return offset;
}



static int
dissect_itsis_DayOfWeek(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t DTM_sequence[] = {
  { &hf_itsis_year          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_T_year },
  { &hf_itsis_month_day     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_T_month_day },
  { &hf_itsis_pmd           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_PMD },
  { &hf_itsis_hourMinutes   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_T_hourMinutes },
  { &hf_itsis_dayOfWeek     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_DayOfWeek },
  { &hf_itsis_period        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_HoursMinutes },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DTM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DTM, DTM_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8__OF_DTM_sequence_of[1] = {
  { &hf_itsis_validity_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DTM },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8__OF_DTM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8__OF_DTM, SEQUENCE_SIZE_1_8__OF_DTM_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}



static int
dissect_itsis_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string itsis_RSCUnit_vals[] = {
  {   0, "kmperh" },
  {   1, "milesperh" },
  {   2, "kilometer" },
  {   3, "meter" },
  {   4, "decimeter" },
  {   5, "centimeter" },
  {   6, "mile" },
  {   7, "yard" },
  {   8, "foot" },
  {   9, "minutesOfTime" },
  {  10, "tonnes" },
  {  11, "hundredkg" },
  {  12, "pound" },
  {  13, "rateOfIncline" },
  { 0, NULL }
};


static int
dissect_itsis_RSCUnit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 13U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VcCode_sequence[] = {
  { &hf_itsis_roadSignClass , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VcClass },
  { &hf_itsis_roadSignCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_64 },
  { &hf_itsis_vcOption      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VcOption },
  { &hf_itsis_validity_01   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_DTM },
  { &hf_itsis_value_02      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_0_65535 },
  { &hf_itsis_unit          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_RSCUnit },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VcCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VcCode, VcCode_sequence);

  return offset;
}



static int
dissect_itsis_OCTET_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const value_string itsis_T_trafficSignPictogram_vals[] = {
  {   0, "dangerWarning" },
  {   1, "regulatory" },
  {   2, "informative" },
  { 0, NULL }
};


static int
dissect_itsis_T_trafficSignPictogram(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string itsis_T_publicFacilitiesPictogram_vals[] = {
  {   0, "publicFacilities" },
  { 0, NULL }
};


static int
dissect_itsis_T_publicFacilitiesPictogram(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string itsis_T_ambientOrRoadConditionPictogram_vals[] = {
  {   0, "ambientCondition" },
  {   1, "roadCondition" },
  { 0, NULL }
};


static int
dissect_itsis_T_ambientOrRoadConditionPictogram(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string itsis_T_serviceCategoryCode_vals[] = {
  {   0, "trafficSignPictogram" },
  {   1, "publicFacilitiesPictogram" },
  {   2, "ambientOrRoadConditionPictogram" },
  { 0, NULL }
};

static const per_choice_t T_serviceCategoryCode_choice[] = {
  {   0, &hf_itsis_trafficSignPictogram, ASN1_EXTENSION_ROOT    , dissect_itsis_T_trafficSignPictogram },
  {   1, &hf_itsis_publicFacilitiesPictogram, ASN1_EXTENSION_ROOT    , dissect_itsis_T_publicFacilitiesPictogram },
  {   2, &hf_itsis_ambientOrRoadConditionPictogram, ASN1_EXTENSION_ROOT    , dissect_itsis_T_ambientOrRoadConditionPictogram },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_T_serviceCategoryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_T_serviceCategoryCode, T_serviceCategoryCode_choice,
                                 NULL);

  return offset;
}



static int
dissect_itsis_INTEGER_1_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 9U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_0_99(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 99U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_pictogramCategoryCode_sequence[] = {
  { &hf_itsis_nature        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_9 },
  { &hf_itsis_serialNumber  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_99 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_T_pictogramCategoryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_T_pictogramCategoryCode, T_pictogramCategoryCode_sequence);

  return offset;
}


static const per_sequence_t T_pictogramCode_sequence[] = {
  { &hf_itsis_countryCode_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_OCTET_STRING_SIZE_2 },
  { &hf_itsis_serviceCategoryCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_serviceCategoryCode },
  { &hf_itsis_pictogramCategoryCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_pictogramCategoryCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_T_pictogramCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_T_pictogramCode, T_pictogramCode_sequence);

  return offset;
}



static int
dissect_itsis_EDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_itsis_DTM(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string itsis_DFL_vals[] = {
  {   1, "sDL" },
  {   2, "sLT" },
  {   3, "sRT" },
  {   4, "lTO" },
  {   5, "rTO" },
  {   6, "cLL" },
  {   7, "cRI" },
  {   8, "oVL" },
  { 0, NULL }
};


static int
dissect_itsis_DFL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_1_16384(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16384U, NULL, FALSE);

  return offset;
}


static const value_string itsis_RSCUnit2468_vals[] = {
  {   2, "kilometer" },
  {   3, "meter" },
  {   4, "decimeter" },
  {   6, "mile" },
  {   7, "yard" },
  {   8, "foot" },
  { 0, NULL }
};


static int
dissect_itsis_RSCUnit2468(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 8U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Distance_sequence[] = {
  { &hf_itsis_value_03      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_16384 },
  { &hf_itsis_unit_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RSCUnit2468 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Distance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Distance, Distance_sequence);

  return offset;
}


static const value_string itsis_RSCUnit1012_vals[] = {
  {  10, "tonnes" },
  {  11, "hundredkg" },
  {  12, "pound" },
  { 0, NULL }
};


static int
dissect_itsis_RSCUnit1012(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            10U, 12U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Weight_sequence[] = {
  { &hf_itsis_value_03      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_16384 },
  { &hf_itsis_unit_03       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RSCUnit1012 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Weight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Weight, Weight_sequence);

  return offset;
}


static const per_sequence_t VED_sequence[] = {
  { &hf_itsis_hei           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_Distance },
  { &hf_itsis_wid           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_Distance },
  { &hf_itsis_vln           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_Distance },
  { &hf_itsis_wei           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_Weight },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VED, VED_sequence);

  return offset;
}



static int
dissect_itsis_INTEGER_0_250(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 250U, NULL, FALSE);

  return offset;
}


static const value_string itsis_RSCUnit01_vals[] = {
  {   0, "kmperh" },
  {   1, "milesperh" },
  { 0, NULL }
};


static int
dissect_itsis_RSCUnit01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SPE_sequence[] = {
  { &hf_itsis_spm           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_0_250 },
  { &hf_itsis_mns           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_0_250 },
  { &hf_itsis_unit_04       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RSCUnit01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SPE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SPE, SPE_sequence);

  return offset;
}



static int
dissect_itsis_ROI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_DBV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_itsis_Distance(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_itsis_INTEGER_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 128U, NULL, FALSE);

  return offset;
}


static const value_string itsis_DDD_DEP_vals[] = {
  {   0, "none" },
  {   1, "importantArea" },
  {   2, "principalArea" },
  {   3, "generalArea" },
  {   4, "wellKnownPoint" },
  {   5, "country" },
  {   6, "city" },
  {   7, "street" },
  {   8, "industrialArea" },
  {   9, "historicArea" },
  {  10, "touristicArea" },
  {  11, "culturalArea" },
  {  12, "touristicRoute" },
  {  13, "recommendedRoute" },
  {  14, "touristicAttraction" },
  {  15, "geographicArea" },
  { 0, NULL }
};


static int
dissect_itsis_DDD_DEP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}



static int
dissect_itsis_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_itsis_INTEGER_1_999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 999U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_UTF8String(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_UTF8String(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, FALSE);

  return offset;
}


static const per_sequence_t DestinationPlace_sequence[] = {
  { &hf_itsis_depType       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DDD_DEP },
  { &hf_itsis_depRSCode     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_ISO14823Code },
  { &hf_itsis_depBlob       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_OCTET_STRING },
  { &hf_itsis_plnId         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_999 },
  { &hf_itsis_plnText       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_UTF8String },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DestinationPlace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DestinationPlace, DestinationPlace_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4__OF_DestinationPlace_sequence_of[1] = {
  { &hf_itsis_dp_item       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DestinationPlace },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_4__OF_DestinationPlace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_4__OF_DestinationPlace, SEQUENCE_SIZE_1_4__OF_DestinationPlace_sequence_of,
                                                  1, 4, TRUE);

  return offset;
}


static const value_string itsis_DDD_DER_vals[] = {
  {   0, "none" },
  {   1, "nationalHighway" },
  {   2, "localHighway" },
  {   3, "tollExpresswayMotorway" },
  {   4, "internationalHighway" },
  {   5, "highway" },
  {   6, "expressway" },
  {   7, "nationalRoad" },
  {   8, "regionalProvincialRoad" },
  {   9, "localRoad" },
  {  10, "motorwayJunction" },
  {  11, "diversion" },
  {  12, "rfu1" },
  {  13, "rfu2" },
  {  14, "rfu3" },
  {  15, "rfu4" },
  { 0, NULL }
};


static int
dissect_itsis_DDD_DER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}


static const per_sequence_t DestinationRoad_sequence[] = {
  { &hf_itsis_derType       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DDD_DER },
  { &hf_itsis_ronId         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_999 },
  { &hf_itsis_ronText       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_UTF8String },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DestinationRoad(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DestinationRoad, DestinationRoad_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4__OF_DestinationRoad_sequence_of[1] = {
  { &hf_itsis_dr_item       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DestinationRoad },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_4__OF_DestinationRoad(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_4__OF_DestinationRoad, SEQUENCE_SIZE_1_4__OF_DestinationRoad_sequence_of,
                                                  1, 4, TRUE);

  return offset;
}


static const value_string itsis_RSCUnit29_vals[] = {
  {   2, "kilometer" },
  {   3, "meter" },
  {   4, "decimeter" },
  {   5, "centimeter" },
  {   6, "mile" },
  {   7, "yard" },
  {   8, "foot" },
  {   9, "minutesOfTime" },
  { 0, NULL }
};


static int
dissect_itsis_RSCUnit29(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 9U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DistanceOrDuration_sequence[] = {
  { &hf_itsis_value_03      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_16384 },
  { &hf_itsis_unit_02       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RSCUnit29 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DistanceOrDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DistanceOrDuration, DistanceOrDuration_sequence);

  return offset;
}


static const per_sequence_t DDD_IO_sequence[] = {
  { &hf_itsis_drn           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_7 },
  { &hf_itsis_dp            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_DestinationPlace },
  { &hf_itsis_dr            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_DestinationRoad },
  { &hf_itsis_rne           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_999 },
  { &hf_itsis_stnId         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_999 },
  { &hf_itsis_stnText       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_UTF8String },
  { &hf_itsis_dcp           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_DistanceOrDuration },
  { &hf_itsis_ddp           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_DistanceOrDuration },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DDD_IO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DDD_IO, DDD_IO_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8__OF_DDD_IO_sequence_of[1] = {
  { &hf_itsis_ioList_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DDD_IO },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8__OF_DDD_IO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8__OF_DDD_IO, SEQUENCE_SIZE_1_8__OF_DDD_IO_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}


static const per_sequence_t DDD_sequence[] = {
  { &hf_itsis_dcj           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_128 },
  { &hf_itsis_dcr           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_128 },
  { &hf_itsis_tpl           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_128 },
  { &hf_itsis_ioList        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SEQUENCE_SIZE_1_8__OF_DDD_IO },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DDD, DDD_sequence);

  return offset;
}


static const value_string itsis_ISO14823Attributes_item_vals[] = {
  {   0, "dtm" },
  {   1, "edt" },
  {   2, "dfl" },
  {   3, "ved" },
  {   4, "spe" },
  {   5, "roi" },
  {   6, "dbv" },
  {   7, "ddd" },
  { 0, NULL }
};

static const per_choice_t ISO14823Attributes_item_choice[] = {
  {   0, &hf_itsis_dtm           , ASN1_NO_EXTENSIONS     , dissect_itsis_DTM },
  {   1, &hf_itsis_edt           , ASN1_NO_EXTENSIONS     , dissect_itsis_EDT },
  {   2, &hf_itsis_dfl           , ASN1_NO_EXTENSIONS     , dissect_itsis_DFL },
  {   3, &hf_itsis_ved           , ASN1_NO_EXTENSIONS     , dissect_itsis_VED },
  {   4, &hf_itsis_spe           , ASN1_NO_EXTENSIONS     , dissect_itsis_SPE },
  {   5, &hf_itsis_roi           , ASN1_NO_EXTENSIONS     , dissect_itsis_ROI },
  {   6, &hf_itsis_dbv           , ASN1_NO_EXTENSIONS     , dissect_itsis_DBV },
  {   7, &hf_itsis_ddd           , ASN1_NO_EXTENSIONS     , dissect_itsis_DDD },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_ISO14823Attributes_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_ISO14823Attributes_item, ISO14823Attributes_item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ISO14823Attributes_sequence_of[1] = {
  { &hf_itsis_ISO14823Attributes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ISO14823Attributes_item },
};

static int
dissect_itsis_ISO14823Attributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_ISO14823Attributes, ISO14823Attributes_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}


static const per_sequence_t ISO14823Code_sequence[] = {
  { &hf_itsis_pictogramCode_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_pictogramCode },
  { &hf_itsis_attributes_01 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_ISO14823Attributes },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ISO14823Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ISO14823Code, ISO14823Code_sequence);

  return offset;
}


static const per_sequence_t AnyCatalogue_sequence[] = {
  { &hf_itsis_owner         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Provider },
  { &hf_itsis_version       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_255 },
  { &hf_itsis_pictogramCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_65535 },
  { &hf_itsis_value_02      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_0_65535 },
  { &hf_itsis_unit          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_RSCUnit },
  { &hf_itsis_attributes_01 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_ISO14823Attributes },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_AnyCatalogue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_AnyCatalogue, AnyCatalogue_sequence);

  return offset;
}


static const value_string itsis_T_code_vals[] = {
  {   0, "viennaConvention" },
  {   1, "iso14823" },
  {   2, "itisCodes" },
  {   3, "anyCatalogue" },
  { 0, NULL }
};

static const per_choice_t T_code_choice[] = {
  {   0, &hf_itsis_viennaConvention, ASN1_EXTENSION_ROOT    , dissect_itsis_VcCode },
  {   1, &hf_itsis_iso14823      , ASN1_EXTENSION_ROOT    , dissect_itsis_ISO14823Code },
  {   2, &hf_itsis_itisCodes     , ASN1_EXTENSION_ROOT    , dissect_itsis_INTEGER_0_65535 },
  {   3, &hf_itsis_anyCatalogue  , ASN1_EXTENSION_ROOT    , dissect_itsis_AnyCatalogue },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_T_code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_T_code, T_code_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RSCode_sequence[] = {
  { &hf_itsis_layoutComponentId_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_4_ },
  { &hf_itsis_code          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_code },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RSCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RSCode, RSCode_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4__OF_RSCode_sequence_of[1] = {
  { &hf_itsis_roadSignCodes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RSCode },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_4__OF_RSCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_4__OF_RSCode, SEQUENCE_SIZE_1_4__OF_RSCode_sequence_of,
                                                  1, 4, TRUE);

  return offset;
}



static int
dissect_itsis_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t Text_sequence[] = {
  { &hf_itsis_layoutComponentId_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_4_ },
  { &hf_itsis_language      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_BIT_STRING_SIZE_10 },
  { &hf_itsis_textContent   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_UTF8String },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Text(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Text, Text_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4__OF_Text_sequence_of[1] = {
  { &hf_itsis_extraText_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Text },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_4__OF_Text(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_4__OF_Text, SEQUENCE_SIZE_1_4__OF_Text_sequence_of,
                                                  1, 4, TRUE);

  return offset;
}


static const per_sequence_t GicPart_sequence[] = {
  { &hf_itsis_detectionZoneIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_Zid },
  { &hf_itsis_its_Rrid      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_VarLengthNumber },
  { &hf_itsis_relevanceZoneIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_Zid },
  { &hf_itsis_direction     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Direction },
  { &hf_itsis_driverAwarenessZoneIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_Zid },
  { &hf_itsis_minimumAwarenessTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_0_255 },
  { &hf_itsis_applicableLanes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_LanePosition },
  { &hf_itsis_iviType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IviType },
  { &hf_itsis_iviPurpose    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IviPurpose },
  { &hf_itsis_laneStatus    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_LaneStatus },
  { &hf_itsis_vehicleCharacteristics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics },
  { &hf_itsis_driverCharacteristics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DriverCharacteristics },
  { &hf_itsis_layoutId      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_4_ },
  { &hf_itsis_preStoredlayoutId, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_64_ },
  { &hf_itsis_roadSignCodes , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SEQUENCE_SIZE_1_4__OF_RSCode },
  { &hf_itsis_extraText     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_Text },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_GicPart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_GicPart, GicPart_sequence);

  return offset;
}


static const per_sequence_t GeneralIviContainer_sequence_of[1] = {
  { &hf_itsis_GeneralIviContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_GicPart },
};

static int
dissect_itsis_GeneralIviContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_GeneralIviContainer, GeneralIviContainer_sequence_of,
                                                  1, 16, TRUE);

  return offset;
}


static const value_string itsis_RoadType_vals[] = {
  {   0, "urban-NoStructuralSeparationToOppositeLanes" },
  {   1, "urban-WithStructuralSeparationToOppositeLanes" },
  {   2, "nonUrban-NoStructuralSeparationToOppositeLanes" },
  {   3, "nonUrban-WithStructuralSeparationToOppositeLanes" },
  { 0, NULL }
};


static int
dissect_itsis_RoadType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_LaneType_vals[] = {
  {   0, "traffic" },
  {   1, "through" },
  {   2, "reversible" },
  {   3, "acceleration" },
  {   4, "deceleration" },
  {   5, "leftHandTurning" },
  {   6, "rightHandTurning" },
  {   7, "dedicatedVehicle" },
  {   8, "bus" },
  {   9, "taxi" },
  {  10, "hov" },
  {  11, "hot" },
  {  12, "pedestrian" },
  {  13, "bikeLane" },
  {  14, "median" },
  {  15, "striping" },
  {  16, "trackedVehicle" },
  {  17, "parking" },
  {  18, "emergency" },
  {  19, "verge" },
  { 0, NULL }
};


static int
dissect_itsis_LaneType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LaneInformation_sequence[] = {
  { &hf_itsis_laneNumber    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LanePosition },
  { &hf_itsis_direction     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Direction },
  { &hf_itsis_validity      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DTM },
  { &hf_itsis_laneType_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LaneType },
  { &hf_itsis_laneTypeQualifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_CompleteVehicleCharacteristics },
  { &hf_itsis_laneStatus    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LaneStatus },
  { &hf_itsis_laneWidth_01  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IVILaneWidth },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_LaneInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_LaneInformation, LaneInformation_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_16__OF_LaneInformation_sequence_of[1] = {
  { &hf_itsis_laneConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LaneInformation },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_16__OF_LaneInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_16__OF_LaneInformation, SEQUENCE_SIZE_1_16__OF_LaneInformation_sequence_of,
                                                  1, 16, TRUE);

  return offset;
}


static const per_sequence_t RccPart_sequence[] = {
  { &hf_itsis_zoneIds       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SEQUENCE_SIZE_1_8__OF_Zid },
  { &hf_itsis_roadType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_RoadType },
  { &hf_itsis_laneConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SEQUENCE_SIZE_1_16__OF_LaneInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RccPart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RccPart, RccPart_sequence);

  return offset;
}


static const per_sequence_t RoadConfigurationContainer_sequence_of[1] = {
  { &hf_itsis_RoadConfigurationContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RccPart },
};

static int
dissect_itsis_RoadConfigurationContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_RoadConfigurationContainer, RoadConfigurationContainer_sequence_of,
                                                  1, 16, TRUE);

  return offset;
}


static const per_sequence_t TcPart_sequence[] = {
  { &hf_itsis_detectionZoneIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_Zid },
  { &hf_itsis_relevanceZoneIds, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SEQUENCE_SIZE_1_8__OF_Zid },
  { &hf_itsis_direction     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Direction },
  { &hf_itsis_driverAwarenessZoneIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_Zid },
  { &hf_itsis_minimumAwarenessTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_0_255 },
  { &hf_itsis_applicableLanes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_LanePosition },
  { &hf_itsis_layoutId      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_4_ },
  { &hf_itsis_preStoredlayoutId, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_1_64_ },
  { &hf_itsis_text          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4__OF_Text },
  { &hf_itsis_data_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_TcPart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_TcPart, TcPart_sequence);

  return offset;
}


static const per_sequence_t TextContainer_sequence_of[1] = {
  { &hf_itsis_TextContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_TcPart },
};

static int
dissect_itsis_TextContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_TextContainer, TextContainer_sequence_of,
                                                  1, 16, TRUE);

  return offset;
}



static int
dissect_itsis_INTEGER_10_73(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            10U, 73U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_10_265(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            10U, 265U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_INTEGER_1_8_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, TRUE);

  return offset;
}


static const value_string itsis_T_textScripting_vals[] = {
  {   0, "horizontal" },
  {   1, "vertical" },
  { 0, NULL }
};


static int
dissect_itsis_T_textScripting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LayoutComponent_sequence[] = {
  { &hf_itsis_layoutComponentId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_8_ },
  { &hf_itsis_height        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_10_73 },
  { &hf_itsis_width         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_10_265 },
  { &hf_itsis_x_06          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_10_265 },
  { &hf_itsis_y_06          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_10_73 },
  { &hf_itsis_textScripting , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_textScripting },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_LayoutComponent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_LayoutComponent, LayoutComponent_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4__OF_LayoutComponent_sequence_of[1] = {
  { &hf_itsis_layoutComponents_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LayoutComponent },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_4__OF_LayoutComponent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_4__OF_LayoutComponent, SEQUENCE_SIZE_1_4__OF_LayoutComponent_sequence_of,
                                                  1, 4, TRUE);

  return offset;
}


static const per_sequence_t LayoutContainer_sequence[] = {
  { &hf_itsis_layoutId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_1_4_ },
  { &hf_itsis_height        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_10_73 },
  { &hf_itsis_width         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_INTEGER_10_265 },
  { &hf_itsis_layoutComponents, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SEQUENCE_SIZE_1_4__OF_LayoutComponent },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_LayoutContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_LayoutContainer, LayoutContainer_sequence);

  return offset;
}


static const value_string itsis_IviContainer_vals[] = {
  {   0, "glc" },
  {   1, "giv" },
  {   2, "rcc" },
  {   3, "tc" },
  {   4, "lac" },
  { 0, NULL }
};

static const per_choice_t IviContainer_choice[] = {
  {   0, &hf_itsis_glc           , ASN1_EXTENSION_ROOT    , dissect_itsis_GeographicLocationContainer },
  {   1, &hf_itsis_giv           , ASN1_EXTENSION_ROOT    , dissect_itsis_GeneralIviContainer },
  {   2, &hf_itsis_rcc           , ASN1_EXTENSION_ROOT    , dissect_itsis_RoadConfigurationContainer },
  {   3, &hf_itsis_tc            , ASN1_EXTENSION_ROOT    , dissect_itsis_TextContainer },
  {   4, &hf_itsis_lac           , ASN1_EXTENSION_ROOT    , dissect_itsis_LayoutContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_IviContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_IviContainer, IviContainer_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8__OF_IviContainer_sequence_of[1] = {
  { &hf_itsis_optional_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IviContainer },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_8__OF_IviContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_8__OF_IviContainer, SEQUENCE_SIZE_1_8__OF_IviContainer_sequence_of,
                                                  1, 8, TRUE);

  return offset;
}


static const per_sequence_t IviStructure_sequence[] = {
  { &hf_itsis_mandatory     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IVIManagementContainer },
  { &hf_itsis_optional      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_8__OF_IviContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_IviStructure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 61 "./asn1/itsis/itsis.cnf"
  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (ETSI TS 103301)");

    offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_IviStructure, IviStructure_sequence);




  return offset;
}


static const per_sequence_t IVIM_sequence[] = {
  { &hf_itsis_header        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ItsPduHeader },
  { &hf_itsis_ivi           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IviStructure },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_IVIM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_IVIM, IVIM_sequence);

  return offset;
}



static int
dissect_itsis_MinuteOfTheYear(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 527040U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_MsgCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const value_string itsis_LayerType_vals[] = {
  {   0, "none" },
  {   1, "mixedContent" },
  {   2, "generalMapData" },
  {   3, "intersectionData" },
  {   4, "curveData" },
  {   5, "roadwaySectionData" },
  {   6, "parkingAreaData" },
  {   7, "sharedLaneData" },
  { 0, NULL }
};


static int
dissect_itsis_LayerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_itsis_LayerID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_DescriptiveName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 63, FALSE);

  return offset;
}



static int
dissect_itsis_RoadRegulatorID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_IntersectionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t IntersectionReferenceID_sequence[] = {
  { &hf_itsis_region        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_RoadRegulatorID },
  { &hf_itsis_id_01         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_IntersectionReferenceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_IntersectionReferenceID, IntersectionReferenceID_sequence);

  return offset;
}



static int
dissect_itsis_Elevation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, FALSE);

  return offset;
}


static const value_string itsis_RegionId_vals[] = {
  { noRegion, "noRegion" },
  { addGrpA, "addGrpA" },
  { addGrpB, "addGrpB" },
  { addGrpC, "addGrpC" },
  { 0, NULL }
};


static int
dissect_itsis_RegionId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

#line 44 "./asn1/itsis/itsis.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(Ref_RegionId, VALS(itsis_RegionId_vals), "unknown (%d)"));
  }

  return offset;
}



static int
dissect_itsis_T_regExtValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_regionalextension_pdu_type);

  return offset;
}


static const per_sequence_t RegionalExtension_sequence[] = {
  { &hf_itsis_regionId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RegionId },
  { &hf_itsis_regExtValue   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_T_regExtValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RegionalExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RegionalExtension, RegionalExtension_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4_OF_RegionalExtension_sequence_of[1] = {
  { &hf_itsis_regional_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RegionalExtension },
};

static int
dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension, SEQUENCE_SIZE_1_4_OF_RegionalExtension_sequence_of,
                                                  1, 4, FALSE);

  return offset;
}


static const per_sequence_t Position3D_sequence[] = {
  { &hf_itsis_lat           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Latitude },
  { &hf_itsis_long          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Longitude },
  { &hf_itsis_elevation     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Elevation },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Position3D(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Position3D, Position3D_sequence);

  return offset;
}



static int
dissect_itsis_LaneWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}


static const value_string itsis_SpeedLimitType_vals[] = {
  {   0, "unknown" },
  {   1, "maxSpeedInSchoolZone" },
  {   2, "maxSpeedInSchoolZoneWhenChildrenArePresent" },
  {   3, "maxSpeedInConstructionZone" },
  {   4, "vehicleMinSpeed" },
  {   5, "vehicleMaxSpeed" },
  {   6, "vehicleNightMaxSpeed" },
  {   7, "truckMinSpeed" },
  {   8, "truckMaxSpeed" },
  {   9, "truckNightMaxSpeed" },
  {  10, "vehiclesWithTrailersMinSpeed" },
  {  11, "vehiclesWithTrailersMaxSpeed" },
  {  12, "vehiclesWithTrailersNightMaxSpeed" },
  { 0, NULL }
};


static int
dissect_itsis_SpeedLimitType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_itsis_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RegulatorySpeedLimit_sequence[] = {
  { &hf_itsis_type_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SpeedLimitType },
  { &hf_itsis_speed_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RegulatorySpeedLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RegulatorySpeedLimit, RegulatorySpeedLimit_sequence);

  return offset;
}


static const per_sequence_t SpeedLimitList_sequence_of[1] = {
  { &hf_itsis_SpeedLimitList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RegulatorySpeedLimit },
};

static int
dissect_itsis_SpeedLimitList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SpeedLimitList, SpeedLimitList_sequence_of,
                                                  1, 9, FALSE);

  return offset;
}



static int
dissect_itsis_LaneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_ApproachID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_LaneDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneSharing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneAttributes_Vehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, TRUE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneAttributes_Crosswalk(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneAttributes_Bike(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneAttributes_Sidewalk(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneAttributes_Barrier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneAttributes_Striping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneAttributes_TrackedVehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_LaneAttributes_Parking(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}


static const value_string itsis_LaneTypeAttributes_vals[] = {
  {   0, "vehicle" },
  {   1, "crosswalk" },
  {   2, "bikeLane" },
  {   3, "sidewalk" },
  {   4, "median" },
  {   5, "striping" },
  {   6, "trackedVehicle" },
  {   7, "parking" },
  { 0, NULL }
};

static const per_choice_t LaneTypeAttributes_choice[] = {
  {   0, &hf_itsis_vehicle       , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneAttributes_Vehicle },
  {   1, &hf_itsis_crosswalk     , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneAttributes_Crosswalk },
  {   2, &hf_itsis_bikeLane      , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneAttributes_Bike },
  {   3, &hf_itsis_sidewalk      , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneAttributes_Sidewalk },
  {   4, &hf_itsis_median        , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneAttributes_Barrier },
  {   5, &hf_itsis_striping      , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneAttributes_Striping },
  {   6, &hf_itsis_trackedVehicle, ASN1_EXTENSION_ROOT    , dissect_itsis_LaneAttributes_TrackedVehicle },
  {   7, &hf_itsis_parking       , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneAttributes_Parking },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_LaneTypeAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_LaneTypeAttributes, LaneTypeAttributes_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LaneAttributes_sequence[] = {
  { &hf_itsis_directionalUse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LaneDirection },
  { &hf_itsis_sharedWith    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LaneSharing },
  { &hf_itsis_laneType      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LaneTypeAttributes },
  { &hf_itsis_regional_01   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_LaneAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_LaneAttributes, LaneAttributes_sequence);

  return offset;
}



static int
dissect_itsis_AllowedManeuvers(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     12, 12, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_Offset_B10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -512, 511U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_20b_sequence[] = {
  { &hf_itsis_x             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B10 },
  { &hf_itsis_y             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Node_XY_20b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Node_XY_20b, Node_XY_20b_sequence);

  return offset;
}



static int
dissect_itsis_Offset_B11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1024, 1023U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_22b_sequence[] = {
  { &hf_itsis_x_01          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B11 },
  { &hf_itsis_y_01          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B11 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Node_XY_22b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Node_XY_22b, Node_XY_22b_sequence);

  return offset;
}



static int
dissect_itsis_Offset_B12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2048, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_24b_sequence[] = {
  { &hf_itsis_x_02          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B12 },
  { &hf_itsis_y_02          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B12 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Node_XY_24b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Node_XY_24b, Node_XY_24b_sequence);

  return offset;
}



static int
dissect_itsis_Offset_B13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4096, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_26b_sequence[] = {
  { &hf_itsis_x_03          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B13 },
  { &hf_itsis_y_03          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B13 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Node_XY_26b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Node_XY_26b, Node_XY_26b_sequence);

  return offset;
}



static int
dissect_itsis_Offset_B14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8192, 8191U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_28b_sequence[] = {
  { &hf_itsis_x_04          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B14 },
  { &hf_itsis_y_04          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B14 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Node_XY_28b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Node_XY_28b, Node_XY_28b_sequence);

  return offset;
}



static int
dissect_itsis_Offset_B16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_32b_sequence[] = {
  { &hf_itsis_x_05          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B16 },
  { &hf_itsis_y_05          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Offset_B16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Node_XY_32b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Node_XY_32b, Node_XY_32b_sequence);

  return offset;
}


static const per_sequence_t Node_LLmD_64b_sequence[] = {
  { &hf_itsis_lon           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Longitude },
  { &hf_itsis_lat           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Latitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Node_LLmD_64b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Node_LLmD_64b, Node_LLmD_64b_sequence);

  return offset;
}


static const value_string itsis_NodeOffsetPointXY_vals[] = {
  {   0, "node-XY1" },
  {   1, "node-XY2" },
  {   2, "node-XY3" },
  {   3, "node-XY4" },
  {   4, "node-XY5" },
  {   5, "node-XY6" },
  {   6, "node-LatLon" },
  {   7, "regional" },
  { 0, NULL }
};

static const per_choice_t NodeOffsetPointXY_choice[] = {
  {   0, &hf_itsis_node_XY1      , ASN1_NO_EXTENSIONS     , dissect_itsis_Node_XY_20b },
  {   1, &hf_itsis_node_XY2      , ASN1_NO_EXTENSIONS     , dissect_itsis_Node_XY_22b },
  {   2, &hf_itsis_node_XY3      , ASN1_NO_EXTENSIONS     , dissect_itsis_Node_XY_24b },
  {   3, &hf_itsis_node_XY4      , ASN1_NO_EXTENSIONS     , dissect_itsis_Node_XY_26b },
  {   4, &hf_itsis_node_XY5      , ASN1_NO_EXTENSIONS     , dissect_itsis_Node_XY_28b },
  {   5, &hf_itsis_node_XY6      , ASN1_NO_EXTENSIONS     , dissect_itsis_Node_XY_32b },
  {   6, &hf_itsis_node_LatLon   , ASN1_NO_EXTENSIONS     , dissect_itsis_Node_LLmD_64b },
  {   7, &hf_itsis_regional_01   , ASN1_NO_EXTENSIONS     , dissect_itsis_RegionalExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_NodeOffsetPointXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_NodeOffsetPointXY, NodeOffsetPointXY_choice,
                                 NULL);

  return offset;
}


static const value_string itsis_NodeAttributeXY_vals[] = {
  {   0, "reserved" },
  {   1, "stopLine" },
  {   2, "roundedCapStyleA" },
  {   3, "roundedCapStyleB" },
  {   4, "mergePoint" },
  {   5, "divergePoint" },
  {   6, "downstreamStopLine" },
  {   7, "downstreamStartNode" },
  {   8, "closedToTraffic" },
  {   9, "safeIsland" },
  {  10, "curbPresentAtStepOff" },
  {  11, "hydrantPresent" },
  { 0, NULL }
};


static int
dissect_itsis_NodeAttributeXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     12, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NodeAttributeXYList_sequence_of[1] = {
  { &hf_itsis_NodeAttributeXYList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_NodeAttributeXY },
};

static int
dissect_itsis_NodeAttributeXYList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_NodeAttributeXYList, NodeAttributeXYList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const value_string itsis_SegmentAttributeXY_vals[] = {
  {   0, "reserved" },
  {   1, "doNotBlock" },
  {   2, "whiteLine" },
  {   3, "mergingLaneLeft" },
  {   4, "mergingLaneRight" },
  {   5, "curbOnLeft" },
  {   6, "curbOnRight" },
  {   7, "loadingzoneOnLeft" },
  {   8, "loadingzoneOnRight" },
  {   9, "turnOutPointOnLeft" },
  {  10, "turnOutPointOnRight" },
  {  11, "adjacentParkingOnLeft" },
  {  12, "adjacentParkingOnRight" },
  {  13, "adjacentBikeLaneOnLeft" },
  {  14, "adjacentBikeLaneOnRight" },
  {  15, "sharedBikeLane" },
  {  16, "bikeBoxInFront" },
  {  17, "transitStopOnLeft" },
  {  18, "transitStopOnRight" },
  {  19, "transitStopInLane" },
  {  20, "sharedWithTrackedVehicle" },
  {  21, "safeIsland" },
  {  22, "lowCurbsPresent" },
  {  23, "rumbleStripPresent" },
  {  24, "audibleSignalingPresent" },
  {  25, "adaptiveTimingPresent" },
  {  26, "rfSignalRequestPresent" },
  {  27, "partialCurbIntrusion" },
  {  28, "taperToLeft" },
  {  29, "taperToRight" },
  {  30, "taperToCenterLine" },
  {  31, "parallelParking" },
  {  32, "headInParking" },
  {  33, "freeParking" },
  {  34, "timeRestrictionsOnParking" },
  {  35, "costToPark" },
  {  36, "midBlockCurbPresent" },
  {  37, "unEvenPavementPresent" },
  { 0, NULL }
};


static int
dissect_itsis_SegmentAttributeXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     38, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SegmentAttributeXYList_sequence_of[1] = {
  { &hf_itsis_SegmentAttributeXYList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SegmentAttributeXY },
};

static int
dissect_itsis_SegmentAttributeXYList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SegmentAttributeXYList, SegmentAttributeXYList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}



static int
dissect_itsis_DeltaAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -150, 150U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_RoadwayCrownAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -128, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_MergeDivergeNodeAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -180, 180U, NULL, FALSE);

  return offset;
}


static const value_string itsis_LaneDataAttribute_vals[] = {
  {   0, "pathEndPointAngle" },
  {   1, "laneCrownPointCenter" },
  {   2, "laneCrownPointLeft" },
  {   3, "laneCrownPointRight" },
  {   4, "laneAngle" },
  {   5, "speedLimits" },
  {   6, "regional" },
  { 0, NULL }
};

static const per_choice_t LaneDataAttribute_choice[] = {
  {   0, &hf_itsis_pathEndPointAngle, ASN1_EXTENSION_ROOT    , dissect_itsis_DeltaAngle },
  {   1, &hf_itsis_laneCrownPointCenter, ASN1_EXTENSION_ROOT    , dissect_itsis_RoadwayCrownAngle },
  {   2, &hf_itsis_laneCrownPointLeft, ASN1_EXTENSION_ROOT    , dissect_itsis_RoadwayCrownAngle },
  {   3, &hf_itsis_laneCrownPointRight, ASN1_EXTENSION_ROOT    , dissect_itsis_RoadwayCrownAngle },
  {   4, &hf_itsis_laneAngle     , ASN1_EXTENSION_ROOT    , dissect_itsis_MergeDivergeNodeAngle },
  {   5, &hf_itsis_speedLimits   , ASN1_EXTENSION_ROOT    , dissect_itsis_SpeedLimitList },
  {   6, &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_LaneDataAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_LaneDataAttribute, LaneDataAttribute_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LaneDataAttributeList_sequence_of[1] = {
  { &hf_itsis_LaneDataAttributeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LaneDataAttribute },
};

static int
dissect_itsis_LaneDataAttributeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_LaneDataAttributeList, LaneDataAttributeList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const per_sequence_t NodeAttributeSetXY_sequence[] = {
  { &hf_itsis_localNode     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_NodeAttributeXYList },
  { &hf_itsis_disabled      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SegmentAttributeXYList },
  { &hf_itsis_enabled       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SegmentAttributeXYList },
  { &hf_itsis_data          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_LaneDataAttributeList },
  { &hf_itsis_dWidth        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Offset_B10 },
  { &hf_itsis_dElevation    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Offset_B10 },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_NodeAttributeSetXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_NodeAttributeSetXY, NodeAttributeSetXY_sequence);

  return offset;
}


static const per_sequence_t NodeXY_sequence[] = {
  { &hf_itsis_delta         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_NodeOffsetPointXY },
  { &hf_itsis_attributes    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_NodeAttributeSetXY },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_NodeXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_NodeXY, NodeXY_sequence);

  return offset;
}


static const per_sequence_t NodeSetXY_sequence_of[1] = {
  { &hf_itsis_NodeSetXY_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_NodeXY },
};

static int
dissect_itsis_NodeSetXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_NodeSetXY, NodeSetXY_sequence_of,
                                                  2, 63, FALSE);

  return offset;
}



static int
dissect_itsis_DrivenLineOffsetSm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2047, 2047U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_DrivenLineOffsetLg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32767, 32767U, NULL, FALSE);

  return offset;
}


static const value_string itsis_T_offsetXaxis_vals[] = {
  {   0, "small" },
  {   1, "large" },
  { 0, NULL }
};

static const per_choice_t T_offsetXaxis_choice[] = {
  {   0, &hf_itsis_small         , ASN1_NO_EXTENSIONS     , dissect_itsis_DrivenLineOffsetSm },
  {   1, &hf_itsis_large         , ASN1_NO_EXTENSIONS     , dissect_itsis_DrivenLineOffsetLg },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_T_offsetXaxis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_T_offsetXaxis, T_offsetXaxis_choice,
                                 NULL);

  return offset;
}


static const value_string itsis_T_offsetYaxis_vals[] = {
  {   0, "small" },
  {   1, "large" },
  { 0, NULL }
};

static const per_choice_t T_offsetYaxis_choice[] = {
  {   0, &hf_itsis_small         , ASN1_NO_EXTENSIONS     , dissect_itsis_DrivenLineOffsetSm },
  {   1, &hf_itsis_large         , ASN1_NO_EXTENSIONS     , dissect_itsis_DrivenLineOffsetLg },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_T_offsetYaxis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_T_offsetYaxis, T_offsetYaxis_choice,
                                 NULL);

  return offset;
}



static int
dissect_itsis_Angle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 28800U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_Scale_B12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2048, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ComputedLane_sequence[] = {
  { &hf_itsis_referenceLaneId, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LaneID },
  { &hf_itsis_offsetXaxis   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_T_offsetXaxis },
  { &hf_itsis_offsetYaxis   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_T_offsetYaxis },
  { &hf_itsis_rotateXY      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Angle },
  { &hf_itsis_scaleXaxis    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Scale_B12 },
  { &hf_itsis_scaleYaxis    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Scale_B12 },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ComputedLane(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ComputedLane, ComputedLane_sequence);

  return offset;
}


static const value_string itsis_NodeListXY_vals[] = {
  {   0, "nodes" },
  {   1, "computed" },
  { 0, NULL }
};

static const per_choice_t NodeListXY_choice[] = {
  {   0, &hf_itsis_nodes         , ASN1_EXTENSION_ROOT    , dissect_itsis_NodeSetXY },
  {   1, &hf_itsis_computed      , ASN1_EXTENSION_ROOT    , dissect_itsis_ComputedLane },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_NodeListXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_NodeListXY, NodeListXY_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ConnectingLane_sequence[] = {
  { &hf_itsis_lane          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LaneID },
  { &hf_itsis_maneuver      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_AllowedManeuvers },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ConnectingLane(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ConnectingLane, ConnectingLane_sequence);

  return offset;
}



static int
dissect_itsis_SignalGroupID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_RestrictionClassID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_LaneConnectionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Connection_sequence[] = {
  { &hf_itsis_connectingLane, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ConnectingLane },
  { &hf_itsis_remoteIntersection, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_IntersectionReferenceID },
  { &hf_itsis_signalGroup   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_SignalGroupID },
  { &hf_itsis_userClass     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_RestrictionClassID },
  { &hf_itsis_connectionID  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_LaneConnectionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Connection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Connection, Connection_sequence);

  return offset;
}


static const per_sequence_t ConnectsToList_sequence_of[1] = {
  { &hf_itsis_ConnectsToList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Connection },
};

static int
dissect_itsis_ConnectsToList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_ConnectsToList, ConnectsToList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t OverlayLaneList_sequence_of[1] = {
  { &hf_itsis_OverlayLaneList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LaneID },
};

static int
dissect_itsis_OverlayLaneList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_OverlayLaneList, OverlayLaneList_sequence_of,
                                                  1, 5, FALSE);

  return offset;
}


static const per_sequence_t GenericLane_sequence[] = {
  { &hf_itsis_laneID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LaneID },
  { &hf_itsis_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DescriptiveName },
  { &hf_itsis_ingressApproach, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_ApproachID },
  { &hf_itsis_egressApproach, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_ApproachID },
  { &hf_itsis_laneAttributes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LaneAttributes },
  { &hf_itsis_maneuvers     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_AllowedManeuvers },
  { &hf_itsis_nodeList      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_NodeListXY },
  { &hf_itsis_connectsTo    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_ConnectsToList },
  { &hf_itsis_overlays      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_OverlayLaneList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_GenericLane(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_GenericLane, GenericLane_sequence);

  return offset;
}


static const per_sequence_t LaneList_sequence_of[1] = {
  { &hf_itsis_LaneList_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_GenericLane },
};

static int
dissect_itsis_LaneList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_LaneList, LaneList_sequence_of,
                                                  1, 255, FALSE);

  return offset;
}


static const per_sequence_t SignalControlZone_sequence[] = {
  { &hf_itsis_zone          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalControlZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalControlZone, SignalControlZone_sequence);

  return offset;
}


static const per_sequence_t PreemptPriorityList_sequence_of[1] = {
  { &hf_itsis_PreemptPriorityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SignalControlZone },
};

static int
dissect_itsis_PreemptPriorityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_PreemptPriorityList, PreemptPriorityList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t IntersectionGeometry_sequence[] = {
  { &hf_itsis_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DescriptiveName },
  { &hf_itsis_id            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionReferenceID },
  { &hf_itsis_revision      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MsgCount },
  { &hf_itsis_refPoint      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Position3D },
  { &hf_itsis_laneWidth     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_LaneWidth },
  { &hf_itsis_speedLimits   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SpeedLimitList },
  { &hf_itsis_laneSet       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LaneList },
  { &hf_itsis_preemptPriorityData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_PreemptPriorityList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_IntersectionGeometry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_IntersectionGeometry, IntersectionGeometry_sequence);

  return offset;
}


static const per_sequence_t IntersectionGeometryList_sequence_of[1] = {
  { &hf_itsis_IntersectionGeometryList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionGeometry },
};

static int
dissect_itsis_IntersectionGeometryList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_IntersectionGeometryList, IntersectionGeometryList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}



static int
dissect_itsis_RoadSegmentID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RoadSegmentReferenceID_sequence[] = {
  { &hf_itsis_region        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_RoadRegulatorID },
  { &hf_itsis_id_04         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RoadSegmentID },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RoadSegmentReferenceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RoadSegmentReferenceID, RoadSegmentReferenceID_sequence);

  return offset;
}


static const per_sequence_t RoadLaneSetList_sequence_of[1] = {
  { &hf_itsis_RoadLaneSetList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_GenericLane },
};

static int
dissect_itsis_RoadLaneSetList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_RoadLaneSetList, RoadLaneSetList_sequence_of,
                                                  1, 255, FALSE);

  return offset;
}


static const per_sequence_t RoadSegment_sequence[] = {
  { &hf_itsis_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DescriptiveName },
  { &hf_itsis_id_05         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_RoadSegmentReferenceID },
  { &hf_itsis_revision      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MsgCount },
  { &hf_itsis_refPoint      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Position3D },
  { &hf_itsis_laneWidth     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_LaneWidth },
  { &hf_itsis_speedLimits   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SpeedLimitList },
  { &hf_itsis_roadLaneSet   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_RoadLaneSetList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RoadSegment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RoadSegment, RoadSegment_sequence);

  return offset;
}


static const per_sequence_t RoadSegmentList_sequence_of[1] = {
  { &hf_itsis_RoadSegmentList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RoadSegment },
};

static int
dissect_itsis_RoadSegmentList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_RoadSegmentList, RoadSegmentList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}



static int
dissect_itsis_IA5String_SIZE_1_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 255, FALSE);

  return offset;
}


static const per_sequence_t DataParameters_sequence[] = {
  { &hf_itsis_processMethod , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IA5String_SIZE_1_255 },
  { &hf_itsis_processAgency , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IA5String_SIZE_1_255 },
  { &hf_itsis_lastCheckedDate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IA5String_SIZE_1_255 },
  { &hf_itsis_geoidUsed     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IA5String_SIZE_1_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DataParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DataParameters, DataParameters_sequence);

  return offset;
}


static const value_string itsis_RestrictionAppliesTo_vals[] = {
  {   0, "none" },
  {   1, "equippedTransit" },
  {   2, "equippedTaxis" },
  {   3, "equippedOther" },
  {   4, "emissionCompliant" },
  {   5, "equippedBicycle" },
  {   6, "weightCompliant" },
  {   7, "heightCompliant" },
  {   8, "pedestrians" },
  {   9, "slowMovingPersons" },
  {  10, "wheelchairUsers" },
  {  11, "visualDisabilities" },
  {  12, "audioDisabilities" },
  {  13, "otherUnknownDisabilities" },
  { 0, NULL }
};


static int
dissect_itsis_RestrictionAppliesTo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string itsis_RestrictionUserType_vals[] = {
  {   0, "basicType" },
  {   1, "regional" },
  { 0, NULL }
};

static const per_choice_t RestrictionUserType_choice[] = {
  {   0, &hf_itsis_basicType     , ASN1_EXTENSION_ROOT    , dissect_itsis_RestrictionAppliesTo },
  {   1, &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_RestrictionUserType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_RestrictionUserType, RestrictionUserType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RestrictionUserTypeList_sequence_of[1] = {
  { &hf_itsis_RestrictionUserTypeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RestrictionUserType },
};

static int
dissect_itsis_RestrictionUserTypeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_RestrictionUserTypeList, RestrictionUserTypeList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t RestrictionClassAssignment_sequence[] = {
  { &hf_itsis_id_03         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RestrictionClassID },
  { &hf_itsis_users         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RestrictionUserTypeList },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RestrictionClassAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RestrictionClassAssignment, RestrictionClassAssignment_sequence);

  return offset;
}


static const per_sequence_t RestrictionClassList_sequence_of[1] = {
  { &hf_itsis_RestrictionClassList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_RestrictionClassAssignment },
};

static int
dissect_itsis_RestrictionClassList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_RestrictionClassList, RestrictionClassList_sequence_of,
                                                  1, 254, FALSE);

  return offset;
}


static const per_sequence_t MapData_sequence[] = {
  { &hf_itsis_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MinuteOfTheYear },
  { &hf_itsis_msgIssueRevision, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MsgCount },
  { &hf_itsis_layerType     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_LayerType },
  { &hf_itsis_layerID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_LayerID },
  { &hf_itsis_intersections_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IntersectionGeometryList },
  { &hf_itsis_roadSegments  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RoadSegmentList },
  { &hf_itsis_dataParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DataParameters },
  { &hf_itsis_restrictionList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RestrictionClassList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_MapData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 51 "./asn1/itsis/itsis.cnf"
  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (ETSI TS 103301)");

    offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_MapData, MapData_sequence);




  return offset;
}


static const per_sequence_t MAPEM_sequence[] = {
  { &hf_itsis_header        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ItsPduHeader },
  { &hf_itsis_map           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_MapData },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_MAPEM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_MAPEM, MAPEM_sequence);

  return offset;
}



static int
dissect_itsis_IntersectionStatusObject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_DSecond(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t EnabledLaneList_sequence_of[1] = {
  { &hf_itsis_EnabledLaneList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LaneID },
};

static int
dissect_itsis_EnabledLaneList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_EnabledLaneList, EnabledLaneList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const value_string itsis_MovementPhaseState_vals[] = {
  {   0, "unavailable" },
  {   1, "dark" },
  {   2, "stop-Then-Proceed" },
  {   3, "stop-And-Remain" },
  {   4, "pre-Movement" },
  {   5, "permissive-Movement-Allowed" },
  {   6, "protected-Movement-Allowed" },
  {   7, "permissive-clearance" },
  {   8, "protected-clearance" },
  {   9, "caution-Conflicting-Traffic" },
  { 0, NULL }
};


static int
dissect_itsis_MovementPhaseState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_itsis_TimeMark(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 36001U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_TimeIntervalConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TimeChangeDetails_sequence[] = {
  { &hf_itsis_startTime     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_TimeMark },
  { &hf_itsis_minEndTime    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_TimeMark },
  { &hf_itsis_maxEndTime    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_TimeMark },
  { &hf_itsis_likelyTime    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_TimeMark },
  { &hf_itsis_confidence_01 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_TimeIntervalConfidence },
  { &hf_itsis_nextTime      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_TimeMark },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_TimeChangeDetails(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_TimeChangeDetails, TimeChangeDetails_sequence);

  return offset;
}


static const value_string itsis_AdvisorySpeedType_vals[] = {
  {   0, "none" },
  {   1, "greenwave" },
  {   2, "ecoDrive" },
  {   3, "transit" },
  { 0, NULL }
};


static int
dissect_itsis_AdvisorySpeedType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_itsis_SpeedAdvice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 500U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_ZoneLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AdvisorySpeed_sequence[] = {
  { &hf_itsis_type          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_AdvisorySpeedType },
  { &hf_itsis_speed         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SpeedAdvice },
  { &hf_itsis_confidence    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SpeedConfidence },
  { &hf_itsis_distance      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_ZoneLength },
  { &hf_itsis_class         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RestrictionClassID },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_AdvisorySpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_AdvisorySpeed, AdvisorySpeed_sequence);

  return offset;
}


static const per_sequence_t AdvisorySpeedList_sequence_of[1] = {
  { &hf_itsis_AdvisorySpeedList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_AdvisorySpeed },
};

static int
dissect_itsis_AdvisorySpeedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_AdvisorySpeedList, AdvisorySpeedList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t MovementEvent_sequence[] = {
  { &hf_itsis_eventState    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MovementPhaseState },
  { &hf_itsis_timing        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TimeChangeDetails },
  { &hf_itsis_speeds        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_AdvisorySpeedList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_MovementEvent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_MovementEvent, MovementEvent_sequence);

  return offset;
}


static const per_sequence_t MovementEventList_sequence_of[1] = {
  { &hf_itsis_MovementEventList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_MovementEvent },
};

static int
dissect_itsis_MovementEventList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_MovementEventList, MovementEventList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_itsis_WaitOnStopline(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_itsis_PedestrianBicycleDetect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t ConnectionManeuverAssist_sequence[] = {
  { &hf_itsis_connectionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LaneConnectionID },
  { &hf_itsis_queueLength   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_ZoneLength },
  { &hf_itsis_availableStorageLength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_ZoneLength },
  { &hf_itsis_waitOnStop    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_WaitOnStopline },
  { &hf_itsis_pedBicycleDetect, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_PedestrianBicycleDetect },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ConnectionManeuverAssist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ConnectionManeuverAssist, ConnectionManeuverAssist_sequence);

  return offset;
}


static const per_sequence_t ManeuverAssistList_sequence_of[1] = {
  { &hf_itsis_ManeuverAssistList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ConnectionManeuverAssist },
};

static int
dissect_itsis_ManeuverAssistList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_ManeuverAssistList, ManeuverAssistList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t MovementState_sequence[] = {
  { &hf_itsis_movementName  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DescriptiveName },
  { &hf_itsis_signalGroup   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SignalGroupID },
  { &hf_itsis_state_time_speed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MovementEventList },
  { &hf_itsis_maneuverAssistList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_ManeuverAssistList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_MovementState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_MovementState, MovementState_sequence);

  return offset;
}


static const per_sequence_t MovementList_sequence_of[1] = {
  { &hf_itsis_MovementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_MovementState },
};

static int
dissect_itsis_MovementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_MovementList, MovementList_sequence_of,
                                                  1, 255, FALSE);

  return offset;
}


static const per_sequence_t IntersectionState_sequence[] = {
  { &hf_itsis_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DescriptiveName },
  { &hf_itsis_id            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionReferenceID },
  { &hf_itsis_revision      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MsgCount },
  { &hf_itsis_status_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionStatusObject },
  { &hf_itsis_moy           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MinuteOfTheYear },
  { &hf_itsis_timeStamp_01  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DSecond },
  { &hf_itsis_enabledLanes  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_EnabledLaneList },
  { &hf_itsis_states        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MovementList },
  { &hf_itsis_maneuverAssistList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_ManeuverAssistList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_IntersectionState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_IntersectionState, IntersectionState_sequence);

  return offset;
}


static const per_sequence_t IntersectionStateList_sequence_of[1] = {
  { &hf_itsis_IntersectionStateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionState },
};

static int
dissect_itsis_IntersectionStateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_IntersectionStateList, IntersectionStateList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t SPAT_sequence[] = {
  { &hf_itsis_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MinuteOfTheYear },
  { &hf_itsis_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DescriptiveName },
  { &hf_itsis_intersections , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionStateList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SPAT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 56 "./asn1/itsis/itsis.cnf"
  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (ETSI TS 103301)");

    offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SPAT, SPAT_sequence);




  return offset;
}


static const per_sequence_t SPATEM_sequence[] = {
  { &hf_itsis_header        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ItsPduHeader },
  { &hf_itsis_spat          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SPAT },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SPATEM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SPATEM, SPATEM_sequence);

  return offset;
}



static int
dissect_itsis_RequestID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_PriorityRequestType_vals[] = {
  {   0, "priorityRequestTypeReserved" },
  {   1, "priorityRequest" },
  {   2, "priorityRequestUpdate" },
  {   3, "priorityCancellation" },
  { 0, NULL }
};


static int
dissect_itsis_PriorityRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string itsis_IntersectionAccessPoint_vals[] = {
  {   0, "lane" },
  {   1, "approach" },
  {   2, "connection" },
  { 0, NULL }
};

static const per_choice_t IntersectionAccessPoint_choice[] = {
  {   0, &hf_itsis_lane          , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneID },
  {   1, &hf_itsis_approach      , ASN1_EXTENSION_ROOT    , dissect_itsis_ApproachID },
  {   2, &hf_itsis_connection    , ASN1_EXTENSION_ROOT    , dissect_itsis_LaneConnectionID },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_IntersectionAccessPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_IntersectionAccessPoint, IntersectionAccessPoint_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SignalRequest_sequence[] = {
  { &hf_itsis_id            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionReferenceID },
  { &hf_itsis_requestID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_RequestID },
  { &hf_itsis_requestType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_PriorityRequestType },
  { &hf_itsis_inBoundLane   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionAccessPoint },
  { &hf_itsis_outBoundLane  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IntersectionAccessPoint },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalRequest, SignalRequest_sequence);

  return offset;
}


static const per_sequence_t SignalRequestPackage_sequence[] = {
  { &hf_itsis_request_02    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SignalRequest },
  { &hf_itsis_minute        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MinuteOfTheYear },
  { &hf_itsis_second        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DSecond },
  { &hf_itsis_duration      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DSecond },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalRequestPackage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalRequestPackage, SignalRequestPackage_sequence);

  return offset;
}


static const per_sequence_t SignalRequestList_sequence_of[1] = {
  { &hf_itsis_SignalRequestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SignalRequestPackage },
};

static int
dissect_itsis_SignalRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SignalRequestList, SignalRequestList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}



static int
dissect_itsis_TemporaryID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const value_string itsis_VehicleID_vals[] = {
  {   0, "entityID" },
  {   1, "stationID" },
  { 0, NULL }
};

static const per_choice_t VehicleID_choice[] = {
  {   0, &hf_itsis_entityID      , ASN1_NO_EXTENSIONS     , dissect_itsis_TemporaryID },
  {   1, &hf_itsis_stationID     , ASN1_NO_EXTENSIONS     , dissect_itsis_StationID },
  { 0, NULL, 0, NULL }
};

static int
dissect_itsis_VehicleID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_itsis_VehicleID, VehicleID_choice,
                                 NULL);

  return offset;
}


static const value_string itsis_BasicVehicleRole_vals[] = {
  {   0, "basicVehicle" },
  {   1, "publicTransport" },
  {   2, "specialTransport" },
  {   3, "dangerousGoods" },
  {   4, "roadWork" },
  {   5, "roadRescue" },
  {   6, "emergency" },
  {   7, "safetyCar" },
  {   8, "none-unknown" },
  {   9, "truck" },
  {  10, "motorcycle" },
  {  11, "roadSideSource" },
  {  12, "police" },
  {  13, "fire" },
  {  14, "ambulance" },
  {  15, "dot" },
  {  16, "transit" },
  {  17, "slowMoving" },
  {  18, "stopNgo" },
  {  19, "cyclist" },
  {  20, "pedestrian" },
  {  21, "nonMotorized" },
  {  22, "military" },
  { 0, NULL }
};


static int
dissect_itsis_BasicVehicleRole(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     23, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string itsis_RequestSubRole_vals[] = {
  {   0, "requestSubRoleUnKnown" },
  {   1, "requestSubRole1" },
  {   2, "requestSubRole2" },
  {   3, "requestSubRole3" },
  {   4, "requestSubRole4" },
  {   5, "requestSubRole5" },
  {   6, "requestSubRole6" },
  {   7, "requestSubRole7" },
  {   8, "requestSubRole8" },
  {   9, "requestSubRole9" },
  {  10, "requestSubRole10" },
  {  11, "requestSubRole11" },
  {  12, "requestSubRole12" },
  {  13, "requestSubRole13" },
  {  14, "requestSubRole14" },
  {  15, "requestSubRoleReserved" },
  { 0, NULL }
};


static int
dissect_itsis_RequestSubRole(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_RequestImportanceLevel_vals[] = {
  {   0, "requestImportanceLevelUnKnown" },
  {   1, "requestImportanceLevel1" },
  {   2, "requestImportanceLevel2" },
  {   3, "requestImportanceLevel3" },
  {   4, "requestImportanceLevel4" },
  {   5, "requestImportanceLevel5" },
  {   6, "requestImportanceLevel6" },
  {   7, "requestImportanceLevel7" },
  {   8, "requestImportanceLevel8" },
  {   9, "requestImportanceLevel9" },
  {  10, "requestImportanceLevel10" },
  {  11, "requestImportanceLevel11" },
  {  12, "requestImportanceLevel12" },
  {  13, "requestImportanceLevel13" },
  {  14, "requestImportanceLevel14" },
  {  15, "requestImportanceReserved" },
  { 0, NULL }
};


static int
dissect_itsis_RequestImportanceLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_VehicleType_vals[] = {
  {   0, "none" },
  {   1, "unknown" },
  {   2, "special" },
  {   3, "moto" },
  {   4, "car" },
  {   5, "carOther" },
  {   6, "bus" },
  {   7, "axleCnt2" },
  {   8, "axleCnt3" },
  {   9, "axleCnt4" },
  {  10, "axleCnt4Trailer" },
  {  11, "axleCnt5Trailer" },
  {  12, "axleCnt6Trailer" },
  {  13, "axleCnt5MultiTrailer" },
  {  14, "axleCnt6MultiTrailer" },
  {  15, "axleCnt7MultiTrailer" },
  { 0, NULL }
};


static int
dissect_itsis_VehicleType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t RequestorType_sequence[] = {
  { &hf_itsis_role          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_BasicVehicleRole },
  { &hf_itsis_subrole       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RequestSubRole },
  { &hf_itsis_request       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RequestImportanceLevel },
  { &hf_itsis_iso3883       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Iso3833VehicleType },
  { &hf_itsis_hpmsType      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_VehicleType },
  { &hf_itsis_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RequestorType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RequestorType, RequestorType_sequence);

  return offset;
}


static const value_string itsis_TransmissionState_vals[] = {
  {   0, "neutral" },
  {   1, "park" },
  {   2, "forwardGears" },
  {   3, "reverseGears" },
  {   4, "reserved1" },
  {   5, "reserved2" },
  {   6, "reserved3" },
  {   7, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_TransmissionState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t TransmissionAndSpeed_sequence[] = {
  { &hf_itsis_transmisson   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_TransmissionState },
  { &hf_itsis_speed_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_TransmissionAndSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_TransmissionAndSpeed, TransmissionAndSpeed_sequence);

  return offset;
}


static const per_sequence_t RequestorPositionVector_sequence[] = {
  { &hf_itsis_position_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Position3D },
  { &hf_itsis_heading       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_Angle },
  { &hf_itsis_speed_02      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TransmissionAndSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RequestorPositionVector(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RequestorPositionVector, RequestorPositionVector_sequence);

  return offset;
}



static int
dissect_itsis_TransitVehicleStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}


static const value_string itsis_TransitVehicleOccupancy_vals[] = {
  {   0, "occupancyUnknown" },
  {   1, "occupancyEmpty" },
  {   2, "occupancyVeryLow" },
  {   3, "occupancyLow" },
  {   4, "occupancyMed" },
  {   5, "occupancyHigh" },
  {   6, "occupancyNearlyFull" },
  {   7, "occupancyFull" },
  { 0, NULL }
};


static int
dissect_itsis_TransitVehicleOccupancy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_itsis_DeltaTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -122, 121U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RequestorDescription_sequence[] = {
  { &hf_itsis_id_02         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_VehicleID },
  { &hf_itsis_type_02       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RequestorType },
  { &hf_itsis_position      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RequestorPositionVector },
  { &hf_itsis_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DescriptiveName },
  { &hf_itsis_routeName     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DescriptiveName },
  { &hf_itsis_transitStatus , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TransitVehicleStatus },
  { &hf_itsis_transitOccupancy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TransitVehicleOccupancy },
  { &hf_itsis_transitSchedule, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DeltaTime },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RequestorDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RequestorDescription, RequestorDescription_sequence);

  return offset;
}


static const per_sequence_t SignalRequestMessage_sequence[] = {
  { &hf_itsis_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MinuteOfTheYear },
  { &hf_itsis_second        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_DSecond },
  { &hf_itsis_sequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MsgCount },
  { &hf_itsis_requests      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SignalRequestList },
  { &hf_itsis_requestor     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_RequestorDescription },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalRequestMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 66 "./asn1/itsis/itsis.cnf"
  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (ETSI TS 103301)");

    offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalRequestMessage, SignalRequestMessage_sequence);




  return offset;
}


static const per_sequence_t SREM_sequence[] = {
  { &hf_itsis_header        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ItsPduHeader },
  { &hf_itsis_srm           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SignalRequestMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SREM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SREM, SREM_sequence);

  return offset;
}


static const per_sequence_t SignalRequesterInfo_sequence[] = {
  { &hf_itsis_id_02         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_VehicleID },
  { &hf_itsis_request_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_RequestID },
  { &hf_itsis_sequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MsgCount },
  { &hf_itsis_role          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_BasicVehicleRole },
  { &hf_itsis_typeData      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_RequestorType },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalRequesterInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalRequesterInfo, SignalRequesterInfo_sequence);

  return offset;
}


static const value_string itsis_PrioritizationResponseStatus_vals[] = {
  {   0, "unknown" },
  {   1, "requested" },
  {   2, "processing" },
  {   3, "watchOtherTraffic" },
  {   4, "granted" },
  {   5, "rejected" },
  {   6, "maxPresence" },
  {   7, "reserviceLocked" },
  { 0, NULL }
};


static int
dissect_itsis_PrioritizationResponseStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SignalStatusPackage_sequence[] = {
  { &hf_itsis_requester     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SignalRequesterInfo },
  { &hf_itsis_inboundOn     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionAccessPoint },
  { &hf_itsis_outboundOn    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_IntersectionAccessPoint },
  { &hf_itsis_minute        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MinuteOfTheYear },
  { &hf_itsis_second        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DSecond },
  { &hf_itsis_duration      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DSecond },
  { &hf_itsis_status_02     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_PrioritizationResponseStatus },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalStatusPackage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalStatusPackage, SignalStatusPackage_sequence);

  return offset;
}


static const per_sequence_t SignalStatusPackageList_sequence_of[1] = {
  { &hf_itsis_SignalStatusPackageList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SignalStatusPackage },
};

static int
dissect_itsis_SignalStatusPackageList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SignalStatusPackageList, SignalStatusPackageList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t SignalStatus_sequence[] = {
  { &hf_itsis_sequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_MsgCount },
  { &hf_itsis_id            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_IntersectionReferenceID },
  { &hf_itsis_sigStatus     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SignalStatusPackageList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalStatus, SignalStatus_sequence);

  return offset;
}


static const per_sequence_t SignalStatusList_sequence_of[1] = {
  { &hf_itsis_SignalStatusList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SignalStatus },
};

static int
dissect_itsis_SignalStatusList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SignalStatusList, SignalStatusList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t SignalStatusMessage_sequence[] = {
  { &hf_itsis_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MinuteOfTheYear },
  { &hf_itsis_second        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_DSecond },
  { &hf_itsis_sequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_MsgCount },
  { &hf_itsis_status        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SignalStatusList },
  { &hf_itsis_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalStatusMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 71 "./asn1/itsis/itsis.cnf"
  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (ETSI TS 103301)");

    offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalStatusMessage, SignalStatusMessage_sequence);




  return offset;
}


static const per_sequence_t SSEM_sequence[] = {
  { &hf_itsis_header        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ItsPduHeader },
  { &hf_itsis_ssm           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SignalStatusMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SSEM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SSEM, SSEM_sequence);

  return offset;
}



static int
dissect_itsis_VisibleString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, FALSE);

  return offset;
}



static int
dissect_itsis_BIT_STRING_SIZE_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     9, 9, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t CS5_sequence[] = {
  { &hf_itsis_vin           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VisibleString },
  { &hf_itsis_fill          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_BIT_STRING_SIZE_9 },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_CS5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_CS5, CS5_sequence);

  return offset;
}



static int
dissect_itsis_INTEGER_0_127_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, TRUE);

  return offset;
}


static const per_sequence_t AttributeIdList_sequence_of[1] = {
  { &hf_itsis_AttributeIdList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_127_ },
};

static int
dissect_itsis_AttributeIdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_AttributeIdList, AttributeIdList_sequence_of,
                                                  0, 127, TRUE);

  return offset;
}


static const per_sequence_t Attributes_sequence[] = {
  { &hf_itsis_attributeId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_127_ },
  { &hf_itsis_attributeValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xxx_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Attributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Attributes, Attributes_sequence);

  return offset;
}


static const per_sequence_t AttributeList_sequence_of[1] = {
  { &hf_itsis_AttributeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Attributes },
};

static int
dissect_itsis_AttributeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_AttributeList, AttributeList_sequence_of,
                                                  0, 127, TRUE);

  return offset;
}


static const value_string itsis_TimeReference_vals[] = {
  {   1, "oneMilliSec" },
  { 0, NULL }
};


static int
dissect_itsis_TimeReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VehicleToLanePosition_sequence[] = {
  { &hf_itsis_stationID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_StationID },
  { &hf_itsis_laneID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_LaneID },
  { &hf_itsis_timeReference , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_TimeReference },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VehicleToLanePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VehicleToLanePosition, VehicleToLanePosition_sequence);

  return offset;
}


static const per_sequence_t VehicleToLanePositionList_sequence_of[1] = {
  { &hf_itsis_VehicleToLanePositionList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VehicleToLanePosition },
};

static int
dissect_itsis_VehicleToLanePositionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_VehicleToLanePositionList, VehicleToLanePositionList_sequence_of,
                                                  1, 5, FALSE);

  return offset;
}


static const per_sequence_t ConnectionManeuverAssist_addGrpC_sequence[] = {
  { &hf_itsis_vehicleToLanePositions, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_VehicleToLanePositionList },
  { &hf_itsis_rsuGNSSOffset , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_NodeOffsetPointXY },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ConnectionManeuverAssist_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ConnectionManeuverAssist_addGrpC, ConnectionManeuverAssist_addGrpC_sequence);

  return offset;
}


static const per_sequence_t ConnectionTrajectory_addGrpC_sequence[] = {
  { &hf_itsis_nodes         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_NodeSetXY },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ConnectionTrajectory_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ConnectionTrajectory_addGrpC, ConnectionTrajectory_addGrpC_sequence);

  return offset;
}


static const value_string itsis_PtvRequestType_vals[] = {
  {   0, "preRequest" },
  {   1, "mainRequest" },
  {   2, "doorCloseRequest" },
  {   3, "cancelRequest" },
  {   4, "emergencyRequest" },
  { 0, NULL }
};


static int
dissect_itsis_PtvRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Control_addGrpC_sequence[] = {
  { &hf_itsis_ptvRequest    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_PtvRequestType },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Control_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Control_addGrpC, Control_addGrpC_sequence);

  return offset;
}


static const per_sequence_t PrioritizationResponse_sequence[] = {
  { &hf_itsis_stationed     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_StationID },
  { &hf_itsis_priorState    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_PrioritizationResponseStatus },
  { &hf_itsis_signalGroup   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SignalGroupID },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_PrioritizationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_PrioritizationResponse, PrioritizationResponse_sequence);

  return offset;
}


static const per_sequence_t PrioritizationResponseList_sequence_of[1] = {
  { &hf_itsis_PrioritizationResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_PrioritizationResponse },
};

static int
dissect_itsis_PrioritizationResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_PrioritizationResponseList, PrioritizationResponseList_sequence_of,
                                                  1, 10, FALSE);

  return offset;
}


static const per_sequence_t IntersectionState_addGrpC_sequence[] = {
  { &hf_itsis_activePrioritizations, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_PrioritizationResponseList },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_IntersectionState_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_IntersectionState_addGrpC, IntersectionState_addGrpC_sequence);

  return offset;
}


static const per_sequence_t SignalHeadLocation_sequence[] = {
  { &hf_itsis_nodeXY        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_NodeOffsetPointXY },
  { &hf_itsis_nodeZ         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaAltitude },
  { &hf_itsis_signalGroupID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_SignalGroupID },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalHeadLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalHeadLocation, SignalHeadLocation_sequence);

  return offset;
}


static const per_sequence_t SignalHeadLocationList_sequence_of[1] = {
  { &hf_itsis_SignalHeadLocationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SignalHeadLocation },
};

static int
dissect_itsis_SignalHeadLocationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_SignalHeadLocationList, SignalHeadLocationList_sequence_of,
                                                  1, 64, FALSE);

  return offset;
}


static const per_sequence_t MapData_addGrpC_sequence[] = {
  { &hf_itsis_signalHeadLocations, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_SignalHeadLocationList },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_MapData_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_MapData_addGrpC, MapData_addGrpC_sequence);

  return offset;
}


static const per_sequence_t Position3D_addGrpC_sequence[] = {
  { &hf_itsis_altitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_Altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Position3D_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Position3D_addGrpC, Position3D_addGrpC_sequence);

  return offset;
}


static const value_string itsis_EmissionType_vals[] = {
  {   0, "euro1" },
  {   1, "euro2" },
  {   2, "euro3" },
  {   3, "euro4" },
  {   4, "euro5" },
  {   5, "euro6" },
  { 0, NULL }
};


static int
dissect_itsis_EmissionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t RestrictionUserType_addGrpC_sequence[] = {
  { &hf_itsis_emission      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_EmissionType },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_RestrictionUserType_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_RestrictionUserType_addGrpC, RestrictionUserType_addGrpC_sequence);

  return offset;
}


static const per_sequence_t SignalStatusPackage_addGrpC_sequence[] = {
  { &hf_itsis_synchToSchedule, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_DeltaTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SignalStatusPackage_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SignalStatusPackage_addGrpC, SignalStatusPackage_addGrpC_sequence);

  return offset;
}


static const value_string itsis_DSRCmsgID_vals[] = {
  { mapData, "mapData" },
  { signalPhaseAndTimingMessage, "signalPhaseAndTimingMessage" },
  { signalRequestMessage, "signalRequestMessage" },
  { signalStatusMessage, "signalStatusMessage" },
  { 0, NULL }
};


static int
dissect_itsis_DSRCmsgID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

#line 35 "./asn1/itsis/itsis.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(Ref_DSRCmsgID, VALS(itsis_DSRCmsgID_vals), "unknown (%d)"));
  }

  return offset;
}



static int
dissect_itsis_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_messageframe_pdu_type);

  return offset;
}


static const per_sequence_t MessageFrame_sequence[] = {
  { &hf_itsis_messageId     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_DSRCmsgID },
  { &hf_itsis_value_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_MessageFrame(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_MessageFrame, MessageFrame_sequence);

  return offset;
}


static const per_sequence_t IVI_sequence[] = {
  { &hf_itsis_header        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ItsPduHeader },
  { &hf_itsis_ivi           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_IviStructure },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_IVI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_IVI, IVI_sequence);

  return offset;
}


static const value_string itsis_PathDeltaTime_vals[] = {
  {   1, "tenMilliSecondsInPast" },
  { 0, NULL }
};


static int
dissect_itsis_PathDeltaTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PathPoint_sequence[] = {
  { &hf_itsis_pathPosition  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaReferencePosition },
  { &hf_itsis_pathDeltaTime , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_PathDeltaTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_PathPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_PathPoint, PathPoint_sequence);

  return offset;
}


static const value_string itsis_PtActivationType_vals[] = {
  {   0, "undefinedCodingType" },
  {   1, "r09-16CodingType" },
  {   2, "vdv-50149CodingType" },
  { 0, NULL }
};


static int
dissect_itsis_PtActivationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_PtActivationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}


static const per_sequence_t PtActivation_sequence[] = {
  { &hf_itsis_ptActivationType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_PtActivationType },
  { &hf_itsis_ptActivationData, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_PtActivationData },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_PtActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_PtActivation, PtActivation_sequence);

  return offset;
}



static int
dissect_itsis_AccelerationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, NULL);

  return offset;
}


static const value_string itsis_CauseCodeType_vals[] = {
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
dissect_itsis_CauseCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_SubCauseCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CauseCode_sequence[] = {
  { &hf_itsis_causeCode     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_CauseCodeType },
  { &hf_itsis_subCauseCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SubCauseCodeType },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_CauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_CauseCode, CauseCode_sequence);

  return offset;
}


static const value_string itsis_TrafficConditionSubCauseCode_vals[] = {
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
dissect_itsis_TrafficConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_AccidentSubCauseCode_vals[] = {
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
dissect_itsis_AccidentSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_RoadworksSubCauseCode_vals[] = {
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
dissect_itsis_RoadworksSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_HumanPresenceOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "childrenOnRoadway" },
  {   2, "cyclistOnRoadway" },
  {   3, "motorcyclistOnRoadway" },
  { 0, NULL }
};


static int
dissect_itsis_HumanPresenceOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_WrongWayDrivingSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "wrongLane" },
  {   2, "wrongDirection" },
  { 0, NULL }
};


static int
dissect_itsis_WrongWayDrivingSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_AdverseWeatherCondition_ExtremeWeatherConditionSubCauseCode_vals[] = {
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
dissect_itsis_AdverseWeatherCondition_ExtremeWeatherConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_AdverseWeatherCondition_AdhesionSubCauseCode_vals[] = {
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
dissect_itsis_AdverseWeatherCondition_AdhesionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_AdverseWeatherCondition_VisibilitySubCauseCode_vals[] = {
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
dissect_itsis_AdverseWeatherCondition_VisibilitySubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_AdverseWeatherCondition_PrecipitationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "heavyRain" },
  {   2, "heavySnowfall" },
  {   3, "softHail" },
  { 0, NULL }
};


static int
dissect_itsis_AdverseWeatherCondition_PrecipitationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_SlowVehicleSubCauseCode_vals[] = {
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
dissect_itsis_SlowVehicleSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_StationaryVehicleSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "humanProblem" },
  {   2, "vehicleBreakdown" },
  {   3, "postCrash" },
  {   4, "publicTransportStop" },
  {   5, "carryingDangerousGoods" },
  { 0, NULL }
};


static int
dissect_itsis_StationaryVehicleSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_HumanProblemSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "glycemiaProblem" },
  {   2, "heartProblem" },
  { 0, NULL }
};


static int
dissect_itsis_HumanProblemSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_EmergencyVehicleApproachingSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyVehicleApproaching" },
  {   2, "prioritizedVehicleApproaching" },
  { 0, NULL }
};


static int
dissect_itsis_EmergencyVehicleApproachingSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_HazardousLocation_DangerousCurveSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "dangerousLeftTurnCurve" },
  {   2, "dangerousRightTurnCurve" },
  {   3, "multipleCurvesStartingWithUnknownTurningDirection" },
  {   4, "multipleCurvesStartingWithLeftTurn" },
  {   5, "multipleCurvesStartingWithRightTurn" },
  { 0, NULL }
};


static int
dissect_itsis_HazardousLocation_DangerousCurveSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_HazardousLocation_SurfaceConditionSubCauseCode_vals[] = {
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
dissect_itsis_HazardousLocation_SurfaceConditionSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_HazardousLocation_ObstacleOnTheRoadSubCauseCode_vals[] = {
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
dissect_itsis_HazardousLocation_ObstacleOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_HazardousLocation_AnimalOnTheRoadSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "wildAnimals" },
  {   2, "herdOfAnimals" },
  {   3, "smallAnimals" },
  {   4, "largeAnimals" },
  { 0, NULL }
};


static int
dissect_itsis_HazardousLocation_AnimalOnTheRoadSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_CollisionRiskSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "longitudinalCollisionRisk" },
  {   2, "crossingCollisionRisk" },
  {   3, "lateralCollisionRisk" },
  {   4, "vulnerableRoadUser" },
  { 0, NULL }
};


static int
dissect_itsis_CollisionRiskSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_SignalViolationSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "stopSignViolation" },
  {   2, "trafficLightViolation" },
  {   3, "turningRegulationViolation" },
  { 0, NULL }
};


static int
dissect_itsis_SignalViolationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_RescueAndRecoveryWorkInProgressSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "emergencyVehicles" },
  {   2, "rescueHelicopterLanding" },
  {   3, "policeActivityOngoing" },
  {   4, "medicalEmergencyOngoing" },
  {   5, "childAbductionInProgress" },
  { 0, NULL }
};


static int
dissect_itsis_RescueAndRecoveryWorkInProgressSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_DangerousEndOfQueueSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "suddenEndOfQueue" },
  {   2, "queueOverHill" },
  {   3, "queueAroundBend" },
  {   4, "queueInTunnel" },
  { 0, NULL }
};


static int
dissect_itsis_DangerousEndOfQueueSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_DangerousSituationSubCauseCode_vals[] = {
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
dissect_itsis_DangerousSituationSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_VehicleBreakdownSubCauseCode_vals[] = {
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
dissect_itsis_VehicleBreakdownSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_PostCrashSubCauseCode_vals[] = {
  {   0, "unavailable" },
  {   1, "accidentWithoutECallTriggered" },
  {   2, "accidentWithECallManuallyTriggered" },
  {   3, "accidentWithECallAutomaticallyTriggered" },
  {   4, "accidentWithECallTriggeredWithoutAccessToCellularNetwork" },
  { 0, NULL }
};


static int
dissect_itsis_PostCrashSubCauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_CurvatureValue_vals[] = {
  {   0, "straight" },
  { -30000, "reciprocalOf1MeterRadiusToRight" },
  { 30000, "reciprocalOf1MeterRadiusToLeft" },
  { 30001, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_CurvatureValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30000, 30001U, NULL, FALSE);

  return offset;
}


static const value_string itsis_CurvatureConfidence_vals[] = {
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
dissect_itsis_CurvatureConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Curvature_sequence[] = {
  { &hf_itsis_curvatureValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_CurvatureValue },
  { &hf_itsis_curvatureConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_CurvatureConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_Curvature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_Curvature, Curvature_sequence);

  return offset;
}


static const value_string itsis_CurvatureCalculationMode_vals[] = {
  {   0, "yawRateUsed" },
  {   1, "yawRateNotUsed" },
  {   2, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_CurvatureCalculationMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string itsis_HardShoulderStatus_vals[] = {
  {   0, "availableForStopping" },
  {   1, "closed" },
  {   2, "availableForDriving" },
  { 0, NULL }
};


static int
dissect_itsis_HardShoulderStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_itsis_DrivingLaneStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 15, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t ClosedLanes_sequence[] = {
  { &hf_itsis_hardShoulderStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_HardShoulderStatus },
  { &hf_itsis_drivingLaneStatus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_itsis_DrivingLaneStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ClosedLanes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ClosedLanes, ClosedLanes_sequence);

  return offset;
}


static const value_string itsis_PerformanceClass_vals[] = {
  {   0, "unavailable" },
  {   1, "performanceClassA" },
  {   2, "performanceClassB" },
  { 0, NULL }
};


static int
dissect_itsis_PerformanceClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string itsis_VehicleMass_vals[] = {
  {   1, "hundredKg" },
  { 1024, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_VehicleMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, FALSE);

  return offset;
}


static const value_string itsis_DriveDirection_vals[] = {
  {   0, "forward" },
  {   1, "backward" },
  {   2, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_DriveDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_itsis_EmbarkationStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string itsis_LongitudinalAccelerationValue_vals[] = {
  {   1, "pointOneMeterPerSecSquaredForward" },
  {  -1, "pointOneMeterPerSecSquaredBackward" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_LongitudinalAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const value_string itsis_AccelerationConfidence_vals[] = {
  {   1, "pointOneMeterPerSecSquared" },
  { 101, "outOfRange" },
  { 102, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_AccelerationConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 102U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LongitudinalAcceleration_sequence[] = {
  { &hf_itsis_longitudinalAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LongitudinalAccelerationValue },
  { &hf_itsis_longitudinalAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_LongitudinalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_LongitudinalAcceleration, LongitudinalAcceleration_sequence);

  return offset;
}


static const value_string itsis_LateralAccelerationValue_vals[] = {
  {  -1, "pointOneMeterPerSecSquaredToRight" },
  {   1, "pointOneMeterPerSecSquaredToLeft" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_LateralAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LateralAcceleration_sequence[] = {
  { &hf_itsis_lateralAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_LateralAccelerationValue },
  { &hf_itsis_lateralAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_LateralAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_LateralAcceleration, LateralAcceleration_sequence);

  return offset;
}


static const value_string itsis_VerticalAccelerationValue_vals[] = {
  {   1, "pointOneMeterPerSecSquaredUp" },
  {  -1, "pointOneMeterPerSecSquaredDown" },
  { 161, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_VerticalAccelerationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -160, 161U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VerticalAcceleration_sequence[] = {
  { &hf_itsis_verticalAccelerationValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VerticalAccelerationValue },
  { &hf_itsis_verticalAccelerationConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_AccelerationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VerticalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VerticalAcceleration, VerticalAcceleration_sequence);

  return offset;
}



static int
dissect_itsis_ExteriorLights(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_itsis_INTEGER_0_9999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9999U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_itsis_IA5String_SIZE_1_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 24, FALSE);

  return offset;
}



static int
dissect_itsis_T_companyName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 29 "./asn1/itsis/itsis.cnf"
  offset=dissect_per_octet_string(tvb, offset, actx, tree, hf_index, NO_BOUND, NO_BOUND, FALSE, NULL);


  return offset;
}


static const per_sequence_t DangerousGoodsExtended_sequence[] = {
  { &hf_itsis_dangerousGoodsType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DangerousGoodsBasic },
  { &hf_itsis_unNumber      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_INTEGER_0_9999 },
  { &hf_itsis_elevatedTemperature, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_BOOLEAN },
  { &hf_itsis_tunnelsRestricted, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_BOOLEAN },
  { &hf_itsis_limitedQuantity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_BOOLEAN },
  { &hf_itsis_emergencyActionCode, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_IA5String_SIZE_1_24 },
  { &hf_itsis_phoneNumber   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_IA5String_SIZE_1_24 },
  { &hf_itsis_companyName   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_T_companyName },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_DangerousGoodsExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_DangerousGoodsExtended, DangerousGoodsExtended_sequence);

  return offset;
}



static int
dissect_itsis_LightBarSirenInUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string itsis_HeightLonCarr_vals[] = {
  {   1, "oneCentimeter" },
  { 100, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_HeightLonCarr(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, FALSE);

  return offset;
}


static const value_string itsis_PosLonCarr_vals[] = {
  {   1, "oneCentimeter" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_PosLonCarr(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string itsis_PosPillar_vals[] = {
  {   1, "tenCentimeters" },
  {  30, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_PosPillar(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 30U, NULL, FALSE);

  return offset;
}


static const value_string itsis_PosCentMass_vals[] = {
  {   1, "tenCentimeters" },
  {  63, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_PosCentMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 63U, NULL, FALSE);

  return offset;
}


static const value_string itsis_RequestResponseIndication_vals[] = {
  {   0, "request" },
  {   1, "response" },
  { 0, NULL }
};


static int
dissect_itsis_RequestResponseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_SpeedLimit_vals[] = {
  {   1, "oneKmPerHour" },
  { 0, NULL }
};


static int
dissect_itsis_SpeedLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_StationarySince_vals[] = {
  {   0, "lessThan1Minute" },
  {   1, "lessThan2Minutes" },
  {   2, "lessThan15Minutes" },
  {   3, "equalOrGreater15Minutes" },
  { 0, NULL }
};


static int
dissect_itsis_StationarySince(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_Temperature_vals[] = {
  { -60, "equalOrSmallerThanMinus60Deg" },
  {   1, "oneDegreeCelsius" },
  {  67, "equalOrGreaterThan67Deg" },
  { 0, NULL }
};


static int
dissect_itsis_Temperature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -60, 67U, NULL, FALSE);

  return offset;
}


static const value_string itsis_TrafficRule_vals[] = {
  {   0, "noPassing" },
  {   1, "noPassingForTrucks" },
  {   2, "passToRight" },
  {   3, "passToLeft" },
  { 0, NULL }
};


static int
dissect_itsis_TrafficRule(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string itsis_WheelBaseVehicle_vals[] = {
  {   1, "tenCentimeters" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_WheelBaseVehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const value_string itsis_TurningRadius_vals[] = {
  {   1, "point4Meters" },
  { 255, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_TurningRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string itsis_PosFrontAx_vals[] = {
  {   1, "tenCentimeters" },
  {  20, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_PosFrontAx(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 20U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_PositionOfOccupants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, NULL);

  return offset;
}


static const value_string itsis_PositioningSolutionType_vals[] = {
  {   0, "noPositioningSolution" },
  {   1, "sGNSS" },
  {   2, "dGNSS" },
  {   3, "sGNSSplusDR" },
  {   4, "dGNSSplusDR" },
  {   5, "dR" },
  { 0, NULL }
};


static int
dissect_itsis_PositioningSolutionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_itsis_WMInumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 3, FALSE);

  return offset;
}



static int
dissect_itsis_VDS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          6, 6, FALSE);

  return offset;
}


static const per_sequence_t VehicleIdentification_sequence[] = {
  { &hf_itsis_wMInumber     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_WMInumber },
  { &hf_itsis_vDS           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_itsis_VDS },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VehicleIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VehicleIdentification, VehicleIdentification_sequence);

  return offset;
}



static int
dissect_itsis_EnergyStorageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, NULL);

  return offset;
}


static const value_string itsis_VehicleLengthValue_vals[] = {
  {   1, "tenCentimeters" },
  { 1022, "outOfRange" },
  { 1023, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_VehicleLengthValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1023U, NULL, FALSE);

  return offset;
}


static const value_string itsis_VehicleLengthConfidenceIndication_vals[] = {
  {   0, "noTrailerPresent" },
  {   1, "trailerPresentWithKnownLength" },
  {   2, "trailerPresentWithUnknownLength" },
  {   3, "trailerPresenceIsUnknown" },
  {   4, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_VehicleLengthConfidenceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t VehicleLength_sequence[] = {
  { &hf_itsis_vehicleLengthValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VehicleLengthValue },
  { &hf_itsis_vehicleLengthConfidenceIndication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_VehicleLengthConfidenceIndication },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_VehicleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_VehicleLength, VehicleLength_sequence);

  return offset;
}


static const value_string itsis_VehicleWidth_vals[] = {
  {   1, "tenCentimeters" },
  {  61, "outOfRange" },
  {  62, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_VehicleWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 62U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PathHistory_sequence_of[1] = {
  { &hf_itsis_PathHistory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_PathPoint },
};

static int
dissect_itsis_PathHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_PathHistory, PathHistory_sequence_of,
                                                  0, 40, FALSE);

  return offset;
}



static int
dissect_itsis_EmergencyPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string itsis_InformationQuality_vals[] = {
  {   0, "unavailable" },
  {   1, "lowest" },
  {   7, "highest" },
  { 0, NULL }
};


static int
dissect_itsis_InformationQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string itsis_SteeringWheelAngleValue_vals[] = {
  {   0, "straight" },
  {  -1, "onePointFiveDegreesToRight" },
  {   1, "onePointFiveDegreesToLeft" },
  { 512, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_SteeringWheelAngleValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -511, 512U, NULL, FALSE);

  return offset;
}


static const value_string itsis_SteeringWheelAngleConfidence_vals[] = {
  {   1, "equalOrWithinOnePointFiveDegree" },
  { 126, "outOfRange" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_SteeringWheelAngleConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SteeringWheelAngle_sequence[] = {
  { &hf_itsis_steeringWheelAngleValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SteeringWheelAngleValue },
  { &hf_itsis_steeringWheelAngleConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SteeringWheelAngleConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_SteeringWheelAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_SteeringWheelAngle, SteeringWheelAngle_sequence);

  return offset;
}


static const value_string itsis_YawRateValue_vals[] = {
  {   0, "straight" },
  {  -1, "degSec-000-01ToRight" },
  {   1, "degSec-000-01ToLeft" },
  { 32767, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_YawRateValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32766, 32767U, NULL, FALSE);

  return offset;
}


static const value_string itsis_YawRateConfidence_vals[] = {
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
dissect_itsis_YawRateConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t YawRate_sequence[] = {
  { &hf_itsis_yawRateValue  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_YawRateValue },
  { &hf_itsis_yawRateConfidence, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_YawRateConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_YawRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_YawRate, YawRate_sequence);

  return offset;
}


static const value_string itsis_ProtectedZoneType_vals[] = {
  {   0, "permanentCenDsrcTolling" },
  {   1, "temporaryCenDsrcTolling" },
  { 0, NULL }
};


static int
dissect_itsis_ProtectedZoneType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}


static const value_string itsis_RelevanceDistance_vals[] = {
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
dissect_itsis_RelevanceDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_RelevanceTrafficDirection_vals[] = {
  {   0, "allTrafficDirections" },
  {   1, "upstreamTraffic" },
  {   2, "downstreamTraffic" },
  {   3, "oppositeTraffic" },
  { 0, NULL }
};


static int
dissect_itsis_RelevanceTrafficDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string itsis_TransmissionInterval_vals[] = {
  {   1, "oneMilliSecond" },
  { 10000, "tenSeconds" },
  { 0, NULL }
};


static int
dissect_itsis_TransmissionInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 10000U, NULL, FALSE);

  return offset;
}


static const value_string itsis_ValidityDuration_vals[] = {
  {   0, "timeOfDetection" },
  {   1, "oneSecondAfterDetection" },
  { 0, NULL }
};


static int
dissect_itsis_ValidityDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86400U, NULL, FALSE);

  return offset;
}



static int
dissect_itsis_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ActionID_sequence[] = {
  { &hf_itsis_originatingStationID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_StationID },
  { &hf_itsis_sequenceNumber_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_SequenceNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ActionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ActionID, ActionID_sequence);

  return offset;
}


static const per_sequence_t ItineraryPath_sequence_of[1] = {
  { &hf_itsis_ItineraryPath_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ReferencePosition },
};

static int
dissect_itsis_ItineraryPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_ItineraryPath, ItineraryPath_sequence_of,
                                                  1, 40, FALSE);

  return offset;
}


static const value_string itsis_ProtectedZoneRadius_vals[] = {
  {   1, "oneMeter" },
  { 0, NULL }
};


static int
dissect_itsis_ProtectedZoneRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_itsis_ProtectedZoneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 134217727U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ProtectedCommunicationZone_sequence[] = {
  { &hf_itsis_protectedZoneType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ProtectedZoneType },
  { &hf_itsis_expiryTime    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_TimestampIts },
  { &hf_itsis_protectedZoneLatitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Latitude },
  { &hf_itsis_protectedZoneLongitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Longitude },
  { &hf_itsis_protectedZoneRadius, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_ProtectedZoneRadius },
  { &hf_itsis_protectedZoneID, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_ProtectedZoneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_ProtectedCommunicationZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_ProtectedCommunicationZone, ProtectedCommunicationZone_sequence);

  return offset;
}


static const per_sequence_t Traces_sequence_of[1] = {
  { &hf_itsis_Traces_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_PathHistory },
};

static int
dissect_itsis_Traces(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_Traces, Traces_sequence_of,
                                                  1, 7, FALSE);

  return offset;
}


static const value_string itsis_NumberOfOccupants_vals[] = {
  {   1, "oneOccupant" },
  { 127, "unavailable" },
  { 0, NULL }
};


static int
dissect_itsis_NumberOfOccupants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PositionOfPillars_sequence_of[1] = {
  { &hf_itsis_PositionOfPillars_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_PosPillar },
};

static int
dissect_itsis_PositionOfPillars(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_PositionOfPillars, PositionOfPillars_sequence_of,
                                                  1, 3, TRUE);

  return offset;
}


static const per_sequence_t RestrictedTypes_sequence_of[1] = {
  { &hf_itsis_RestrictedTypes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_StationType },
};

static int
dissect_itsis_RestrictedTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_RestrictedTypes, RestrictedTypes_sequence_of,
                                                  1, 3, TRUE);

  return offset;
}


static const per_sequence_t EventPoint_sequence[] = {
  { &hf_itsis_eventPosition , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_DeltaReferencePosition },
  { &hf_itsis_eventDeltaTime, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_PathDeltaTime },
  { &hf_itsis_informationQuality, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_InformationQuality },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_EventPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_EventPoint, EventPoint_sequence);

  return offset;
}


static const per_sequence_t EventHistory_sequence_of[1] = {
  { &hf_itsis_EventHistory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_EventPoint },
};

static int
dissect_itsis_EventHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_EventHistory, EventHistory_sequence_of,
                                                  1, 23, FALSE);

  return offset;
}


static const per_sequence_t ProtectedCommunicationZonesRSU_sequence_of[1] = {
  { &hf_itsis_ProtectedCommunicationZonesRSU_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_ProtectedCommunicationZone },
};

static int
dissect_itsis_ProtectedCommunicationZonesRSU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_itsis_ProtectedCommunicationZonesRSU, ProtectedCommunicationZonesRSU_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_itsis_CenDsrcTollingZoneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_itsis_ProtectedZoneID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CenDsrcTollingZone_sequence[] = {
  { &hf_itsis_protectedZoneLatitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Latitude },
  { &hf_itsis_protectedZoneLongitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_itsis_Longitude },
  { &hf_itsis_cenDsrcTollingZoneID, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_itsis_CenDsrcTollingZoneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_itsis_CenDsrcTollingZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_itsis_CenDsrcTollingZone, CenDsrcTollingZone_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_IVIM_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_itsis_IVIM(tvb, offset, &asn1_ctx, tree, hf_itsis_IVIM_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MAPEM_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_itsis_MAPEM(tvb, offset, &asn1_ctx, tree, hf_itsis_MAPEM_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SPATEM_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_itsis_SPATEM(tvb, offset, &asn1_ctx, tree, hf_itsis_SPATEM_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SREM_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_itsis_SREM(tvb, offset, &asn1_ctx, tree, hf_itsis_SREM_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SSEM_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_itsis_SSEM(tvb, offset, &asn1_ctx, tree, hf_itsis_SSEM_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-itsis-fn.c ---*/
#line 92 "./asn1/itsis/packet-itsis-template.c"

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


/*--- Included file: packet-itsis-hfarr.c ---*/
#line 1 "./asn1/itsis/packet-itsis-hfarr.c"
    { &hf_itsis_IVIM_PDU,
      { "IVIM", "itsis.IVIM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_MAPEM_PDU,
      { "MAPEM", "itsis.MAPEM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_SPATEM_PDU,
      { "SPATEM", "itsis.SPATEM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_SREM_PDU,
      { "SREM", "itsis.SREM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_SSEM_PDU,
      { "SSEM", "itsis.SSEM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_header,
      { "header", "itsis.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ItsPduHeader", HFILL }},
    { &hf_itsis_ivi,
      { "ivi", "itsis.ivi_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IviStructure", HFILL }},
    { &hf_itsis_map,
      { "map", "itsis.map_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MapData", HFILL }},
    { &hf_itsis_spat,
      { "spat", "itsis.spat_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_srm,
      { "srm", "itsis.srm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalRequestMessage", HFILL }},
    { &hf_itsis_ssm,
      { "ssm", "itsis.ssm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalStatusMessage", HFILL }},
    { &hf_itsis_vin,
      { "vin", "itsis.vin",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_itsis_fill,
      { "fill", "itsis.fill",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_9", HFILL }},
    { &hf_itsis_maxLadenweightOnAxle1,
      { "maxLadenweightOnAxle1", "itsis.maxLadenweightOnAxle1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_maxLadenweightOnAxle2,
      { "maxLadenweightOnAxle2", "itsis.maxLadenweightOnAxle2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_maxLadenweightOnAxle3,
      { "maxLadenweightOnAxle3", "itsis.maxLadenweightOnAxle3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_maxLadenweightOnAxle4,
      { "maxLadenweightOnAxle4", "itsis.maxLadenweightOnAxle4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_maxLadenweightOnAxle5,
      { "maxLadenweightOnAxle5", "itsis.maxLadenweightOnAxle5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_particulate,
      { "particulate", "itsis.particulate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_unitType,
      { "unitType", "itsis.unitType",
        FT_UINT32, BASE_DEC, VALS(itsis_UnitType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_value,
      { "value", "itsis.value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_itsis_absorptionCoeff,
      { "absorptionCoeff", "itsis.absorptionCoeff",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_euroValue,
      { "euroValue", "itsis.euroValue",
        FT_UINT32, BASE_DEC, VALS(itsis_EuroValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_copValue,
      { "copValue", "itsis.copValue",
        FT_UINT32, BASE_DEC, VALS(itsis_CopValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_emissionCO,
      { "emissionCO", "itsis.emissionCO",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_itsis_emissionHC,
      { "emissionHC", "itsis.emissionHC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_emissionNOX,
      { "emissionNOX", "itsis.emissionNOX",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_emissionHCNOX,
      { "emissionHCNOX", "itsis.emissionHCNOX",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_numberOfSeats,
      { "numberOfSeats", "itsis.numberOfSeats",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int1", HFILL }},
    { &hf_itsis_numberOfStandingPlaces,
      { "numberOfStandingPlaces", "itsis.numberOfStandingPlaces",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int1", HFILL }},
    { &hf_itsis_countryCode,
      { "countryCode", "itsis.countryCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_providerIdentifier,
      { "providerIdentifier", "itsis.providerIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IssuerIdentifier", HFILL }},
    { &hf_itsis_soundstationary,
      { "soundstationary", "itsis.soundstationary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int1", HFILL }},
    { &hf_itsis_sounddriveby,
      { "sounddriveby", "itsis.sounddriveby",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int1", HFILL }},
    { &hf_itsis_vehicleLengthOverall,
      { "vehicleLengthOverall", "itsis.vehicleLengthOverall",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int1", HFILL }},
    { &hf_itsis_vehicleHeigthOverall,
      { "vehicleHeigthOverall", "itsis.vehicleHeigthOverall",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int1", HFILL }},
    { &hf_itsis_vehicleWidthOverall,
      { "vehicleWidthOverall", "itsis.vehicleWidthOverall",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int1", HFILL }},
    { &hf_itsis_vehicleMaxLadenWeight,
      { "vehicleMaxLadenWeight", "itsis.vehicleMaxLadenWeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_vehicleTrainMaximumWeight,
      { "vehicleTrainMaximumWeight", "itsis.vehicleTrainMaximumWeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_vehicleWeightUnladen,
      { "vehicleWeightUnladen", "itsis.vehicleWeightUnladen",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Int2", HFILL }},
    { &hf_itsis_AttributeIdList_item,
      { "AttributeIdList item", "itsis.AttributeIdList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127_", HFILL }},
    { &hf_itsis_AttributeList_item,
      { "Attributes", "itsis.Attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_attributeId,
      { "attributeId", "itsis.attributeId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127_", HFILL }},
    { &hf_itsis_attributeValue,
      { "attributeValue", "itsis.attributeValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Container", HFILL }},
    { &hf_itsis_content,
      { "content", "itsis.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_itsis_extension,
      { "extension", "itsis.extension",
        FT_UINT32, BASE_DEC, VALS(itsis_Ext1_vals), 0,
        "Ext1", HFILL }},
    { &hf_itsis_content_01,
      { "content", "itsis.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_128_16511", HFILL }},
    { &hf_itsis_extension_01,
      { "extension", "itsis.extension",
        FT_UINT32, BASE_DEC, VALS(itsis_Ext2_vals), 0,
        "Ext2", HFILL }},
    { &hf_itsis_content_02,
      { "content", "itsis.content",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_16512_2113663", HFILL }},
    { &hf_itsis_extension_02,
      { "extension", "itsis.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ext3", HFILL }},
    { &hf_itsis_vehicleToLanePositions,
      { "vehicleToLanePositions", "itsis.vehicleToLanePositions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VehicleToLanePositionList", HFILL }},
    { &hf_itsis_rsuGNSSOffset,
      { "rsuGNSSOffset", "itsis.rsuGNSSOffset",
        FT_UINT32, BASE_DEC, VALS(itsis_NodeOffsetPointXY_vals), 0,
        "NodeOffsetPointXY", HFILL }},
    { &hf_itsis_nodes,
      { "nodes", "itsis.nodes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NodeSetXY", HFILL }},
    { &hf_itsis_ptvRequest,
      { "ptvRequest", "itsis.ptvRequest",
        FT_UINT32, BASE_DEC, VALS(itsis_PtvRequestType_vals), 0,
        "PtvRequestType", HFILL }},
    { &hf_itsis_activePrioritizations,
      { "activePrioritizations", "itsis.activePrioritizations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrioritizationResponseList", HFILL }},
    { &hf_itsis_signalHeadLocations,
      { "signalHeadLocations", "itsis.signalHeadLocations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalHeadLocationList", HFILL }},
    { &hf_itsis_altitude,
      { "altitude", "itsis.altitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_PrioritizationResponseList_item,
      { "PrioritizationResponse", "itsis.PrioritizationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_stationed,
      { "stationed", "itsis.stationed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StationID", HFILL }},
    { &hf_itsis_priorState,
      { "priorState", "itsis.priorState",
        FT_UINT32, BASE_DEC, VALS(itsis_PrioritizationResponseStatus_vals), 0,
        "PrioritizationResponseStatus", HFILL }},
    { &hf_itsis_signalGroup,
      { "signalGroup", "itsis.signalGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalGroupID", HFILL }},
    { &hf_itsis_emission,
      { "emission", "itsis.emission",
        FT_UINT32, BASE_DEC, VALS(itsis_EmissionType_vals), 0,
        "EmissionType", HFILL }},
    { &hf_itsis_SignalHeadLocationList_item,
      { "SignalHeadLocation", "itsis.SignalHeadLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_nodeXY,
      { "nodeXY", "itsis.nodeXY",
        FT_UINT32, BASE_DEC, VALS(itsis_NodeOffsetPointXY_vals), 0,
        "NodeOffsetPointXY", HFILL }},
    { &hf_itsis_nodeZ,
      { "nodeZ", "itsis.nodeZ",
        FT_INT32, BASE_DEC, VALS(itsis_DeltaAltitude_vals), 0,
        "DeltaAltitude", HFILL }},
    { &hf_itsis_signalGroupID,
      { "signalGroupID", "itsis.signalGroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_synchToSchedule,
      { "synchToSchedule", "itsis.synchToSchedule",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeltaTime", HFILL }},
    { &hf_itsis_VehicleToLanePositionList_item,
      { "VehicleToLanePosition", "itsis.VehicleToLanePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_stationID,
      { "stationID", "itsis.stationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_laneID,
      { "laneID", "itsis.laneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_timeReference,
      { "timeReference", "itsis.timeReference",
        FT_UINT32, BASE_DEC, VALS(itsis_TimeReference_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_messageId,
      { "messageId", "itsis.messageId",
        FT_UINT32, BASE_DEC, VALS(itsis_DSRCmsgID_vals), 0,
        "DSRCmsgID", HFILL }},
    { &hf_itsis_value_01,
      { "value", "itsis.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_regionId,
      { "regionId", "itsis.regionId",
        FT_UINT32, BASE_DEC, VALS(itsis_RegionId_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_regExtValue,
      { "regExtValue", "itsis.regExtValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_timeStamp,
      { "timeStamp", "itsis.timeStamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinuteOfTheYear", HFILL }},
    { &hf_itsis_name,
      { "name", "itsis.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "DescriptiveName", HFILL }},
    { &hf_itsis_intersections,
      { "intersections", "itsis.intersections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IntersectionStateList", HFILL }},
    { &hf_itsis_regional,
      { "regional", "itsis.regional",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4_OF_RegionalExtension", HFILL }},
    { &hf_itsis_regional_item,
      { "RegionalExtension", "itsis.RegionalExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_second,
      { "second", "itsis.second",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSecond", HFILL }},
    { &hf_itsis_sequenceNumber,
      { "sequenceNumber", "itsis.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgCount", HFILL }},
    { &hf_itsis_requests,
      { "requests", "itsis.requests",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalRequestList", HFILL }},
    { &hf_itsis_requestor,
      { "requestor", "itsis.requestor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestorDescription", HFILL }},
    { &hf_itsis_status,
      { "status", "itsis.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalStatusList", HFILL }},
    { &hf_itsis_msgIssueRevision,
      { "msgIssueRevision", "itsis.msgIssueRevision",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgCount", HFILL }},
    { &hf_itsis_layerType,
      { "layerType", "itsis.layerType",
        FT_UINT32, BASE_DEC, VALS(itsis_LayerType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_layerID,
      { "layerID", "itsis.layerID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_intersections_01,
      { "intersections", "itsis.intersections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IntersectionGeometryList", HFILL }},
    { &hf_itsis_roadSegments,
      { "roadSegments", "itsis.roadSegments",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadSegmentList", HFILL }},
    { &hf_itsis_dataParameters,
      { "dataParameters", "itsis.dataParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_restrictionList,
      { "restrictionList", "itsis.restrictionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionClassList", HFILL }},
    { &hf_itsis_type,
      { "type", "itsis.type",
        FT_UINT32, BASE_DEC, VALS(itsis_AdvisorySpeedType_vals), 0,
        "AdvisorySpeedType", HFILL }},
    { &hf_itsis_speed,
      { "speed", "itsis.speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedAdvice", HFILL }},
    { &hf_itsis_confidence,
      { "confidence", "itsis.confidence",
        FT_UINT32, BASE_DEC, VALS(itsis_SpeedConfidence_vals), 0,
        "SpeedConfidence", HFILL }},
    { &hf_itsis_distance,
      { "distance", "itsis.distance",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ZoneLength", HFILL }},
    { &hf_itsis_class,
      { "class", "itsis.class",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionClassID", HFILL }},
    { &hf_itsis_AdvisorySpeedList_item,
      { "AdvisorySpeed", "itsis.AdvisorySpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_referenceLaneId,
      { "referenceLaneId", "itsis.referenceLaneId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneID", HFILL }},
    { &hf_itsis_offsetXaxis,
      { "offsetXaxis", "itsis.offsetXaxis",
        FT_UINT32, BASE_DEC, VALS(itsis_T_offsetXaxis_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_small,
      { "small", "itsis.small",
        FT_INT32, BASE_DEC, NULL, 0,
        "DrivenLineOffsetSm", HFILL }},
    { &hf_itsis_large,
      { "large", "itsis.large",
        FT_INT32, BASE_DEC, NULL, 0,
        "DrivenLineOffsetLg", HFILL }},
    { &hf_itsis_offsetYaxis,
      { "offsetYaxis", "itsis.offsetYaxis",
        FT_UINT32, BASE_DEC, VALS(itsis_T_offsetYaxis_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_rotateXY,
      { "rotateXY", "itsis.rotateXY",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_itsis_scaleXaxis,
      { "scaleXaxis", "itsis.scaleXaxis",
        FT_INT32, BASE_DEC, NULL, 0,
        "Scale_B12", HFILL }},
    { &hf_itsis_scaleYaxis,
      { "scaleYaxis", "itsis.scaleYaxis",
        FT_INT32, BASE_DEC, NULL, 0,
        "Scale_B12", HFILL }},
    { &hf_itsis_ConnectsToList_item,
      { "Connection", "itsis.Connection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_lane,
      { "lane", "itsis.lane",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneID", HFILL }},
    { &hf_itsis_maneuver,
      { "maneuver", "itsis.maneuver",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AllowedManeuvers", HFILL }},
    { &hf_itsis_connectingLane,
      { "connectingLane", "itsis.connectingLane_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_remoteIntersection,
      { "remoteIntersection", "itsis.remoteIntersection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntersectionReferenceID", HFILL }},
    { &hf_itsis_userClass,
      { "userClass", "itsis.userClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionClassID", HFILL }},
    { &hf_itsis_connectionID,
      { "connectionID", "itsis.connectionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneConnectionID", HFILL }},
    { &hf_itsis_queueLength,
      { "queueLength", "itsis.queueLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ZoneLength", HFILL }},
    { &hf_itsis_availableStorageLength,
      { "availableStorageLength", "itsis.availableStorageLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ZoneLength", HFILL }},
    { &hf_itsis_waitOnStop,
      { "waitOnStop", "itsis.waitOnStop",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "WaitOnStopline", HFILL }},
    { &hf_itsis_pedBicycleDetect,
      { "pedBicycleDetect", "itsis.pedBicycleDetect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "PedestrianBicycleDetect", HFILL }},
    { &hf_itsis_processMethod,
      { "processMethod", "itsis.processMethod",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_255", HFILL }},
    { &hf_itsis_processAgency,
      { "processAgency", "itsis.processAgency",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_255", HFILL }},
    { &hf_itsis_lastCheckedDate,
      { "lastCheckedDate", "itsis.lastCheckedDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_255", HFILL }},
    { &hf_itsis_geoidUsed,
      { "geoidUsed", "itsis.geoidUsed",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_255", HFILL }},
    { &hf_itsis_EnabledLaneList_item,
      { "LaneID", "itsis.LaneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_ingressApproach,
      { "ingressApproach", "itsis.ingressApproach",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ApproachID", HFILL }},
    { &hf_itsis_egressApproach,
      { "egressApproach", "itsis.egressApproach",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ApproachID", HFILL }},
    { &hf_itsis_laneAttributes,
      { "laneAttributes", "itsis.laneAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_maneuvers,
      { "maneuvers", "itsis.maneuvers",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AllowedManeuvers", HFILL }},
    { &hf_itsis_nodeList,
      { "nodeList", "itsis.nodeList",
        FT_UINT32, BASE_DEC, VALS(itsis_NodeListXY_vals), 0,
        "NodeListXY", HFILL }},
    { &hf_itsis_connectsTo,
      { "connectsTo", "itsis.connectsTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ConnectsToList", HFILL }},
    { &hf_itsis_overlays,
      { "overlays", "itsis.overlays",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OverlayLaneList", HFILL }},
    { &hf_itsis_approach,
      { "approach", "itsis.approach",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ApproachID", HFILL }},
    { &hf_itsis_connection,
      { "connection", "itsis.connection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneConnectionID", HFILL }},
    { &hf_itsis_id,
      { "id", "itsis.id_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntersectionReferenceID", HFILL }},
    { &hf_itsis_revision,
      { "revision", "itsis.revision",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgCount", HFILL }},
    { &hf_itsis_refPoint,
      { "refPoint", "itsis.refPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Position3D", HFILL }},
    { &hf_itsis_laneWidth,
      { "laneWidth", "itsis.laneWidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_speedLimits,
      { "speedLimits", "itsis.speedLimits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedLimitList", HFILL }},
    { &hf_itsis_laneSet,
      { "laneSet", "itsis.laneSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneList", HFILL }},
    { &hf_itsis_preemptPriorityData,
      { "preemptPriorityData", "itsis.preemptPriorityData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PreemptPriorityList", HFILL }},
    { &hf_itsis_IntersectionGeometryList_item,
      { "IntersectionGeometry", "itsis.IntersectionGeometry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_region,
      { "region", "itsis.region",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadRegulatorID", HFILL }},
    { &hf_itsis_id_01,
      { "id", "itsis.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IntersectionID", HFILL }},
    { &hf_itsis_status_01,
      { "status", "itsis.status",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IntersectionStatusObject", HFILL }},
    { &hf_itsis_moy,
      { "moy", "itsis.moy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinuteOfTheYear", HFILL }},
    { &hf_itsis_timeStamp_01,
      { "timeStamp", "itsis.timeStamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSecond", HFILL }},
    { &hf_itsis_enabledLanes,
      { "enabledLanes", "itsis.enabledLanes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EnabledLaneList", HFILL }},
    { &hf_itsis_states,
      { "states", "itsis.states",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MovementList", HFILL }},
    { &hf_itsis_maneuverAssistList,
      { "maneuverAssistList", "itsis.maneuverAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStateList_item,
      { "IntersectionState", "itsis.IntersectionState_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_directionalUse,
      { "directionalUse", "itsis.directionalUse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneDirection", HFILL }},
    { &hf_itsis_sharedWith,
      { "sharedWith", "itsis.sharedWith",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneSharing", HFILL }},
    { &hf_itsis_laneType,
      { "laneType", "itsis.laneType",
        FT_UINT32, BASE_DEC, VALS(itsis_LaneTypeAttributes_vals), 0,
        "LaneTypeAttributes", HFILL }},
    { &hf_itsis_regional_01,
      { "regional", "itsis.regional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegionalExtension", HFILL }},
    { &hf_itsis_pathEndPointAngle,
      { "pathEndPointAngle", "itsis.pathEndPointAngle",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeltaAngle", HFILL }},
    { &hf_itsis_laneCrownPointCenter,
      { "laneCrownPointCenter", "itsis.laneCrownPointCenter",
        FT_INT32, BASE_DEC, NULL, 0,
        "RoadwayCrownAngle", HFILL }},
    { &hf_itsis_laneCrownPointLeft,
      { "laneCrownPointLeft", "itsis.laneCrownPointLeft",
        FT_INT32, BASE_DEC, NULL, 0,
        "RoadwayCrownAngle", HFILL }},
    { &hf_itsis_laneCrownPointRight,
      { "laneCrownPointRight", "itsis.laneCrownPointRight",
        FT_INT32, BASE_DEC, NULL, 0,
        "RoadwayCrownAngle", HFILL }},
    { &hf_itsis_laneAngle,
      { "laneAngle", "itsis.laneAngle",
        FT_INT32, BASE_DEC, NULL, 0,
        "MergeDivergeNodeAngle", HFILL }},
    { &hf_itsis_LaneDataAttributeList_item,
      { "LaneDataAttribute", "itsis.LaneDataAttribute",
        FT_UINT32, BASE_DEC, VALS(itsis_LaneDataAttribute_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_LaneList_item,
      { "GenericLane", "itsis.GenericLane_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_vehicle,
      { "vehicle", "itsis.vehicle",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Vehicle", HFILL }},
    { &hf_itsis_crosswalk,
      { "crosswalk", "itsis.crosswalk",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Crosswalk", HFILL }},
    { &hf_itsis_bikeLane,
      { "bikeLane", "itsis.bikeLane",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Bike", HFILL }},
    { &hf_itsis_sidewalk,
      { "sidewalk", "itsis.sidewalk",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Sidewalk", HFILL }},
    { &hf_itsis_median,
      { "median", "itsis.median",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Barrier", HFILL }},
    { &hf_itsis_striping,
      { "striping", "itsis.striping",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Striping", HFILL }},
    { &hf_itsis_trackedVehicle,
      { "trackedVehicle", "itsis.trackedVehicle",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_TrackedVehicle", HFILL }},
    { &hf_itsis_parking,
      { "parking", "itsis.parking",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Parking", HFILL }},
    { &hf_itsis_ManeuverAssistList_item,
      { "ConnectionManeuverAssist", "itsis.ConnectionManeuverAssist_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_MovementEventList_item,
      { "MovementEvent", "itsis.MovementEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_eventState,
      { "eventState", "itsis.eventState",
        FT_UINT32, BASE_DEC, VALS(itsis_MovementPhaseState_vals), 0,
        "MovementPhaseState", HFILL }},
    { &hf_itsis_timing,
      { "timing", "itsis.timing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeChangeDetails", HFILL }},
    { &hf_itsis_speeds,
      { "speeds", "itsis.speeds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AdvisorySpeedList", HFILL }},
    { &hf_itsis_MovementList_item,
      { "MovementState", "itsis.MovementState_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_movementName,
      { "movementName", "itsis.movementName",
        FT_STRING, BASE_NONE, NULL, 0,
        "DescriptiveName", HFILL }},
    { &hf_itsis_state_time_speed,
      { "state-time-speed", "itsis.state_time_speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MovementEventList", HFILL }},
    { &hf_itsis_localNode,
      { "localNode", "itsis.localNode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NodeAttributeXYList", HFILL }},
    { &hf_itsis_disabled,
      { "disabled", "itsis.disabled",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SegmentAttributeXYList", HFILL }},
    { &hf_itsis_enabled,
      { "enabled", "itsis.enabled",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SegmentAttributeXYList", HFILL }},
    { &hf_itsis_data,
      { "data", "itsis.data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneDataAttributeList", HFILL }},
    { &hf_itsis_dWidth,
      { "dWidth", "itsis.dWidth",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_itsis_dElevation,
      { "dElevation", "itsis.dElevation",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_itsis_NodeAttributeXYList_item,
      { "NodeAttributeXY", "itsis.NodeAttributeXY",
        FT_UINT32, BASE_DEC, VALS(itsis_NodeAttributeXY_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_lon,
      { "lon", "itsis.lon",
        FT_INT32, BASE_DEC, VALS(itsis_Longitude_vals), 0,
        "Longitude", HFILL }},
    { &hf_itsis_lat,
      { "lat", "itsis.lat",
        FT_INT32, BASE_DEC, VALS(itsis_Latitude_vals), 0,
        "Latitude", HFILL }},
    { &hf_itsis_x,
      { "x", "itsis.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_itsis_y,
      { "y", "itsis.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_itsis_x_01,
      { "x", "itsis.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B11", HFILL }},
    { &hf_itsis_y_01,
      { "y", "itsis.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B11", HFILL }},
    { &hf_itsis_x_02,
      { "x", "itsis.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B12", HFILL }},
    { &hf_itsis_y_02,
      { "y", "itsis.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B12", HFILL }},
    { &hf_itsis_x_03,
      { "x", "itsis.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B13", HFILL }},
    { &hf_itsis_y_03,
      { "y", "itsis.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B13", HFILL }},
    { &hf_itsis_x_04,
      { "x", "itsis.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B14", HFILL }},
    { &hf_itsis_y_04,
      { "y", "itsis.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B14", HFILL }},
    { &hf_itsis_x_05,
      { "x", "itsis.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B16", HFILL }},
    { &hf_itsis_y_05,
      { "y", "itsis.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B16", HFILL }},
    { &hf_itsis_computed,
      { "computed", "itsis.computed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ComputedLane", HFILL }},
    { &hf_itsis_node_XY1,
      { "node-XY1", "itsis.node_XY1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_20b", HFILL }},
    { &hf_itsis_node_XY2,
      { "node-XY2", "itsis.node_XY2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_22b", HFILL }},
    { &hf_itsis_node_XY3,
      { "node-XY3", "itsis.node_XY3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_24b", HFILL }},
    { &hf_itsis_node_XY4,
      { "node-XY4", "itsis.node_XY4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_26b", HFILL }},
    { &hf_itsis_node_XY5,
      { "node-XY5", "itsis.node_XY5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_28b", HFILL }},
    { &hf_itsis_node_XY6,
      { "node-XY6", "itsis.node_XY6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_32b", HFILL }},
    { &hf_itsis_node_LatLon,
      { "node-LatLon", "itsis.node_LatLon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LLmD_64b", HFILL }},
    { &hf_itsis_NodeSetXY_item,
      { "NodeXY", "itsis.NodeXY_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_delta,
      { "delta", "itsis.delta",
        FT_UINT32, BASE_DEC, VALS(itsis_NodeOffsetPointXY_vals), 0,
        "NodeOffsetPointXY", HFILL }},
    { &hf_itsis_attributes,
      { "attributes", "itsis.attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NodeAttributeSetXY", HFILL }},
    { &hf_itsis_OverlayLaneList_item,
      { "LaneID", "itsis.LaneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_long,
      { "long", "itsis.long",
        FT_INT32, BASE_DEC, VALS(itsis_Longitude_vals), 0,
        "Longitude", HFILL }},
    { &hf_itsis_elevation,
      { "elevation", "itsis.elevation",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_PreemptPriorityList_item,
      { "SignalControlZone", "itsis.SignalControlZone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_type_01,
      { "type", "itsis.type",
        FT_UINT32, BASE_DEC, VALS(itsis_SpeedLimitType_vals), 0,
        "SpeedLimitType", HFILL }},
    { &hf_itsis_speed_01,
      { "speed", "itsis.speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Velocity", HFILL }},
    { &hf_itsis_id_02,
      { "id", "itsis.id",
        FT_UINT32, BASE_DEC, VALS(itsis_VehicleID_vals), 0,
        "VehicleID", HFILL }},
    { &hf_itsis_type_02,
      { "type", "itsis.type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestorType", HFILL }},
    { &hf_itsis_position,
      { "position", "itsis.position_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestorPositionVector", HFILL }},
    { &hf_itsis_routeName,
      { "routeName", "itsis.routeName",
        FT_STRING, BASE_NONE, NULL, 0,
        "DescriptiveName", HFILL }},
    { &hf_itsis_transitStatus,
      { "transitStatus", "itsis.transitStatus",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransitVehicleStatus", HFILL }},
    { &hf_itsis_transitOccupancy,
      { "transitOccupancy", "itsis.transitOccupancy",
        FT_UINT32, BASE_DEC, VALS(itsis_TransitVehicleOccupancy_vals), 0,
        "TransitVehicleOccupancy", HFILL }},
    { &hf_itsis_transitSchedule,
      { "transitSchedule", "itsis.transitSchedule",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeltaTime", HFILL }},
    { &hf_itsis_position_01,
      { "position", "itsis.position_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Position3D", HFILL }},
    { &hf_itsis_heading,
      { "heading", "itsis.heading",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_itsis_speed_02,
      { "speed", "itsis.speed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransmissionAndSpeed", HFILL }},
    { &hf_itsis_role,
      { "role", "itsis.role",
        FT_UINT32, BASE_DEC, VALS(itsis_BasicVehicleRole_vals), 0,
        "BasicVehicleRole", HFILL }},
    { &hf_itsis_subrole,
      { "subrole", "itsis.subrole",
        FT_UINT32, BASE_DEC, VALS(itsis_RequestSubRole_vals), 0,
        "RequestSubRole", HFILL }},
    { &hf_itsis_request,
      { "request", "itsis.request",
        FT_UINT32, BASE_DEC, VALS(itsis_RequestImportanceLevel_vals), 0,
        "RequestImportanceLevel", HFILL }},
    { &hf_itsis_iso3883,
      { "iso3883", "itsis.iso3883",
        FT_UINT32, BASE_DEC, VALS(itsis_Iso3833VehicleType_vals), 0,
        "Iso3833VehicleType", HFILL }},
    { &hf_itsis_hpmsType,
      { "hpmsType", "itsis.hpmsType",
        FT_UINT32, BASE_DEC, VALS(itsis_VehicleType_vals), 0,
        "VehicleType", HFILL }},
    { &hf_itsis_id_03,
      { "id", "itsis.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionClassID", HFILL }},
    { &hf_itsis_users,
      { "users", "itsis.users",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionUserTypeList", HFILL }},
    { &hf_itsis_RestrictionClassList_item,
      { "RestrictionClassAssignment", "itsis.RestrictionClassAssignment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_RestrictionUserTypeList_item,
      { "RestrictionUserType", "itsis.RestrictionUserType",
        FT_UINT32, BASE_DEC, VALS(itsis_RestrictionUserType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_basicType,
      { "basicType", "itsis.basicType",
        FT_UINT32, BASE_DEC, VALS(itsis_RestrictionAppliesTo_vals), 0,
        "RestrictionAppliesTo", HFILL }},
    { &hf_itsis_RoadLaneSetList_item,
      { "GenericLane", "itsis.GenericLane_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_id_04,
      { "id", "itsis.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadSegmentID", HFILL }},
    { &hf_itsis_id_05,
      { "id", "itsis.id_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RoadSegmentReferenceID", HFILL }},
    { &hf_itsis_roadLaneSet,
      { "roadLaneSet", "itsis.roadLaneSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadLaneSetList", HFILL }},
    { &hf_itsis_RoadSegmentList_item,
      { "RoadSegment", "itsis.RoadSegment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_SegmentAttributeXYList_item,
      { "SegmentAttributeXY", "itsis.SegmentAttributeXY",
        FT_UINT32, BASE_DEC, VALS(itsis_SegmentAttributeXY_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_zone,
      { "zone", "itsis.zone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegionalExtension", HFILL }},
    { &hf_itsis_request_01,
      { "request", "itsis.request",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestID", HFILL }},
    { &hf_itsis_typeData,
      { "typeData", "itsis.typeData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestorType", HFILL }},
    { &hf_itsis_SignalRequestList_item,
      { "SignalRequestPackage", "itsis.SignalRequestPackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_request_02,
      { "request", "itsis.request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalRequest", HFILL }},
    { &hf_itsis_minute,
      { "minute", "itsis.minute",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinuteOfTheYear", HFILL }},
    { &hf_itsis_duration,
      { "duration", "itsis.duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSecond", HFILL }},
    { &hf_itsis_requestID,
      { "requestID", "itsis.requestID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_requestType,
      { "requestType", "itsis.requestType",
        FT_UINT32, BASE_DEC, VALS(itsis_PriorityRequestType_vals), 0,
        "PriorityRequestType", HFILL }},
    { &hf_itsis_inBoundLane,
      { "inBoundLane", "itsis.inBoundLane",
        FT_UINT32, BASE_DEC, VALS(itsis_IntersectionAccessPoint_vals), 0,
        "IntersectionAccessPoint", HFILL }},
    { &hf_itsis_outBoundLane,
      { "outBoundLane", "itsis.outBoundLane",
        FT_UINT32, BASE_DEC, VALS(itsis_IntersectionAccessPoint_vals), 0,
        "IntersectionAccessPoint", HFILL }},
    { &hf_itsis_SignalStatusList_item,
      { "SignalStatus", "itsis.SignalStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_SignalStatusPackageList_item,
      { "SignalStatusPackage", "itsis.SignalStatusPackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_requester,
      { "requester", "itsis.requester_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalRequesterInfo", HFILL }},
    { &hf_itsis_inboundOn,
      { "inboundOn", "itsis.inboundOn",
        FT_UINT32, BASE_DEC, VALS(itsis_IntersectionAccessPoint_vals), 0,
        "IntersectionAccessPoint", HFILL }},
    { &hf_itsis_outboundOn,
      { "outboundOn", "itsis.outboundOn",
        FT_UINT32, BASE_DEC, VALS(itsis_IntersectionAccessPoint_vals), 0,
        "IntersectionAccessPoint", HFILL }},
    { &hf_itsis_status_02,
      { "status", "itsis.status",
        FT_UINT32, BASE_DEC, VALS(itsis_PrioritizationResponseStatus_vals), 0,
        "PrioritizationResponseStatus", HFILL }},
    { &hf_itsis_sigStatus,
      { "sigStatus", "itsis.sigStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalStatusPackageList", HFILL }},
    { &hf_itsis_SpeedLimitList_item,
      { "RegulatorySpeedLimit", "itsis.RegulatorySpeedLimit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_startTime,
      { "startTime", "itsis.startTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_itsis_minEndTime,
      { "minEndTime", "itsis.minEndTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_itsis_maxEndTime,
      { "maxEndTime", "itsis.maxEndTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_itsis_likelyTime,
      { "likelyTime", "itsis.likelyTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_itsis_confidence_01,
      { "confidence", "itsis.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeIntervalConfidence", HFILL }},
    { &hf_itsis_nextTime,
      { "nextTime", "itsis.nextTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_itsis_transmisson,
      { "transmisson", "itsis.transmisson",
        FT_UINT32, BASE_DEC, VALS(itsis_TransmissionState_vals), 0,
        "TransmissionState", HFILL }},
    { &hf_itsis_entityID,
      { "entityID", "itsis.entityID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TemporaryID", HFILL }},
    { &hf_itsis_mandatory,
      { "mandatory", "itsis.mandatory_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IVIManagementContainer", HFILL }},
    { &hf_itsis_optional,
      { "optional", "itsis.optional",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_IviContainer", HFILL }},
    { &hf_itsis_optional_item,
      { "IviContainer", "itsis.IviContainer",
        FT_UINT32, BASE_DEC, VALS(itsis_IviContainer_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_glc,
      { "glc", "itsis.glc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicLocationContainer", HFILL }},
    { &hf_itsis_giv,
      { "giv", "itsis.giv",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralIviContainer", HFILL }},
    { &hf_itsis_rcc,
      { "rcc", "itsis.rcc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadConfigurationContainer", HFILL }},
    { &hf_itsis_tc,
      { "tc", "itsis.tc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TextContainer", HFILL }},
    { &hf_itsis_lac,
      { "lac", "itsis.lac_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LayoutContainer", HFILL }},
    { &hf_itsis_serviceProviderId,
      { "serviceProviderId", "itsis.serviceProviderId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Provider", HFILL }},
    { &hf_itsis_iviIdentificationNumber,
      { "iviIdentificationNumber", "itsis.iviIdentificationNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_timeStamp_02,
      { "timeStamp", "itsis.timeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimestampIts", HFILL }},
    { &hf_itsis_validFrom,
      { "validFrom", "itsis.validFrom",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimestampIts", HFILL }},
    { &hf_itsis_validTo,
      { "validTo", "itsis.validTo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimestampIts", HFILL }},
    { &hf_itsis_connectedIviStructures,
      { "connectedIviStructures", "itsis.connectedIviStructures",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber", HFILL }},
    { &hf_itsis_connectedIviStructures_item,
      { "IviIdentificationNumber", "itsis.IviIdentificationNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_iviStatus,
      { "iviStatus", "itsis.iviStatus",
        FT_UINT32, BASE_DEC, VALS(itsis_IviStatus_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_referencePosition,
      { "referencePosition", "itsis.referencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_referencePositionTime,
      { "referencePositionTime", "itsis.referencePositionTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimestampIts", HFILL }},
    { &hf_itsis_referencePositionHeading,
      { "referencePositionHeading", "itsis.referencePositionHeading_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Heading", HFILL }},
    { &hf_itsis_referencePositionSpeed,
      { "referencePositionSpeed", "itsis.referencePositionSpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Speed", HFILL }},
    { &hf_itsis_parts,
      { "parts", "itsis.parts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_16__OF_GlcPart", HFILL }},
    { &hf_itsis_parts_item,
      { "GlcPart", "itsis.GlcPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_zoneId,
      { "zoneId", "itsis.zoneId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Zid", HFILL }},
    { &hf_itsis_laneNumber,
      { "laneNumber", "itsis.laneNumber",
        FT_INT32, BASE_DEC, VALS(itsis_LanePosition_vals), 0,
        "LanePosition", HFILL }},
    { &hf_itsis_zoneExtension,
      { "zoneExtension", "itsis.zoneExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_itsis_zoneHeading,
      { "zoneHeading", "itsis.zoneHeading",
        FT_UINT32, BASE_DEC, VALS(itsis_HeadingValue_vals), 0,
        "HeadingValue", HFILL }},
    { &hf_itsis_zone_01,
      { "zone", "itsis.zone",
        FT_UINT32, BASE_DEC, VALS(itsis_Zone_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_GeneralIviContainer_item,
      { "GicPart", "itsis.GicPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_detectionZoneIds,
      { "detectionZoneIds", "itsis.detectionZoneIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_Zid", HFILL }},
    { &hf_itsis_detectionZoneIds_item,
      { "Zid", "itsis.Zid",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_its_Rrid,
      { "its-Rrid", "itsis.its_Rrid",
        FT_UINT32, BASE_DEC, VALS(itsis_VarLengthNumber_vals), 0,
        "VarLengthNumber", HFILL }},
    { &hf_itsis_relevanceZoneIds,
      { "relevanceZoneIds", "itsis.relevanceZoneIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_Zid", HFILL }},
    { &hf_itsis_relevanceZoneIds_item,
      { "Zid", "itsis.Zid",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_direction,
      { "direction", "itsis.direction",
        FT_UINT32, BASE_DEC, VALS(itsis_Direction_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_driverAwarenessZoneIds,
      { "driverAwarenessZoneIds", "itsis.driverAwarenessZoneIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_Zid", HFILL }},
    { &hf_itsis_driverAwarenessZoneIds_item,
      { "Zid", "itsis.Zid",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_minimumAwarenessTime,
      { "minimumAwarenessTime", "itsis.minimumAwarenessTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_itsis_applicableLanes,
      { "applicableLanes", "itsis.applicableLanes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_LanePosition", HFILL }},
    { &hf_itsis_applicableLanes_item,
      { "LanePosition", "itsis.LanePosition",
        FT_INT32, BASE_DEC, VALS(itsis_LanePosition_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_iviType,
      { "iviType", "itsis.iviType",
        FT_UINT32, BASE_DEC, VALS(itsis_IviType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_iviPurpose,
      { "iviPurpose", "itsis.iviPurpose",
        FT_UINT32, BASE_DEC, VALS(itsis_IviPurpose_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_laneStatus,
      { "laneStatus", "itsis.laneStatus",
        FT_UINT32, BASE_DEC, VALS(itsis_LaneStatus_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_vehicleCharacteristics,
      { "vehicleCharacteristics", "itsis.vehicleCharacteristics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics", HFILL }},
    { &hf_itsis_vehicleCharacteristics_item,
      { "CompleteVehicleCharacteristics", "itsis.CompleteVehicleCharacteristics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_driverCharacteristics,
      { "driverCharacteristics", "itsis.driverCharacteristics",
        FT_UINT32, BASE_DEC, VALS(itsis_DriverCharacteristics_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_layoutId,
      { "layoutId", "itsis.layoutId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4_", HFILL }},
    { &hf_itsis_preStoredlayoutId,
      { "preStoredlayoutId", "itsis.preStoredlayoutId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_64_", HFILL }},
    { &hf_itsis_roadSignCodes,
      { "roadSignCodes", "itsis.roadSignCodes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_RSCode", HFILL }},
    { &hf_itsis_roadSignCodes_item,
      { "RSCode", "itsis.RSCode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_extraText,
      { "extraText", "itsis.extraText",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_Text", HFILL }},
    { &hf_itsis_extraText_item,
      { "Text", "itsis.Text_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_RoadConfigurationContainer_item,
      { "RccPart", "itsis.RccPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_zoneIds,
      { "zoneIds", "itsis.zoneIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_Zid", HFILL }},
    { &hf_itsis_zoneIds_item,
      { "Zid", "itsis.Zid",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_roadType,
      { "roadType", "itsis.roadType",
        FT_UINT32, BASE_DEC, VALS(itsis_RoadType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_laneConfiguration,
      { "laneConfiguration", "itsis.laneConfiguration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_16__OF_LaneInformation", HFILL }},
    { &hf_itsis_laneConfiguration_item,
      { "LaneInformation", "itsis.LaneInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_TextContainer_item,
      { "TcPart", "itsis.TcPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_text,
      { "text", "itsis.text",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_Text", HFILL }},
    { &hf_itsis_text_item,
      { "Text", "itsis.Text_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_data_01,
      { "data", "itsis.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_itsis_height,
      { "height", "itsis.height",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_73", HFILL }},
    { &hf_itsis_width,
      { "width", "itsis.width",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_265", HFILL }},
    { &hf_itsis_layoutComponents,
      { "layoutComponents", "itsis.layoutComponents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_LayoutComponent", HFILL }},
    { &hf_itsis_layoutComponents_item,
      { "LayoutComponent", "itsis.LayoutComponent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_latitude,
      { "latitude", "itsis.latitude",
        FT_INT32, BASE_DEC, VALS(itsis_Latitude_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_longitude,
      { "longitude", "itsis.longitude",
        FT_INT32, BASE_DEC, VALS(itsis_Longitude_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_owner,
      { "owner", "itsis.owner_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Provider", HFILL }},
    { &hf_itsis_version,
      { "version", "itsis.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_itsis_pictogramCode,
      { "pictogramCode", "itsis.pictogramCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_itsis_value_02,
      { "value", "itsis.value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_itsis_unit,
      { "unit", "itsis.unit",
        FT_UINT32, BASE_DEC, VALS(itsis_RSCUnit_vals), 0,
        "RSCUnit", HFILL }},
    { &hf_itsis_attributes_01,
      { "attributes", "itsis.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ISO14823Attributes", HFILL }},
    { &hf_itsis_tractor,
      { "tractor", "itsis.tractor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TractorCharacteristics", HFILL }},
    { &hf_itsis_trailer,
      { "trailer", "itsis.trailer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics", HFILL }},
    { &hf_itsis_trailer_item,
      { "TrailerCharacteristics", "itsis.TrailerCharacteristics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_train,
      { "train", "itsis.train_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TrainCharacteristics", HFILL }},
    { &hf_itsis_laneWidth_01,
      { "laneWidth", "itsis.laneWidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IVILaneWidth", HFILL }},
    { &hf_itsis_offsetDistance,
      { "offsetDistance", "itsis.offsetDistance",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_itsis_offsetPosition,
      { "offsetPosition", "itsis.offsetPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_itsis_deltaLatitude,
      { "deltaLatitude", "itsis.deltaLatitude",
        FT_INT32, BASE_DEC, VALS(itsis_DeltaLatitude_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_deltaLongitude,
      { "deltaLongitude", "itsis.deltaLongitude",
        FT_INT32, BASE_DEC, VALS(itsis_DeltaLongitude_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_value_03,
      { "value", "itsis.value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16384", HFILL }},
    { &hf_itsis_unit_01,
      { "unit", "itsis.unit",
        FT_UINT32, BASE_DEC, VALS(itsis_RSCUnit2468_vals), 0,
        "RSCUnit2468", HFILL }},
    { &hf_itsis_unit_02,
      { "unit", "itsis.unit",
        FT_UINT32, BASE_DEC, VALS(itsis_RSCUnit29_vals), 0,
        "RSCUnit29", HFILL }},
    { &hf_itsis_ISO14823Attributes_item,
      { "ISO14823Attributes item", "itsis.ISO14823Attributes_item",
        FT_UINT32, BASE_DEC, VALS(itsis_ISO14823Attributes_item_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_dtm,
      { "dtm", "itsis.dtm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_edt,
      { "edt", "itsis.edt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_dfl,
      { "dfl", "itsis.dfl",
        FT_UINT32, BASE_DEC, VALS(itsis_DFL_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_ved,
      { "ved", "itsis.ved_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_spe,
      { "spe", "itsis.spe_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_roi,
      { "roi", "itsis.roi",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_dbv,
      { "dbv", "itsis.dbv_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_ddd,
      { "ddd", "itsis.ddd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_pictogramCode_01,
      { "pictogramCode", "itsis.pictogramCode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_countryCode_01,
      { "countryCode", "itsis.countryCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_itsis_serviceCategoryCode,
      { "serviceCategoryCode", "itsis.serviceCategoryCode",
        FT_UINT32, BASE_DEC, VALS(itsis_T_serviceCategoryCode_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_trafficSignPictogram,
      { "trafficSignPictogram", "itsis.trafficSignPictogram",
        FT_UINT32, BASE_DEC, VALS(itsis_T_trafficSignPictogram_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_publicFacilitiesPictogram,
      { "publicFacilitiesPictogram", "itsis.publicFacilitiesPictogram",
        FT_UINT32, BASE_DEC, VALS(itsis_T_publicFacilitiesPictogram_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_ambientOrRoadConditionPictogram,
      { "ambientOrRoadConditionPictogram", "itsis.ambientOrRoadConditionPictogram",
        FT_UINT32, BASE_DEC, VALS(itsis_T_ambientOrRoadConditionPictogram_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_pictogramCategoryCode,
      { "pictogramCategoryCode", "itsis.pictogramCategoryCode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_nature,
      { "nature", "itsis.nature",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_9", HFILL }},
    { &hf_itsis_serialNumber,
      { "serialNumber", "itsis.serialNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_99", HFILL }},
    { &hf_itsis_validity,
      { "validity", "itsis.validity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DTM", HFILL }},
    { &hf_itsis_laneType_01,
      { "laneType", "itsis.laneType",
        FT_UINT32, BASE_DEC, VALS(itsis_LaneType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_laneTypeQualifier,
      { "laneTypeQualifier", "itsis.laneTypeQualifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompleteVehicleCharacteristics", HFILL }},
    { &hf_itsis_layoutComponentId,
      { "layoutComponentId", "itsis.layoutComponentId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8_", HFILL }},
    { &hf_itsis_x_06,
      { "x", "itsis.x",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_265", HFILL }},
    { &hf_itsis_y_06,
      { "y", "itsis.y",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_73", HFILL }},
    { &hf_itsis_textScripting,
      { "textScripting", "itsis.textScripting",
        FT_UINT32, BASE_DEC, VALS(itsis_T_textScripting_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_goodsType,
      { "goodsType", "itsis.goodsType",
        FT_UINT32, BASE_DEC, VALS(itsis_GoodsType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_dangerousGoodsType,
      { "dangerousGoodsType", "itsis.dangerousGoodsType",
        FT_UINT32, BASE_DEC, VALS(itsis_DangerousGoodsBasic_vals), 0,
        "DangerousGoodsBasic", HFILL }},
    { &hf_itsis_specialTransportType,
      { "specialTransportType", "itsis.specialTransportType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_deltaPositions,
      { "deltaPositions", "itsis.deltaPositions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_32__OF_DeltaPosition", HFILL }},
    { &hf_itsis_deltaPositions_item,
      { "DeltaPosition", "itsis.DeltaPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_deltaPositionsWithAltitude,
      { "deltaPositionsWithAltitude", "itsis.deltaPositionsWithAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition", HFILL }},
    { &hf_itsis_deltaPositionsWithAltitude_item,
      { "DeltaReferencePosition", "itsis.DeltaReferencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_absolutePositions,
      { "absolutePositions", "itsis.absolutePositions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_AbsolutePosition", HFILL }},
    { &hf_itsis_absolutePositions_item,
      { "AbsolutePosition", "itsis.AbsolutePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_absolutePositionsWithAltitude,
      { "absolutePositionsWithAltitude", "itsis.absolutePositionsWithAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude", HFILL }},
    { &hf_itsis_absolutePositionsWithAltitude_item,
      { "AbsolutePositionWAltitude", "itsis.AbsolutePositionWAltitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_layoutComponentId_01,
      { "layoutComponentId", "itsis.layoutComponentId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4_", HFILL }},
    { &hf_itsis_code,
      { "code", "itsis.code",
        FT_UINT32, BASE_DEC, VALS(itsis_T_code_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_viennaConvention,
      { "viennaConvention", "itsis.viennaConvention_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VcCode", HFILL }},
    { &hf_itsis_iso14823,
      { "iso14823", "itsis.iso14823_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ISO14823Code", HFILL }},
    { &hf_itsis_itisCodes,
      { "itisCodes", "itsis.itisCodes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_itsis_anyCatalogue,
      { "anyCatalogue", "itsis.anyCatalogue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_line,
      { "line", "itsis.line",
        FT_UINT32, BASE_DEC, VALS(itsis_PolygonalLine_vals), 0,
        "PolygonalLine", HFILL }},
    { &hf_itsis_language,
      { "language", "itsis.language",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_itsis_textContent,
      { "textContent", "itsis.textContent",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_itsis_equalTo,
      { "equalTo", "itsis.equalTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues", HFILL }},
    { &hf_itsis_equalTo_item,
      { "VehicleCharacteristicsFixValues", "itsis.VehicleCharacteristicsFixValues",
        FT_UINT32, BASE_DEC, VALS(itsis_VehicleCharacteristicsFixValues_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_notEqualTo,
      { "notEqualTo", "itsis.notEqualTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues", HFILL }},
    { &hf_itsis_notEqualTo_item,
      { "VehicleCharacteristicsFixValues", "itsis.VehicleCharacteristicsFixValues",
        FT_UINT32, BASE_DEC, VALS(itsis_VehicleCharacteristicsFixValues_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_ranges,
      { "ranges", "itsis.ranges",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges", HFILL }},
    { &hf_itsis_ranges_item,
      { "VehicleCharacteristicsRanges", "itsis.VehicleCharacteristicsRanges_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_roadSignClass,
      { "roadSignClass", "itsis.roadSignClass",
        FT_UINT32, BASE_DEC, VALS(itsis_VcClass_vals), 0,
        "VcClass", HFILL }},
    { &hf_itsis_roadSignCode,
      { "roadSignCode", "itsis.roadSignCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_64", HFILL }},
    { &hf_itsis_vcOption,
      { "vcOption", "itsis.vcOption",
        FT_UINT32, BASE_DEC, VALS(itsis_VcOption_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_validity_01,
      { "validity", "itsis.validity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_DTM", HFILL }},
    { &hf_itsis_validity_item,
      { "DTM", "itsis.DTM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_simpleVehicleType,
      { "simpleVehicleType", "itsis.simpleVehicleType",
        FT_UINT32, BASE_DEC, VALS(itsis_StationType_vals), 0,
        "StationType", HFILL }},
    { &hf_itsis_euVehicleCategoryCode,
      { "euVehicleCategoryCode", "itsis.euVehicleCategoryCode",
        FT_UINT32, BASE_DEC, VALS(itsis_EuVehicleCategoryCode_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_iso3833VehicleType,
      { "iso3833VehicleType", "itsis.iso3833VehicleType",
        FT_UINT32, BASE_DEC, VALS(itsis_Iso3833VehicleType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_euroAndCo2value,
      { "euroAndCo2value", "itsis.euroAndCo2value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EnvironmentalCharacteristics", HFILL }},
    { &hf_itsis_engineCharacteristics,
      { "engineCharacteristics", "itsis.engineCharacteristics",
        FT_UINT32, BASE_DEC, VALS(itsis_EngineCharacteristics_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_loadType,
      { "loadType", "itsis.loadType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_usage,
      { "usage", "itsis.usage",
        FT_UINT32, BASE_DEC, VALS(itsis_VehicleRole_vals), 0,
        "VehicleRole", HFILL }},
    { &hf_itsis_comparisonOperator,
      { "comparisonOperator", "itsis.comparisonOperator",
        FT_UINT32, BASE_DEC, VALS(itsis_ComparisonOperator_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_limits,
      { "limits", "itsis.limits",
        FT_UINT32, BASE_DEC, VALS(itsis_T_limits_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_numberOfAxles,
      { "numberOfAxles", "itsis.numberOfAxles",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_itsis_vehicleDimensions,
      { "vehicleDimensions", "itsis.vehicleDimensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_vehicleWeightLimits,
      { "vehicleWeightLimits", "itsis.vehicleWeightLimits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_axleWeightLimits,
      { "axleWeightLimits", "itsis.axleWeightLimits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_passengerCapacity,
      { "passengerCapacity", "itsis.passengerCapacity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_exhaustEmissionValues,
      { "exhaustEmissionValues", "itsis.exhaustEmissionValues_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_dieselEmissionValues,
      { "dieselEmissionValues", "itsis.dieselEmissionValues_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_soundLevel,
      { "soundLevel", "itsis.soundLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_unit_03,
      { "unit", "itsis.unit",
        FT_UINT32, BASE_DEC, VALS(itsis_RSCUnit1012_vals), 0,
        "RSCUnit1012", HFILL }},
    { &hf_itsis_segment,
      { "segment", "itsis.segment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_area,
      { "area", "itsis.area",
        FT_UINT32, BASE_DEC, VALS(itsis_PolygonalLine_vals), 0,
        "PolygonalLine", HFILL }},
    { &hf_itsis_computedSegment,
      { "computedSegment", "itsis.computedSegment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_year,
      { "year", "itsis.year_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_syr,
      { "syr", "itsis.syr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2000_2127_", HFILL }},
    { &hf_itsis_eyr,
      { "eyr", "itsis.eyr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2000_2127_", HFILL }},
    { &hf_itsis_month_day,
      { "month-day", "itsis.month_day_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_smd,
      { "smd", "itsis.smd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MonthDay", HFILL }},
    { &hf_itsis_emd,
      { "emd", "itsis.emd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MonthDay", HFILL }},
    { &hf_itsis_pmd,
      { "pmd", "itsis.pmd",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_hourMinutes,
      { "hourMinutes", "itsis.hourMinutes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_shm,
      { "shm", "itsis.shm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HoursMinutes", HFILL }},
    { &hf_itsis_ehm,
      { "ehm", "itsis.ehm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HoursMinutes", HFILL }},
    { &hf_itsis_dayOfWeek,
      { "dayOfWeek", "itsis.dayOfWeek",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_period,
      { "period", "itsis.period_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HoursMinutes", HFILL }},
    { &hf_itsis_month,
      { "month", "itsis.month",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_12", HFILL }},
    { &hf_itsis_day,
      { "day", "itsis.day",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_31", HFILL }},
    { &hf_itsis_hours,
      { "hours", "itsis.hours",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_23", HFILL }},
    { &hf_itsis_mins,
      { "mins", "itsis.mins",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_59", HFILL }},
    { &hf_itsis_hei,
      { "hei", "itsis.hei_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Distance", HFILL }},
    { &hf_itsis_wid,
      { "wid", "itsis.wid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Distance", HFILL }},
    { &hf_itsis_vln,
      { "vln", "itsis.vln_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Distance", HFILL }},
    { &hf_itsis_wei,
      { "wei", "itsis.wei_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Weight", HFILL }},
    { &hf_itsis_spm,
      { "spm", "itsis.spm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_250", HFILL }},
    { &hf_itsis_mns,
      { "mns", "itsis.mns",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_250", HFILL }},
    { &hf_itsis_unit_04,
      { "unit", "itsis.unit",
        FT_UINT32, BASE_DEC, VALS(itsis_RSCUnit01_vals), 0,
        "RSCUnit01", HFILL }},
    { &hf_itsis_dcj,
      { "dcj", "itsis.dcj",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_itsis_dcr,
      { "dcr", "itsis.dcr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_itsis_tpl,
      { "tpl", "itsis.tpl",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_itsis_ioList,
      { "ioList", "itsis.ioList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8__OF_DDD_IO", HFILL }},
    { &hf_itsis_ioList_item,
      { "DDD-IO", "itsis.DDD_IO_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_drn,
      { "drn", "itsis.drn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_itsis_dp,
      { "dp", "itsis.dp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_DestinationPlace", HFILL }},
    { &hf_itsis_dp_item,
      { "DestinationPlace", "itsis.DestinationPlace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_dr,
      { "dr", "itsis.dr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4__OF_DestinationRoad", HFILL }},
    { &hf_itsis_dr_item,
      { "DestinationRoad", "itsis.DestinationRoad_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_rne,
      { "rne", "itsis.rne",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_999", HFILL }},
    { &hf_itsis_stnId,
      { "stnId", "itsis.stnId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_999", HFILL }},
    { &hf_itsis_stnText,
      { "stnText", "itsis.stnText",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_itsis_dcp,
      { "dcp", "itsis.dcp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceOrDuration", HFILL }},
    { &hf_itsis_ddp,
      { "ddp", "itsis.ddp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistanceOrDuration", HFILL }},
    { &hf_itsis_depType,
      { "depType", "itsis.depType",
        FT_UINT32, BASE_DEC, VALS(itsis_DDD_DEP_vals), 0,
        "DDD_DEP", HFILL }},
    { &hf_itsis_depRSCode,
      { "depRSCode", "itsis.depRSCode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ISO14823Code", HFILL }},
    { &hf_itsis_depBlob,
      { "depBlob", "itsis.depBlob",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_itsis_plnId,
      { "plnId", "itsis.plnId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_999", HFILL }},
    { &hf_itsis_plnText,
      { "plnText", "itsis.plnText",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_itsis_derType,
      { "derType", "itsis.derType",
        FT_UINT32, BASE_DEC, VALS(itsis_DDD_DER_vals), 0,
        "DDD_DER", HFILL }},
    { &hf_itsis_ronId,
      { "ronId", "itsis.ronId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_999", HFILL }},
    { &hf_itsis_ronText,
      { "ronText", "itsis.ronText",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_itsis_euVehicleCategoryL,
      { "euVehicleCategoryL", "itsis.euVehicleCategoryL",
        FT_UINT32, BASE_DEC, VALS(itsis_EuVehicleCategoryL_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_euVehicleCategoryM,
      { "euVehicleCategoryM", "itsis.euVehicleCategoryM",
        FT_UINT32, BASE_DEC, VALS(itsis_EuVehicleCategoryM_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_euVehicleCategoryN,
      { "euVehicleCategoryN", "itsis.euVehicleCategoryN",
        FT_UINT32, BASE_DEC, VALS(itsis_EuVehicleCategoryN_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_euVehicleCategoryO,
      { "euVehicleCategoryO", "itsis.euVehicleCategoryO",
        FT_UINT32, BASE_DEC, VALS(itsis_EuVehicleCategoryO_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_euVehilcleCategoryT,
      { "euVehilcleCategoryT", "itsis.euVehilcleCategoryT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_euVehilcleCategoryG,
      { "euVehilcleCategoryG", "itsis.euVehilcleCategoryG_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_protocolVersion,
      { "protocolVersion", "itsis.protocolVersion",
        FT_UINT32, BASE_DEC, VALS(itsis_T_protocolVersion_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_messageID,
      { "messageID", "itsis.messageID",
        FT_UINT32, BASE_DEC, VALS(itsis_T_messageID_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_positionConfidenceEllipse,
      { "positionConfidenceEllipse", "itsis.positionConfidenceEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosConfidenceEllipse", HFILL }},
    { &hf_itsis_deltaAltitude,
      { "deltaAltitude", "itsis.deltaAltitude",
        FT_INT32, BASE_DEC, VALS(itsis_DeltaAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_altitudeValue,
      { "altitudeValue", "itsis.altitudeValue",
        FT_INT32, BASE_DEC, VALS(itsis_AltitudeValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_altitudeConfidence,
      { "altitudeConfidence", "itsis.altitudeConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_AltitudeConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_semiMajorConfidence,
      { "semiMajorConfidence", "itsis.semiMajorConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_SemiAxisLength_vals), 0,
        "SemiAxisLength", HFILL }},
    { &hf_itsis_semiMinorConfidence,
      { "semiMinorConfidence", "itsis.semiMinorConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_SemiAxisLength_vals), 0,
        "SemiAxisLength", HFILL }},
    { &hf_itsis_semiMajorOrientation,
      { "semiMajorOrientation", "itsis.semiMajorOrientation",
        FT_UINT32, BASE_DEC, VALS(itsis_HeadingValue_vals), 0,
        "HeadingValue", HFILL }},
    { &hf_itsis_pathPosition,
      { "pathPosition", "itsis.pathPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_itsis_pathDeltaTime,
      { "pathDeltaTime", "itsis.pathDeltaTime",
        FT_UINT32, BASE_DEC, VALS(itsis_PathDeltaTime_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_ptActivationType,
      { "ptActivationType", "itsis.ptActivationType",
        FT_UINT32, BASE_DEC, VALS(itsis_PtActivationType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_ptActivationData,
      { "ptActivationData", "itsis.ptActivationData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_causeCode,
      { "causeCode", "itsis.causeCode",
        FT_UINT32, BASE_DEC, VALS(itsis_CauseCodeType_vals), 0,
        "CauseCodeType", HFILL }},
    { &hf_itsis_subCauseCode,
      { "subCauseCode", "itsis.subCauseCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubCauseCodeType", HFILL }},
    { &hf_itsis_curvatureValue,
      { "curvatureValue", "itsis.curvatureValue",
        FT_INT32, BASE_DEC, VALS(itsis_CurvatureValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_curvatureConfidence,
      { "curvatureConfidence", "itsis.curvatureConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_CurvatureConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_headingValue,
      { "headingValue", "itsis.headingValue",
        FT_UINT32, BASE_DEC, VALS(itsis_HeadingValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_headingConfidence,
      { "headingConfidence", "itsis.headingConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_HeadingConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_hardShoulderStatus,
      { "hardShoulderStatus", "itsis.hardShoulderStatus",
        FT_UINT32, BASE_DEC, VALS(itsis_HardShoulderStatus_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_drivingLaneStatus,
      { "drivingLaneStatus", "itsis.drivingLaneStatus",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_speedValue,
      { "speedValue", "itsis.speedValue",
        FT_UINT32, BASE_DEC, VALS(itsis_SpeedValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_speedConfidence,
      { "speedConfidence", "itsis.speedConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_SpeedConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_longitudinalAccelerationValue,
      { "longitudinalAccelerationValue", "itsis.longitudinalAccelerationValue",
        FT_INT32, BASE_DEC, VALS(itsis_LongitudinalAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_longitudinalAccelerationConfidence,
      { "longitudinalAccelerationConfidence", "itsis.longitudinalAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_itsis_lateralAccelerationValue,
      { "lateralAccelerationValue", "itsis.lateralAccelerationValue",
        FT_INT32, BASE_DEC, VALS(itsis_LateralAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_lateralAccelerationConfidence,
      { "lateralAccelerationConfidence", "itsis.lateralAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_itsis_verticalAccelerationValue,
      { "verticalAccelerationValue", "itsis.verticalAccelerationValue",
        FT_INT32, BASE_DEC, VALS(itsis_VerticalAccelerationValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_verticalAccelerationConfidence,
      { "verticalAccelerationConfidence", "itsis.verticalAccelerationConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_itsis_unNumber,
      { "unNumber", "itsis.unNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9999", HFILL }},
    { &hf_itsis_elevatedTemperature,
      { "elevatedTemperature", "itsis.elevatedTemperature",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_itsis_tunnelsRestricted,
      { "tunnelsRestricted", "itsis.tunnelsRestricted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_itsis_limitedQuantity,
      { "limitedQuantity", "itsis.limitedQuantity",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_itsis_emergencyActionCode,
      { "emergencyActionCode", "itsis.emergencyActionCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_24", HFILL }},
    { &hf_itsis_phoneNumber,
      { "phoneNumber", "itsis.phoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_24", HFILL }},
    { &hf_itsis_companyName,
      { "companyName", "itsis.companyName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_wMInumber,
      { "wMInumber", "itsis.wMInumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_vDS,
      { "vDS", "itsis.vDS",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_vehicleLengthValue,
      { "vehicleLengthValue", "itsis.vehicleLengthValue",
        FT_UINT32, BASE_DEC, VALS(itsis_VehicleLengthValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_vehicleLengthConfidenceIndication,
      { "vehicleLengthConfidenceIndication", "itsis.vehicleLengthConfidenceIndication",
        FT_UINT32, BASE_DEC, VALS(itsis_VehicleLengthConfidenceIndication_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_PathHistory_item,
      { "PathPoint", "itsis.PathPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_steeringWheelAngleValue,
      { "steeringWheelAngleValue", "itsis.steeringWheelAngleValue",
        FT_INT32, BASE_DEC, VALS(itsis_SteeringWheelAngleValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_steeringWheelAngleConfidence,
      { "steeringWheelAngleConfidence", "itsis.steeringWheelAngleConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_SteeringWheelAngleConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_yawRateValue,
      { "yawRateValue", "itsis.yawRateValue",
        FT_INT32, BASE_DEC, VALS(itsis_YawRateValue_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_yawRateConfidence,
      { "yawRateConfidence", "itsis.yawRateConfidence",
        FT_UINT32, BASE_DEC, VALS(itsis_YawRateConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_originatingStationID,
      { "originatingStationID", "itsis.originatingStationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StationID", HFILL }},
    { &hf_itsis_sequenceNumber_01,
      { "sequenceNumber", "itsis.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_ItineraryPath_item,
      { "ReferencePosition", "itsis.ReferencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_protectedZoneType,
      { "protectedZoneType", "itsis.protectedZoneType",
        FT_UINT32, BASE_DEC, VALS(itsis_ProtectedZoneType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_expiryTime,
      { "expiryTime", "itsis.expiryTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimestampIts", HFILL }},
    { &hf_itsis_protectedZoneLatitude,
      { "protectedZoneLatitude", "itsis.protectedZoneLatitude",
        FT_INT32, BASE_DEC, VALS(itsis_Latitude_vals), 0,
        "Latitude", HFILL }},
    { &hf_itsis_protectedZoneLongitude,
      { "protectedZoneLongitude", "itsis.protectedZoneLongitude",
        FT_INT32, BASE_DEC, VALS(itsis_Longitude_vals), 0,
        "Longitude", HFILL }},
    { &hf_itsis_protectedZoneRadius,
      { "protectedZoneRadius", "itsis.protectedZoneRadius",
        FT_UINT32, BASE_DEC, VALS(itsis_ProtectedZoneRadius_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_protectedZoneID,
      { "protectedZoneID", "itsis.protectedZoneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_Traces_item,
      { "PathHistory", "itsis.PathHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_PositionOfPillars_item,
      { "PosPillar", "itsis.PosPillar",
        FT_UINT32, BASE_DEC, VALS(itsis_PosPillar_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_RestrictedTypes_item,
      { "StationType", "itsis.StationType",
        FT_UINT32, BASE_DEC, VALS(itsis_StationType_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_EventHistory_item,
      { "EventPoint", "itsis.EventPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_eventPosition,
      { "eventPosition", "itsis.eventPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaReferencePosition", HFILL }},
    { &hf_itsis_eventDeltaTime,
      { "eventDeltaTime", "itsis.eventDeltaTime",
        FT_UINT32, BASE_DEC, VALS(itsis_PathDeltaTime_vals), 0,
        "PathDeltaTime", HFILL }},
    { &hf_itsis_informationQuality,
      { "informationQuality", "itsis.informationQuality",
        FT_UINT32, BASE_DEC, VALS(itsis_InformationQuality_vals), 0,
        NULL, HFILL }},
    { &hf_itsis_ProtectedCommunicationZonesRSU_item,
      { "ProtectedCommunicationZone", "itsis.ProtectedCommunicationZone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_cenDsrcTollingZoneID,
      { "cenDsrcTollingZoneID", "itsis.cenDsrcTollingZoneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_overlappingLaneDescriptionProvided,
      { "overlappingLaneDescriptionProvided", "itsis.overlappingLaneDescriptionProvided",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_multipleLanesTreatedAsOneLane,
      { "multipleLanesTreatedAsOneLane", "itsis.multipleLanesTreatedAsOneLane",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_otherNonMotorizedTrafficTypes,
      { "otherNonMotorizedTrafficTypes", "itsis.otherNonMotorizedTrafficTypes",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_individualMotorizedVehicleTraffic,
      { "individualMotorizedVehicleTraffic", "itsis.individualMotorizedVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_busVehicleTraffic,
      { "busVehicleTraffic", "itsis.busVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_taxiVehicleTraffic,
      { "taxiVehicleTraffic", "itsis.taxiVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_pedestriansTraffic,
      { "pedestriansTraffic", "itsis.pedestriansTraffic",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_cyclistVehicleTraffic,
      { "cyclistVehicleTraffic", "itsis.cyclistVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_trackedVehicleTraffic,
      { "trackedVehicleTraffic", "itsis.trackedVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneSharing_pedestrianTraffic,
      { "pedestrianTraffic", "itsis.pedestrianTraffic",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_maneuverStraightAllowed,
      { "maneuverStraightAllowed", "itsis.maneuverStraightAllowed",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_maneuverLeftAllowed,
      { "maneuverLeftAllowed", "itsis.maneuverLeftAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_maneuverRightAllowed,
      { "maneuverRightAllowed", "itsis.maneuverRightAllowed",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_maneuverUTurnAllowed,
      { "maneuverUTurnAllowed", "itsis.maneuverUTurnAllowed",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_maneuverLeftTurnOnRedAllowed,
      { "maneuverLeftTurnOnRedAllowed", "itsis.maneuverLeftTurnOnRedAllowed",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_maneuverRightTurnOnRedAllowed,
      { "maneuverRightTurnOnRedAllowed", "itsis.maneuverRightTurnOnRedAllowed",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_maneuverLaneChangeAllowed,
      { "maneuverLaneChangeAllowed", "itsis.maneuverLaneChangeAllowed",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_maneuverNoStoppingAllowed,
      { "maneuverNoStoppingAllowed", "itsis.maneuverNoStoppingAllowed",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_yieldAllwaysRequired,
      { "yieldAllwaysRequired", "itsis.yieldAllwaysRequired",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_goWithHalt,
      { "goWithHalt", "itsis.goWithHalt",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_caution,
      { "caution", "itsis.caution",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_AllowedManeuvers_reserved1,
      { "reserved1", "itsis.reserved1",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_manualControlIsEnabled,
      { "manualControlIsEnabled", "itsis.manualControlIsEnabled",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_stopTimeIsActivated,
      { "stopTimeIsActivated", "itsis.stopTimeIsActivated",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_failureFlash,
      { "failureFlash", "itsis.failureFlash",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_preemptIsActive,
      { "preemptIsActive", "itsis.preemptIsActive",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_signalPriorityIsActive,
      { "signalPriorityIsActive", "itsis.signalPriorityIsActive",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_fixedTimeOperation,
      { "fixedTimeOperation", "itsis.fixedTimeOperation",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_trafficDependentOperation,
      { "trafficDependentOperation", "itsis.trafficDependentOperation",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_standbyOperation,
      { "standbyOperation", "itsis.standbyOperation",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_failureMode,
      { "failureMode", "itsis.failureMode",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_off,
      { "off", "itsis.off",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_recentMAPmessageUpdate,
      { "recentMAPmessageUpdate", "itsis.recentMAPmessageUpdate",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_recentChangeInMAPassignedLanesIDsUsed,
      { "recentChangeInMAPassignedLanesIDsUsed", "itsis.recentChangeInMAPassignedLanesIDsUsed",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_noValidMAPisAvailableAtThisTime,
      { "noValidMAPisAvailableAtThisTime", "itsis.noValidMAPisAvailableAtThisTime",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_IntersectionStatusObject_noValidSPATisAvailableAtThisTime,
      { "noValidSPATisAvailableAtThisTime", "itsis.noValidSPATisAvailableAtThisTime",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_median_RevocableLane,
      { "median-RevocableLane", "itsis.median-RevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_median,
      { "median", "itsis.median",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_whiteLineHashing,
      { "whiteLineHashing", "itsis.whiteLineHashing",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_stripedLines,
      { "stripedLines", "itsis.stripedLines",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_doubleStripedLines,
      { "doubleStripedLines", "itsis.doubleStripedLines",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_trafficCones,
      { "trafficCones", "itsis.trafficCones",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_constructionBarrier,
      { "constructionBarrier", "itsis.constructionBarrier",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_trafficChannels,
      { "trafficChannels", "itsis.trafficChannels",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_lowCurbs,
      { "lowCurbs", "itsis.lowCurbs",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Barrier_highCurbs,
      { "highCurbs", "itsis.highCurbs",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Bike_bikeRevocableLane,
      { "bikeRevocableLane", "itsis.bikeRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Bike_pedestrianUseAllowed,
      { "pedestrianUseAllowed", "itsis.pedestrianUseAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Bike_isBikeFlyOverLane,
      { "isBikeFlyOverLane", "itsis.isBikeFlyOverLane",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Bike_fixedCycleTime,
      { "fixedCycleTime", "itsis.fixedCycleTime",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Bike_biDirectionalCycleTimes,
      { "biDirectionalCycleTimes", "itsis.biDirectionalCycleTimes",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Bike_isolatedByBarrier,
      { "isolatedByBarrier", "itsis.isolatedByBarrier",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Bike_unsignalizedSegmentsPresent,
      { "unsignalizedSegmentsPresent", "itsis.unsignalizedSegmentsPresent",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_crosswalkRevocableLane,
      { "crosswalkRevocableLane", "itsis.crosswalkRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_bicyleUseAllowed,
      { "bicyleUseAllowed", "itsis.bicyleUseAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_isXwalkFlyOverLane,
      { "isXwalkFlyOverLane", "itsis.isXwalkFlyOverLane",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_fixedCycleTime,
      { "fixedCycleTime", "itsis.fixedCycleTime",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_biDirectionalCycleTimes,
      { "biDirectionalCycleTimes", "itsis.biDirectionalCycleTimes",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_hasPushToWalkButton,
      { "hasPushToWalkButton", "itsis.hasPushToWalkButton",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_audioSupport,
      { "audioSupport", "itsis.audioSupport",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_rfSignalRequestPresent,
      { "rfSignalRequestPresent", "itsis.rfSignalRequestPresent",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Crosswalk_unsignalizedSegmentsPresent,
      { "unsignalizedSegmentsPresent", "itsis.unsignalizedSegmentsPresent",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Parking_parkingRevocableLane,
      { "parkingRevocableLane", "itsis.parkingRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Parking_parallelParkingInUse,
      { "parallelParkingInUse", "itsis.parallelParkingInUse",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Parking_headInParkingInUse,
      { "headInParkingInUse", "itsis.headInParkingInUse",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Parking_doNotParkZone,
      { "doNotParkZone", "itsis.doNotParkZone",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Parking_parkingForBusUse,
      { "parkingForBusUse", "itsis.parkingForBusUse",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Parking_parkingForTaxiUse,
      { "parkingForTaxiUse", "itsis.parkingForTaxiUse",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Parking_noPublicParkingUse,
      { "noPublicParkingUse", "itsis.noPublicParkingUse",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Sidewalk_sidewalk_RevocableLane,
      { "sidewalk-RevocableLane", "itsis.sidewalk-RevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Sidewalk_bicyleUseAllowed,
      { "bicyleUseAllowed", "itsis.bicyleUseAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Sidewalk_isSidewalkFlyOverLane,
      { "isSidewalkFlyOverLane", "itsis.isSidewalkFlyOverLane",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Sidewalk_walkBikes,
      { "walkBikes", "itsis.walkBikes",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Striping_stripeToConnectingLanesRevocableLane,
      { "stripeToConnectingLanesRevocableLane", "itsis.stripeToConnectingLanesRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Striping_stripeDrawOnLeft,
      { "stripeDrawOnLeft", "itsis.stripeDrawOnLeft",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Striping_stripeDrawOnRight,
      { "stripeDrawOnRight", "itsis.stripeDrawOnRight",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Striping_stripeToConnectingLanesLeft,
      { "stripeToConnectingLanesLeft", "itsis.stripeToConnectingLanesLeft",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Striping_stripeToConnectingLanesRight,
      { "stripeToConnectingLanesRight", "itsis.stripeToConnectingLanesRight",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Striping_stripeToConnectingLanesAhead,
      { "stripeToConnectingLanesAhead", "itsis.stripeToConnectingLanesAhead",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_TrackedVehicle_spec_RevocableLane,
      { "spec-RevocableLane", "itsis.spec-RevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_TrackedVehicle_spec_commuterRailRoadTrack,
      { "spec-commuterRailRoadTrack", "itsis.spec-commuterRailRoadTrack",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_TrackedVehicle_spec_lightRailRoadTrack,
      { "spec-lightRailRoadTrack", "itsis.spec-lightRailRoadTrack",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_TrackedVehicle_spec_heavyRailRoadTrack,
      { "spec-heavyRailRoadTrack", "itsis.spec-heavyRailRoadTrack",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_TrackedVehicle_spec_otherRailType,
      { "spec-otherRailType", "itsis.spec-otherRailType",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Vehicle_isVehicleRevocableLane,
      { "isVehicleRevocableLane", "itsis.isVehicleRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Vehicle_isVehicleFlyOverLane,
      { "isVehicleFlyOverLane", "itsis.isVehicleFlyOverLane",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Vehicle_hovLaneUseOnly,
      { "hovLaneUseOnly", "itsis.hovLaneUseOnly",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Vehicle_restrictedToBusUse,
      { "restrictedToBusUse", "itsis.restrictedToBusUse",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Vehicle_restrictedToTaxiUse,
      { "restrictedToTaxiUse", "itsis.restrictedToTaxiUse",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Vehicle_restrictedFromPublicUse,
      { "restrictedFromPublicUse", "itsis.restrictedFromPublicUse",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Vehicle_hasIRbeaconCoverage,
      { "hasIRbeaconCoverage", "itsis.hasIRbeaconCoverage",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_LaneAttributes_Vehicle_permissionOnRequest,
      { "permissionOnRequest", "itsis.permissionOnRequest",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_LaneDirection_ingressPath,
      { "ingressPath", "itsis.ingressPath",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LaneDirection_egressPath,
      { "egressPath", "itsis.egressPath",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_TransitVehicleStatus_loading,
      { "loading", "itsis.loading",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_TransitVehicleStatus_anADAuse,
      { "anADAuse", "itsis.anADAuse",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_TransitVehicleStatus_aBikeLoad,
      { "aBikeLoad", "itsis.aBikeLoad",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_TransitVehicleStatus_doorOpen,
      { "doorOpen", "itsis.doorOpen",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_TransitVehicleStatus_charging,
      { "charging", "itsis.charging",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_TransitVehicleStatus_atStopLine,
      { "atStopLine", "itsis.atStopLine",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_PMD_national_holiday,
      { "national-holiday", "itsis.national-holiday",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_PMD_even_days,
      { "even-days", "itsis.even-days",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_PMD_odd_days,
      { "odd-days", "itsis.odd-days",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_PMD_market_day,
      { "market-day", "itsis.market-day",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_DayOfWeek_unused,
      { "unused", "itsis.unused",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_DayOfWeek_monday,
      { "monday", "itsis.monday",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_DayOfWeek_tuesday,
      { "tuesday", "itsis.tuesday",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_DayOfWeek_wednesday,
      { "wednesday", "itsis.wednesday",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_DayOfWeek_thursday,
      { "thursday", "itsis.thursday",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_DayOfWeek_friday,
      { "friday", "itsis.friday",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_DayOfWeek_saturday,
      { "saturday", "itsis.saturday",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_DayOfWeek_sunday,
      { "sunday", "itsis.sunday",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_AccelerationControl_brakePedalEngaged,
      { "brakePedalEngaged", "itsis.brakePedalEngaged",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_AccelerationControl_gasPedalEngaged,
      { "gasPedalEngaged", "itsis.gasPedalEngaged",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_AccelerationControl_emergencyBrakeEngaged,
      { "emergencyBrakeEngaged", "itsis.emergencyBrakeEngaged",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_AccelerationControl_collisionWarningEngaged,
      { "collisionWarningEngaged", "itsis.collisionWarningEngaged",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_AccelerationControl_accEngaged,
      { "accEngaged", "itsis.accEngaged",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_AccelerationControl_cruiseControlEngaged,
      { "cruiseControlEngaged", "itsis.cruiseControlEngaged",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_AccelerationControl_speedLimiterEngaged,
      { "speedLimiterEngaged", "itsis.speedLimiterEngaged",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_ExteriorLights_lowBeamHeadlightsOn,
      { "lowBeamHeadlightsOn", "itsis.lowBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_ExteriorLights_highBeamHeadlightsOn,
      { "highBeamHeadlightsOn", "itsis.highBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_ExteriorLights_leftTurnSignalOn,
      { "leftTurnSignalOn", "itsis.leftTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_ExteriorLights_rightTurnSignalOn,
      { "rightTurnSignalOn", "itsis.rightTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_ExteriorLights_daytimeRunningLightsOn,
      { "daytimeRunningLightsOn", "itsis.daytimeRunningLightsOn",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_ExteriorLights_reverseLightOn,
      { "reverseLightOn", "itsis.reverseLightOn",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_ExteriorLights_fogLightOn,
      { "fogLightOn", "itsis.fogLightOn",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_ExteriorLights_parkingLightsOn,
      { "parkingLightsOn", "itsis.parkingLightsOn",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_SpecialTransportType_heavyLoad,
      { "heavyLoad", "itsis.heavyLoad",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_SpecialTransportType_excessWidth,
      { "excessWidth", "itsis.excessWidth",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_SpecialTransportType_excessLength,
      { "excessLength", "itsis.excessLength",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_SpecialTransportType_excessHeight,
      { "excessHeight", "itsis.excessHeight",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_LightBarSirenInUse_lightBarActivated,
      { "lightBarActivated", "itsis.lightBarActivated",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_LightBarSirenInUse_sirenActivated,
      { "sirenActivated", "itsis.sirenActivated",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row1LeftOccupied,
      { "row1LeftOccupied", "itsis.row1LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row1RightOccupied,
      { "row1RightOccupied", "itsis.row1RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row1MidOccupied,
      { "row1MidOccupied", "itsis.row1MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row1NotDetectable,
      { "row1NotDetectable", "itsis.row1NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row1NotPresent,
      { "row1NotPresent", "itsis.row1NotPresent",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row2LeftOccupied,
      { "row2LeftOccupied", "itsis.row2LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row2RightOccupied,
      { "row2RightOccupied", "itsis.row2RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row2MidOccupied,
      { "row2MidOccupied", "itsis.row2MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row2NotDetectable,
      { "row2NotDetectable", "itsis.row2NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row2NotPresent,
      { "row2NotPresent", "itsis.row2NotPresent",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row3LeftOccupied,
      { "row3LeftOccupied", "itsis.row3LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row3RightOccupied,
      { "row3RightOccupied", "itsis.row3RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row3MidOccupied,
      { "row3MidOccupied", "itsis.row3MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row3NotDetectable,
      { "row3NotDetectable", "itsis.row3NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row3NotPresent,
      { "row3NotPresent", "itsis.row3NotPresent",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row4LeftOccupied,
      { "row4LeftOccupied", "itsis.row4LeftOccupied",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row4RightOccupied,
      { "row4RightOccupied", "itsis.row4RightOccupied",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row4MidOccupied,
      { "row4MidOccupied", "itsis.row4MidOccupied",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row4NotDetectable,
      { "row4NotDetectable", "itsis.row4NotDetectable",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_PositionOfOccupants_row4NotPresent,
      { "row4NotPresent", "itsis.row4NotPresent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_EnergyStorageType_hydrogenStorage,
      { "hydrogenStorage", "itsis.hydrogenStorage",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_EnergyStorageType_electricEnergyStorage,
      { "electricEnergyStorage", "itsis.electricEnergyStorage",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_itsis_EnergyStorageType_liquidPropaneGas,
      { "liquidPropaneGas", "itsis.liquidPropaneGas",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_itsis_EnergyStorageType_compressedNaturalGas,
      { "compressedNaturalGas", "itsis.compressedNaturalGas",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_itsis_EnergyStorageType_diesel,
      { "diesel", "itsis.diesel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_itsis_EnergyStorageType_gasoline,
      { "gasoline", "itsis.gasoline",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_itsis_EnergyStorageType_ammonia,
      { "ammonia", "itsis.ammonia",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_itsis_EmergencyPriority_requestForRightOfWay,
      { "requestForRightOfWay", "itsis.requestForRightOfWay",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_itsis_EmergencyPriority_requestForFreeCrossingAtATrafficLight,
      { "requestForFreeCrossingAtATrafficLight", "itsis.requestForFreeCrossingAtATrafficLight",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

/*--- End of included file: packet-itsis-hfarr.c ---*/
#line 178 "./asn1/itsis/packet-itsis-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_itsis,

/*--- Included file: packet-itsis-ettarr.c ---*/
#line 1 "./asn1/itsis/packet-itsis-ettarr.c"
    &ett_itsis_IVIM,
    &ett_itsis_MAPEM,
    &ett_itsis_SPATEM,
    &ett_itsis_SREM,
    &ett_itsis_SSEM,
    &ett_itsis_CS5,
    &ett_itsis_AxleWeightLimits,
    &ett_itsis_DieselEmissionValues,
    &ett_itsis_T_particulate,
    &ett_itsis_EnvironmentalCharacteristics,
    &ett_itsis_ExhaustEmissionValues,
    &ett_itsis_PassengerCapacity,
    &ett_itsis_Provider,
    &ett_itsis_SoundLevel,
    &ett_itsis_VehicleDimensions,
    &ett_itsis_VehicleWeightLimits,
    &ett_itsis_AttributeIdList,
    &ett_itsis_AttributeList,
    &ett_itsis_Attributes,
    &ett_itsis_VarLengthNumber,
    &ett_itsis_Ext1,
    &ett_itsis_Ext2,
    &ett_itsis_ConnectionManeuverAssist_addGrpC,
    &ett_itsis_ConnectionTrajectory_addGrpC,
    &ett_itsis_Control_addGrpC,
    &ett_itsis_IntersectionState_addGrpC,
    &ett_itsis_MapData_addGrpC,
    &ett_itsis_Position3D_addGrpC,
    &ett_itsis_PrioritizationResponseList,
    &ett_itsis_PrioritizationResponse,
    &ett_itsis_RestrictionUserType_addGrpC,
    &ett_itsis_SignalHeadLocationList,
    &ett_itsis_SignalHeadLocation,
    &ett_itsis_SignalStatusPackage_addGrpC,
    &ett_itsis_VehicleToLanePositionList,
    &ett_itsis_VehicleToLanePosition,
    &ett_itsis_MessageFrame,
    &ett_itsis_RegionalExtension,
    &ett_itsis_SPAT,
    &ett_itsis_SEQUENCE_SIZE_1_4_OF_RegionalExtension,
    &ett_itsis_SignalRequestMessage,
    &ett_itsis_SignalStatusMessage,
    &ett_itsis_MapData,
    &ett_itsis_AdvisorySpeed,
    &ett_itsis_AdvisorySpeedList,
    &ett_itsis_ComputedLane,
    &ett_itsis_T_offsetXaxis,
    &ett_itsis_T_offsetYaxis,
    &ett_itsis_ConnectsToList,
    &ett_itsis_ConnectingLane,
    &ett_itsis_Connection,
    &ett_itsis_ConnectionManeuverAssist,
    &ett_itsis_DataParameters,
    &ett_itsis_EnabledLaneList,
    &ett_itsis_GenericLane,
    &ett_itsis_IntersectionAccessPoint,
    &ett_itsis_IntersectionGeometry,
    &ett_itsis_IntersectionGeometryList,
    &ett_itsis_IntersectionReferenceID,
    &ett_itsis_IntersectionState,
    &ett_itsis_IntersectionStateList,
    &ett_itsis_LaneAttributes,
    &ett_itsis_LaneDataAttribute,
    &ett_itsis_LaneDataAttributeList,
    &ett_itsis_LaneList,
    &ett_itsis_LaneSharing,
    &ett_itsis_LaneTypeAttributes,
    &ett_itsis_ManeuverAssistList,
    &ett_itsis_MovementEventList,
    &ett_itsis_MovementEvent,
    &ett_itsis_MovementList,
    &ett_itsis_MovementState,
    &ett_itsis_NodeAttributeSetXY,
    &ett_itsis_NodeAttributeXYList,
    &ett_itsis_Node_LLmD_64b,
    &ett_itsis_Node_XY_20b,
    &ett_itsis_Node_XY_22b,
    &ett_itsis_Node_XY_24b,
    &ett_itsis_Node_XY_26b,
    &ett_itsis_Node_XY_28b,
    &ett_itsis_Node_XY_32b,
    &ett_itsis_NodeListXY,
    &ett_itsis_NodeOffsetPointXY,
    &ett_itsis_NodeSetXY,
    &ett_itsis_NodeXY,
    &ett_itsis_OverlayLaneList,
    &ett_itsis_Position3D,
    &ett_itsis_PreemptPriorityList,
    &ett_itsis_RegulatorySpeedLimit,
    &ett_itsis_RequestorDescription,
    &ett_itsis_RequestorPositionVector,
    &ett_itsis_RequestorType,
    &ett_itsis_RestrictionClassAssignment,
    &ett_itsis_RestrictionClassList,
    &ett_itsis_RestrictionUserTypeList,
    &ett_itsis_RestrictionUserType,
    &ett_itsis_RoadLaneSetList,
    &ett_itsis_RoadSegmentReferenceID,
    &ett_itsis_RoadSegment,
    &ett_itsis_RoadSegmentList,
    &ett_itsis_SegmentAttributeXYList,
    &ett_itsis_SignalControlZone,
    &ett_itsis_SignalRequesterInfo,
    &ett_itsis_SignalRequestList,
    &ett_itsis_SignalRequestPackage,
    &ett_itsis_SignalRequest,
    &ett_itsis_SignalStatusList,
    &ett_itsis_SignalStatusPackageList,
    &ett_itsis_SignalStatusPackage,
    &ett_itsis_SignalStatus,
    &ett_itsis_SpeedLimitList,
    &ett_itsis_TimeChangeDetails,
    &ett_itsis_TransmissionAndSpeed,
    &ett_itsis_VehicleID,
    &ett_itsis_AllowedManeuvers,
    &ett_itsis_IntersectionStatusObject,
    &ett_itsis_LaneAttributes_Barrier,
    &ett_itsis_LaneAttributes_Bike,
    &ett_itsis_LaneAttributes_Crosswalk,
    &ett_itsis_LaneAttributes_Parking,
    &ett_itsis_LaneAttributes_Sidewalk,
    &ett_itsis_LaneAttributes_Striping,
    &ett_itsis_LaneAttributes_TrackedVehicle,
    &ett_itsis_LaneAttributes_Vehicle,
    &ett_itsis_LaneDirection,
    &ett_itsis_TransitVehicleStatus,
    &ett_itsis_IVI,
    &ett_itsis_IviStructure,
    &ett_itsis_SEQUENCE_SIZE_1_8__OF_IviContainer,
    &ett_itsis_IviContainer,
    &ett_itsis_IVIManagementContainer,
    &ett_itsis_SEQUENCE_SIZE_1_8_OF_IviIdentificationNumber,
    &ett_itsis_GeographicLocationContainer,
    &ett_itsis_SEQUENCE_SIZE_1_16__OF_GlcPart,
    &ett_itsis_GlcPart,
    &ett_itsis_GeneralIviContainer,
    &ett_itsis_GicPart,
    &ett_itsis_SEQUENCE_SIZE_1_8__OF_Zid,
    &ett_itsis_SEQUENCE_SIZE_1_8__OF_LanePosition,
    &ett_itsis_SEQUENCE_SIZE_1_8__OF_CompleteVehicleCharacteristics,
    &ett_itsis_SEQUENCE_SIZE_1_4__OF_RSCode,
    &ett_itsis_SEQUENCE_SIZE_1_4__OF_Text,
    &ett_itsis_RoadConfigurationContainer,
    &ett_itsis_RccPart,
    &ett_itsis_SEQUENCE_SIZE_1_16__OF_LaneInformation,
    &ett_itsis_TextContainer,
    &ett_itsis_TcPart,
    &ett_itsis_LayoutContainer,
    &ett_itsis_SEQUENCE_SIZE_1_4__OF_LayoutComponent,
    &ett_itsis_AbsolutePosition,
    &ett_itsis_AbsolutePositionWAltitude,
    &ett_itsis_AnyCatalogue,
    &ett_itsis_CompleteVehicleCharacteristics,
    &ett_itsis_SEQUENCE_SIZE_1_3_OF_TrailerCharacteristics,
    &ett_itsis_ComputedSegment,
    &ett_itsis_DeltaPosition,
    &ett_itsis_Distance,
    &ett_itsis_DistanceOrDuration,
    &ett_itsis_ISO14823Attributes,
    &ett_itsis_ISO14823Attributes_item,
    &ett_itsis_ISO14823Code,
    &ett_itsis_T_pictogramCode,
    &ett_itsis_T_serviceCategoryCode,
    &ett_itsis_T_pictogramCategoryCode,
    &ett_itsis_LaneInformation,
    &ett_itsis_LayoutComponent,
    &ett_itsis_LoadType,
    &ett_itsis_PolygonalLine,
    &ett_itsis_SEQUENCE_SIZE_1_32__OF_DeltaPosition,
    &ett_itsis_SEQUENCE_SIZE_1_32__OF_DeltaReferencePosition,
    &ett_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePosition,
    &ett_itsis_SEQUENCE_SIZE_1_8__OF_AbsolutePositionWAltitude,
    &ett_itsis_RSCode,
    &ett_itsis_T_code,
    &ett_itsis_Segment,
    &ett_itsis_Text,
    &ett_itsis_TractorCharacteristics,
    &ett_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsFixValues,
    &ett_itsis_SEQUENCE_SIZE_1_4__OF_VehicleCharacteristicsRanges,
    &ett_itsis_TrailerCharacteristics,
    &ett_itsis_VcCode,
    &ett_itsis_SEQUENCE_SIZE_1_8__OF_DTM,
    &ett_itsis_VehicleCharacteristicsFixValues,
    &ett_itsis_VehicleCharacteristicsRanges,
    &ett_itsis_T_limits,
    &ett_itsis_Weight,
    &ett_itsis_Zone,
    &ett_itsis_DTM,
    &ett_itsis_T_year,
    &ett_itsis_T_month_day,
    &ett_itsis_T_hourMinutes,
    &ett_itsis_MonthDay,
    &ett_itsis_PMD,
    &ett_itsis_HoursMinutes,
    &ett_itsis_DayOfWeek,
    &ett_itsis_VED,
    &ett_itsis_SPE,
    &ett_itsis_DDD,
    &ett_itsis_SEQUENCE_SIZE_1_8__OF_DDD_IO,
    &ett_itsis_DDD_IO,
    &ett_itsis_SEQUENCE_SIZE_1_4__OF_DestinationPlace,
    &ett_itsis_SEQUENCE_SIZE_1_4__OF_DestinationRoad,
    &ett_itsis_DestinationPlace,
    &ett_itsis_DestinationRoad,
    &ett_itsis_EuVehicleCategoryCode,
    &ett_itsis_ItsPduHeader,
    &ett_itsis_ReferencePosition,
    &ett_itsis_DeltaReferencePosition,
    &ett_itsis_Altitude,
    &ett_itsis_PosConfidenceEllipse,
    &ett_itsis_PathPoint,
    &ett_itsis_PtActivation,
    &ett_itsis_AccelerationControl,
    &ett_itsis_CauseCode,
    &ett_itsis_Curvature,
    &ett_itsis_Heading,
    &ett_itsis_ClosedLanes,
    &ett_itsis_Speed,
    &ett_itsis_LongitudinalAcceleration,
    &ett_itsis_LateralAcceleration,
    &ett_itsis_VerticalAcceleration,
    &ett_itsis_ExteriorLights,
    &ett_itsis_DangerousGoodsExtended,
    &ett_itsis_SpecialTransportType,
    &ett_itsis_LightBarSirenInUse,
    &ett_itsis_PositionOfOccupants,
    &ett_itsis_VehicleIdentification,
    &ett_itsis_EnergyStorageType,
    &ett_itsis_VehicleLength,
    &ett_itsis_PathHistory,
    &ett_itsis_EmergencyPriority,
    &ett_itsis_SteeringWheelAngle,
    &ett_itsis_YawRate,
    &ett_itsis_ActionID,
    &ett_itsis_ItineraryPath,
    &ett_itsis_ProtectedCommunicationZone,
    &ett_itsis_Traces,
    &ett_itsis_PositionOfPillars,
    &ett_itsis_RestrictedTypes,
    &ett_itsis_EventHistory,
    &ett_itsis_EventPoint,
    &ett_itsis_ProtectedCommunicationZonesRSU,
    &ett_itsis_CenDsrcTollingZone,

/*--- End of included file: packet-itsis-ettarr.c ---*/
#line 184 "./asn1/itsis/packet-itsis-template.c"
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

