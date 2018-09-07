# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME itsis )

set( PROTO_OPT )

set( EXPORT_FILES
	${PROTOCOL_NAME}-exp.cnf
)

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	ITS-Container.asn
	ETSI_TS_103301_IVIM_PDU_Descriptions.asn
	ISO_TS_14816.asn
	ISO_TS_19091_DSRC.asn
	ETSI_TS_103301_MAPEM_PDU_Descriptions.asn
	ISO_TS_14906_Application.asn
	ISO_TS_19091_REGION.asn
	ETSI_TS_103301_SPATEM_PDU_Descriptions.asn
	ISO_TS_14906_Generic.asn
	ISO_TS_19321.asn
	ETSI_TS_103301_SREM_PDU_Descriptions.asn
	ISO_TS_17419.asn
	ISO_TS_24534-3.asn
	ETSI_TS_103301_SSEM_PDU_Descriptions.asn
	ISO_TS_19091_AddGrpC.asn
)

set( EXTRA_DIST
	${ASN_FILE_LIST}
	packet-${PROTOCOL_NAME}-template.c
	${PROTOCOL_NAME}.cnf
)

set( SRC_FILES
	${EXTRA_DIST}
	${EXT_ASN_FILE_LIST}
)

set_source_files_properties(
        ${CLEAN_FILES}
        PROPERTIES
        COMPILE_FLAGS "${WERROR_COMMON_FLAGS}" -Wno-unused-function -Wno-unused-const-variable
)

set( A2W_FLAGS -u -L )

set( EXTRA_CNF
)

ASN2WRS()
