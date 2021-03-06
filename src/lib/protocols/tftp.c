/*
 * tftp.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_TFTP

static void ndpi_int_tftp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct,
					 struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TFTP,
				NDPI_REAL_PROTOCOL);
}

void ndpi_search_tftp(struct ndpi_detection_module_struct
		      *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG,
		 "search TFTP.\n");

	if (packet->payload_packet_len > 3 && flow->l4.udp.tftp_stage == 0
	    && ntohl(get_u_int32_t(packet->payload, 0)) == 0x00030001) {
		NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG,
			 "maybe tftp. need next packet.\n");
		flow->l4.udp.tftp_stage = 1;
		return;
	}
	if (packet->payload_packet_len > 3 && (flow->l4.udp.tftp_stage == 1)
	    && ntohl(get_u_int32_t(packet->payload, 0)) == 0x00040001) {

		NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG,
			 "found tftp.\n");
		ndpi_int_tftp_add_connection(ndpi_struct, flow);
		return;
	}
	if (packet->payload_packet_len > 1
	    &&
	    ((packet->payload[0] == 0
	      && packet->payload[packet->payload_packet_len - 1] == 0)
	     || (packet->payload_packet_len == 4
		 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x00040000))) {
		NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG,
			 "skip initial packet.\n");
		return;
	}

	NDPI_LOG(NDPI_PROTOCOL_TFTP, ndpi_struct, NDPI_LOG_DEBUG,
		 "exclude TFTP.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask,
				     NDPI_PROTOCOL_TFTP);
}
#endif
