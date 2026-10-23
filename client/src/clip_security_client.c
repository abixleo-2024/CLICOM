/*
 * clip_security_client.c — CLICOM Client-Side Security Analysis Network API
 */

#include "clip_security_client.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ClipError clip_client_submit_security_transcript(ClipClientNet*  net,
                                                 const ClipUuid* session_uuid,
                                                 const ClipUuid* speaker_uuid,
                                                 const char*     transcript_text,
                                                 uint64_t        timestamp_ms)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid || !transcript_text) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[1024];
    size_t offset = 0;

    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);
    if (speaker_uuid && !clip_uuid_is_zero(speaker_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NODE_UUID, speaker_uuid->bytes, CLIP_UUID_BYTES);
    } else {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NODE_UUID, net->assigned_uuid, CLIP_UUID_BYTES);
    }

    uint8_t ts_buf[8];
    for (int b = 0; b < 8; b++) {
        ts_buf[b] = (uint8_t)((timestamp_ms >> (56 - b * 8)) & 0xFF);
    }
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);

    uint16_t txt_len = (uint16_t)strlen(transcript_text);
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_TRANSCRIPT_TEXT, (const uint8_t*)transcript_text, txt_len);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SECURITY_TRANSCRIPT, (uint32_t)offset, ++net->seq_counter, session_uuid->bytes);

    return clip_client_send_frame(net, &tx_hdr, payload);
}

ClipError clip_client_list_security_events(ClipClientNet*      net,
                                           const ClipUuid*     session_uuid,
                                           ClipSecurityEvent** out_events,
                                           size_t*             out_count)
{
    if (!net || !net->is_connected || !net->is_registered || !out_events || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_events = NULL;
    *out_count = 0;

    uint8_t payload[64];
    size_t offset = 0;
    if (session_uuid && !clip_uuid_is_zero(session_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr,
                           CLIP_MSG_SECURITY_EVENT_LIST_REQ,
                           (uint32_t)offset,
                           ++net->seq_counter,
                           (session_uuid && !clip_uuid_is_zero(session_uuid)) ? session_uuid->bytes : NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, offset > 0 ? payload : NULL);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[16384];
    uint32_t rx_len = 0;

    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_SECURITY_EVENT_LIST_RESP ||
            rx_hdr.msg_type == CLIP_MSG_SECURITY_EVENT_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_SECURITY_EVENT_FAIL || rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_SECURITY_EVENT_LIST_RESP) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* cnt_ptr = NULL;
    uint16_t cnt_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_EVENT_COUNT, &cnt_ptr, &cnt_len);
    size_t count = 0;
    if (cnt_ptr && cnt_len == 2) {
        count = ((size_t)cnt_ptr[0] << 8) | (size_t)cnt_ptr[1];
    }

    if (count == 0) {
        return CLIP_OK;
    }

    ClipSecurityEvent* list = (ClipSecurityEvent*)calloc(count, sizeof(ClipSecurityEvent));
    if (!list) return CLIP_ERR_NOMEM;

    size_t parse_offset = 0;
    size_t parsed = 0;

    /* Skip leading session_uuid and event_count tags */
    while (parse_offset + CLIP_TLV_HEADER_SIZE <= rx_len) {
        uint16_t tag = ((uint16_t)rx_payload[parse_offset] << 8) | (uint16_t)rx_payload[parse_offset + 1];
        uint16_t val_len = ((uint16_t)rx_payload[parse_offset + 2] << 8) | (uint16_t)rx_payload[parse_offset + 3];
        if (tag == CLIP_TAG_EVENT_UUID) {
            break;
        }
        parse_offset += CLIP_TLV_HEADER_SIZE + val_len;
    }

    while (parse_offset + CLIP_TLV_HEADER_SIZE <= rx_len && parsed < count) {
        uint16_t tag = ((uint16_t)rx_payload[parse_offset] << 8) | (uint16_t)rx_payload[parse_offset + 1];
        uint16_t val_len = ((uint16_t)rx_payload[parse_offset + 2] << 8) | (uint16_t)rx_payload[parse_offset + 3];
        parse_offset += CLIP_TLV_HEADER_SIZE;
        if (parse_offset + val_len > rx_len) break;
        const uint8_t* val_ptr = rx_payload + parse_offset;

        if (tag == CLIP_TAG_EVENT_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].event_uuid, val_ptr, CLIP_UUID_BYTES);
            ClipUuid u;
            memcpy(u.bytes, val_ptr, CLIP_UUID_BYTES);
            clip_uuid_to_string(&u, list[parsed].event_uuid_str, sizeof(list[parsed].event_uuid_str));
        } else if (tag == CLIP_TAG_EVENT_ID && val_len == 4) {
            list[parsed].event_id = ((uint32_t)val_ptr[0] << 24) | ((uint32_t)val_ptr[1] << 16) |
                                    ((uint32_t)val_ptr[2] << 8) | (uint32_t)val_ptr[3];
        } else if (tag == CLIP_TAG_SESSION_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].session_uuid, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_CHANNEL_UUID && val_len == CLIP_UUID_BYTES) {
            ClipUuid u;
            memcpy(u.bytes, val_ptr, CLIP_UUID_BYTES);
            clip_uuid_to_string(&u, list[parsed].channel_uuid_str, sizeof(list[parsed].channel_uuid_str));
        } else if (tag == CLIP_TAG_NODE_UUID && val_len == CLIP_UUID_BYTES) {
            ClipUuid u;
            memcpy(u.bytes, val_ptr, CLIP_UUID_BYTES);
            clip_uuid_to_string(&u, list[parsed].node_uuid_str, sizeof(list[parsed].node_uuid_str));
        } else if (tag == CLIP_TAG_TIMESTAMP_MS && val_len == 8) {
            uint64_t ts = 0;
            for (int b = 0; b < 8; b++) ts = (ts << 8) | val_ptr[b];
            list[parsed].timestamp_ms = ts;
        } else if (tag == CLIP_TAG_CATEGORY && val_len == 1) {
            list[parsed].category = (ClipSecurityCategory)val_ptr[0];
        } else if (tag == CLIP_TAG_SEVERITY && val_len == 1) {
            list[parsed].severity = (ClipSecuritySeverity)val_ptr[0];
        } else if (tag == CLIP_TAG_MATCHED_RULE) {
            size_t cpy = (val_len < sizeof(list[parsed].matched_rule) - 1) ? val_len : sizeof(list[parsed].matched_rule) - 1;
            memcpy(list[parsed].matched_rule, val_ptr, cpy);
            list[parsed].matched_rule[cpy] = '\0';
        } else if (tag == CLIP_TAG_MATCHED_TEXT) {
            size_t cpy = (val_len < sizeof(list[parsed].matched_term) - 1) ? val_len : sizeof(list[parsed].matched_term) - 1;
            memcpy(list[parsed].matched_term, val_ptr, cpy);
            list[parsed].matched_term[cpy] = '\0';
        } else if (tag == CLIP_TAG_CONTEXT_TEXT) {
            size_t cpy = (val_len < sizeof(list[parsed].context_text) - 1) ? val_len : sizeof(list[parsed].context_text) - 1;
            memcpy(list[parsed].context_text, val_ptr, cpy);
            list[parsed].context_text[cpy] = '\0';
        } else if (tag == CLIP_TAG_EVENT_STATUS && val_len == 1) {
            list[parsed].status = (ClipSecurityEventStatus)val_ptr[0];
            parsed++;
        }

        parse_offset += val_len;
    }

    *out_events = list;
    *out_count = parsed;
    return CLIP_OK;
}

void clip_client_free_security_events(ClipSecurityEvent* events, size_t count)
{
    (void)count;
    if (events) {
        free(events);
    }
}

ClipError clip_client_get_security_event(ClipClientNet*     net,
                                         uint32_t           event_id,
                                         const ClipUuid*    event_uuid,
                                         ClipSecurityEvent* out_event)
{
    if (!net || !net->is_connected || !net->is_registered || !out_event) {
        return CLIP_ERR_INVALID;
    }
    if (event_id == 0 && (!event_uuid || clip_uuid_is_zero(event_uuid))) {
        return CLIP_ERR_INVALID;
    }

    memset(out_event, 0, sizeof(ClipSecurityEvent));

    uint8_t payload[128];
    size_t offset = 0;

    if (event_id > 0) {
        uint8_t id_buf[4] = {
            (uint8_t)((event_id >> 24) & 0xFF),
            (uint8_t)((event_id >> 16) & 0xFF),
            (uint8_t)((event_id >> 8) & 0xFF),
            (uint8_t)(event_id & 0xFF)
        };
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_EVENT_ID, id_buf, 4);
    }
    if (event_uuid && !clip_uuid_is_zero(event_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_EVENT_UUID, event_uuid->bytes, CLIP_UUID_BYTES);
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SECURITY_EVENT_GET_REQ, (uint32_t)offset, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[1024];
    uint32_t rx_len = 0;

    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_SECURITY_EVENT_GET_RESP ||
            rx_hdr.msg_type == CLIP_MSG_SECURITY_EVENT_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_SECURITY_EVENT_FAIL || rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_SECURITY_EVENT_GET_RESP) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* val_ptr = NULL;
    uint16_t val_len = 0;

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_EVENT_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        memcpy(out_event->event_uuid, val_ptr, CLIP_UUID_BYTES);
        ClipUuid u;
        memcpy(u.bytes, val_ptr, CLIP_UUID_BYTES);
        clip_uuid_to_string(&u, out_event->event_uuid_str, sizeof(out_event->event_uuid_str));
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_EVENT_ID, &val_ptr, &val_len) == CLIP_OK && val_len == 4) {
        out_event->event_id = ((uint32_t)val_ptr[0] << 24) | ((uint32_t)val_ptr[1] << 16) |
                              ((uint32_t)val_ptr[2] << 8) | (uint32_t)val_ptr[3];
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_SESSION_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        memcpy(out_event->session_uuid, val_ptr, CLIP_UUID_BYTES);
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CHANNEL_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        ClipUuid u;
        memcpy(u.bytes, val_ptr, CLIP_UUID_BYTES);
        clip_uuid_to_string(&u, out_event->channel_uuid_str, sizeof(out_event->channel_uuid_str));
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        ClipUuid u;
        memcpy(u.bytes, val_ptr, CLIP_UUID_BYTES);
        clip_uuid_to_string(&u, out_event->node_uuid_str, sizeof(out_event->node_uuid_str));
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_TIMESTAMP_MS, &val_ptr, &val_len) == CLIP_OK && val_len == 8) {
        uint64_t ts = 0;
        for (int b = 0; b < 8; b++) ts = (ts << 8) | val_ptr[b];
        out_event->timestamp_ms = ts;
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CATEGORY, &val_ptr, &val_len) == CLIP_OK && val_len == 1) {
        out_event->category = (ClipSecurityCategory)val_ptr[0];
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_SEVERITY, &val_ptr, &val_len) == CLIP_OK && val_len == 1) {
        out_event->severity = (ClipSecuritySeverity)val_ptr[0];
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_MATCHED_RULE, &val_ptr, &val_len) == CLIP_OK) {
        size_t cpy = (val_len < sizeof(out_event->matched_rule) - 1) ? val_len : sizeof(out_event->matched_rule) - 1;
        memcpy(out_event->matched_rule, val_ptr, cpy);
        out_event->matched_rule[cpy] = '\0';
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_MATCHED_TEXT, &val_ptr, &val_len) == CLIP_OK) {
        size_t cpy = (val_len < sizeof(out_event->matched_term) - 1) ? val_len : sizeof(out_event->matched_term) - 1;
        memcpy(out_event->matched_term, val_ptr, cpy);
        out_event->matched_term[cpy] = '\0';
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CONTEXT_TEXT, &val_ptr, &val_len) == CLIP_OK) {
        size_t cpy = (val_len < sizeof(out_event->context_text) - 1) ? val_len : sizeof(out_event->context_text) - 1;
        memcpy(out_event->context_text, val_ptr, cpy);
        out_event->context_text[cpy] = '\0';
    }

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_EVENT_STATUS, &val_ptr, &val_len) == CLIP_OK && val_len == 1) {
        out_event->status = (ClipSecurityEventStatus)val_ptr[0];
    }

    return CLIP_OK;
}
