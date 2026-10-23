/*
 * clip_notes_client.c — CLICOM Client-Side Notes & Session Logs Network API
 */

#include "clip_notes_client.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ClipError clip_client_list_session_logs(ClipClientNet*        net,
                                        ClipSessionLogEntry** out_entries,
                                        size_t*               out_count)
{
    if (!net || !net->is_connected || !net->is_registered || !out_entries || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_entries = NULL;
    *out_count = 0;

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_LOG_LIST_REQ, 0, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, NULL);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[16384];
    uint32_t rx_len = 0;

    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_SESSION_LOG_LIST_RESP || rx_hdr.msg_type == CLIP_MSG_NOTE_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_NOTE_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_SESSION_LOG_LIST_RESP) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* cnt_ptr = NULL;
    uint16_t cnt_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_LOG_COUNT, &cnt_ptr, &cnt_len);
    size_t count = 0;
    if (cnt_ptr && cnt_len == 2) {
        count = ((size_t)cnt_ptr[0] << 8) | (size_t)cnt_ptr[1];
    }

    if (count == 0) {
        return CLIP_OK;
    }

    ClipSessionLogEntry* list = (ClipSessionLogEntry*)calloc(count, sizeof(ClipSessionLogEntry));
    if (!list) return CLIP_ERR_NOMEM;

    size_t offset = 0;
    size_t parsed = 0;

    /* Skip initial count TLV */
    if (offset + CLIP_TLV_HEADER_SIZE <= rx_len) {
        uint16_t first_tag = ((uint16_t)rx_payload[offset] << 8) | (uint16_t)rx_payload[offset + 1];
        if (first_tag == CLIP_TAG_LOG_COUNT) {
            uint16_t vlen = ((uint16_t)rx_payload[offset + 2] << 8) | (uint16_t)rx_payload[offset + 3];
            offset += CLIP_TLV_HEADER_SIZE + vlen;
        }
    }

    while (offset + CLIP_TLV_HEADER_SIZE <= rx_len && parsed < count) {
        uint16_t tag = ((uint16_t)rx_payload[offset] << 8) | (uint16_t)rx_payload[offset + 1];
        uint16_t val_len = ((uint16_t)rx_payload[offset + 2] << 8) | (uint16_t)rx_payload[offset + 3];
        offset += CLIP_TLV_HEADER_SIZE;
        if (offset + val_len > rx_len) break;
        const uint8_t* val_ptr = rx_payload + offset;

        if (tag == CLIP_TAG_SESSION_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].session_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_CHANNEL_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].channel_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_CONNECTION_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].connection_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_NODE_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].initiator_node_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_TARGET_NODE_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].peer_node_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_SESSION_STATE && val_len == 1) {
            list[parsed].state = val_ptr[0];
        } else if (tag == CLIP_TAG_TIMESTAMP_MS && val_len == 8) {
            uint64_t ts = 0;
            for (int b = 0; b < 8; b++) ts = (ts << 8) | val_ptr[b];
            list[parsed].created_at = ts;
        } else if (tag == CLIP_TAG_DURATION_MS && val_len == 8) {
            uint64_t dur = 0;
            for (int b = 0; b < 8; b++) dur = (dur << 8) | val_ptr[b];
            list[parsed].duration_ms = dur;
        } else if (tag == CLIP_TAG_NOTE_COUNT && val_len == 2) {
            list[parsed].note_count = ((uint32_t)val_ptr[0] << 8) | (uint32_t)val_ptr[1];
            parsed++;
        }

        offset += val_len;
    }

    *out_entries = list;
    *out_count = parsed;
    return CLIP_OK;
}

void clip_client_free_session_logs(ClipSessionLogEntry* entries)
{
    if (entries) {
        free(entries);
    }
}

ClipError clip_client_get_session_log(ClipClientNet*       net,
                                      const ClipUuid*      session_uuid,
                                      ClipSessionLogEntry* out_entry)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid || !out_entry) {
        return CLIP_ERR_INVALID;
    }
    memset(out_entry, 0, sizeof(ClipSessionLogEntry));

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_LOG_GET_REQ, (uint32_t)payload_len, ++net->seq_counter, session_uuid->bytes);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[1024];
    uint32_t rx_len = 0;

    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_SESSION_LOG_GET_RESP || rx_hdr.msg_type == CLIP_MSG_NOTE_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_NOTE_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_SESSION_LOG_GET_RESP) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* val_ptr = NULL;
    uint16_t val_len = 0;

    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_SESSION_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        memcpy(out_entry->session_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    }
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CHANNEL_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        memcpy(out_entry->channel_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    }
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CONNECTION_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        memcpy(out_entry->connection_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    }
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        memcpy(out_entry->initiator_node_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    }
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_TARGET_NODE_UUID, &val_ptr, &val_len) == CLIP_OK && val_len == CLIP_UUID_BYTES) {
        memcpy(out_entry->peer_node_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    }
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_SESSION_STATE, &val_ptr, &val_len) == CLIP_OK && val_len == 1) {
        out_entry->state = *val_ptr;
    }
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_TIMESTAMP_MS, &val_ptr, &val_len) == CLIP_OK && val_len == 8) {
        uint64_t ts = 0;
        for (int b = 0; b < 8; b++) ts = (ts << 8) | val_ptr[b];
        out_entry->created_at = ts;
    }
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_DURATION_MS, &val_ptr, &val_len) == CLIP_OK && val_len == 8) {
        uint64_t dur = 0;
        for (int b = 0; b < 8; b++) dur = (dur << 8) | val_ptr[b];
        out_entry->duration_ms = dur;
    }
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NOTE_COUNT, &val_ptr, &val_len) == CLIP_OK && val_len == 2) {
        out_entry->note_count = ((uint32_t)val_ptr[0] << 8) | (uint32_t)val_ptr[1];
    }

    return CLIP_OK;
}

ClipError clip_client_create_note(ClipClientNet*   net,
                                  const ClipUuid*  session_uuid,
                                  ClipNoteType     note_type,
                                  const char*      note_text,
                                  uint32_t*        out_note_id)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid || !note_text) {
        return CLIP_ERR_INVALID;
    }

    size_t text_len = strlen(note_text);
    if (text_len == 0 || text_len > CLIP_NOTE_TEXT_MAX_LEN) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[2048];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_NOTE_TEXT, note_text, (uint16_t)text_len);
    uint8_t tb = (uint8_t)note_type;
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_NOTE_TYPE, &tb, 1);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_NOTE_CREATE, (uint32_t)payload_len, ++net->seq_counter, session_uuid->bytes);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[512];
    uint32_t rx_len = 0;

    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_NOTE_CREATE_OK || rx_hdr.msg_type == CLIP_MSG_NOTE_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_NOTE_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_NOTE_CREATE_OK) {
        return CLIP_ERR_PROTO;
    }

    if (out_note_id) {
        const uint8_t* nid_ptr = NULL;
        uint16_t nid_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NOTE_ID, &nid_ptr, &nid_len) == CLIP_OK && nid_len == 4) {
            *out_note_id = ((uint32_t)nid_ptr[0] << 24) | ((uint32_t)nid_ptr[1] << 16) |
                           ((uint32_t)nid_ptr[2] << 8) | (uint32_t)nid_ptr[3];
        }
    }

    return CLIP_OK;
}

ClipError clip_client_list_notes(ClipClientNet*          net,
                                 const ClipUuid*         session_uuid,
                                 const char*             query,
                                 ClipSessionNoteEntry**  out_notes,
                                 size_t*                 out_count)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid || !out_notes || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_notes = NULL;
    *out_count = 0;

    uint8_t payload[512];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);
    if (query && query[0] != '\0') {
        clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_NOTE_TEXT, query, (uint16_t)strlen(query));
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_NOTE_LIST_REQ, (uint32_t)payload_len, ++net->seq_counter, session_uuid->bytes);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[32768];
    uint32_t rx_len = 0;

    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_NOTE_LIST_RESP || rx_hdr.msg_type == CLIP_MSG_NOTE_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_NOTE_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_NOTE_LIST_RESP) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* cnt_ptr = NULL;
    uint16_t cnt_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NOTE_COUNT, &cnt_ptr, &cnt_len);
    size_t count = 0;
    if (cnt_ptr && cnt_len == 2) {
        count = ((size_t)cnt_ptr[0] << 8) | (size_t)cnt_ptr[1];
    }

    if (count == 0) {
        return CLIP_OK;
    }

    ClipSessionNoteEntry* list = (ClipSessionNoteEntry*)calloc(count, sizeof(ClipSessionNoteEntry));
    if (!list) return CLIP_ERR_NOMEM;

    size_t offset = 0;
    size_t parsed = 0;

    /* Skip leading session_uuid and note_count tags */
    while (offset + CLIP_TLV_HEADER_SIZE <= rx_len) {
        uint16_t tag = ((uint16_t)rx_payload[offset] << 8) | (uint16_t)rx_payload[offset + 1];
        uint16_t val_len = ((uint16_t)rx_payload[offset + 2] << 8) | (uint16_t)rx_payload[offset + 3];
        if (tag == CLIP_TAG_NOTE_ID) {
            break;
        }
        offset += CLIP_TLV_HEADER_SIZE + val_len;
    }

    while (offset + CLIP_TLV_HEADER_SIZE <= rx_len && parsed < count) {
        uint16_t tag = ((uint16_t)rx_payload[offset] << 8) | (uint16_t)rx_payload[offset + 1];
        uint16_t val_len = ((uint16_t)rx_payload[offset + 2] << 8) | (uint16_t)rx_payload[offset + 3];
        offset += CLIP_TLV_HEADER_SIZE;
        if (offset + val_len > rx_len) break;
        const uint8_t* val_ptr = rx_payload + offset;

        if (tag == CLIP_TAG_NOTE_ID && val_len == 4) {
            list[parsed].note_id = ((uint32_t)val_ptr[0] << 24) | ((uint32_t)val_ptr[1] << 16) |
                                   ((uint32_t)val_ptr[2] << 8) | (uint32_t)val_ptr[3];
            memcpy(list[parsed].session_uuid.bytes, session_uuid->bytes, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_NOTE_AUTHOR_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].author_node_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_NOTE_TYPE && val_len == 1) {
            list[parsed].note_type = (ClipNoteType)val_ptr[0];
        } else if (tag == CLIP_TAG_TIMESTAMP_MS && val_len == 8) {
            uint64_t ts = 0;
            for (int b = 0; b < 8; b++) ts = (ts << 8) | val_ptr[b];
            list[parsed].created_at = ts;
        } else if (tag == CLIP_TAG_NOTE_TEXT) {
            size_t copy_len = (val_len < CLIP_NOTE_TEXT_MAX_LEN) ? val_len : CLIP_NOTE_TEXT_MAX_LEN;
            memcpy(list[parsed].note_text, val_ptr, copy_len);
            list[parsed].note_text[copy_len] = '\0';
            parsed++;
        }

        offset += val_len;
    }

    *out_notes = list;
    *out_count = parsed;
    return CLIP_OK;
}

void clip_client_free_notes(ClipSessionNoteEntry* notes)
{
    if (notes) {
        free(notes);
    }
}
