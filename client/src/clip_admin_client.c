/*
 * clip_admin_client.c — CLICOM Client-Side Administrative Network API
 */

#include "clip_admin_client.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

ClipError clip_admin_client_login(ClipClientNet*       net,
                                  const char*          username,
                                  const char*          password,
                                  ClipAdminPermission* out_role,
                                  ClipUuid*            out_admin_uuid)
{
    if (!net || !net->is_connected || !username || !password) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[512];
    size_t offset = 0;

    clip_tlv_write(payload, sizeof(payload), &offset,
                   CLIP_TAG_ADMIN_USERNAME, (const uint8_t*)username, (uint16_t)strlen(username));
    clip_tlv_write(payload, sizeof(payload), &offset,
                   CLIP_TAG_TEXT, (const uint8_t*)password, (uint16_t)strlen(password));

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_AUTH_REQ, (uint32_t)offset, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    OPENSSL_cleanse(payload, sizeof(payload));
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[1024];
    uint32_t rx_len = 0;

    while (1) {
        ClipError recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_ADMIN_AUTH_RESP ||
            rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
        return CLIP_ERR_AUTH;
    }

    /* Check status TLV or error code */
    const uint8_t* st_ptr = NULL;
    uint16_t st_len = 0;
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_AUTH_STATUS, &st_ptr, &st_len) == CLIP_OK && st_len == 2) {
        uint16_t code = ((uint16_t)st_ptr[0] << 8) | (uint16_t)st_ptr[1];
        if (code != 0) {
            return (ClipError)(-((int)code));
        }
    }

    if (out_role) {
        const uint8_t* r_ptr = NULL;
        uint16_t r_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_PERMISSION_LEVEL, &r_ptr, &r_len) == CLIP_OK && r_len >= 1) {
            *out_role = (ClipAdminPermission)r_ptr[0];
        } else {
            *out_role = CLIP_ADMIN_PERM_NONE;
        }
    }

    if (out_admin_uuid) {
        const uint8_t* u_ptr = NULL;
        uint16_t u_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NODE_UUID, &u_ptr, &u_len) == CLIP_OK && u_len == CLIP_UUID_BYTES) {
            memcpy(out_admin_uuid->bytes, u_ptr, CLIP_UUID_BYTES);
        } else {
            memset(out_admin_uuid->bytes, 0, CLIP_UUID_BYTES);
        }
    }

    return CLIP_OK;
}

ClipError clip_admin_client_send_action(ClipClientNet*           net,
                                        ClipAdminActionType      action_type,
                                        const ClipUuid*          target_uuid,
                                        const char*              reason,
                                        uint32_t                 related_event_id,
                                        const ClipUuid*          related_session_uuid,
                                        const ClipUuid*          related_channel_uuid,
                                        uint32_t*                out_audit_id)
{
    if (!net || !net->is_connected || !reason) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[1024];
    size_t offset = 0;

    uint8_t act_byte = (uint8_t)action_type;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ADMIN_ACTION, &act_byte, 1);
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ADMIN_REASON, (const uint8_t*)reason, (uint16_t)strlen(reason));

    if (target_uuid && !clip_uuid_is_zero(target_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ADMIN_TARGET_UUID, target_uuid->bytes, CLIP_UUID_BYTES);
    }

    if (related_event_id > 0) {
        uint8_t eid_buf[4] = {
            (uint8_t)((related_event_id >> 24) & 0xFF),
            (uint8_t)((related_event_id >> 16) & 0xFF),
            (uint8_t)((related_event_id >> 8) & 0xFF),
            (uint8_t)(related_event_id & 0xFF)
        };
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_RELATED_EVENT_ID, eid_buf, 4);
    }

    if (related_session_uuid && !clip_uuid_is_zero(related_session_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_RELATED_SESSION_UUID, related_session_uuid->bytes, CLIP_UUID_BYTES);
    }

    if (related_channel_uuid && !clip_uuid_is_zero(related_channel_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_RELATED_CHANNEL_UUID, related_channel_uuid->bytes, CLIP_UUID_BYTES);
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_ACTION, (uint32_t)offset, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[1024];
    uint32_t rx_len = 0;

    while (1) {
        ClipError recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_OK ||
            rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (out_audit_id) {
        *out_audit_id = 0;
        const uint8_t* aid_ptr = NULL;
        uint16_t aid_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ADMIN_AUDIT_ID, &aid_ptr, &aid_len) == CLIP_OK && aid_len == 4) {
            *out_audit_id = ((uint32_t)aid_ptr[0] << 24) | ((uint32_t)aid_ptr[1] << 16) |
                            ((uint32_t)aid_ptr[2] << 8) | (uint32_t)aid_ptr[3];
        }
    }

    return CLIP_OK;
}

ClipError clip_admin_client_list_events(ClipClientNet*      net,
                                        int                 status_filter,
                                        ClipSecurityEvent** out_events,
                                        size_t*             out_count)
{
    if (!net || !net->is_connected || !out_events || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_events = NULL;
    *out_count = 0;

    uint8_t payload[32];
    size_t offset = 0;

    if (status_filter >= 0) {
        uint8_t sf = (uint8_t)status_filter;
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_EVENT_STATUS, &sf, 1);
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_EVENTS_REQ, (uint32_t)offset, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, offset > 0 ? payload : NULL);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[16384];
    uint32_t rx_len = 0;

    while (1) {
        ClipError recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_ADMIN_EVENTS_RESP ||
            rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
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

    while (parse_offset + 4 <= rx_len && parsed < count) {
        uint16_t tag = ((uint16_t)rx_payload[parse_offset] << 8) | rx_payload[parse_offset + 1];
        uint16_t len = ((uint16_t)rx_payload[parse_offset + 2] << 8) | rx_payload[parse_offset + 3];

        if (tag == CLIP_TAG_EVENT_COUNT) {
            parse_offset += 4 + len;
            continue;
        }

        if (tag == CLIP_TAG_EVENT_UUID && len == CLIP_UUID_BYTES) {
            ClipSecurityEvent* ev = &list[parsed++];
            memcpy(ev->event_uuid, &rx_payload[parse_offset + 4], CLIP_UUID_BYTES);
            parse_offset += 4 + len;

            while (parse_offset + 4 <= rx_len) {
                uint16_t sub_tag = ((uint16_t)rx_payload[parse_offset] << 8) | rx_payload[parse_offset + 1];
                uint16_t sub_len = ((uint16_t)rx_payload[parse_offset + 2] << 8) | rx_payload[parse_offset + 3];

                if (sub_tag == CLIP_TAG_EVENT_UUID) {
                    break;
                }

                const uint8_t* val = &rx_payload[parse_offset + 4];
                if (sub_tag == CLIP_TAG_EVENT_ID && sub_len == 4) {
                    ev->event_id = ((uint32_t)val[0] << 24) | ((uint32_t)val[1] << 16) | ((uint32_t)val[2] << 8) | (uint32_t)val[3];
                } else if (sub_tag == CLIP_TAG_SESSION_UUID && sub_len == CLIP_UUID_BYTES) {
                    memcpy(ev->session_uuid, val, CLIP_UUID_BYTES);
                } else if (sub_tag == CLIP_TAG_CHANNEL_UUID && sub_len == CLIP_UUID_BYTES) {
                    clip_uuid_to_string((const ClipUuid*)val, ev->channel_uuid_str, sizeof(ev->channel_uuid_str));
                } else if (sub_tag == CLIP_TAG_NODE_UUID && sub_len == CLIP_UUID_BYTES) {
                    clip_uuid_to_string((const ClipUuid*)val, ev->node_uuid_str, sizeof(ev->node_uuid_str));
                } else if (sub_tag == CLIP_TAG_TIMESTAMP_MS && sub_len == 8) {
                    ev->timestamp_ms = 0;
                    for (int b = 0; b < 8; b++) ev->timestamp_ms = (ev->timestamp_ms << 8) | val[b];
                } else if (sub_tag == CLIP_TAG_CATEGORY && sub_len == 1) {
                    ev->category = (ClipSecurityCategory)val[0];
                } else if (sub_tag == CLIP_TAG_SEVERITY && sub_len == 1) {
                    ev->severity = (ClipSecuritySeverity)val[0];
                } else if (sub_tag == CLIP_TAG_MATCHED_RULE) {
                    size_t cp = sub_len < sizeof(ev->matched_rule) - 1 ? sub_len : sizeof(ev->matched_rule) - 1;
                    memcpy(ev->matched_rule, val, cp);
                    ev->matched_rule[cp] = '\0';
                } else if (sub_tag == CLIP_TAG_MATCHED_TEXT) {
                    size_t cp = sub_len < sizeof(ev->matched_term) - 1 ? sub_len : sizeof(ev->matched_term) - 1;
                    memcpy(ev->matched_term, val, cp);
                    ev->matched_term[cp] = '\0';
                } else if (sub_tag == CLIP_TAG_CONTEXT_TEXT) {
                    size_t cp = sub_len < sizeof(ev->context_text) - 1 ? sub_len : sizeof(ev->context_text) - 1;
                    memcpy(ev->context_text, val, cp);
                    ev->context_text[cp] = '\0';
                } else if (sub_tag == CLIP_TAG_EVENT_STATUS && sub_len == 1) {
                    ev->status = (ClipSecurityEventStatus)val[0];
                }

                parse_offset += 4 + sub_len;
            }
        } else {
            parse_offset += 4 + len;
        }
    }

    *out_events = list;
    *out_count = parsed;
    return CLIP_OK;
}

void clip_admin_client_free_events(ClipSecurityEvent* events, size_t count)
{
    (void)count;
    if (events) {
        free(events);
    }
}

ClipError clip_admin_client_list_audit(ClipClientNet*         net,
                                       uint32_t               limit,
                                       ClipAdminAuditRecord** out_records,
                                       size_t*                out_count)
{
    if (!net || !net->is_connected || !out_records || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_records = NULL;
    *out_count = 0;

    uint8_t payload[32];
    size_t offset = 0;

    if (limit > 0) {
        uint16_t l16 = (uint16_t)limit;
        uint8_t l_buf[2] = { (uint8_t)((l16 >> 8) & 0xFF), (uint8_t)(l16 & 0xFF) };
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ADMIN_AUDIT_COUNT, l_buf, 2);
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_AUDIT_REQ, (uint32_t)offset, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, offset > 0 ? payload : NULL);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[16384];
    uint32_t rx_len = 0;

    while (1) {
        ClipError recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_ADMIN_AUDIT_RESP ||
            rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    const uint8_t* cnt_ptr = NULL;
    uint16_t cnt_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ADMIN_AUDIT_COUNT, &cnt_ptr, &cnt_len);
    size_t count = 0;
    if (cnt_ptr && cnt_len == 2) {
        count = ((size_t)cnt_ptr[0] << 8) | (size_t)cnt_ptr[1];
    }

    if (count == 0) {
        return CLIP_OK;
    }

    ClipAdminAuditRecord* list = (ClipAdminAuditRecord*)calloc(count, sizeof(ClipAdminAuditRecord));
    if (!list) return CLIP_ERR_NOMEM;

    size_t parse_offset = 0;
    size_t parsed = 0;

    while (parse_offset + 4 <= rx_len && parsed < count) {
        uint16_t tag = ((uint16_t)rx_payload[parse_offset] << 8) | rx_payload[parse_offset + 1];
        uint16_t len = ((uint16_t)rx_payload[parse_offset + 2] << 8) | rx_payload[parse_offset + 3];

        if (tag == CLIP_TAG_ADMIN_AUDIT_COUNT) {
            parse_offset += 4 + len;
            continue;
        }

        if (tag == CLIP_TAG_ADMIN_AUDIT_ID && len == 4) {
            ClipAdminAuditRecord* rec = &list[parsed++];
            const uint8_t* val = &rx_payload[parse_offset + 4];
            rec->audit_id = ((uint32_t)val[0] << 24) | ((uint32_t)val[1] << 16) | ((uint32_t)val[2] << 8) | (uint32_t)val[3];
            parse_offset += 4 + len;

            while (parse_offset + 4 <= rx_len) {
                uint16_t sub_tag = ((uint16_t)rx_payload[parse_offset] << 8) | rx_payload[parse_offset + 1];
                uint16_t sub_len = ((uint16_t)rx_payload[parse_offset + 2] << 8) | rx_payload[parse_offset + 3];

                if (sub_tag == CLIP_TAG_ADMIN_AUDIT_ID) {
                    break;
                }

                const uint8_t* sub_val = &rx_payload[parse_offset + 4];
                if (sub_tag == CLIP_TAG_NODE_UUID && sub_len == CLIP_UUID_BYTES) {
                    memcpy(rec->admin_uuid, sub_val, CLIP_UUID_BYTES);
                } else if (sub_tag == CLIP_TAG_ADMIN_ACTION && sub_len == 1) {
                    rec->action_type = (ClipAdminActionType)sub_val[0];
                } else if (sub_tag == CLIP_TAG_ADMIN_TARGET_UUID && sub_len == CLIP_UUID_BYTES) {
                    memcpy(rec->target_uuid, sub_val, CLIP_UUID_BYTES);
                    rec->has_target_uuid = true;
                } else if (sub_tag == CLIP_TAG_ADMIN_REASON) {
                    size_t cp = sub_len < sizeof(rec->reason) - 1 ? sub_len : sizeof(rec->reason) - 1;
                    memcpy(rec->reason, sub_val, cp);
                    rec->reason[cp] = '\0';
                } else if (sub_tag == CLIP_TAG_RELATED_EVENT_ID && sub_len == 4) {
                    rec->related_event_id = ((uint32_t)sub_val[0] << 24) | ((uint32_t)sub_val[1] << 16) |
                                            ((uint32_t)sub_val[2] << 8) | (uint32_t)sub_val[3];
                } else if (sub_tag == CLIP_TAG_RELATED_SESSION_UUID && sub_len == CLIP_UUID_BYTES) {
                    memcpy(rec->related_session_uuid, sub_val, CLIP_UUID_BYTES);
                    rec->has_related_session = true;
                } else if (sub_tag == CLIP_TAG_RELATED_CHANNEL_UUID && sub_len == CLIP_UUID_BYTES) {
                    memcpy(rec->related_channel_uuid, sub_val, CLIP_UUID_BYTES);
                    rec->has_related_channel = true;
                } else if (sub_tag == CLIP_TAG_AUTH_STATUS && sub_len == 1) {
                    rec->status = (ClipAuditStatus)sub_val[0];
                } else if (sub_tag == CLIP_TAG_ERROR_CODE && sub_len == 2) {
                    uint16_t c = ((uint16_t)sub_val[0] << 8) | (uint16_t)sub_val[1];
                    rec->error_code = (int16_t)(-((int)c));
                } else if (sub_tag == CLIP_TAG_TIMESTAMP_MS && sub_len == 8) {
                    rec->created_at_ms = 0;
                    for (int b = 0; b < 8; b++) rec->created_at_ms = (rec->created_at_ms << 8) | sub_val[b];
                }

                parse_offset += 4 + sub_len;
            }
        } else {
            parse_offset += 4 + len;
        }
    }

    *out_records = list;
    *out_count = parsed;
    return CLIP_OK;
}

void clip_admin_client_free_audit(ClipAdminAuditRecord* records, size_t count)
{
    (void)count;
    if (records) {
        free(records);
    }
}

ClipError clip_admin_client_create_admin(ClipClientNet*      net,
                                         const char*         new_username,
                                         const char*         new_password,
                                         ClipAdminPermission role,
                                         const char*         reason,
                                         uint32_t*           out_audit_id)
{
    if (!net || !net->is_connected || !new_username || !new_password || !reason) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[1024];
    size_t offset = 0;

    uint8_t act_byte = (uint8_t)CLIP_ADMIN_CREATE_ADMIN;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ADMIN_ACTION, &act_byte, 1);
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ADMIN_REASON, (const uint8_t*)reason, (uint16_t)strlen(reason));
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ADMIN_USERNAME, (const uint8_t*)new_username, (uint16_t)strlen(new_username));
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_TEXT, (const uint8_t*)new_password, (uint16_t)strlen(new_password));

    uint8_t role_byte = (uint8_t)role;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_PERMISSION_LEVEL, &role_byte, 1);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_ACTION, (uint32_t)offset, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    OPENSSL_cleanse(payload, sizeof(payload));
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[1024];
    uint32_t rx_len = 0;

    while (1) {
        ClipError recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_OK ||
            rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_ADMIN_ACTION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (out_audit_id) {
        *out_audit_id = 0;
        const uint8_t* aid_ptr = NULL;
        uint16_t aid_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ADMIN_AUDIT_ID, &aid_ptr, &aid_len) == CLIP_OK && aid_len == 4) {
            *out_audit_id = ((uint32_t)aid_ptr[0] << 24) | ((uint32_t)aid_ptr[1] << 16) |
                            ((uint32_t)aid_ptr[2] << 8) | (uint32_t)aid_ptr[3];
        }
    }

    return CLIP_OK;
}
