/**
 * @file audio_state.c
 * @brief Audio engine lifecycle and bounded audio frame queues
 */

#include "engine_internal.h"
#if defined(_WIN32) || defined(__CYGWIN__)
#include <mmsystem.h>
#endif
#include "clip_audio.h"
#include "clip_audio_device.h"
#include "network.h"
#include "codec.h"
#include <stdlib.h>
#include <string.h>

/* ── Audio Queue Helper Functions ────────────────────────────────────────── */

int32_t audio_queue_init(AudioQueue* q, uint32_t capacity) {
    if (q == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (capacity == 0) {
        return CLICOM_ERR_INVALID_ARG;
    }

    q->frames = (ClicomAudioFrame*)calloc(capacity, sizeof(ClicomAudioFrame));
    if (q->frames == NULL) {
        return CLICOM_ERR_OUT_OF_MEMORY;
    }

    q->capacity = capacity;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    return CLICOM_OK;
}

void audio_queue_destroy(AudioQueue* q) {
    if (q == NULL) {
        return;
    }
    if (q->frames != NULL) {
        free(q->frames);
        q->frames = NULL;
    }
    q->capacity = 0;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
}

void audio_queue_clear_internal(AudioQueue* q) {
    if (q == NULL) {
        return;
    }
    q->head = 0;
    q->tail = 0;
    q->count = 0;
}

int32_t audio_queue_push_internal(AudioQueue* q, const ClicomAudioFrame* frame) {
    if (q == NULL || frame == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (q->frames == NULL || q->capacity == 0) {
        return CLICOM_ERR_NOT_INITIALIZED;
    }
    if (q->count >= q->capacity) {
        return CLICOM_ERR_QUEUE_FULL;
    }

    q->frames[q->tail] = *frame;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;

    return CLICOM_OK;
}

int32_t audio_queue_pop_internal(AudioQueue* q, ClicomAudioFrame* out_frame) {
    if (q == NULL || out_frame == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (q->frames == NULL || q->capacity == 0) {
        return CLICOM_ERR_NOT_INITIALIZED;
    }
    if (q->count == 0) {
        return CLICOM_ERR_QUEUE_EMPTY;
    }

    *out_frame = q->frames[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->count--;

    return CLICOM_OK;
}

/* ── Hardware/Network Audio Callbacks ─────────────────────────────────────── */

static void engine_audio_capture_callback(const int16_t* pcm,
                                          size_t         sample_count,
                                          uint64_t       timestamp_ms,
                                          void*          user_data)
{
    ClicomEngine* engine = (ClicomEngine*)user_data;
    if (!engine || !pcm || sample_count == 0) return;

    engine_lock(engine);
    if (engine->state != CLICOM_ENGINE_RUNNING || engine->audio_state != CLICOM_AUDIO_RUNNING) {
        engine_unlock(engine);
        return;
    }

    /* Requirement 5: Mute suppresses real microphone transmission */
    if (engine->mic_state.is_muted) {
        engine_unlock(engine);
        return;
    }

    /* Apply software input gain */
    int16_t scaled_pcm[CLICOM_AUDIO_MAX_SAMPLES];
    size_t copy_samples = (sample_count <= CLICOM_AUDIO_MAX_SAMPLES) ? sample_count : CLICOM_AUDIO_MAX_SAMPLES;
    float gain = engine->mic_state.gain;
    for (size_t i = 0; i < copy_samples; i++) {
        if (gain == 1.0f) {
            scaled_pcm[i] = pcm[i];
        } else {
            float s = (float)pcm[i] * gain;
            if (s > 32767.0f) s = 32767.0f;
            if (s < -32768.0f) s = -32768.0f;
            scaled_pcm[i] = (int16_t)s;
        }
    }

    /* Push into local capture FIFO queue */
    ClicomAudioFrame frame;
    frame.timestamp_ns = timestamp_ms * 1000000ULL;
    frame.sample_rate = engine->audio_sample_rate;
    frame.channels = engine->audio_channels;
    frame.num_samples = (uint16_t)copy_samples;
    memcpy(frame.pcm_data, scaled_pcm, copy_samples * sizeof(int16_t));

    if (audio_queue_push_internal(&engine->capture_queue, &frame) == CLICOM_OK) {
        engine->total_frames_pushed++;
    } else {
        engine->total_frames_dropped++;
    }

    /* Transmit over TLS 1.3 socket if floor held and session active */
    if (engine->net && engine->net->is_connected && engine->room_session_active &&
        !engine->mic_state.is_muted && engine->mic_state.is_ptt_active) {
        ClipUuid sess_uuid;
        memcpy(sess_uuid.bytes, engine->room_session_uuid, 16);
        ClipError send_err = clip_client_send_audio_frame(engine->net,
                                                          &sess_uuid,
                                                          timestamp_ms,
                                                          scaled_pcm,
                                                          copy_samples);
        if (send_err == CLIP_OK) {
            engine->telemetry.frames_sent++;
            engine->telemetry.bytes_sent += (copy_samples * sizeof(int16_t));
        }
    }

    engine_unlock(engine);
}

static void engine_network_audio_recv_callback(const ClipUuid* session_uuid,
                                               uint64_t timestamp_ms,
                                               const int16_t* pcm,
                                               size_t sample_count,
                                               void* user_data)
{
    ClicomEngine* engine = (ClicomEngine*)user_data;
    if (!engine || !pcm || sample_count == 0) return;

    engine_lock(engine);
    if (engine->state != CLICOM_ENGINE_RUNNING) {
        engine_unlock(engine);
        return;
    }

    /* Push into local playback queue */
    ClicomAudioFrame frame;
    frame.timestamp_ns = timestamp_ms * 1000000ULL;
    frame.sample_rate = engine->audio_sample_rate;
    frame.channels = engine->audio_channels;
    frame.num_samples = (uint16_t)((sample_count <= CLICOM_AUDIO_MAX_SAMPLES) ? sample_count : CLICOM_AUDIO_MAX_SAMPLES);
    memcpy(frame.pcm_data, pcm, frame.num_samples * sizeof(int16_t));

    if (audio_queue_push_internal(&engine->playback_queue, &frame) == CLICOM_OK) {
        engine->total_frames_pushed++;
    }

    engine->telemetry.frames_received++;
    engine->telemetry.bytes_received += (frame.num_samples * sizeof(int16_t));

    /* Play out speaker through audio hardware */
    if (engine->audio_hw && engine->audio_state == CLICOM_AUDIO_RUNNING) {
        clip_audio_play_frame((ClipAudioEngine*)engine->audio_hw, pcm, sample_count);
    }

    engine_unlock(engine);
}

/* ── Audio Engine Lifecycle API ──────────────────────────────────────────── */

int32_t clicom_audio_start(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }
    if (engine->state != CLICOM_ENGINE_RUNNING) {
        engine_unlock(engine);
        return CLICOM_ERR_NOT_INITIALIZED;
    }

    /* Initialize low-level ClipAudioEngine if not already initialized */
    if (!engine->audio_hw_initialized) {
        ClipAudioEngine* hw = (ClipAudioEngine*)calloc(1, sizeof(ClipAudioEngine));
        if (hw == NULL) {
            engine_unlock(engine);
            return CLICOM_ERR_OUT_OF_MEMORY;
        }

        ClipAudioConfig cfg;
        clip_audio_config_init_default(&cfg);
        cfg.sample_rate = engine->audio_sample_rate ? (uint32_t)engine->audio_sample_rate : 16000;
        cfg.channels = engine->audio_channels ? engine->audio_channels : 1;
        cfg.frame_duration_ms = 20;

        /* If mock backend explicitly requested, use mock; otherwise attempt real WinMM */
        if (engine->audio_mock_mode) {
            cfg.backend = CLIP_AUDIO_BACKEND_MOCK;
        } else {
            cfg.backend = CLIP_AUDIO_BACKEND_WINMM;
        }

        ClipError a_err = clip_audio_engine_init(hw, &cfg);
        if (a_err != CLIP_OK && cfg.backend == CLIP_AUDIO_BACKEND_WINMM) {
            /* Fallback safely to mock if WinMM hardware unavailable (e.g. no audio device in VM) */
            cfg.backend = CLIP_AUDIO_BACKEND_MOCK;
            a_err = clip_audio_engine_init(hw, &cfg);
        }

        if (a_err != CLIP_OK) {
            free(hw);
            engine_unlock(engine);
            return CLICOM_ERR_AUDIO_DEVICE;
        }

        clip_audio_set_capture_callback(hw, engine_audio_capture_callback, engine);
        clip_audio_start_playback(hw);

        engine->audio_hw = hw;
        engine->audio_hw_initialized = true;

        clip_audio_on_floor_granted(hw);
    }

    /* Configure network codec to Opus and attach receive callback if net is initialized */
    if (engine->net != NULL) {
        clip_client_set_codec_params(engine->net,
                                     CLIP_CODEC_OPUS,
                                     engine->audio_sample_rate ? (uint32_t)engine->audio_sample_rate : 16000,
                                     engine->audio_channels ? engine->audio_channels : 1);
        clip_client_set_audio_recv_callback(engine->net, engine_network_audio_recv_callback, engine);
    }

    engine->audio_state = CLICOM_AUDIO_RUNNING;
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_audio_stop(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    engine->audio_state = CLICOM_AUDIO_STOPPED;
    if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
        ClipAudioEngine* hw = (ClipAudioEngine*)engine->audio_hw;
        clip_audio_on_floor_released(hw);
        clip_audio_stop_playback(hw);
        clip_audio_engine_cleanup(hw);
        free(hw);
        engine->audio_hw = NULL;
        engine->audio_hw_initialized = false;
    }

    audio_queue_clear_internal(&engine->capture_queue);
    audio_queue_clear_internal(&engine->playback_queue);

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_audio_set_mock_backend(ClicomEngine* engine, bool use_mock) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    engine->audio_mock_mode = use_mock;
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_audio_get_backend(ClicomEngine* engine, int32_t* out_backend, bool* out_is_mock) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    int32_t backend = engine->audio_mock_mode ? 0 : 1;
    bool is_mock = engine->audio_mock_mode;
    if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
        ClipAudioEngine* hw = (ClipAudioEngine*)engine->audio_hw;
        backend = (int32_t)hw->config.backend;
        is_mock = (hw->config.backend == CLIP_AUDIO_BACKEND_MOCK);
    }
    if (out_backend != NULL) {
        *out_backend = backend;
    }
    if (out_is_mock != NULL) {
        *out_is_mock = is_mock;
    }
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_audio_get_device_counts(ClicomEngine* engine, uint32_t* out_inputs, uint32_t* out_outputs) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    uint32_t in_devs = 0;
    uint32_t out_devs = 0;
#if defined(_WIN32) || defined(__CYGWIN__)
    in_devs = (uint32_t)waveInGetNumDevs();
    out_devs = (uint32_t)waveOutGetNumDevs();
#else
    in_devs = 1;
    out_devs = 1;
#endif

    if (out_inputs) *out_inputs = in_devs;
    if (out_outputs) *out_outputs = out_devs;

    return CLICOM_OK;
}

int32_t clicom_get_active_session_id(ClicomEngine* engine, char* out_buf, size_t buf_len) {
    if (engine == NULL || out_buf == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (buf_len < CLICOM_MAX_UUID_LEN) {
        return CLICOM_ERR_BUFFER_TOO_SMALL;
    }

    engine_lock(engine);
    if (!engine->room_session_active) {
        engine_unlock(engine);
        return CLICOM_ERR_NOT_FOUND;
    }

    ClipUuid sess;
    memcpy(sess.bytes, engine->room_session_uuid, 16);
    clip_uuid_to_string(&sess, out_buf, buf_len);
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_get_audio_status(ClicomEngine* engine, ClicomAudioStatus* out_status) {
    if (engine == NULL || out_status == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);

    out_status->state = engine->audio_state;
    out_status->sample_rate = engine->audio_sample_rate;
    out_status->channels = engine->audio_channels;
    out_status->capture_queue_depth = engine->capture_queue.count;
    out_status->capture_queue_capacity = engine->capture_queue.capacity;
    out_status->playback_queue_depth = engine->playback_queue.count;
    out_status->playback_queue_capacity = engine->playback_queue.capacity;
    out_status->total_frames_pushed = engine->total_frames_pushed;
    out_status->total_frames_popped = engine->total_frames_popped;
    out_status->total_frames_dropped = engine->total_frames_dropped;

    engine_unlock(engine);
    return CLICOM_OK;
}

/* ── Bounded Frame Queue Operations ──────────────────────────────────────── */

int32_t clicom_audio_queue_push_capture(ClicomEngine* engine, const ClicomAudioFrame* frame) {
    if (engine == NULL || frame == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (frame->num_samples == 0 || frame->num_samples > CLICOM_AUDIO_MAX_SAMPLES) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }
    if (engine->audio_state != CLICOM_AUDIO_RUNNING) {
        engine_unlock(engine);
        return CLICOM_ERR_INVALID_STATE;
    }

    int32_t rc = audio_queue_push_internal(&engine->capture_queue, frame);
    if (rc == CLICOM_OK) {
        engine->total_frames_pushed++;

        /* Transmit over TLS 1.3 socket if floor held, session active, and not muted */
        if (!engine->mic_state.is_muted && engine->net && engine->net->is_connected &&
            engine->room_session_active && engine->mic_state.is_ptt_active) {
            ClipUuid sess_uuid;
            memcpy(sess_uuid.bytes, engine->room_session_uuid, 16);
            uint64_t ts_ms = frame->timestamp_ns / 1000000ULL;
            ClipError send_err = clip_client_send_audio_frame(engine->net,
                                                              &sess_uuid,
                                                              ts_ms,
                                                              frame->pcm_data,
                                                              frame->num_samples);
            if (send_err == CLIP_OK) {
                engine->telemetry.frames_sent++;
                engine->telemetry.bytes_sent += (frame->num_samples * sizeof(int16_t));
            }
        }
    } else if (rc == CLICOM_ERR_QUEUE_FULL) {
        engine->total_frames_dropped++;
    }

    engine_unlock(engine);
    return rc;
}

int32_t clicom_audio_queue_pop_capture(ClicomEngine* engine, ClicomAudioFrame* out_frame) {
    if (engine == NULL || out_frame == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    int32_t rc = audio_queue_pop_internal(&engine->capture_queue, out_frame);
    if (rc == CLICOM_OK) {
        engine->total_frames_popped++;
    }

    engine_unlock(engine);
    return rc;
}

int32_t clicom_audio_queue_push_playback(ClicomEngine* engine, const ClicomAudioFrame* frame) {
    if (engine == NULL || frame == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (frame->num_samples == 0 || frame->num_samples > CLICOM_AUDIO_MAX_SAMPLES) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }
    if (engine->audio_state != CLICOM_AUDIO_RUNNING) {
        engine_unlock(engine);
        return CLICOM_ERR_INVALID_STATE;
    }

    int32_t rc = audio_queue_push_internal(&engine->playback_queue, frame);
    if (rc == CLICOM_OK) {
        engine->total_frames_pushed++;
    } else if (rc == CLICOM_ERR_QUEUE_FULL) {
        engine->total_frames_dropped++;
    }

    engine_unlock(engine);
    return rc;
}

int32_t clicom_audio_queue_pop_playback(ClicomEngine* engine, ClicomAudioFrame* out_frame) {
    if (engine == NULL || out_frame == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    int32_t rc = audio_queue_pop_internal(&engine->playback_queue, out_frame);
    if (rc == CLICOM_OK) {
        engine->total_frames_popped++;
    }

    engine_unlock(engine);
    return rc;
}

int32_t clicom_audio_queue_clear(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    audio_queue_clear_internal(&engine->capture_queue);
    audio_queue_clear_internal(&engine->playback_queue);
    engine_unlock(engine);

    return CLICOM_OK;
}
