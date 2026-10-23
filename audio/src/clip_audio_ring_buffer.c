/*
 * clip_audio_ring_buffer.c — Thread-Safe SPSC Circular Buffer Implementation
 */

#include "clip_audio_ring_buffer.h"
#include <stdlib.h>
#include <string.h>

ClipError clip_audio_ring_buffer_init(ClipAudioRingBuffer* rb, size_t capacity_samples)
{
    if (!rb || capacity_samples == 0) return CLIP_ERR_INVALID;

    memset(rb, 0, sizeof(ClipAudioRingBuffer));
    rb->buffer = (int16_t*)calloc(capacity_samples, sizeof(int16_t));
    if (!rb->buffer) {
        return CLIP_ERR_NOMEM;
    }

    rb->capacity = capacity_samples;
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
    rb->overruns = 0;
    rb->underruns = 0;
    InitializeCriticalSection(&rb->cs);
    rb->initialized = true;

    return CLIP_OK;
}

void clip_audio_ring_buffer_cleanup(ClipAudioRingBuffer* rb)
{
    if (!rb || !rb->initialized) return;

    EnterCriticalSection(&rb->cs);
    if (rb->buffer) {
        free(rb->buffer);
        rb->buffer = NULL;
    }
    rb->capacity = 0;
    rb->count = 0;
    rb->head = 0;
    rb->tail = 0;
    rb->initialized = false;
    LeaveCriticalSection(&rb->cs);
    DeleteCriticalSection(&rb->cs);
}

void clip_audio_ring_buffer_reset(ClipAudioRingBuffer* rb)
{
    if (!rb || !rb->initialized) return;

    EnterCriticalSection(&rb->cs);
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
    rb->overruns = 0;
    rb->underruns = 0;
    LeaveCriticalSection(&rb->cs);
}

size_t clip_audio_ring_buffer_write(ClipAudioRingBuffer* rb,
                                    const int16_t*       samples,
                                    size_t               sample_count)
{
    if (!rb || !rb->initialized || !samples || sample_count == 0) return 0;

    EnterCriticalSection(&rb->cs);

    size_t space = rb->capacity - rb->count;
    size_t to_write = (sample_count <= space) ? sample_count : space;
    size_t dropped = sample_count - to_write;

    if (dropped > 0) {
        rb->overruns += (uint64_t)dropped;
    }

    for (size_t i = 0; i < to_write; i++) {
        rb->buffer[rb->head] = samples[i];
        rb->head = (rb->head + 1) % rb->capacity;
    }
    rb->count += to_write;

    LeaveCriticalSection(&rb->cs);
    return to_write;
}

size_t clip_audio_ring_buffer_read(ClipAudioRingBuffer* rb,
                                   int16_t*             out_samples,
                                   size_t               max_samples)
{
    if (!rb || !rb->initialized || !out_samples || max_samples == 0) return 0;

    EnterCriticalSection(&rb->cs);

    size_t to_read = (max_samples <= rb->count) ? max_samples : rb->count;
    if (to_read < max_samples) {
        rb->underruns += (uint64_t)(max_samples - to_read);
    }

    for (size_t i = 0; i < to_read; i++) {
        out_samples[i] = rb->buffer[rb->tail];
        rb->tail = (rb->tail + 1) % rb->capacity;
    }
    rb->count -= to_read;

    LeaveCriticalSection(&rb->cs);
    return to_read;
}

size_t clip_audio_ring_buffer_available_read(ClipAudioRingBuffer* rb)
{
    if (!rb || !rb->initialized) return 0;
    EnterCriticalSection(&rb->cs);
    size_t c = rb->count;
    LeaveCriticalSection(&rb->cs);
    return c;
}

size_t clip_audio_ring_buffer_available_write(ClipAudioRingBuffer* rb)
{
    if (!rb || !rb->initialized) return 0;
    EnterCriticalSection(&rb->cs);
    size_t s = rb->capacity - rb->count;
    LeaveCriticalSection(&rb->cs);
    return s;
}

size_t clip_audio_ring_buffer_capacity(const ClipAudioRingBuffer* rb)
{
    return (rb && rb->initialized) ? rb->capacity : 0;
}

void clip_audio_ring_buffer_get_stats(ClipAudioRingBuffer* rb,
                                      uint64_t*            out_overruns,
                                      uint64_t*            out_underruns)
{
    if (!rb || !rb->initialized) return;
    EnterCriticalSection(&rb->cs);
    if (out_overruns) *out_overruns = rb->overruns;
    if (out_underruns) *out_underruns = rb->underruns;
    LeaveCriticalSection(&rb->cs);
}
