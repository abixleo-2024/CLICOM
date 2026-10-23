/*
 * clip_audio_ring_buffer.h — Thread-Safe SPSC Circular Buffer for PCM Audio
 *
 * Implements a thread-safe circular ring buffer for 16-bit PCM audio samples,
 * decoupling device I/O callbacks from application-level processing with
 * overrun and underrun tracking.
 */

#ifndef CLIP_AUDIO_RING_BUFFER_H
#define CLIP_AUDIO_RING_BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <windows.h>
#include "clip_errors.h"

typedef struct {
    int16_t*         buffer;             /* Circular sample storage           */
    size_t           capacity;           /* Max sample capacity               */
    size_t           head;               /* Write pointer (sample index)      */
    size_t           tail;               /* Read pointer (sample index)       */
    size_t           count;              /* Current samples stored            */
    uint64_t         overruns;           /* Count of overwritten/dropped data */
    uint64_t         underruns;          /* Count of requested empty reads    */
    CRITICAL_SECTION cs;                 /* Thread safety lock                */
    bool             initialized;
} ClipAudioRingBuffer;

/* Lifecycle */
ClipError clip_audio_ring_buffer_init(ClipAudioRingBuffer* rb, size_t capacity_samples);
void      clip_audio_ring_buffer_cleanup(ClipAudioRingBuffer* rb);
void      clip_audio_ring_buffer_reset(ClipAudioRingBuffer* rb);

/* I/O Operations */
/* Writes sample_count samples into the ring buffer. If buffer overflows, overruns++ */
size_t    clip_audio_ring_buffer_write(ClipAudioRingBuffer* rb,
                                       const int16_t*       samples,
                                       size_t               sample_count);

/* Reads up to max_samples from ring buffer. If buffer underflows, underruns++ */
size_t    clip_audio_ring_buffer_read(ClipAudioRingBuffer* rb,
                                      int16_t*             out_samples,
                                      size_t               max_samples);

/* Capacity & Status Queries */
size_t    clip_audio_ring_buffer_available_read(ClipAudioRingBuffer* rb);
size_t    clip_audio_ring_buffer_available_write(ClipAudioRingBuffer* rb);
size_t    clip_audio_ring_buffer_capacity(const ClipAudioRingBuffer* rb);
void      clip_audio_ring_buffer_get_stats(ClipAudioRingBuffer* rb,
                                           uint64_t*            out_overruns,
                                           uint64_t*            out_underruns);

#endif /* CLIP_AUDIO_RING_BUFFER_H */
