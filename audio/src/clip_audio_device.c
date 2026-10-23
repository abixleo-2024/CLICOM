/*
 * clip_audio_device.c — Audio Device Implementation: Mock & WinMM Backends
 */

#include "clip_audio_device.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <mmsystem.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ══════════════════════════════════════════════════════════════════════════════
 * 1. Mock Backend Implementation (Deterministic In-Memory Virtual Audio)
 * ══════════════════════════════════════════════════════════════════════════════ */

typedef struct {
    HANDLE           hCaptureThread;
    HANDLE           hStopEvent;
    bool             capturing;
    float            frequency_hz;       /* Tone frequency for synthetic capture */
    double           phase;
    int16_t*         playback_history;   /* Stored playback samples for verification */
    size_t           playback_history_cap;
    size_t           playback_history_cnt;
    CRITICAL_SECTION history_cs;
} MockBackendCtx;

static DWORD WINAPI mock_capture_thread_func(LPVOID arg)
{
    ClipAudioDevice* dev = (ClipAudioDevice*)arg;
    MockBackendCtx* ctx = (MockBackendCtx*)dev->backend_ctx;

    size_t frame_samples = clip_audio_samples_per_frame(&dev->config);
    if (frame_samples == 0) frame_samples = 320;

    int16_t* frame_buf = (int16_t*)calloc(frame_samples, sizeof(int16_t));
    if (!frame_buf) return 1;

    DWORD sleep_ms = dev->config.frame_duration_ms ? dev->config.frame_duration_ms : 20;

    while (ctx->capturing) {
        DWORD wait_res = WaitForSingleObject(ctx->hStopEvent, sleep_ms);
        if (wait_res == WAIT_OBJECT_0 || !ctx->capturing) {
            break;
        }

        /* Synthesize clean PCM sine wave */
        double phase_inc = (2.0 * M_PI * ctx->frequency_hz) / (double)dev->config.sample_rate;
        for (size_t i = 0; i < frame_samples; i++) {
            frame_buf[i] = (int16_t)(sin(ctx->phase) * 16000.0);
            ctx->phase += phase_inc;
            if (ctx->phase >= 2.0 * M_PI) ctx->phase -= 2.0 * M_PI;
        }

        /* Deliver frame to callback */
        if (dev->capture_cb && ctx->capturing) {
            uint64_t now_ms = (uint64_t)GetTickCount64();
            dev->capture_cb(frame_buf, frame_samples, now_ms, dev->capture_user_data);
        }
    }

    free(frame_buf);
    return 0;
}

static ClipError mock_init(ClipAudioDevice* dev, const ClipAudioConfig* config)
{
    MockBackendCtx* ctx = (MockBackendCtx*)calloc(1, sizeof(MockBackendCtx));
    if (!ctx) return CLIP_ERR_NOMEM;

    ctx->hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ctx->frequency_hz = 440.0f; /* 440 Hz standard test tone */
    ctx->phase = 0.0;
    ctx->playback_history_cap = 48000 * 5; /* 5 seconds buffer */
    ctx->playback_history = (int16_t*)calloc(ctx->playback_history_cap, sizeof(int16_t));
    InitializeCriticalSection(&ctx->history_cs);

    dev->backend_ctx = ctx;
    return CLIP_OK;
}

static ClipError mock_start_capture(ClipAudioDevice* dev, ClipAudioCaptureCallback cb, void* user_data)
{
    MockBackendCtx* ctx = (MockBackendCtx*)dev->backend_ctx;
    if (!ctx) return CLIP_ERR_INVALID;
    if (ctx->capturing) return CLIP_ERR_AUDIO_BUSY;

    dev->capture_cb = cb;
    dev->capture_user_data = user_data;
    ctx->capturing = true;
    ResetEvent(ctx->hStopEvent);

    ctx->hCaptureThread = CreateThread(NULL, 0, mock_capture_thread_func, dev, 0, NULL);
    if (!ctx->hCaptureThread) {
        ctx->capturing = false;
        dev->capture_state = CLIP_AUDIO_STATE_ERROR;
        return CLIP_ERR_AUDIO_DEVICE;
    }

    dev->capture_state = CLIP_AUDIO_STATE_CAPTURING;
    return CLIP_OK;
}

static ClipError mock_stop_capture(ClipAudioDevice* dev)
{
    MockBackendCtx* ctx = (MockBackendCtx*)dev->backend_ctx;
    if (!ctx) return CLIP_ERR_INVALID;
    if (!ctx->capturing) return CLIP_OK;

    ctx->capturing = false;
    SetEvent(ctx->hStopEvent);

    if (ctx->hCaptureThread) {
        WaitForSingleObject(ctx->hCaptureThread, 2000);
        CloseHandle(ctx->hCaptureThread);
        ctx->hCaptureThread = NULL;
    }

    dev->capture_state = CLIP_AUDIO_STATE_IDLE;
    return CLIP_OK;
}

static ClipError mock_start_playback(ClipAudioDevice* dev)
{
    dev->playback_state = CLIP_AUDIO_STATE_PLAYING;
    return CLIP_OK;
}

static ClipError mock_write_playback(ClipAudioDevice* dev, const int16_t* pcm, size_t sample_count)
{
    MockBackendCtx* ctx = (MockBackendCtx*)dev->backend_ctx;
    if (!ctx || !pcm || sample_count == 0) return CLIP_ERR_INVALID;

    EnterCriticalSection(&ctx->history_cs);
    size_t space = ctx->playback_history_cap - ctx->playback_history_cnt;
    size_t to_copy = (sample_count <= space) ? sample_count : space;
    if (to_copy > 0) {
        memcpy(&ctx->playback_history[ctx->playback_history_cnt], pcm, to_copy * sizeof(int16_t));
        ctx->playback_history_cnt += to_copy;
    }
    LeaveCriticalSection(&ctx->history_cs);

    return CLIP_OK;
}

static ClipError mock_stop_playback(ClipAudioDevice* dev)
{
    dev->playback_state = CLIP_AUDIO_STATE_IDLE;
    return CLIP_OK;
}

static ClipError mock_shutdown(ClipAudioDevice* dev)
{
    if (!dev || !dev->backend_ctx) return CLIP_OK;
    MockBackendCtx* ctx = (MockBackendCtx*)dev->backend_ctx;

    mock_stop_capture(dev);
    mock_stop_playback(dev);

    if (ctx->hStopEvent) {
        CloseHandle(ctx->hStopEvent);
        ctx->hStopEvent = NULL;
    }

    EnterCriticalSection(&ctx->history_cs);
    if (ctx->playback_history) {
        free(ctx->playback_history);
        ctx->playback_history = NULL;
    }
    LeaveCriticalSection(&ctx->history_cs);
    DeleteCriticalSection(&ctx->history_cs);

    free(ctx);
    dev->backend_ctx = NULL;
    return CLIP_OK;
}

static ClipError mock_probe_devices(ClipAudioDeviceType type, uint32_t* out_count)
{
    if (!out_count) return CLIP_ERR_INVALID;
    *out_count = 1; /* Always 1 virtual mock device available */
    return CLIP_OK;
}

static const ClipAudioDeviceOps s_mock_ops = {
    .init           = mock_init,
    .start_capture  = mock_start_capture,
    .stop_capture   = mock_stop_capture,
    .start_playback = mock_start_playback,
    .write_playback = mock_write_playback,
    .stop_playback  = mock_stop_playback,
    .shutdown       = mock_shutdown,
    .probe_devices  = mock_probe_devices
};

size_t clip_audio_mock_get_playback_samples(ClipAudioDevice* dev, int16_t* out_buf, size_t max_samples)
{
    if (!dev || !dev->backend_ctx || !out_buf || max_samples == 0) return 0;
    MockBackendCtx* ctx = (MockBackendCtx*)dev->backend_ctx;

    EnterCriticalSection(&ctx->history_cs);
    size_t count = (max_samples <= ctx->playback_history_cnt) ? max_samples : ctx->playback_history_cnt;
    if (count > 0) {
        memcpy(out_buf, ctx->playback_history, count * sizeof(int16_t));
    }
    LeaveCriticalSection(&ctx->history_cs);
    return count;
}

void clip_audio_mock_set_synthetic_frequency(ClipAudioDevice* dev, float freq_hz)
{
    if (!dev || !dev->backend_ctx) return;
    MockBackendCtx* ctx = (MockBackendCtx*)dev->backend_ctx;
    ctx->frequency_hz = freq_hz;
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 2. Windows WinMM Backend Implementation (Native waveIn / waveOut)
 * ══════════════════════════════════════════════════════════════════════════════ */

#define WINMM_NUM_BUFFERS 4
#define WINMM_OUT_BUFFERS 16

typedef struct {
    HWAVEIN          hWaveIn;
    HWAVEOUT         hWaveOut;
    WAVEFORMATEX     wfx;
    WAVEHDR          in_headers[WINMM_NUM_BUFFERS];
    uint8_t*         in_buffers[WINMM_NUM_BUFFERS];
    size_t           in_buffer_size;
    bool             capturing;
    bool             playing;
    CRITICAL_SECTION cs;

    /* Reusable playback ring buffer pool */
    WAVEHDR          out_headers[WINMM_OUT_BUFFERS];
    uint8_t*         out_buffers[WINMM_OUT_BUFFERS];
    size_t           out_buffer_size;
    uint32_t         out_write_idx;
    uint32_t         out_active_count;
} WinmmBackendCtx;

static void CALLBACK winmm_wave_in_proc(HWAVEIN   hwi,
                                        UINT      uMsg,
                                        DWORD_PTR dwInstance,
                                        DWORD_PTR dwParam1,
                                        DWORD_PTR dwParam2)
{
    ClipAudioDevice* dev = (ClipAudioDevice*)dwInstance;
    if (!dev || uMsg != WIM_DATA) return;

    WAVEHDR* hdr = (WAVEHDR*)dwParam1;
    WinmmBackendCtx* ctx = (WinmmBackendCtx*)dev->backend_ctx;
    if (!ctx) return;

    if (hdr->dwBytesRecorded > 0 && dev->capture_cb && ctx->capturing) {
        size_t samples = hdr->dwBytesRecorded / sizeof(int16_t);
        uint64_t now_ms = (uint64_t)GetTickCount64();
        dev->capture_cb((const int16_t*)hdr->lpData, samples, now_ms, dev->capture_user_data);
    }

    /* Re-queue buffer if capture still active */
    if (ctx->capturing && ctx->hWaveIn) {
        waveInAddBuffer(ctx->hWaveIn, hdr, sizeof(WAVEHDR));
    }
}

static void CALLBACK winmm_wave_out_proc(HWAVEOUT  hwo,
                                         UINT      uMsg,
                                         DWORD_PTR dwInstance,
                                         DWORD_PTR dwParam1,
                                         DWORD_PTR dwParam2)
{
    (void)hwo;
    (void)dwInstance;
    (void)dwParam2;
    if (uMsg != WOM_DONE) return;

    WAVEHDR* hdr = (WAVEHDR*)dwParam1;
    if (hdr) {
        hdr->dwUser = 1; /* Mark completed safely; waveOutUnprepareHeader is called from caller thread */
    }
}

static ClipError winmm_init(ClipAudioDevice* dev, const ClipAudioConfig* config)
{
    WinmmBackendCtx* ctx = (WinmmBackendCtx*)calloc(1, sizeof(WinmmBackendCtx));
    if (!ctx) return CLIP_ERR_NOMEM;

    InitializeCriticalSection(&ctx->cs);

    ctx->wfx.wFormatTag      = WAVE_FORMAT_PCM;
    ctx->wfx.nChannels       = config->channels;
    ctx->wfx.nSamplesPerSec  = config->sample_rate;
    ctx->wfx.wBitsPerSample  = config->bits_per_sample;
    ctx->wfx.nBlockAlign     = (WORD)((ctx->wfx.nChannels * ctx->wfx.wBitsPerSample) / 8);
    ctx->wfx.nAvgBytesPerSec = ctx->wfx.nSamplesPerSec * ctx->wfx.nBlockAlign;
    ctx->wfx.cbSize          = 0;

    ctx->in_buffer_size = clip_audio_bytes_per_frame(config);
    if (ctx->in_buffer_size == 0) {
        ctx->in_buffer_size = 1920;
    }
    ctx->out_buffer_size = ctx->in_buffer_size;

    for (int i = 0; i < WINMM_NUM_BUFFERS; i++) {
        ctx->in_buffers[i] = (uint8_t*)calloc(1, ctx->in_buffer_size);
        if (!ctx->in_buffers[i]) {
            DeleteCriticalSection(&ctx->cs);
            free(ctx);
            return CLIP_ERR_NOMEM;
        }
    }

    for (int i = 0; i < WINMM_OUT_BUFFERS; i++) {
        ctx->out_buffers[i] = (uint8_t*)calloc(1, ctx->out_buffer_size);
        if (!ctx->out_buffers[i]) {
            for (int j = 0; j < i; j++) {
                free(ctx->out_buffers[j]);
            }
            for (int j = 0; j < WINMM_NUM_BUFFERS; j++) {
                free(ctx->in_buffers[j]);
            }
            DeleteCriticalSection(&ctx->cs);
            free(ctx);
            return CLIP_ERR_NOMEM;
        }
    }

    dev->backend_ctx = ctx;
    return CLIP_OK;
}

static ClipError winmm_start_capture(ClipAudioDevice* dev, ClipAudioCaptureCallback cb, void* user_data)
{
    WinmmBackendCtx* ctx = (WinmmBackendCtx*)dev->backend_ctx;
    if (!ctx) return CLIP_ERR_INVALID;
    if (ctx->capturing) return CLIP_ERR_AUDIO_BUSY;

    dev->capture_cb = cb;
    dev->capture_user_data = user_data;

    UINT dev_id = (dev->config.device_id_in == 0) ? WAVE_MAPPER : (dev->config.device_id_in - 1);
    MMRESULT res = waveInOpen(&ctx->hWaveIn, dev_id, &ctx->wfx,
                              (DWORD_PTR)winmm_wave_in_proc, (DWORD_PTR)dev, CALLBACK_FUNCTION);
    if (res != MMSYSERR_NOERROR) {
        dev->capture_state = CLIP_AUDIO_STATE_ERROR;
        return CLIP_ERR_AUDIO_DEVICE;
    }

    ctx->capturing = true;

    for (int i = 0; i < WINMM_NUM_BUFFERS; i++) {
        memset(&ctx->in_headers[i], 0, sizeof(WAVEHDR));
        ctx->in_headers[i].lpData         = (LPSTR)ctx->in_buffers[i];
        ctx->in_headers[i].dwBufferLength = (DWORD)ctx->in_buffer_size;
        waveInPrepareHeader(ctx->hWaveIn, &ctx->in_headers[i], sizeof(WAVEHDR));
        waveInAddBuffer(ctx->hWaveIn, &ctx->in_headers[i], sizeof(WAVEHDR));
    }

    waveInStart(ctx->hWaveIn);
    dev->capture_state = CLIP_AUDIO_STATE_CAPTURING;
    return CLIP_OK;
}

static ClipError winmm_stop_capture(ClipAudioDevice* dev)
{
    WinmmBackendCtx* ctx = (WinmmBackendCtx*)dev->backend_ctx;
    if (!ctx) return CLIP_ERR_INVALID;
    if (!ctx->capturing) return CLIP_OK;

    ctx->capturing = false;

    if (ctx->hWaveIn) {
        waveInStop(ctx->hWaveIn);
        waveInReset(ctx->hWaveIn);

        for (int i = 0; i < WINMM_NUM_BUFFERS; i++) {
            waveInUnprepareHeader(ctx->hWaveIn, &ctx->in_headers[i], sizeof(WAVEHDR));
        }

        waveInClose(ctx->hWaveIn);
        ctx->hWaveIn = NULL;
    }

    dev->capture_state = CLIP_AUDIO_STATE_IDLE;
    return CLIP_OK;
}

static ClipError winmm_start_playback(ClipAudioDevice* dev)
{
    WinmmBackendCtx* ctx = (WinmmBackendCtx*)dev->backend_ctx;
    if (!ctx) return CLIP_ERR_INVALID;
    if (ctx->playing) return CLIP_ERR_AUDIO_BUSY;

    EnterCriticalSection(&ctx->cs);
    ctx->out_write_idx = 0;
    ctx->out_active_count = 0;
    for (int i = 0; i < WINMM_OUT_BUFFERS; i++) {
        memset(&ctx->out_headers[i], 0, sizeof(WAVEHDR));
    }

    UINT dev_id = (dev->config.device_id_out == 0) ? WAVE_MAPPER : (dev->config.device_id_out - 1);
    MMRESULT res = waveOutOpen(&ctx->hWaveOut, dev_id, &ctx->wfx,
                               (DWORD_PTR)winmm_wave_out_proc, (DWORD_PTR)dev, CALLBACK_FUNCTION);
    if (res != MMSYSERR_NOERROR) {
        LeaveCriticalSection(&ctx->cs);
        dev->playback_state = CLIP_AUDIO_STATE_ERROR;
        return CLIP_ERR_AUDIO_DEVICE;
    }

    ctx->playing = true;
    dev->playback_state = CLIP_AUDIO_STATE_PLAYING;
    LeaveCriticalSection(&ctx->cs);
    return CLIP_OK;
}

static ClipError winmm_write_playback(ClipAudioDevice* dev, const int16_t* pcm, size_t sample_count)
{
    WinmmBackendCtx* ctx = (WinmmBackendCtx*)dev->backend_ctx;
    if (!ctx || !ctx->playing || !ctx->hWaveOut || !pcm || sample_count == 0) {
        return CLIP_ERR_INVALID;
    }

    size_t bytes = sample_count * sizeof(int16_t);
    if (bytes > ctx->out_buffer_size) {
        bytes = ctx->out_buffer_size;
    }

    /* Never invoke WinMM system driver functions inside a critical section that could deadlock */
    HWAVEOUT hwo = ctx->hWaveOut;
    if (!hwo || !ctx->playing) {
        return CLIP_OK;
    }

    uint32_t idx = ctx->out_write_idx;
    WAVEHDR* hdr = &ctx->out_headers[idx];

    /* If this slot was still prepared from an earlier cycle, unprepare if done or recycle */
    if (hdr->dwFlags & WHDR_PREPARED) {
        if ((hdr->dwFlags & WHDR_DONE) || hdr->dwUser == 1) {
            waveOutUnprepareHeader(hwo, hdr, sizeof(WAVEHDR));
            hdr->dwUser = 0;
            hdr->dwFlags = 0;
        } else {
            /* Ring is fully saturated; drop frame immediately to prevent stalling caller thread */
            return CLIP_OK;
        }
    }

    memcpy(ctx->out_buffers[idx], pcm, bytes);
    memset(hdr, 0, sizeof(WAVEHDR));
    hdr->lpData = (LPSTR)ctx->out_buffers[idx];
    hdr->dwBufferLength = (DWORD)bytes;

    MMRESULT prep = waveOutPrepareHeader(hwo, hdr, sizeof(WAVEHDR));
    if (prep == MMSYSERR_NOERROR) {
        MMRESULT wr = waveOutWrite(hwo, hdr, sizeof(WAVEHDR));
        if (wr == MMSYSERR_NOERROR) {
            ctx->out_write_idx = (idx + 1) % WINMM_OUT_BUFFERS;
        } else {
            waveOutUnprepareHeader(hwo, hdr, sizeof(WAVEHDR));
        }
    }

    return CLIP_OK;
}

static ClipError winmm_stop_playback(ClipAudioDevice* dev)
{
    WinmmBackendCtx* ctx = (WinmmBackendCtx*)dev->backend_ctx;
    if (!ctx) return CLIP_ERR_INVALID;
    if (!ctx->playing) return CLIP_OK;

    EnterCriticalSection(&ctx->cs);
    ctx->playing = false;

    if (ctx->hWaveOut) {
        waveOutReset(ctx->hWaveOut);
        for (int i = 0; i < WINMM_OUT_BUFFERS; i++) {
            if (ctx->out_headers[i].dwFlags & WHDR_PREPARED) {
                waveOutUnprepareHeader(ctx->hWaveOut, &ctx->out_headers[i], sizeof(WAVEHDR));
            }
        }
        waveOutClose(ctx->hWaveOut);
        ctx->hWaveOut = NULL;
    }

    dev->playback_state = CLIP_AUDIO_STATE_IDLE;
    LeaveCriticalSection(&ctx->cs);
    return CLIP_OK;
}

static ClipError winmm_shutdown(ClipAudioDevice* dev)
{
    if (!dev || !dev->backend_ctx) return CLIP_OK;
    WinmmBackendCtx* ctx = (WinmmBackendCtx*)dev->backend_ctx;

    winmm_stop_capture(dev);
    winmm_stop_playback(dev);

    for (int i = 0; i < WINMM_NUM_BUFFERS; i++) {
        if (ctx->in_buffers[i]) {
            free(ctx->in_buffers[i]);
            ctx->in_buffers[i] = NULL;
        }
    }

    for (int i = 0; i < WINMM_OUT_BUFFERS; i++) {
        if (ctx->out_buffers[i]) {
            free(ctx->out_buffers[i]);
            ctx->out_buffers[i] = NULL;
        }
    }

    DeleteCriticalSection(&ctx->cs);
    free(ctx);
    dev->backend_ctx = NULL;
    return CLIP_OK;
}

static ClipError winmm_probe_devices(ClipAudioDeviceType type, uint32_t* out_count)
{
    if (!out_count) return CLIP_ERR_INVALID;
    if (type == CLIP_AUDIO_DEVICE_INPUT) {
        *out_count = (uint32_t)waveInGetNumDevs();
    } else {
        *out_count = (uint32_t)waveOutGetNumDevs();
    }
    return CLIP_OK;
}

static const ClipAudioDeviceOps s_winmm_ops = {
    .init           = winmm_init,
    .start_capture  = winmm_start_capture,
    .stop_capture   = winmm_stop_capture,
    .start_playback = winmm_start_playback,
    .write_playback = winmm_write_playback,
    .stop_playback  = winmm_stop_playback,
    .shutdown       = winmm_shutdown,
    .probe_devices  = winmm_probe_devices
};

/* ══════════════════════════════════════════════════════════════════════════════
 * 3. Factory & Public Device Functions
 * ══════════════════════════════════════════════════════════════════════════════ */

ClipAudioDevice* clip_audio_device_create(ClipAudioBackendType backend, const ClipAudioConfig* config)
{
    ClipAudioConfig safe_cfg;
    if (config) {
        safe_cfg = *config;
    } else {
        clip_audio_config_init_default(&safe_cfg);
        safe_cfg.backend = backend;
    }

    if (clip_audio_config_validate(&safe_cfg) != CLIP_OK) {
        return NULL;
    }

    ClipAudioDevice* dev = (ClipAudioDevice*)calloc(1, sizeof(ClipAudioDevice));
    if (!dev) return NULL;

    dev->config = safe_cfg;
    dev->capture_state = CLIP_AUDIO_STATE_IDLE;
    dev->playback_state = CLIP_AUDIO_STATE_IDLE;

    if (backend == CLIP_AUDIO_BACKEND_WINMM) {
        dev->ops = &s_winmm_ops;
    } else {
        dev->ops = &s_mock_ops;
    }

    if (dev->ops->init(dev, &safe_cfg) != CLIP_OK) {
        free(dev);
        return NULL;
    }

    return dev;
}

ClipAudioDevice* clip_audio_device_create_mock(const ClipAudioConfig* config)
{
    return clip_audio_device_create(CLIP_AUDIO_BACKEND_MOCK, config);
}

ClipAudioDevice* clip_audio_device_create_winmm(const ClipAudioConfig* config)
{
    return clip_audio_device_create(CLIP_AUDIO_BACKEND_WINMM, config);
}

void clip_audio_device_destroy(ClipAudioDevice* dev)
{
    if (!dev) return;
    if (dev->ops && dev->ops->shutdown) {
        dev->ops->shutdown(dev);
    }
    free(dev);
}

ClipError clip_audio_device_start_capture(ClipAudioDevice* dev, ClipAudioCaptureCallback cb, void* user_data)
{
    if (!dev || !dev->ops || !dev->ops->start_capture) return CLIP_ERR_INVALID;
    return dev->ops->start_capture(dev, cb, user_data);
}

ClipError clip_audio_device_stop_capture(ClipAudioDevice* dev)
{
    if (!dev || !dev->ops || !dev->ops->stop_capture) return CLIP_ERR_INVALID;
    return dev->ops->stop_capture(dev);
}

ClipError clip_audio_device_start_playback(ClipAudioDevice* dev)
{
    if (!dev || !dev->ops || !dev->ops->start_playback) return CLIP_ERR_INVALID;
    return dev->ops->start_playback(dev);
}

ClipError clip_audio_device_write_playback(ClipAudioDevice* dev, const int16_t* pcm, size_t sample_count)
{
    if (!dev || !dev->ops || !dev->ops->write_playback) return CLIP_ERR_INVALID;
    return dev->ops->write_playback(dev, pcm, sample_count);
}

ClipError clip_audio_device_stop_playback(ClipAudioDevice* dev)
{
    if (!dev || !dev->ops || !dev->ops->stop_playback) return CLIP_ERR_INVALID;
    return dev->ops->stop_playback(dev);
}
