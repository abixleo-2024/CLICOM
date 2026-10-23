/*
 * test_waveout_return.c — Check return codes of waveOutPrepareHeader and waveOutWrite over 200 frames
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <mmsystem.h>

int main(void) {
    WAVEFORMATEX wfx;
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = 1;
    wfx.nSamplesPerSec = 48000;
    wfx.wBitsPerSample = 16;
    wfx.nBlockAlign = 2;
    wfx.nAvgBytesPerSec = 96000;
    wfx.cbSize = 0;

    HWAVEOUT hWaveOut = NULL;
    MMRESULT res = waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
    if (res != MMSYSERR_NOERROR) {
        printf("waveOutOpen failed: %u\n", res);
        return 1;
    }

    printf("waveOutOpen succeeded. Streaming 200 frames (4 seconds)...\n");

    int prep_errors = 0;
    int write_errors = 0;

    for (int i = 0; i < 200; i++) {
        WAVEHDR* hdr = (WAVEHDR*)calloc(1, sizeof(WAVEHDR));
        int16_t* buf = (int16_t*)calloc(960, sizeof(int16_t));

        hdr->lpData = (LPSTR)buf;
        hdr->dwBufferLength = 960 * sizeof(int16_t);

        MMRESULT r_prep = waveOutPrepareHeader(hWaveOut, hdr, sizeof(WAVEHDR));
        if (r_prep != MMSYSERR_NOERROR) {
            prep_errors++;
            printf("Frame %d waveOutPrepareHeader failed: %u\n", i, r_prep);
        }

        MMRESULT r_write = waveOutWrite(hWaveOut, hdr, sizeof(WAVEHDR));
        if (r_write != MMSYSERR_NOERROR) {
            write_errors++;
            printf("Frame %d waveOutWrite failed: %u\n", i, r_write);
        }

        Sleep(20);
    }

    printf("Results after 200 frames:\n");
    printf("  waveOutPrepareHeader errors: %d\n", prep_errors);
    printf("  waveOutWrite errors: %d\n", write_errors);

    waveOutReset(hWaveOut);
    waveOutClose(hWaveOut);
    return 0;
}
