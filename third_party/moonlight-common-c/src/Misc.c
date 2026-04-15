#include "Limelight-internal.h"

#define ENET_INTERNAL_TIMEOUT_MS 100

int extractVersionQuadFromString(const char* string, int* quad) {
    const char* nextNumber = string;
    for (int i = 0; i < 4; i++) {
        // Parse the next component
        quad[i] = (int)strtol(nextNumber, (char**)&nextNumber, 10);

        // Skip the dot if we still have version components left.
        //
        // We continue looping even when we're at the end of the
        // input string to ensure all subsequent version components
        // are zeroed.
        if (*nextNumber != 0) {
            nextNumber++;
        }
    }

    return 0;
}

void* extendBuffer(void* ptr, size_t newSize) {
    void* newBuf = realloc(ptr, newSize);
    if (newBuf == NULL && ptr != NULL) {
        free(ptr);
    }
    return newBuf;
}

bool isReferenceFrameInvalidationSupportedByDecoder(void) {
    LC_ASSERT(NegotiatedVideoFormat != 0);

    return ((NegotiatedVideoFormat & VIDEO_FORMAT_MASK_H264) && (VideoCallbacks.capabilities & CAPABILITY_REFERENCE_FRAME_INVALIDATION_AVC)) ||
           ((NegotiatedVideoFormat & VIDEO_FORMAT_MASK_H265) && (VideoCallbacks.capabilities & CAPABILITY_REFERENCE_FRAME_INVALIDATION_HEVC)) ||
           ((NegotiatedVideoFormat & VIDEO_FORMAT_MASK_AV1) && (VideoCallbacks.capabilities & CAPABILITY_REFERENCE_FRAME_INVALIDATION_AV1));
}

bool isReferenceFrameInvalidationEnabled(void) {
    // RFI must be supported by the server and the client decoder to be used
    return ReferenceFrameInvalidationSupported && isReferenceFrameInvalidationSupportedByDecoder();
}

void LiInitializeStreamConfiguration(PSTREAM_CONFIGURATION streamConfig) {
    memset(streamConfig, 0, sizeof(*streamConfig));
}

void LiInitializeVideoCallbacks(PDECODER_RENDERER_CALLBACKS drCallbacks) {
    memset(drCallbacks, 0, sizeof(*drCallbacks));
}

void LiInitializeAudioCallbacks(PAUDIO_RENDERER_CALLBACKS arCallbacks) {
    memset(arCallbacks, 0, sizeof(*arCallbacks));
}

void LiInitializeConnectionCallbacks(PCONNECTION_LISTENER_CALLBACKS clCallbacks) {
    memset(clCallbacks, 0, sizeof(*clCallbacks));
}

void LiInitializeServerInformation(PSERVER_INFORMATION serverInfo) {
    memset(serverInfo, 0, sizeof(*serverInfo));
}

uint64_t LiGetMillis(void) {
    return PltGetMillis();
}

uint64_t LiGetMicroseconds(void) {
    return PltGetMicroseconds();
}

uint32_t LiGetHostFeatureFlags(void) {
    return SunshineFeatureFlags;
}
