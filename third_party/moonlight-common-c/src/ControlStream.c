#include "Limelight-internal.h"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

// NV control stream packet header for TCP
typedef struct _NVCTL_TCP_PACKET_HEADER {
    unsigned short type;
    unsigned short payloadLength;
} NVCTL_TCP_PACKET_HEADER, *PNVCTL_TCP_PACKET_HEADER;

typedef struct _NVCTL_ENET_PACKET_HEADER_V1 {
    unsigned short type;
} NVCTL_ENET_PACKET_HEADER_V1, *PNVCTL_ENET_PACKET_HEADER_V1;

typedef struct _NVCTL_ENET_PACKET_HEADER_V2 {
    unsigned short type;
    unsigned short payloadLength;
} NVCTL_ENET_PACKET_HEADER_V2, *PNVCTL_ENET_PACKET_HEADER_V2;

#define AES_GCM_TAG_LENGTH 16
typedef struct _NVCTL_ENCRYPTED_PACKET_HEADER {
    unsigned short encryptedHeaderType; // Always LE 0x0001
    unsigned short length; // sizeof(seq) + 16 byte tag + secondary header and data
    unsigned int seq; // Monotonically increasing sequence number (used as IV for AES-GCM)

    // encrypted NVCTL_ENET_PACKET_HEADER_V2 and payload data follow
} NVCTL_ENCRYPTED_PACKET_HEADER, *PNVCTL_ENCRYPTED_PACKET_HEADER;

typedef struct _QUEUED_FRAME_INVALIDATION_TUPLE {
    uint32_t startFrame;
    uint32_t endFrame;
    LINKED_BLOCKING_QUEUE_ENTRY entry;
} QUEUED_FRAME_INVALIDATION_TUPLE, *PQUEUED_FRAME_INVALIDATION_TUPLE;

typedef struct _QUEUED_FRAME_FEC_STATUS {
    SS_FRAME_FEC_STATUS fecStatus;
    LINKED_BLOCKING_QUEUE_ENTRY entry;
} QUEUED_FRAME_FEC_STATUS, *PQUEUED_FRAME_FEC_STATUS;

typedef struct _QUEUED_ASYNC_CALLBACK {
    int typeIndex;
    union {
        struct {
            uint16_t controllerNumber;
            uint16_t lowFreqRumble;
            uint16_t highFreqRumble;
        } rumble;
        struct {
            uint16_t controllerNumber;
            uint16_t leftTriggerMotor;
            uint16_t rightTriggerMotor;
        } rumbleTriggers;
        struct {
            uint16_t controllerNumber;
            uint16_t reportRateHz;
            uint8_t motionType;
        } setMotionEventState;
        struct {
            uint16_t controllerNumber;
            uint8_t r;
            uint8_t g;
            uint8_t b;
        } setControllerLed;
        struct {
            uint16_t controllerNumber;
            /**
             * 0x04 - Right trigger
             * 0x08 - Left trigger
             */
            uint8_t eventFlags;
            uint8_t typeLeft;
            uint8_t typeRight;
            // arrays of size DS_EFFECT_PAYLOAD_SIZE
            // this is an opaque payload that will be read directly from the joypad and set as is to the client controller
            // if you are curious about the actual data, there's some rationale in
            // https://gist.github.com/Nielk1/6d54cc2c00d2201ccb8c2720ad7538db
            uint8_t left[DS_EFFECT_PAYLOAD_SIZE];
            uint8_t right[DS_EFFECT_PAYLOAD_SIZE];
        } dsAdaptiveTrigger;
    } data;
    LINKED_BLOCKING_QUEUE_ENTRY entry;
} QUEUED_ASYNC_CALLBACK, *PQUEUED_ASYNC_CALLBACK;

static SOCKET ctlSock = INVALID_SOCKET;
static PLT_MUTEX enetMutex;
static bool usePeriodicPing;

static PLT_THREAD lossStatsThread;
static PLT_THREAD invalidateRefFramesThread;
static PLT_THREAD requestIdrFrameThread;
static PLT_THREAD controlReceiveThread;
static PLT_THREAD asyncCallbackThread;
static uint32_t lastGoodFrame;
static uint32_t lastSeenFrame;
static bool stopping;
static bool disconnectPending;
static bool encryptedControlStream;
static bool hdrEnabled;
static SS_HDR_METADATA hdrMetadata;

static int intervalGoodFrameCount;
static int intervalTotalFrameCount;
static uint64_t intervalStartTimeMs;
static int lastIntervalLossPercentage;
static int lastConnectionStatusUpdate;
static uint32_t currentEnetSequenceNumber;
static uint64_t firstFrameTimeMs;

static LINKED_BLOCKING_QUEUE invalidReferenceFrameTuples;
static LINKED_BLOCKING_QUEUE frameFecStatusQueue;
static LINKED_BLOCKING_QUEUE asyncCallbackQueue;
static PLT_EVENT idrFrameRequiredEvent;

static PPLT_CRYPTO_CONTEXT encryptionCtx;
static PPLT_CRYPTO_CONTEXT decryptionCtx;

#define CONN_IMMEDIATE_POOR_LOSS_RATE 30
#define CONN_CONSECUTIVE_POOR_LOSS_RATE 15
#define CONN_OKAY_LOSS_RATE 5
#define CONN_STATUS_SAMPLE_PERIOD 3000

#define IDX_START_A 0
#define IDX_REQUEST_IDR_FRAME 0
#define IDX_START_B 1
#define IDX_INVALIDATE_REF_FRAMES 2
#define IDX_LOSS_STATS 3
#define IDX_INPUT_DATA 5
#define IDX_RUMBLE_DATA 6
#define IDX_TERMINATION 7
#define IDX_HDR_INFO 8
#define IDX_RUMBLE_TRIGGER_DATA 9
#define IDX_SET_MOTION_EVENT 10
#define IDX_SET_RGB_LED 11
#define IDX_DS_ADAPTIVE_TRIGGERS 12

#define CONTROL_STREAM_TIMEOUT_SEC 10
#define CONTROL_STREAM_LINGER_TIMEOUT_SEC 2

static const short packetTypesGen3[] = {
    0x1407, // Request IDR frame
    0x1410, // Start B
    0x1404, // Invalidate reference frames
    0x140c, // Loss Stats
    0x1417, // Frame Stats (unused)
    -1,     // Input data (unused)
    -1,     // Rumble data (unused)
    -1,     // Termination (unused)
    -1,     // HDR mode (unused)
    -1,     // Rumble triggers (unused)
    -1,     // Set motion event (unused)
    -1,     // Set RGB LED (unused)
};
static const short packetTypesGen4[] = {
    0x0606, // Request IDR frame
    0x0609, // Start B
    0x0604, // Invalidate reference frames
    0x060a, // Loss Stats
    0x0611, // Frame Stats (unused)
    -1,     // Input data (unused)
    -1,     // Rumble data (unused)
    -1,     // Termination (unused)
    -1,     // HDR mode (unused)
    -1,     // Rumble triggers (unused)
    -1,     // Set motion event (unused)
    -1,     // Set RGB LED (unused)
};
static const short packetTypesGen5[] = {
    0x0305, // Start A
    0x0307, // Start B
    0x0301, // Invalidate reference frames
    0x0201, // Loss Stats
    0x0204, // Frame Stats (unused)
    0x0207, // Input data
    -1,     // Rumble data (unused)
    -1,     // Termination (unused)
    -1,     // HDR mode (unknown)
    -1,     // Rumble triggers (unused)
    -1,     // Set motion event (unused)
    -1,     // Set RGB LED (unused)
};
static const short packetTypesGen7[] = {
    0x0305, // Start A
    0x0307, // Start B
    0x0301, // Invalidate reference frames
    0x0201, // Loss Stats
    0x0204, // Frame Stats (unused)
    0x0206, // Input data
    0x010b, // Rumble data
    0x0100, // Termination
    0x010e, // HDR mode
    -1,     // Rumble triggers (unused)
    -1,     // Set motion event (unused)
    -1,     // Set RGB LED (unused)
};
static const short packetTypesGen7Enc[] = {
    0x0302, // Request IDR frame
    0x0307, // Start B
    0x0301, // Invalidate reference frames
    0x0201, // Loss Stats
    0x0204, // Frame Stats (unused)
    0x0206, // Input data
    0x010b, // Rumble data
    0x0109, // Termination (extended)
    0x010e, // HDR mode
    0x5500, // Rumble triggers (Sunshine protocol extension)
    0x5501, // Set motion event (Sunshine protocol extension)
    0x5502, // Set RGB LED (Sunshine protocol extension)
    0x5503, // Set Adaptive Triggers (Sunshine protocol extension)
};

static const char requestIdrFrameGen3[] = { 0, 0 };
static const int startBGen3[] = { 0, 0, 0, 0xa };

static const char requestIdrFrameGen4[] = { 0, 0 };
static const char startBGen4[] = { 0 };

static const char startAGen5[] = { 0, 0 };
static const char startBGen5[] = { 0 };

static const char requestIdrFrameGen7Enc[] = { 0, 0 };

static const short payloadLengthsGen3[] = {
    sizeof(requestIdrFrameGen3), // Request IDR frame
    sizeof(startBGen3), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    64, // Frame Stats
    -1, // Input data
};
static const short payloadLengthsGen4[] = {
    sizeof(requestIdrFrameGen4), // Request IDR frame
    sizeof(startBGen4), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    64, // Frame Stats
    -1, // Input data
};
static const short payloadLengthsGen5[] = {
    sizeof(startAGen5), // Start A
    sizeof(startBGen5), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    80, // Frame Stats
    -1, // Input data
};
static const short payloadLengthsGen7[] = {
    sizeof(startAGen5), // Start A
    sizeof(startBGen5), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    80, // Frame Stats
    -1, // Input data
};
static const short payloadLengthsGen7Enc[] = {
    sizeof(requestIdrFrameGen7Enc), // Request IDR frame
    sizeof(startBGen5), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    80, // Frame Stats
    -1, // Input data
};

static const char* preconstructedPayloadsGen3[] = {
    requestIdrFrameGen3,
    (char*)startBGen3
};
static const char* preconstructedPayloadsGen4[] = {
    requestIdrFrameGen4,
    startBGen4
};
static const char* preconstructedPayloadsGen5[] = {
    startAGen5,
    startBGen5
};
static const char* preconstructedPayloadsGen7[] = {
    startAGen5,
    startBGen5
};
static const char* preconstructedPayloadsGen7Enc[] = {
    requestIdrFrameGen7Enc,
    startBGen5
};

static short* packetTypes;
static short* payloadLengths;
static char**preconstructedPayloads;
static bool supportsIdrFrameRequest;

#define LOSS_REPORT_INTERVAL_MS 50
#define PERIODIC_PING_INTERVAL_MS 100

// Initializes the control stream
int initializeControlStream(void) {
    stopping = false;
    PltCreateEvent(&idrFrameRequiredEvent);
    LbqInitializeLinkedBlockingQueue(&invalidReferenceFrameTuples, 20);
    LbqInitializeLinkedBlockingQueue(&frameFecStatusQueue, 8); // Limits number of frame status reports per periodic ping interval
    LbqInitializeLinkedBlockingQueue(&asyncCallbackQueue, 30);
    PltCreateMutex(&enetMutex);

    encryptedControlStream = APP_VERSION_AT_LEAST(7, 1, 431);

    if (AppVersionQuad[0] == 3) {
        packetTypes = (short*)packetTypesGen3;
        payloadLengths = (short*)payloadLengthsGen3;
        preconstructedPayloads = (char**)preconstructedPayloadsGen3;
        supportsIdrFrameRequest = true;
    }
    else if (AppVersionQuad[0] == 4) {
        packetTypes = (short*)packetTypesGen4;
        payloadLengths = (short*)payloadLengthsGen4;
        preconstructedPayloads = (char**)preconstructedPayloadsGen4;
        supportsIdrFrameRequest = true;
    }
    else if (AppVersionQuad[0] == 5) {
        packetTypes = (short*)packetTypesGen5;
        payloadLengths = (short*)payloadLengthsGen5;
        preconstructedPayloads = (char**)preconstructedPayloadsGen5;
        supportsIdrFrameRequest = false;
    }
    else {
        if (encryptedControlStream) {
            packetTypes = (short*)packetTypesGen7Enc;
            payloadLengths = (short*)payloadLengthsGen7Enc;
            preconstructedPayloads = (char**)preconstructedPayloadsGen7Enc;
            supportsIdrFrameRequest = true;
        }
        else {
            packetTypes = (short*)packetTypesGen7;
            payloadLengths = (short*)payloadLengthsGen7;
            preconstructedPayloads = (char**)preconstructedPayloadsGen7;
            supportsIdrFrameRequest = false;
        }
    }

    lastGoodFrame = 0;
    lastSeenFrame = 0;
    disconnectPending = false;
    intervalGoodFrameCount = 0;
    intervalTotalFrameCount = 0;
    intervalStartTimeMs = 0;
    lastIntervalLossPercentage = 0;
    lastConnectionStatusUpdate = CONN_STATUS_OKAY;
    firstFrameTimeMs = 0;
    currentEnetSequenceNumber = 0;
    usePeriodicPing = APP_VERSION_AT_LEAST(7, 1, 415);
    encryptionCtx = PltCreateCryptoContext();
    decryptionCtx = PltCreateCryptoContext();
    hdrEnabled = false;
    memset(&hdrMetadata, 0, sizeof(hdrMetadata));

    return 0;
}

static void freeBasicLbqList(PLINKED_BLOCKING_QUEUE_ENTRY entry) {
    PLINKED_BLOCKING_QUEUE_ENTRY nextEntry;

    while (entry != NULL) {
        nextEntry = entry->flink;
        free(entry->data);
        entry = nextEntry;
    }
}

// Cleans up control stream
void destroyControlStream(void) {
    LC_ASSERT(stopping);
    PltDestroyCryptoContext(encryptionCtx);
    PltDestroyCryptoContext(decryptionCtx);
    PltCloseEvent(&idrFrameRequiredEvent);
    freeBasicLbqList(LbqDestroyLinkedBlockingQueue(&invalidReferenceFrameTuples));
    freeBasicLbqList(LbqDestroyLinkedBlockingQueue(&frameFecStatusQueue));
    freeBasicLbqList(LbqDestroyLinkedBlockingQueue(&asyncCallbackQueue));

    PltDeleteMutex(&enetMutex);
}

static void queueFrameInvalidationTuple(uint32_t startFrame, uint32_t endFrame) {
    LC_ASSERT(startFrame <= endFrame);

    if (isReferenceFrameInvalidationEnabled()) {
        PQUEUED_FRAME_INVALIDATION_TUPLE qfit;
        qfit = malloc(sizeof(*qfit));
        if (qfit != NULL) {
            qfit->startFrame = startFrame;
            qfit->endFrame = endFrame;
            if (LbqOfferQueueItem(&invalidReferenceFrameTuples, qfit, &qfit->entry) == LBQ_BOUND_EXCEEDED) {
                // Too many invalidation tuples, so we need an IDR frame now
                Limelog("RFI range list reached maximum size limit\n");
                free(qfit);
                LiRequestIdrFrame();
            }
        }
        else {
            LiRequestIdrFrame();
        }
    }
    else {
        LiRequestIdrFrame();
    }
}

// Request an IDR frame on demand by the decoder
void LiRequestIdrFrame(void) {
    // Any reference frame invalidation requests should be dropped now.
    // We require a full IDR frame to recover.
    freeBasicLbqList(LbqFlushQueueItems(&invalidReferenceFrameTuples));

    // Request the IDR frame
    PltSetEvent(&idrFrameRequiredEvent);
}

// Invalidate reference frames lost by the network
void connectionDetectedFrameLoss(uint32_t startFrame, uint32_t endFrame) {
    queueFrameInvalidationTuple(startFrame, endFrame);
}

// When we receive a frame, update the number of our current frame
void connectionReceivedCompleteFrame(uint32_t frameIndex) {
    lastGoodFrame = frameIndex;
    intervalGoodFrameCount++;
}

void connectionSendFrameFecStatus(PSS_FRAME_FEC_STATUS fecStatus) {
    // This is a Sunshine protocol extension
    if (!IS_SUNSHINE()) {
        return;
    }

    // Queue a frame FEC status message. This is best-effort only.
    PQUEUED_FRAME_FEC_STATUS queuedFecStatus = malloc(sizeof(*queuedFecStatus));
    if (queuedFecStatus != NULL) {
        queuedFecStatus->fecStatus = *fecStatus;
        if (LbqOfferQueueItem(&frameFecStatusQueue, queuedFecStatus, &queuedFecStatus->entry) == LBQ_BOUND_EXCEEDED) {
            free(queuedFecStatus);
        }
    }
}

void connectionSawFrame(uint32_t frameIndex) {
    LC_ASSERT_VT(!isBefore16(frameIndex, lastSeenFrame));

    uint64_t now = PltGetMillis();

    // Suppress connection status warnings for the first sampling period
    // to allow the network and host to settle.
    if (lastSeenFrame == 0) {
        lastSeenFrame = frameIndex;
        firstFrameTimeMs = now;
        return;
    }
    else if (now - firstFrameTimeMs < CONN_STATUS_SAMPLE_PERIOD) {
        lastSeenFrame = frameIndex;
        return;
    }

    if (now - intervalStartTimeMs >= CONN_STATUS_SAMPLE_PERIOD) {
        if (intervalTotalFrameCount != 0) {
            // Notify the client of connection status changes based on frame loss rate
            int frameLossPercent = 100 - (intervalGoodFrameCount * 100) / intervalTotalFrameCount;
            if (lastConnectionStatusUpdate != CONN_STATUS_POOR &&
                    (frameLossPercent >= CONN_IMMEDIATE_POOR_LOSS_RATE ||
                     (frameLossPercent >= CONN_CONSECUTIVE_POOR_LOSS_RATE && lastIntervalLossPercentage >= CONN_CONSECUTIVE_POOR_LOSS_RATE))) {
                // We require 2 consecutive intervals above CONN_CONSECUTIVE_POOR_LOSS_RATE or a single
                // interval above CONN_IMMEDIATE_POOR_LOSS_RATE to notify of a poor connection.
                ListenerCallbacks.connectionStatusUpdate(CONN_STATUS_POOR);
                lastConnectionStatusUpdate = CONN_STATUS_POOR;
            }
            else if (frameLossPercent <= CONN_OKAY_LOSS_RATE && lastConnectionStatusUpdate != CONN_STATUS_OKAY) {
                ListenerCallbacks.connectionStatusUpdate(CONN_STATUS_OKAY);
                lastConnectionStatusUpdate = CONN_STATUS_OKAY;
            }

            lastIntervalLossPercentage = frameLossPercent;
        }

        // Reset interval
        intervalStartTimeMs = now;
        intervalGoodFrameCount = intervalTotalFrameCount = 0;
    }

    intervalTotalFrameCount += frameIndex - lastSeenFrame;
    lastSeenFrame = frameIndex;
}

// Reads an NV control stream packet from the TCP connection
static PNVCTL_TCP_PACKET_HEADER readNvctlPacketTcp(void) {
    NVCTL_TCP_PACKET_HEADER staticHeader;
    PNVCTL_TCP_PACKET_HEADER fullPacket;
    SOCK_RET err;

    err = recv(ctlSock, (char*)&staticHeader, sizeof(staticHeader), 0);
    if (err != sizeof(staticHeader)) {
        return NULL;
    }

    staticHeader.type = LE16(staticHeader.type);
    staticHeader.payloadLength = LE16(staticHeader.payloadLength);

    fullPacket = (PNVCTL_TCP_PACKET_HEADER)malloc(staticHeader.payloadLength + sizeof(staticHeader));
    if (fullPacket == NULL) {
        return NULL;
    }

    memcpy(fullPacket, &staticHeader, sizeof(staticHeader));
    if (staticHeader.payloadLength != 0) {
        err = recv(ctlSock, (char*)(fullPacket + 1), staticHeader.payloadLength, 0);
        if (err != staticHeader.payloadLength) {
            free(fullPacket);
            return NULL;
        }
    }

    return fullPacket;
}

// Caller must free() *packet on success!!!
static bool sendMessageTcp(short ptype, short paylen, const void* payload) {
    PNVCTL_TCP_PACKET_HEADER packet;
    SOCK_RET err;

    LC_ASSERT(AppVersionQuad[0] < 5);

    packet = malloc(sizeof(*packet) + paylen);
    if (packet == NULL) {
        return false;
    }

    packet->type = LE16(ptype);
    packet->payloadLength = LE16(paylen);
    memcpy(&packet[1], payload, paylen);

    err = send(ctlSock, (char*) packet, sizeof(*packet) + paylen, 0);
    free(packet);

    if (err != (SOCK_RET)(sizeof(*packet) + paylen)) {
        return false;
    }

    return true;
}

static bool sendMessageAndForget(short ptype, short paylen, const void* payload, uint8_t channelId, uint32_t flags, bool moreData) {
  abort(); // TODO
}

static bool sendMessageAndDiscardReply(short ptype, short paylen, const void* payload, uint8_t channelId, uint32_t flags, bool moreData) {
    PNVCTL_TCP_PACKET_HEADER reply;

    if (!sendMessageTcp(ptype, paylen, payload)) {
        return false;
    }

    // Discard the response
    reply = readNvctlPacketTcp();
    if (reply == NULL) {
        return false;
    }

    free(reply);

    return true;
}

static void asyncCallbackThreadFunc(void* context) {
    PQUEUED_ASYNC_CALLBACK queuedCb, nextCb;

    while (LbqWaitForQueueElement(&asyncCallbackQueue, (void**)&queuedCb) == LBQ_SUCCESS) {
        switch (queuedCb->typeIndex) {
        case IDX_RUMBLE_DATA:
            // Look for another rumble packet to batch with
            while (LbqPeekQueueElement(&asyncCallbackQueue, (void**)&nextCb) == LBQ_SUCCESS) {
                // Don't batch with the next packet if it is a different type or controller number
                if (nextCb->typeIndex != queuedCb->typeIndex ||
                        nextCb->data.rumble.controllerNumber != queuedCb->data.rumble.controllerNumber) {
                    break;
                }

                // This entry is batchable, so pop it off the queue
                if (LbqPollQueueElement(&asyncCallbackQueue, (void**)&nextCb) != LBQ_SUCCESS) {
                    break;
                }

                // Replace the old entry with the new one
                free(queuedCb);
                queuedCb = nextCb;
            }

            ListenerCallbacks.rumble(queuedCb->data.rumble.controllerNumber,
                                     queuedCb->data.rumble.lowFreqRumble,
                                     queuedCb->data.rumble.highFreqRumble);
            break;
        case IDX_RUMBLE_TRIGGER_DATA:
            // Look for another rumble triggers packet to batch with
            while (LbqPeekQueueElement(&asyncCallbackQueue, (void**)&nextCb) == LBQ_SUCCESS) {
                // Don't batch with the next packet if it is a different type or controller number
                if (nextCb->typeIndex != queuedCb->typeIndex ||
                        nextCb->data.rumbleTriggers.controllerNumber != queuedCb->data.rumbleTriggers.controllerNumber) {
                    break;
                }

                // This entry is batchable, so pop it off the queue
                if (LbqPollQueueElement(&asyncCallbackQueue, (void**)&nextCb) != LBQ_SUCCESS) {
                    break;
                }

                // Replace the old entry with the new one
                free(queuedCb);
                queuedCb = nextCb;
            }

            ListenerCallbacks.rumbleTriggers(queuedCb->data.rumbleTriggers.controllerNumber,
                                             queuedCb->data.rumbleTriggers.leftTriggerMotor,
                                             queuedCb->data.rumbleTriggers.rightTriggerMotor);
            break;
        case IDX_SET_RGB_LED:
            // Look for another controller LED packet to batch with
            while (LbqPeekQueueElement(&asyncCallbackQueue, (void**)&nextCb) == LBQ_SUCCESS) {
                // Don't batch with the next packet if it is a different type or controller number
                if (nextCb->typeIndex != queuedCb->typeIndex ||
                        nextCb->data.setControllerLed.controllerNumber != queuedCb->data.setControllerLed.controllerNumber) {
                    break;
                }

                // This entry is batchable, so pop it off the queue
                if (LbqPollQueueElement(&asyncCallbackQueue, (void**)&nextCb) != LBQ_SUCCESS) {
                    break;
                }

                // Replace the old entry with the new one
                free(queuedCb);
                queuedCb = nextCb;
            }

            ListenerCallbacks.setControllerLED(queuedCb->data.setControllerLed.controllerNumber,
                                               queuedCb->data.setControllerLed.r,
                                               queuedCb->data.setControllerLed.g,
                                               queuedCb->data.setControllerLed.b);
            break;
        case IDX_HDR_INFO:
            // HDR state is maintained globally, so we just invoke the client callback here.
            // These events are stateless, so we can consume all of them now.
            while (LbqPeekQueueElement(&asyncCallbackQueue, (void**)&nextCb) == LBQ_SUCCESS && nextCb->typeIndex == queuedCb->typeIndex) {
                // This entry is batchable, so pop it off the queue
                if (LbqPollQueueElement(&asyncCallbackQueue, (void**)&nextCb) != LBQ_SUCCESS) {
                    break;
                }

                // Replace the old entry with the new one
                free(queuedCb);
                queuedCb = nextCb;
            }

            ListenerCallbacks.setHdrMode(hdrEnabled);
            break;

        case IDX_SET_MOTION_EVENT:
            // These events are infrequent and cannot be batched
            ListenerCallbacks.setMotionEventState(queuedCb->data.setMotionEventState.controllerNumber,
                                                  queuedCb->data.setMotionEventState.motionType,
                                                  queuedCb->data.setMotionEventState.reportRateHz);
            break;
        case IDX_DS_ADAPTIVE_TRIGGERS:
            ListenerCallbacks.setAdaptiveTriggers(queuedCb->data.dsAdaptiveTrigger.controllerNumber,
                                                  queuedCb->data.dsAdaptiveTrigger.eventFlags,
                                                  queuedCb->data.dsAdaptiveTrigger.typeLeft,
                                                  queuedCb->data.dsAdaptiveTrigger.typeRight,
                                                  queuedCb->data.dsAdaptiveTrigger.left,
                                                  queuedCb->data.dsAdaptiveTrigger.right);
            break;
        default:
            // Unhandled packet type from queueAsyncCallback()
            LC_ASSERT(false);
            break;
        }

        free(queuedCb);
    }
}

static bool needsAsyncCallback(unsigned short packetType) {
    return packetType == packetTypes[IDX_RUMBLE_DATA] ||
           packetType == packetTypes[IDX_RUMBLE_TRIGGER_DATA] ||
           packetType == packetTypes[IDX_SET_MOTION_EVENT] ||
           packetType == packetTypes[IDX_SET_RGB_LED] ||
           packetType == packetTypes[IDX_HDR_INFO] ||
           packetType == packetTypes[IDX_DS_ADAPTIVE_TRIGGERS];
}

static void queueAsyncCallback(PNVCTL_ENET_PACKET_HEADER_V1 ctlHdr, int packetLength) {
    BYTE_BUFFER bb;
    PQUEUED_ASYNC_CALLBACK queuedCb;
    int err;

    LC_ASSERT(needsAsyncCallback(ctlHdr->type));

    queuedCb = malloc(sizeof(*queuedCb));
    if (!queuedCb) {
        return;
    }

    BbInitializeWrappedBuffer(&bb, (char*)ctlHdr, sizeof(*ctlHdr), packetLength - sizeof(*ctlHdr), BYTE_ORDER_LITTLE);

    if (ctlHdr->type == packetTypes[IDX_RUMBLE_DATA]) {
        BbAdvanceBuffer(&bb, 4);

        BbGet16(&bb, &queuedCb->data.rumble.controllerNumber);
        BbGet16(&bb, &queuedCb->data.rumble.lowFreqRumble);
        BbGet16(&bb, &queuedCb->data.rumble.highFreqRumble);

        queuedCb->typeIndex = IDX_RUMBLE_DATA;
    }
    else if (ctlHdr->type == packetTypes[IDX_RUMBLE_TRIGGER_DATA]) {
        BbGet16(&bb, &queuedCb->data.rumbleTriggers.controllerNumber);
        BbGet16(&bb, &queuedCb->data.rumbleTriggers.leftTriggerMotor);
        BbGet16(&bb, &queuedCb->data.rumbleTriggers.rightTriggerMotor);

        queuedCb->typeIndex = IDX_RUMBLE_TRIGGER_DATA;
    }
    else if (ctlHdr->type == packetTypes[IDX_SET_MOTION_EVENT]) {
        BbGet16(&bb, &queuedCb->data.setMotionEventState.controllerNumber);
        BbGet16(&bb, &queuedCb->data.setMotionEventState.reportRateHz);
        BbGet8(&bb, &queuedCb->data.setMotionEventState.motionType);

        queuedCb->typeIndex = IDX_SET_MOTION_EVENT;
    }
    else if (ctlHdr->type == packetTypes[IDX_SET_RGB_LED]) {
        BbGet16(&bb, &queuedCb->data.setControllerLed.controllerNumber);
        BbGet8(&bb, &queuedCb->data.setControllerLed.r);
        BbGet8(&bb, &queuedCb->data.setControllerLed.g);
        BbGet8(&bb, &queuedCb->data.setControllerLed.b);

        queuedCb->typeIndex = IDX_SET_RGB_LED;
    }
    else if (ctlHdr->type == packetTypes[IDX_HDR_INFO]) {
        queuedCb->typeIndex = IDX_HDR_INFO;
    }
    else if (ctlHdr->type == packetTypes[IDX_DS_ADAPTIVE_TRIGGERS]){
        BbGet16(&bb, &queuedCb->data.dsAdaptiveTrigger.controllerNumber);
        BbGet8(&bb, &queuedCb->data.dsAdaptiveTrigger.eventFlags);
        BbGet8(&bb, &queuedCb->data.dsAdaptiveTrigger.typeLeft);
        BbGet8(&bb, &queuedCb->data.dsAdaptiveTrigger.typeRight);

        BbGetBytes(&bb, queuedCb->data.dsAdaptiveTrigger.left, DS_EFFECT_PAYLOAD_SIZE);
        BbGetBytes(&bb, queuedCb->data.dsAdaptiveTrigger.right, DS_EFFECT_PAYLOAD_SIZE);
        queuedCb->typeIndex = IDX_DS_ADAPTIVE_TRIGGERS;
    }
    else {
        // Unhandled packet type from needsAsyncCallback()
        LC_ASSERT(false);
        free(queuedCb);
        return;
    }

    err = LbqOfferQueueItem(&asyncCallbackQueue, queuedCb, &queuedCb->entry);
    if (err != LBQ_SUCCESS) {
        Limelog("Failed to queue async callback: %d\n", err);
        free(queuedCb);
    }
}

static void controlReceiveThreadFunc(void* context) {
    int err;

    // This is only used for ENet
    if (AppVersionQuad[0] < 5) {
        return;
    }

    while (!PltIsThreadInterrupted(&controlReceiveThread)) {
      struct {int type;} event;

        // Poll for new packets and process retransmissions

        // Compute the next time we need to wake up to handle
        // the RTO timer or a ping.

        if (event.type == 0 /*ENET_EVENT_TYPE_RECEIVE*/) {
          // Parse packet
          PNVCTL_ENET_PACKET_HEADER_V1 ctlHdr;
          int packetLength;

            // Process HDR data immediately to update global HDR enabled state and HDR metadata.
            // The actual client callback will be invoked in the async callback thread.
            if (ctlHdr->type == packetTypes[IDX_HDR_INFO]) {
                BYTE_BUFFER bb;
                uint8_t enableByte;

                BbInitializeWrappedBuffer(&bb, (char*)ctlHdr, sizeof(*ctlHdr), packetLength - sizeof(*ctlHdr), BYTE_ORDER_LITTLE);

                BbGet8(&bb, &enableByte);
                if (IS_SUNSHINE()) {
                    // Zero the metadata buffer to properly handle older servers if we have to add new fields
                    memset(&hdrMetadata, 0, sizeof(hdrMetadata));

                    // Sunshine sends HDR metadata in this message too
                    for (int i = 0; i < 3; i++) {
                        BbGet16(&bb, &hdrMetadata.displayPrimaries[i].x);
                        BbGet16(&bb, &hdrMetadata.displayPrimaries[i].y);
                    }
                    BbGet16(&bb, &hdrMetadata.whitePoint.x);
                    BbGet16(&bb, &hdrMetadata.whitePoint.y);
                    BbGet16(&bb, &hdrMetadata.maxDisplayLuminance);
                    BbGet16(&bb, &hdrMetadata.minDisplayLuminance);
                    BbGet16(&bb, &hdrMetadata.maxContentLightLevel);
                    BbGet16(&bb, &hdrMetadata.maxFrameAverageLightLevel);
                    BbGet16(&bb, &hdrMetadata.maxFullFrameLuminance);
                }

                hdrEnabled = (enableByte != 0);
            }

            // Process client callbacks in a separate thread
            if (needsAsyncCallback(ctlHdr->type)) {
                queueAsyncCallback(ctlHdr, packetLength);
            }
            else if (ctlHdr->type == packetTypes[IDX_TERMINATION]) {
                BYTE_BUFFER bb;


                uint32_t terminationErrorCode;

                if (packetLength >= 6) {
                    // This is the extended termination message which contains a full HRESULT
                    BbInitializeWrappedBuffer(&bb, (char*)ctlHdr, sizeof(*ctlHdr), packetLength - sizeof(*ctlHdr), BYTE_ORDER_BIG);
                    BbGet32(&bb, &terminationErrorCode);

                    Limelog("Server notified termination reason: 0x%08x\n", terminationErrorCode);

                    // Normalize the termination error codes for specific values we recognize
                    switch (terminationErrorCode) {
                    case 0x800e9403: // NVST_DISCONN_SERVER_VIDEO_ENCODER_CONVERT_INPUT_FRAME_FAILED
                        terminationErrorCode = ML_ERROR_FRAME_CONVERSION;
                        break;
                    case 0x800e9302: // NVST_DISCONN_SERVER_VFP_PROTECTED_CONTENT
                        terminationErrorCode = ML_ERROR_PROTECTED_CONTENT;
                        break;
                    case 0x80030023: // NVST_DISCONN_SERVER_TERMINATED_CLOSED
                        if (lastSeenFrame != 0) {
                            // Pass error code 0 to notify the client that this was not an error
                            terminationErrorCode = ML_ERROR_GRACEFUL_TERMINATION;
                        }
                        else {
                            // We never saw a frame, so this is probably an error that caused
                            // NvStreamer to terminate prior to sending any frames.
                            terminationErrorCode = ML_ERROR_UNEXPECTED_EARLY_TERMINATION;
                        }
                        break;
                    default:
                        break;
                    }
                }
                else {
                    uint16_t terminationReason;

                    // This is the short termination message
                    BbInitializeWrappedBuffer(&bb, (char*)ctlHdr, sizeof(*ctlHdr), packetLength - sizeof(*ctlHdr), BYTE_ORDER_LITTLE);
                    BbGet16(&bb, &terminationReason);

                    Limelog("Server notified termination reason: 0x%04x\n", terminationReason);

                    // SERVER_TERMINATED_INTENDED
                    if (terminationReason == 0x0100) {
                        if (lastSeenFrame != 0) {
                            // Pass error code 0 to notify the client that this was not an error
                            terminationErrorCode = ML_ERROR_GRACEFUL_TERMINATION;
                        }
                        else {
                            // We never saw a frame, so this is probably an error that caused
                            // NvStreamer to terminate prior to sending any frames.
                            terminationErrorCode = ML_ERROR_UNEXPECTED_EARLY_TERMINATION;
                        }
                    }
                    else {
                        // Otherwise pass the reason unmodified
                        terminationErrorCode = terminationReason;
                    }
                }

                // We used to wait for a ENET_EVENT_TYPE_DISCONNECT event, but since
                // GFE 3.20.3.63 we don't get one for 10 seconds after we first get
                // this termination message. The termination message should be reliable
                // enough to end the stream now, rather than waiting for an explicit
                // disconnect. The server will also not acknowledge our disconnect
                // message once it sends this message, so we mark the peer as fully
                // disconnected now to avoid delays waiting for an ack that will
                // never arrive.
                ListenerCallbacks.connectionTerminated((int)terminationErrorCode);
                free(ctlHdr);
                return;
            }

            free(ctlHdr);
        }
        else if (event.type == 0 /* DISCONNECT */) {
            Limelog("Control stream received unexpected disconnect event\n");
            ListenerCallbacks.connectionTerminated(-1);
            return;
        }
    }
}

static void requestIdrFrame(void) {
    // If this server does not have a known IDR frame request
    // message, we'll accomplish the same thing by creating a
    // reference frame invalidation request.
    if (!supportsIdrFrameRequest) {
        int64_t payload[3];

        // Form the payload
        if (lastSeenFrame < 0x20) {
            payload[0] = 0;
            payload[1] = LE64(lastSeenFrame);
        }
        else {
            payload[0] = LE64(lastSeenFrame - 0x20);
            payload[1] = LE64(lastSeenFrame);
        }

        payload[2] = 0;

        // Send the reference frame invalidation request and read the response
        if (!sendMessageAndDiscardReply(packetTypes[IDX_INVALIDATE_REF_FRAMES],
                                        sizeof(payload),
                                        payload,
                                        CTRL_CHANNEL_URGENT,
                                        0,
                                        false)) {
            Limelog("Request IDR Frame: Transaction failed: %d\n", (int)LastSocketError());
            ListenerCallbacks.connectionTerminated(LastSocketFail());
            return;
        }
    }
    else {
        // Send IDR frame request and read the response
        if (!sendMessageAndDiscardReply(packetTypes[IDX_REQUEST_IDR_FRAME],
                                        payloadLengths[IDX_REQUEST_IDR_FRAME],
                                        preconstructedPayloads[IDX_REQUEST_IDR_FRAME],
                                        CTRL_CHANNEL_URGENT,
                                        0,
                                        false)) {
            Limelog("Request IDR Frame: Transaction failed: %d\n", (int)LastSocketError());
            ListenerCallbacks.connectionTerminated(LastSocketFail());
            return;
        }
    }

    Limelog("IDR frame request sent\n");
}

static void requestInvalidateReferenceFrames(uint32_t startFrame, uint32_t endFrame) {
    int64_t payload[3];

    LC_ASSERT(startFrame <= endFrame);
    LC_ASSERT(isReferenceFrameInvalidationEnabled());

    payload[0] = LE64(startFrame);
    payload[1] = LE64(endFrame);
    payload[2] = 0;

    // Send the reference frame invalidation request and read the response
    if (!sendMessageAndDiscardReply(packetTypes[IDX_INVALIDATE_REF_FRAMES],
                                    sizeof(payload),
                                    payload, CTRL_CHANNEL_URGENT,
                                    0,
                                    false)) {
        Limelog("Request Invaldiate Reference Frames: Transaction failed: %d\n", (int)LastSocketError());
        ListenerCallbacks.connectionTerminated(LastSocketFail());
        return;
    }

    Limelog("Invalidate reference frame request sent (%d to %d)\n", startFrame, endFrame);
}

static void invalidateRefFramesFunc(void* context) {
    LC_ASSERT(isReferenceFrameInvalidationEnabled());

    while (!PltIsThreadInterrupted(&invalidateRefFramesThread)) {
        PQUEUED_FRAME_INVALIDATION_TUPLE qfit;
        uint32_t startFrame;
        uint32_t endFrame;

        // Wait for a reference frame invalidation request or a request to shutdown
        if (LbqWaitForQueueElement(&invalidReferenceFrameTuples, (void**)&qfit) != LBQ_SUCCESS) {
            // Bail if we're stopping
            return;
        }

        startFrame = qfit->startFrame;
        endFrame = qfit->endFrame;

        // Aggregate all lost frames into one range
        do {
            LC_ASSERT(qfit->endFrame >= endFrame);
            endFrame = qfit->endFrame;
            free(qfit);
        } while (LbqPollQueueElement(&invalidReferenceFrameTuples, (void**)&qfit) == LBQ_SUCCESS);

        // Send the reference frame invalidation request
        requestInvalidateReferenceFrames(startFrame, endFrame);
    }
}

static void requestIdrFrameFunc(void* context) {
    while (!PltIsThreadInterrupted(&requestIdrFrameThread)) {
        PltWaitForEvent(&idrFrameRequiredEvent);
        PltClearEvent(&idrFrameRequiredEvent);

        if (stopping) {
            // Bail if we're stopping
            return;
        }

        // Any pending reference frame invalidation requests are now redundant
        freeBasicLbqList(LbqFlushQueueItems(&invalidReferenceFrameTuples));

        // Request the IDR frame
        requestIdrFrame();
    }
}

// Stops the control stream
int stopControlStream(void) {
    stopping = true;
    LbqSignalQueueShutdown(&invalidReferenceFrameTuples);
    LbqSignalQueueShutdown(&frameFecStatusQueue);
    LbqSignalQueueDrain(&asyncCallbackQueue);
    PltSetEvent(&idrFrameRequiredEvent);

    // This must be set to stop in a timely manner
    LC_ASSERT(ConnectionInterrupted);

    if (ctlSock != INVALID_SOCKET) {
        shutdownTcpSocket(ctlSock);
    }

    PltInterruptThread(&lossStatsThread);
    PltInterruptThread(&requestIdrFrameThread);
    PltInterruptThread(&controlReceiveThread);
    PltInterruptThread(&asyncCallbackThread);

    PltJoinThread(&lossStatsThread);
    PltJoinThread(&requestIdrFrameThread);
    PltJoinThread(&controlReceiveThread);
    PltJoinThread(&asyncCallbackThread);

    // We will only have an RFI thread if RFI is enabled
    if (isReferenceFrameInvalidationEnabled()) {
        PltInterruptThread(&invalidateRefFramesThread);
        PltJoinThread(&invalidateRefFramesThread);
    }

    if (ctlSock != INVALID_SOCKET) {
        closeSocket(ctlSock);
        ctlSock = INVALID_SOCKET;
    }

    return 0;
}

// Called by the input stream to send a packet for Gen 5+ servers
int sendInputPacketOnControlStream(unsigned char* data, int length, uint8_t channelId, uint32_t flags, bool moreData) {
    LC_ASSERT(AppVersionQuad[0] >= 5);

    // Send the input data (no reply expected)
    if (sendMessageAndForget(packetTypes[IDX_INPUT_DATA], length, data, channelId, flags, moreData) == 0) {
        return -1;
    }

    return 0;
}

// Called by the input stream to flush queued packets before a batching wait
void flushInputOnControlStream(void) {}

bool isControlDataInTransit(void) {
    return false;
}

bool LiGetEstimatedRttInfo(uint32_t* estimatedRtt, uint32_t* estimatedRttVariance) {
    return false;
}

// Starts the control stream
int startControlStream(void) {
    int err;

    // NB: Do NOT use ControlPortNumber here. 47995 is correct for these old versions.
    LC_ASSERT(ControlPortNumber == 0);
    ctlSock = connectTcpSocket(&RemoteAddr, AddrLen,
        47995, CONTROL_STREAM_TIMEOUT_SEC);
    if (ctlSock == INVALID_SOCKET) {
        stopping = true;
        return LastSocketFail();
    }

    enableNoDelay(ctlSock);

    err = PltCreateThread("ControlRecv", controlReceiveThreadFunc, NULL, &controlReceiveThread);
    if (err != 0) {
        stopping = true;
        if (ctlSock != INVALID_SOCKET) {
            closeSocket(ctlSock);
            ctlSock = INVALID_SOCKET;
        }
        return err;
    }

    // Send START A
    if (!sendMessageAndDiscardReply(packetTypes[IDX_START_A],
                                    payloadLengths[IDX_START_A],
                                    preconstructedPayloads[IDX_START_A],
                                    CTRL_CHANNEL_GENERIC,
                                    0,
                                    false)) {
        Limelog("Start A failed: %d\n", (int)LastSocketError());
        err = LastSocketFail();
        stopping = true;

        if (ctlSock != INVALID_SOCKET) {
            shutdownTcpSocket(ctlSock);
        }
        else {
            ConnectionInterrupted = true;
        }

        PltInterruptThread(&controlReceiveThread);
        PltJoinThread(&controlReceiveThread);

        if (ctlSock != INVALID_SOCKET) {
            closeSocket(ctlSock);
            ctlSock = INVALID_SOCKET;
        }
        return err;
    }

    // Send START B
    if (!sendMessageAndDiscardReply(packetTypes[IDX_START_B],
                                    payloadLengths[IDX_START_B],
                                    preconstructedPayloads[IDX_START_B],
                                    CTRL_CHANNEL_GENERIC,
                                    0,
                                    false)) {
        Limelog("Start B failed: %d\n", (int)LastSocketError());
        err = LastSocketFail();
        stopping = true;

        if (ctlSock != INVALID_SOCKET) {
            shutdownTcpSocket(ctlSock);
        }
        else {
            ConnectionInterrupted = true;
        }

        PltInterruptThread(&controlReceiveThread);
        PltJoinThread(&controlReceiveThread);

        if (ctlSock != INVALID_SOCKET) {
            closeSocket(ctlSock);
            ctlSock = INVALID_SOCKET;
        }
        return err;
    }

    err = PltCreateThread("ReqIdrFrame", requestIdrFrameFunc, NULL, &requestIdrFrameThread);
    if (err != 0) {
        stopping = true;

        if (ctlSock != INVALID_SOCKET) {
            shutdownTcpSocket(ctlSock);
        }
        else {
            ConnectionInterrupted = true;
        }

        PltInterruptThread(&lossStatsThread);
        PltJoinThread(&lossStatsThread);

        PltInterruptThread(&controlReceiveThread);
        PltJoinThread(&controlReceiveThread);

        if (ctlSock != INVALID_SOCKET) {
            closeSocket(ctlSock);
            ctlSock = INVALID_SOCKET;
        }

        return err;
    }

    err = PltCreateThread("CtrlAsyncCb", asyncCallbackThreadFunc, NULL, &asyncCallbackThread);
    if (err != 0) {
        stopping = true;
        PltSetEvent(&idrFrameRequiredEvent);

        if (ctlSock != INVALID_SOCKET) {
            shutdownTcpSocket(ctlSock);
        }
        else {
            ConnectionInterrupted = true;
        }

        PltInterruptThread(&lossStatsThread);
        PltJoinThread(&lossStatsThread);

        PltInterruptThread(&controlReceiveThread);
        PltJoinThread(&controlReceiveThread);

        PltInterruptThread(&requestIdrFrameThread);
        PltJoinThread(&requestIdrFrameThread);

        if (ctlSock != INVALID_SOCKET) {
            closeSocket(ctlSock);
            ctlSock = INVALID_SOCKET;
        }

        return err;
    }

    // Only create the reference frame invalidation thread if RFI is enabled
    if (isReferenceFrameInvalidationEnabled()) {
        err = PltCreateThread("InvRefFrames", invalidateRefFramesFunc, NULL, &invalidateRefFramesThread);
        if (err != 0) {
            stopping = true;
            PltSetEvent(&idrFrameRequiredEvent);
            LbqSignalQueueShutdown(&asyncCallbackQueue);

            if (ctlSock != INVALID_SOCKET) {
                shutdownTcpSocket(ctlSock);
            }
            else {
                ConnectionInterrupted = true;
            }

            PltInterruptThread(&lossStatsThread);
            PltJoinThread(&lossStatsThread);

            PltInterruptThread(&controlReceiveThread);
            PltJoinThread(&controlReceiveThread);

            PltInterruptThread(&requestIdrFrameThread);
            PltJoinThread(&requestIdrFrameThread);

            PltInterruptThread(&asyncCallbackThread);
            PltJoinThread(&asyncCallbackThread);

            if (ctlSock != INVALID_SOCKET) {
                closeSocket(ctlSock);
                ctlSock = INVALID_SOCKET;
            }

            return err;
        }
    }

    return 0;
}

bool LiGetCurrentHostDisplayHdrMode(void) {
    return hdrEnabled;
}

bool LiGetHdrMetadata(PSS_HDR_METADATA metadata) {
    if (!IS_SUNSHINE() || !hdrEnabled) {
        return false;
    }

    *metadata = hdrMetadata;
    return true;
}
