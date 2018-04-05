/* Wolf Includes */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfmqtt/mqtt_client.h"
#include "wolfssl/ssl.h"

/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>

/* FreeRTOS includes */
#include "FreeRTOS.h"
#include "task.h"

/* FreeRTOS+TCP includes */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_DNS.h"
#include "FreeRTOS_Sockets.h"


/* Configuration */
#define MQTT_BUF_SIZE	1024
#define DEFAULT_MQTT_HOST       "iot.eclipse.org" /* broker.hivemq.com */
#define DEFAULT_CMD_TIMEOUT_MS  30000
#define DEFAULT_CON_TIMEOUT_MS  5000
#define DEFAULT_MQTT_QOS        MQTT_QOS_0
#define DEFAULT_KEEP_ALIVE_SEC  60
#define DEFAULT_CLIENT_ID       "WolfMQTTClient"
#define WOLFMQTT_TOPIC_NAME     "wolfMQTT/example/"
#define DEFAULT_TOPIC_NAME      WOLFMQTT_TOPIC_NAME"testTopic"


/* Context for network callbacks */
typedef enum NB_Stat {
    SOCK_BEGIN = 0,
    SOCK_CONN,
} NB_Stat;

typedef struct SocketContext {
    Socket_t fd;
    NB_Stat  state;
    int      bytes;
    struct freertos_sockaddr addr;
} SocketContext;


static MqttClient gMQTTC;
static MqttNet gMQTTN;
static byte	gMqttTxBuf[MQTT_BUF_SIZE];
static byte	gMqttRxBuf[MQTT_BUF_SIZE];
static SocketSet_t gxFDSet;
static SocketContext gMqttContext;
static int mPacketIdLast;


static uint32_t ConvertIpFromString(const char* host)
{
	union {
		uint8_t  b[4];
		uint32_t iv;
	} ip;
	uint8_t	k = 0;

	ip.iv = 0;
	while (*host) {
		if (*host == '.') {
			if (k < 3)
				k++;
			else {
				/* error too many dots */
				ip.iv = 0;
				break;
			}
		}
		else if ((*host >= '0') && (*host <= '9')) {
			ip.b[k] *= 10;
			ip.b[k] += (*host - '0');
		}
		else {
			/* error invalid number found */
			ip.iv = 0;
			break;
		}
		host++;
	}
	if (k != 3)
		ip.iv = 0; /* error not enough dots */

	return ip.iv;
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
	SocketContext *sock = (SocketContext*)context;
	uint32_t hostIp = 0;
	int rc = -1;

	(void)timeout_ms;

	switch (sock->state) {
	case SOCK_BEGIN:
		hostIp = ConvertIpFromString(host);
		if (hostIp == 0)
			hostIp = FreeRTOS_gethostbyname_a(host, NULL, 0, 0);

		if (hostIp == 0)
            break;

		sock->addr.sin_family = FREERTOS_AF_INET;
		sock->addr.sin_port = FreeRTOS_htons(port);
		sock->addr.sin_addr = hostIp;

		/* Create socket */
		sock->fd = FreeRTOS_socket(sock->addr.sin_family, FREERTOS_SOCK_STREAM,
            FREERTOS_IPPROTO_TCP );

		if (sock->fd == FREERTOS_INVALID_SOCKET)
            break;

        /* Set timeouts for socket */
        FreeRTOS_setsockopt(sock->fd, 0, FREERTOS_SO_SNDTIMEO,
            (void*)&timeout_ms, sizeof(timeout_ms));
        FreeRTOS_setsockopt(sock->fd, 0, FREERTOS_SO_RCVTIMEO,
            (void*)&timeout_ms, sizeof(timeout_ms));

		sock->state = SOCK_CONN;

		/* fall through */
	case SOCK_CONN:
		/* Start connect */
		rc = FreeRTOS_connect(sock->fd, (struct freertos_sockaddr*)&sock->addr,
            sizeof(sock->addr));
		break;
	}

	return rc;
}

static int NetRead(void *context, byte* buf, int buf_len, int timeout_ms)
{
	SocketContext *sock = (SocketContext*)context;
	int rc = -1, timeout = 0;

	if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Create the set of sockets that will be passed into FreeRTOS_select(). */
	if (gxFDSet == NULL)
		gxFDSet = FreeRTOS_CreateSocketSet();
    if (gxFDSet == NULL)
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;

	sock->bytes = 0;

	/* Loop until buf_len has been read, error or timeout */
	while ((sock->bytes < buf_len) && (timeout == 0)) {

		/* set the socket to do used */
		FreeRTOS_FD_SET(sock->fd, gxFDSet, eSELECT_READ | eSELECT_EXCEPT);

		/* Wait for any event within the socket set. */
		rc = FreeRTOS_select(gxFDSet, timeout_ms);
		if (rc != 0) {
			if (FreeRTOS_FD_ISSET(sock->fd, gxFDSet)) {
				/* Try and read number of buf_len provided,
                    minus what's already been read */
				rc = (int)FreeRTOS_recv(sock->fd, &buf[sock->bytes],
                    buf_len - sock->bytes, 0);

				if (rc <= 0) {
					rc = -1;
					break; /* Error */
				}
				else {
					sock->bytes += rc; /* Data */
				}
			}
		}
		else {
			timeout = 1;
		}
	}

    if (rc == 0 && timeout) {
        rc = MQTT_CODE_ERROR_TIMEOUT;
    }
    else if (rc < 0) {
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == -pdFREERTOS_ERRNO_EWOULDBLOCK) {
            return MQTT_CODE_CONTINUE;
        }
    #endif
        PRINTF("NetRead: Error %d", rc);
        rc = MQTT_CODE_ERROR_NETWORK;
    }
    else {
        rc = sock->bytes;
    }
    sock->bytes = 0;

	return rc;
}

static int NetWrite(void *context, const byte* buf, int buf_len, int timeout_ms)
{
	SocketContext *sock = (SocketContext*)context;
	int rc = -1;

	(void)timeout_ms;

	if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

	rc = (int)FreeRTOS_send(sock->fd, buf, buf_len, 0);

    if (rc < 0) {
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == -pdFREERTOS_ERRNO_EWOULDBLOCK) {
            return MQTT_CODE_CONTINUE;
        }
    #endif
        PRINTF("NetWrite: Error %d", rc);
        rc = MQTT_CODE_ERROR_NETWORK;
    }

	return rc;
}

static int NetDisconnect(void *context)
{
	SocketContext *sock = (SocketContext*)context;
	if (sock) {
		FreeRTOS_closesocket(sock->fd);
		sock->state = SOCK_BEGIN;
		sock->bytes = 0;
	}

	if (gxFDSet != NULL) {
		FreeRTOS_DeleteSocketSet(gxFDSet);
		gxFDSet = NULL;
	}

	return 0;
}


#define PRINT_BUFFER_SIZE 80
static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;

	(void)client;

    if (msg_new) {
        /* Determine min size to dump */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure its null terminated */

        /* Print incoming message */
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);
    }

    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure its null terminated */
    PRINTF("Payload (%d - %d): %s",
        msg->buffer_pos, msg->buffer_pos + len, buf);

    if (msg_done) {
        PRINTF("MQTT Message: Done");
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

#define MAX_PACKET_ID ((1 << 16) - 1)
static word16 mqttclient_get_packetid(void)
{
    mPacketIdLast = (mPacketIdLast >= MAX_PACKET_ID) ? 1 : mPacketIdLast + 1;
    return (word16)mPacketIdLast;
}

#ifdef ENABLE_MQTT_TLS
static int mqtt_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    PRINTF("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)", preverify,
        store->error, store->error != 0 ?
            wolfSSL_ERR_error_string(store->error, buffer) : "none");
    PRINTF("  Subject's domain name is %s", store->domain);

    if (store->error != 0) {
        /* Allowing to continue */
        /* Should check certificate and return 0 if not okay */
        PRINTF("  Allowing cert anyways");
    }

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
static int mqtt_tls_cb(MqttClient* client)
{
    int rc = WOLFSSL_FAILURE;

    client->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_PEER,
                               mqtt_tls_verify_cb);

        /* default to success */
        rc = WOLFSSL_SUCCESS;

    #if !defined(NO_CERT)
    #if !defined(NO_FILESYSTEM)
#if 0
        if (mTlsCaFile) {
            /* Load CA certificate file */
            rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx, mTlsCaFile, NULL);
        }

        /* If using a client certificate it can be loaded using: */
        /* rc = wolfSSL_CTX_use_certificate_file(client->tls.ctx,
         *                              clientCertFile, WOLFSSL_FILETYPE_PEM);*/
#endif
    #else
        /* Load CA certificate buffer */
        rc = wolfSSL_CTX_load_verify_buffer(client->tls.ctx, caCertBuf,
                                          2047, WOLFSSL_FILETYPE_PEM);

        #if 0
        if (mTlsCaFile) {
            long  caCertSize = 0;
            /* As example, load file into buffer for testing */
            byte  caCertBuf[10000];
            FILE* file = fopen(mTlsCaFile, "rb");
            if (!file) {
                err_sys("can't open file for CA buffer load");
            }
            fseek(file, 0, SEEK_END);
            caCertSize = ftell(file);
            rewind(file);
            fread(caCertBuf, sizeof(caCertBuf), 1, file);
            fclose(file);

            /* Load CA certificate buffer */
            rc = wolfSSL_CTX_load_verify_buffer(client->tls.ctx, caCertBuf,
                                              caCertSize, WOLFSSL_FILETYPE_PEM);
        }
        #endif


        /* If using a client certificate it can be loaded using: */
        /* rc = wolfSSL_CTX_use_certificate_buffer(client->tls.ctx,
         *               clientCertBuf, clientCertSize, WOLFSSL_FILETYPE_PEM);*/
    #endif /* !NO_FILESYSTEM */
    #endif /* !NO_CERT */
    }

    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}
#else
int mqtt_tls_cb(MqttClient* client)
{
    (void)client;
    return 0;
}
#endif /* ENABLE_MQTT_TLS */


void* vSecureMQTTClientTask( void *pvParameters )
{
    int rc;
    int state = -1;
    uint32_t cntr = 0;
    uint8_t pubcnt = 2;
    MqttConnect connect;
    MqttMessage lwt_msg;
    MqttPublish publish;
    char PubMsg[16];

	(void)pvParameters;

    PRINTF("Starting MQTT");

    for(;;) {
        /* setup network callbacks */
        XMEMSET(&gMQTTN, 0, sizeof(gMQTTN));
        gMQTTN.connect=NetConnect;
        gMQTTN.read=NetRead;
        gMQTTN.write=NetWrite;
        gMQTTN.disconnect=NetDisconnect;
        XMEMSET(&gMqttContext, 0, sizeof(gMqttContext));
        gMQTTN.context= &gMqttContext;

        /* initialize network state */
        ((SocketContext *)(gMQTTN.context))->state = SOCK_BEGIN;

        rc = MqttClient_Init(&gMQTTC, &gMQTTN,
                mqtt_message_cb,
                gMqttTxBuf, MQTT_BUF_SIZE,
                gMqttRxBuf, MQTT_BUF_SIZE,
                DEFAULT_CMD_TIMEOUT_MS);

        if (rc == MQTT_CODE_SUCCESS)
            state = 0;

        cntr/=100000;
        cntr*=100000;

        while ((rc == MQTT_CODE_SUCCESS) || (rc == MQTT_CODE_CONTINUE)) {
            switch (state) {
            case 0:
            {
                rc = MqttClient_NetConnect(&gMQTTC, DEFAULT_MQTT_HOST, 0,
                        DEFAULT_CON_TIMEOUT_MS, 1, mqtt_tls_cb);

                if (rc != MQTT_CODE_SUCCESS) {
                    vTaskDelay(250);
                    PRINTF("NetConnect continue(%d)...", rc);
                    break;
                }
                XMEMSET(&connect,0,sizeof(connect));
                connect.keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;

                connect.clean_session = 1;
                connect.client_id = DEFAULT_CLIENT_ID;
                //connect.username = DEFAULT_USERNAME;
                //connect.password = DEFAULT_USERPW;


                XMEMSET(&lwt_msg,0,sizeof(lwt_msg));
                connect.enable_lwt = 0;
                connect.lwt_msg = &lwt_msg;
            }
            /* fall through */
            case 1:
            {
                state = 1;

                rc = MqttClient_Connect(&gMQTTC, &connect);
                if (rc == MQTT_CODE_CONTINUE) {
                    vTaskDelay(250);
                    PRINTF("Connect continue...");
                    break;
                }

                if (rc == MQTT_CODE_SUCCESS) {
                    PRINTF("MQTT is Connected!");
                    state = 2;
                }
                else {
                    PRINTF("MQTT connected failed: %d", rc);
                    state = -1;
                }
                break;
            }
            case 2:
            {
                MqttSubscribe subscribe;
                MqttTopic topics[1];

                /* Build list of topics */
                XMEMSET(topics, 0, sizeof(topics));
                topics[0].topic_filter = DEFAULT_TOPIC_NAME;
                topics[0].qos = MQTT_QOS_0;

                /* Subscribe Topic */
                XMEMSET(&subscribe, 0, sizeof(MqttSubscribe));
                subscribe.packet_id = mqttclient_get_packetid();
                subscribe.topic_count = sizeof(topics)/sizeof(MqttTopic);
                subscribe.topics = topics;
                rc = MqttClient_Subscribe(&gMQTTC, &subscribe);

                PRINTF("Subcribed, result=%d", rc);

                state = 3;
                break;
            }
            case 3:
            {
                rc = MqttClient_WaitMessage(&gMQTTC, 750);
                if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    /* A timeout is not an error, it just means there is no data */
                    rc = MQTT_CODE_SUCCESS;
                };

                if (rc == MQTT_CODE_SUCCESS) {
                    pubcnt--;
                    if (pubcnt == 0) {
                        pubcnt = 2;
                        cntr++;

                        XSNPRINTF(PubMsg, sizeof(PubMsg), "counter:%d", (int)cntr);

                        /* Publish Topic */
                        XMEMSET(&publish, 0, sizeof(publish));
                        publish.retain = 0;
                        publish.qos = DEFAULT_MQTT_QOS;
                        publish.duplicate = 0;
                        publish.topic_name = DEFAULT_TOPIC_NAME;
                        publish.packet_id = mqttclient_get_packetid();
                        publish.buffer = (byte*)PubMsg;
                        publish.total_len = (word16)XSTRLEN(PubMsg);
                        rc = MqttClient_Publish(&gMQTTC, &publish);

                        PRINTF("Published: %s (%d)", PubMsg, rc);
                    }
                }
                break;
            }
            default:
                break;
            } /* switch */

            if ((rc != MQTT_CODE_SUCCESS) && (rc != MQTT_CODE_CONTINUE)) {
                PRINTF("Disconnect %d code %d reason %s",
                    state, rc, MqttClient_ReturnCodeToString(rc));

                MqttClient_NetDisconnect(&gMQTTC);
            }
        }

        PRINTF("While break: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);

        cntr += 100000;
        vTaskDelay(5000);
    }

    return (void*)rc;
}
