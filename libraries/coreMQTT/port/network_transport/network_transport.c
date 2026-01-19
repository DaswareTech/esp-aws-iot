#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "network_transport.h"
#include "sdkconfig.h"

#if CONFIG_ESP_TLS_USING_LWGSM
#include "esp_lwgsm.h"
#else
#include <sys/socket.h>
#endif

/* Short receive timeout for responsive send/receive interleaving (in ms) */
#define SOCKET_RECV_TIMEOUT_MS  100

static const char *TAG = "NET_TRANSPORT";

TlsTransportStatus_t xTlsConnect( NetworkContext_t* pxNetworkContext )
{
    TlsTransportStatus_t xRet = TLS_TRANSPORT_SUCCESS;

    esp_tls_cfg_t xEspTlsConfig = {
        .cacert_buf = (const unsigned char*) ( pxNetworkContext->pcServerRootCAPem ),
        .cacert_bytes = strlen( pxNetworkContext->pcServerRootCAPem ) + 1,
        .clientcert_buf = (const unsigned char*) ( pxNetworkContext->pcClientCertPem ),
        .clientcert_bytes = strlen( pxNetworkContext->pcClientCertPem ) + 1,
        .skip_common_name = pxNetworkContext->disableSni,
        .alpn_protos = pxNetworkContext->pAlpnProtos,
#if CONFIG_CORE_MQTT_USE_SECURE_ELEMENT
        .use_secure_element = true,
#elif CONFIG_CORE_MQTT_USE_DS_PERIPHERAL
        .ds_data = pxNetworkContext->ds_data,
#else
        .use_secure_element = false,
        .ds_data = NULL,
        .clientkey_buf = ( const unsigned char* )( pxNetworkContext->pcClientKeyPem ),
        .clientkey_bytes = strlen( pxNetworkContext->pcClientKeyPem ) + 1,
#endif
        .timeout_ms = 10000,  /* Long timeout for TLS handshake */
    };

    esp_tls_t* pxTls = esp_tls_init();

    xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
    pxNetworkContext->pxTls = pxTls;

    if (esp_tls_conn_new_sync( pxNetworkContext->pcHostname,
            strlen( pxNetworkContext->pcHostname ),
            pxNetworkContext->xPort,
            &xEspTlsConfig, pxTls) <= 0)
    {
        if (pxNetworkContext->pxTls)
        {
            esp_tls_conn_destroy(pxNetworkContext->pxTls);
            pxNetworkContext->pxTls = NULL;
        }
        xRet = TLS_TRANSPORT_CONNECT_FAILURE;
    }
    else
    {
        /* Connection successful - set shorter recv timeout for responsive operation */
        int sockfd = -1;
        if (esp_tls_get_conn_sockfd(pxTls, &sockfd) == ESP_OK && sockfd >= 0)
        {
#if CONFIG_ESP_TLS_USING_LWGSM
            /* LWGSM uses virtual connection IDs, not real sockets - use lwgsm timeout API */
            if (esp_lwgsm_set_recv_timeout(sockfd, SOCKET_RECV_TIMEOUT_MS) != 0)
            {
                ESP_LOGW(TAG, "Failed to set LWGSM recv timeout");
            }
#else
            /* LWIP uses real BSD sockets - use setsockopt */
            struct timeval tv;
            tv.tv_sec = SOCKET_RECV_TIMEOUT_MS / 1000;
            tv.tv_usec = (SOCKET_RECV_TIMEOUT_MS % 1000) * 1000;
            if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
            {
                ESP_LOGW(TAG, "Failed to set SO_RCVTIMEO");
            }
#endif
        }
    }

    xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);

    return xRet;
}

TlsTransportStatus_t xTlsDisconnect( NetworkContext_t* pxNetworkContext )
{
    BaseType_t xRet = TLS_TRANSPORT_SUCCESS;

    xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
    if (pxNetworkContext->pxTls != NULL && 
        esp_tls_conn_destroy(pxNetworkContext->pxTls) < 0)
    {
        xRet = TLS_TRANSPORT_DISCONNECT_FAILURE;
    }
    pxNetworkContext->pxTls = NULL;
    xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);

    return xRet;
}

int32_t espTlsTransportSend(NetworkContext_t* pxNetworkContext,
    const void* pvData, size_t uxDataLen)
{
    if (pvData == NULL || uxDataLen == 0)
    {
        return -1;
    }

    int32_t lBytesSent = 0;

    if(pxNetworkContext != NULL && pxNetworkContext->pxTls != NULL)
    {
        xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
        lBytesSent = esp_tls_conn_write(pxNetworkContext->pxTls, pvData, uxDataLen);
        xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);
    }
    else
    {
        lBytesSent = -1;
    }

    return lBytesSent;
}

int32_t espTlsTransportRecv(NetworkContext_t* pxNetworkContext,
    void* pvData, size_t uxDataLen)
{
    if (pvData == NULL || uxDataLen == 0)
    {
        return -1;
    }
    int32_t lBytesRead = 0;
    if(pxNetworkContext != NULL && pxNetworkContext->pxTls != NULL)
    {
        xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
        lBytesRead = esp_tls_conn_read(pxNetworkContext->pxTls, pvData, uxDataLen);
        xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);
    }
    else
    {
        return -1; /* pxNetworkContext or pxTls uninitialised */
    }
    if (lBytesRead == ESP_TLS_ERR_SSL_WANT_WRITE  || lBytesRead == ESP_TLS_ERR_SSL_WANT_READ) {
        return 0;
    }
    if (lBytesRead < 0) {
        return lBytesRead;
    }
    if (lBytesRead == 0) {
        /* Connection closed */
        return -1;
    }
    return lBytesRead;
}
