; ============================================================================
; mbedtls.inc — minimal FASM bindings for mbedTLS 2.16.6 (32-bit x86)
; Stock config.h, KolibriOS build
; ============================================================================

; ---------------------------------------------------------------------------
; Constants (only what is actually used)
; ---------------------------------------------------------------------------

; ssl.h
MBEDTLS_SSL_IS_CLIENT                   = 0
MBEDTLS_SSL_IS_SERVER                   = 1

MBEDTLS_SSL_TRANSPORT_STREAM            = 0
MBEDTLS_SSL_TRANSPORT_DATAGRAM          = 1

MBEDTLS_SSL_PRESET_DEFAULT              = 0
MBEDTLS_SSL_PRESET_SUITEB               = 2

MBEDTLS_SSL_VERIFY_NONE                 = 0
MBEDTLS_SSL_VERIFY_OPTIONAL             = 1
MBEDTLS_SSL_VERIFY_REQUIRED             = 2
MBEDTLS_SSL_VERIFY_UNSET                = 3

MBEDTLS_ERR_SSL_WANT_READ               = -0x6900
MBEDTLS_ERR_SSL_WANT_WRITE              = -0x6880
MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY       = -0x7880

; net_sockets.h
MBEDTLS_NET_PROTO_TCP                   = 0
MBEDTLS_NET_PROTO_UDP                   = 1


; ---------------------------------------------------------------------------
; Opaque structure definitions (EXACT SIZES)
; Stock mbedTLS 2.16.6, 32-bit x86
; ---------------------------------------------------------------------------

; net_sockets.h
struct mbedtls_net_context
        rb 12
ends

; entropy.h
struct mbedtls_entropy_context
        rb 112
ends

; ctr_drbg.h
struct mbedtls_ctr_drbg_context
        rb 104
ends

; ssl.h
struct mbedtls_ssl_context
        rb 6928
ends

struct mbedtls_ssl_config
        rb 240
ends

; x509_crt.h
struct mbedtls_x509_crt
        rb 208
ends

; ---------------------------------------------------------------------------
; End of file
; ---------------------------------------------------------------------------
