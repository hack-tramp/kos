;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                                 ;;
;; Copyright (C) KolibriOS team 2021. All rights reserved.         ;;
;; Distributed under terms of the GNU General Public License       ;;
;;                                                                 ;;
;;          GNU GENERAL PUBLIC LICENSE                             ;;
;;             Version 2, June 1991                                ;;
;;                                                                 ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

__DEBUG__ = 1
__DEBUG_LEVEL__ = 1

BUFFER_LENGTH   = 4095

format binary as ""
use32
        org     0x0

        db      'MENUET01'      ; header
        dd      0x01            ; header version
        dd      START           ; entry point
        dd      IM_END          ; image size
        dd      I_END+0x1000    ; required memory
        dd      I_END+0x1000    ; esp
        dd      0               ; I_Param
        dd      0               ; I_Path

include 'include/macros.inc'
include 'include/debug-fdo.inc'
include 'include/proc32.inc'
include 'include/dll.inc'
include 'include/struct.inc'
include 'mbedtls.inc'

;------------------------------------------------------------
; Real CA: ISRG Root X1 (Let’s Encrypt)
;------------------------------------------------------------
isrg_root_x1_pem db "-----BEGIN CERTIFICATE-----",13,10,\
"MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw",13,10,\
"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh",13,10,\
"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4",13,10,\
"WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu",13,10,\
"ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY",13,10,\
"MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc",13,10,\
"h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+",13,10,\
"0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U",13,10,\
"A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW",13,10,\
"T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH",13,10,\
"B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC",13,10,\
"B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv",13,10,\
"KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn",13,10,\
"OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn",13,10,\
"jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw",13,10,\
"qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI",13,10,\
"rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV",13,10,\
"HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq",13,10,\
"hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL",13,10,\
"ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ",13,10,\
"3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK",13,10,\
"NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5",13,10,\
"ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur",13,10,\
"TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC",13,10,\
"jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc",13,10,\
"oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq",13,10,\
"4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA",13,10,\
"mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d",13,10,\
"emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=",13,10,\
"-----END CERTIFICATE-----",13,10,0

isrg_root_x1_pem_len = $ - isrg_root_x1_pem

;---------------------------------------------------------------------
; Start program

START:
        mcall   68, 11                  ; init heap

        stdcall dll.Load, @IMPORT
        test    eax, eax
        jnz     exit.no_tls

        cinvoke mbedtls_init
        test    eax, eax
        jnz     exit.no_tls

        ; Initialize TLS objects
        cinvoke mbedtls_net_init, server_fd
        cinvoke mbedtls_ssl_init, ssl
        cinvoke mbedtls_ssl_config_init, conf
        cinvoke mbedtls_x509_crt_init, cacert
        cinvoke mbedtls_ctr_drbg_init, ctr_drbg
        DEBUGF 1, "Seeding RNG..."
        cinvoke mbedtls_entropy_init, entropy
        cinvoke mbedtls_ctr_drbg_seed, ctr_drbg, [mbedtls_entropy_func], entropy, pers, pers.len
        test eax, eax
        jnz fail.seed
        DEBUGF 1, " ok"

        ; Load certificates
        DEBUGF 1, " Loading CA root certificate..."
	cinvoke mbedtls_x509_crt_parse, cacert, isrg_root_x1_pem, isrg_root_x1_pem_len
        cmp eax, 0
        jb fail.cert
        DEBUGF 1, " ok (%d skipped)", eax

        ; Connect to server
        DEBUGF 1, " Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT
        cinvoke mbedtls_net_connect, server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP
        test eax, eax
        jnz fail.connect
        DEBUGF 1, " ok"

        ; Setup SSL
        DEBUGF 1, " Setting up SSL..."
        cinvoke mbedtls_ssl_config_defaults, conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT
        test eax, eax
        jnz fail.config
        DEBUGF 1, " ok"

        cinvoke mbedtls_ssl_conf_authmode, conf, MBEDTLS_SSL_VERIFY_REQUIRED
        cinvoke mbedtls_ssl_conf_ca_chain, conf, cacert, 0
        cinvoke mbedtls_ssl_conf_rng, conf, [mbedtls_ctr_drbg_random], ctr_drbg
        cinvoke mbedtls_ssl_setup, ssl, conf
        test eax, eax
        jnz fail.setup
        cinvoke mbedtls_ssl_set_hostname, ssl, SERVER_NAME
        test eax, eax
        jnz fail.hostname
        cinvoke mbedtls_ssl_set_bio, ssl, server_fd, [mbedtls_net_send], [mbedtls_net_recv], 0

        ; Handshake
        DEBUGF 1, " Performing TLS handshake..."
@@:
        cinvoke mbedtls_ssl_handshake, ssl
        cmp eax, MBEDTLS_ERR_SSL_WANT_READ
        je @r
        cmp eax, MBEDTLS_ERR_SSL_WANT_WRITE
        je @r
        test eax, eax
        jnz fail.handshake
        DEBUGF 1, " ok"

        ; Verify peer certificate
        DEBUGF 1, " Verifying peer X.509 certificate..."
        cinvoke mbedtls_ssl_get_verify_result, ssl
        test eax, eax
        jz @f
        DEBUGF 1, " failed"
        cinvoke mbedtls_x509_crt_verify_info, vrfy_buf, 512, exc_sz, eax
        DEBUGF 1, "%s", vrfy_buf
        jmp verify_done
@@:
        DEBUGF 1, " ok"
verify_done:

        ; Write HTTP GET
        DEBUGF 1, " Writing GET request..."
@@write:
        cinvoke mbedtls_ssl_write, ssl, GET_REQUEST, GET_REQUEST.len
        cmp eax, MBEDTLS_ERR_SSL_WANT_READ
        je @r
        cmp eax, MBEDTLS_ERR_SSL_WANT_WRITE
        je @r
        cmp eax, 0
        jb fail.write
        DEBUGF 1, " %d bytes written", eax
        jmp @@write

        ; Read HTTP response
        DEBUGF 1, " Reading response..."
@@read:
        cinvoke mbedtls_ssl_read, ssl, rcv_buf, BUFFER_LENGTH
        cmp eax, MBEDTLS_ERR_SSL_WANT_READ
        je @r
        cmp eax, MBEDTLS_ERR_SSL_WANT_WRITE
        je @r
        cmp eax, MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
        je closed
        cmp eax, 0
        jb fail.read
        je eof
        mov byte [rcv_buf+eax], 0
        DEBUGF 1, " %d bytes read", eax
        jmp @@read

eof:
        DEBUGF 1, " EOF"
closed:
        cinvoke mbedtls_ssl_close_notify, ssl
        jmp exit

;---------------------------------------------------------------------
; Fail labels
fail:
  .read:
        DEBUGF 1, " failed read %d", eax
        jmp exit
  .write:
        DEBUGF 1, " failed write %d", eax
        jmp exit
  .handshake:
        neg eax
        DEBUGF 1, " handshake failed -0x%x", eax
        jmp exit
  .hostname:
        DEBUGF 1, " hostname failed %d", eax
        jmp exit
  .setup:
        DEBUGF 1, " ssl_setup failed %d", eax
        jmp exit
  .config:
        DEBUGF 1, " config_defaults failed %d", eax
        jmp exit
  .connect:
        DEBUGF 1, " net_connect failed %d", eax
        jmp exit
  .cert:
        neg eax
        DEBUGF 1, " cert_parse failed -0x%x", eax
        jmp exit
  .seed:
        DEBUGF 1, " ctr_drbg_seed failed %d", eax
        jmp exit

;---------------------------------------------------------------------
; Exit
exit:
        cinvoke mbedtls_net_free, server_fd
        cinvoke mbedtls_x509_crt_free, cacert
        cinvoke mbedtls_ssl_free, ssl
        cinvoke mbedtls_ssl_config_free, conf
        cinvoke mbedtls_ctr_drbg_free, ctr_drbg
        cinvoke mbedtls_entropy_free, entropy

exit.no_tls:
        mcall -1

;---------------------------------------------------------------------
; Data Section
align 4
@IMPORT:
library lib_kosnet, 'libkosnet.a'

library lib_mbedtls, 'mbedtls.obj'

import lib_mbedtls, \
mbedtls_init, 'mbedtls_init',\
mbedtls_strerror, 'mbedtls_strerror',\
mbedtls_x509_crt_free, 'mbedtls_x509_crt_free',\
mbedtls_x509_crt_init, 'mbedtls_x509_crt_init',\
mbedtls_x509_crt_parse, 'mbedtls_x509_crt_parse',\
mbedtls_x509_crt_verify_info, 'mbedtls_x509_crt_verify_info',\
mbedtls_ctr_drbg_free, 'mbedtls_ctr_drbg_free',\
mbedtls_ctr_drbg_init, 'mbedtls_ctr_drbg_init',\
mbedtls_ctr_drbg_random, 'mbedtls_ctr_drbg_random',\
mbedtls_ctr_drbg_seed, 'mbedtls_ctr_drbg_seed',\
mbedtls_entropy_free, 'mbedtls_entropy_free',\
mbedtls_entropy_func, 'mbedtls_entropy_func',\
mbedtls_entropy_init, 'mbedtls_entropy_init',\
mbedtls_net_connect, 'mbedtls_net_connect',\
mbedtls_net_free, 'mbedtls_net_free',\
mbedtls_net_init, 'mbedtls_net_init',\
mbedtls_net_recv, 'mbedtls_net_recv',\
mbedtls_net_send, 'mbedtls_net_send',\
mbedtls_ssl_close_notify, 'mbedtls_ssl_close_notify',\
mbedtls_ssl_conf_authmode, 'mbedtls_ssl_conf_authmode',\
mbedtls_ssl_conf_ca_chain, 'mbedtls_ssl_conf_ca_chain',\
mbedtls_ssl_conf_rng, 'mbedtls_ssl_conf_rng',\
mbedtls_ssl_config_defaults, 'mbedtls_ssl_config_defaults',\
mbedtls_ssl_config_free, 'mbedtls_ssl_config_free',\
mbedtls_ssl_config_init, 'mbedtls_ssl_config_init',\
mbedtls_ssl_free, 'mbedtls_ssl_free',\
mbedtls_ssl_get_verify_result, 'mbedtls_ssl_get_verify_result',\
mbedtls_ssl_handshake, 'mbedtls_ssl_handshake',\
mbedtls_ssl_init, 'mbedtls_ssl_init',\
mbedtls_ssl_read, 'mbedtls_ssl_read',\
mbedtls_ssl_set_bio, 'mbedtls_ssl_set_bio',\
mbedtls_ssl_set_hostname, 'mbedtls_ssl_set_hostname',\
mbedtls_ssl_setup, 'mbedtls_ssl_setup',\
mbedtls_ssl_write, 'mbedtls_ssl_write'

include_debug_strings

pers db "ssl_client1"
  .len = $ - pers

exc_sz  db "  ! ", 0

SERVER_PORT db "443", 0
SERVER_NAME db "kolibrios.org", 0
GET_REQUEST db "GET / HTTP/1.1", 13, 10
            db "Host: kolibrios.org", 13, 10, 13, 10
  .len = $ - GET_REQUEST
            db 0

IM_END:

server_fd       mbedtls_net_context
rcv_buf         rb BUFFER_LENGTH + 1
entropy         mbedtls_entropy_context
ctr_drbg        mbedtls_ctr_drbg_context
ssl             mbedtls_ssl_context
conf            mbedtls_ssl_config
cacert          mbedtls_x509_crt
vrfy_buf        rb 512

I_END:
