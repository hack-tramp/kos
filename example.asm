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


include '../../../../../macros.inc'
include '../../../../../debug-fdo.inc'
include '../../../../../proc32.inc'
include '../../../../../dll.inc'
include '../../../../../struct.inc'
include 'mbedtls.inc'


START:
        mcall   68, 11                  ; init heap so we can allocate memory dynamically

; load libraries
        stdcall dll.Load, @IMPORT
        test    eax, eax
        jnz     exit.no_tls

        cinvoke mbedtls_init
        test    eax, eax
        jnz     exit.no_tls

; Initialize RNG and session data
        cinvoke mbedtls_net_init, server_fd
        cinvoke mbedtls_ssl_init, ssl
        cinvoke mbedtls_ssl_config_init, conf
        cinvoke mbedtls_x509_crt_init, cacert
        cinvoke mbedtls_ctr_drbg_init, ctr_drbg
        DEBUGF  1, "Seeding the random number generator... "
        cinvoke mbedtls_entropy_init, entropy
        cinvoke mbedtls_ctr_drbg_seed, ctr_drbg, [mbedtls_entropy_func], entropy, pers, pers.len
        test    eax, eax
        jnz     fail.seed
        DEBUGF  1,  " ok\n"

; Initialize certificates
        DEBUGF  1, "  . Loading the CA root certificate ..."
        mov     eax, [mbedtls_test_cas_pem_len]
        cinvoke mbedtls_x509_crt_parse, cacert, [mbedtls_test_cas_pem], [eax]
        cmp     eax, 0
        jb      fail.cert
        DEBUGF  1, " ok (%d skipped)\n", eax

; Start the connection
        DEBUGF  1, "  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT
        cinvoke mbedtls_net_connect, server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP
        test    eax, eax
        jnz     fail.connect
        DEBUGF  1,  " ok\n"

; Setup stuff
        DEBUGF  1, "  . Setting up the SSL/TLS structure..."
        cinvoke mbedtls_ssl_config_defaults, conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT
        test    eax, eax
        jnz     fail.config
        DEBUGF  1,  " ok\n"

        cinvoke mbedtls_ssl_conf_authmode, conf, MBEDTLS_SSL_VERIFY_OPTIONAL
        cinvoke mbedtls_ssl_conf_ca_chain, conf, cacert, 0
        cinvoke mbedtls_ssl_conf_rng, conf, [mbedtls_ctr_drbg_random], ctr_drbg
;        cinvoke mbedtls_ssl_conf_dbg, conf, my_debug, stdout
        cinvoke mbedtls_ssl_setup, ssl, conf
        test    eax, eax
        jnz     fail.setup
        cinvoke mbedtls_ssl_set_hostname, ssl, SERVER_NAME
        test    eax, eax
        jnz     fail.hostname
        cinvoke mbedtls_ssl_set_bio, ssl, server_fd, [mbedtls_net_send], [mbedtls_net_recv], 0

; Handshake
        DEBUGF  1, "  . Performing the SSL/TLS handshake..."
  @@:
        cinvoke mbedtls_ssl_handshake, ssl
        cmp     eax, MBEDTLS_ERR_SSL_WANT_READ
        je      @r
        cmp     eax, MBEDTLS_ERR_SSL_WANT_WRITE
        je      @r
        test    eax, eax
        jnz     fail.handshake
        DEBUGF  1,  " ok\n"

; Verify server certificate
        DEBUGF  1, "  . Verifying peer X.509 certificate..."

        cinvoke mbedtls_ssl_get_verify_result, ssl
        test    eax, eax
        jz      @f
        DEBUGF  1, " failed\n"
        cinvoke mbedtls_x509_crt_verify_info, vrfy_buf, 512, exc_sz, eax
        DEBUGF  1, "%s\n", vrfy_buf
        jmp     verify_done             ; In real life, we probably want to bail out here
  @@:
        DEBUGF  1,  " ok\n"
verify_done:

; Write GET request
        DEBUGF  1, "  > Write to server:"
  @@:
        cinvoke mbedtls_ssl_write, ssl, GET_REQUEST, GET_REQUEST.len
        cmp     eax, MBEDTLS_ERR_SSL_WANT_READ
        je      @r
        cmp     eax, MBEDTLS_ERR_SSL_WANT_WRITE
        je      @r
        cmp     eax, 0
        jb      fail.write

        DEBUGF  1, " %d bytes written\n\n%s", eax, GET_REQUEST

; Read HTTP response
        DEBUGF  1, "  < Read from server:"
  @@:
        cinvoke mbedtls_ssl_read, ssl, rcv_buf, BUFFER_LENGTH
        cmp     eax, MBEDTLS_ERR_SSL_WANT_READ
        je      @r
        cmp     eax, MBEDTLS_ERR_SSL_WANT_WRITE
        je      @r
        cmp     eax, MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
        je      closed
        cmp     eax, 0
        jb      fail.read
        je      eof

        mov     byte[rcv_buf+eax], 0
        DEBUGF  1, " %d bytes read\n\n%s", eax, rcv_buf
        jmp     @r

eof:
        DEBUGF  1, "\n\nEOF\n\n"
closed:
        cinvoke mbedtls_ssl_close_notify, ssl
        jmp     exit

fail:
  .read:
        DEBUGF  1, " failed\n  ! mbedtls_ssl_read returned %d\n\n", eax
        jmp     exit

  .write:
        DEBUGF  1, " failed\n  ! mbedtls_ssl_write returned %d\n\n", eax
        jmp     exit

  .handshake:
        neg     eax
        DEBUGF  1, " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", eax
        jmp     exit

  .hostname:
        DEBUGF  1, " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", eax
        jmp     exit

  .setup:
        DEBUGF  1, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", eax
        jmp     exit

  .config:
        DEBUGF  1, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", eax
        jmp     exit

  .connect:
        DEBUGF  1, " failed\n  ! mbedtls_net_connect returned %d\n\n", eax
        jmp     exit

  .cert:
        neg     eax
        DEBUGF  1, " failed\n  ! mbedtls_x509_crt_parse returned -0x%x\n\n", eax
        jmp     exit

  .seed:
        DEBUGF  1, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", eax
;        jmp     exit

exit:
        cinvoke mbedtls_net_free, server_fd

        cinvoke mbedtls_x509_crt_free, cacert
        cinvoke mbedtls_ssl_free, ssl
        cinvoke mbedtls_ssl_config_free, conf
        cinvoke mbedtls_ctr_drbg_free, ctr_drbg
        cinvoke mbedtls_entropy_free, entropy

  .no_tls:

        mcall   -1

;---------------------------------------------------------------------
; Data area
;-----------------------------------------------------------------------------
align   4
@IMPORT:

library lib_mbedtls,               'mbedtls.obj'

import  lib_mbedtls, \
mbedtls_init                   ,   'mbedtls_init'                   ,\
mbedtls_strerror               ,   'mbedtls_strerror'               ,\
mbedtls_test_cas_pem           ,   'mbedtls_test_cas_pem'           ,\
mbedtls_test_cas_pem_len       ,   'mbedtls_test_cas_pem_len'       ,\
mbedtls_x509_crt_free          ,   'mbedtls_x509_crt_free'          ,\
mbedtls_x509_crt_init          ,   'mbedtls_x509_crt_init'          ,\
mbedtls_x509_crt_parse         ,   'mbedtls_x509_crt_parse'         ,\
mbedtls_x509_crt_verify_info   ,   'mbedtls_x509_crt_verify_info'   ,\
mbedtls_ctr_drbg_free          ,   'mbedtls_ctr_drbg_free'          ,\
mbedtls_ctr_drbg_init          ,   'mbedtls_ctr_drbg_init'          ,\
mbedtls_ctr_drbg_random        ,   'mbedtls_ctr_drbg_random'        ,\
mbedtls_ctr_drbg_seed          ,   'mbedtls_ctr_drbg_seed'          ,\
mbedtls_debug_set_threshold    ,   'mbedtls_debug_set_threshold'    ,\
mbedtls_entropy_free           ,   'mbedtls_entropy_free'           ,\
mbedtls_entropy_func           ,   'mbedtls_entropy_func'           ,\
mbedtls_entropy_init           ,   'mbedtls_entropy_init'           ,\
mbedtls_net_connect            ,   'mbedtls_net_connect'            ,\
mbedtls_net_free               ,   'mbedtls_net_free'               ,\
mbedtls_net_init               ,   'mbedtls_net_init'               ,\
mbedtls_net_recv               ,   'mbedtls_net_recv'               ,\
mbedtls_net_send               ,   'mbedtls_net_send'               ,\
mbedtls_ssl_close_notify       ,   'mbedtls_ssl_close_notify'       ,\
mbedtls_ssl_conf_authmode      ,   'mbedtls_ssl_conf_authmode'      ,\
mbedtls_ssl_conf_ca_chain      ,   'mbedtls_ssl_conf_ca_chain'      ,\
mbedtls_ssl_conf_dbg           ,   'mbedtls_ssl_conf_dbg'           ,\
mbedtls_ssl_config_defaults    ,   'mbedtls_ssl_config_defaults'    ,\
mbedtls_ssl_config_free        ,   'mbedtls_ssl_config_free'        ,\
mbedtls_ssl_config_init        ,   'mbedtls_ssl_config_init'        ,\
mbedtls_ssl_conf_rng           ,   'mbedtls_ssl_conf_rng'           ,\
mbedtls_ssl_free               ,   'mbedtls_ssl_free'               ,\
mbedtls_ssl_get_verify_result  ,   'mbedtls_ssl_get_verify_result'  ,\
mbedtls_ssl_handshake          ,   'mbedtls_ssl_handshake'          ,\
mbedtls_ssl_init               ,   'mbedtls_ssl_init'               ,\
mbedtls_ssl_read               ,   'mbedtls_ssl_read'               ,\
mbedtls_ssl_set_bio            ,   'mbedtls_ssl_set_bio'            ,\
mbedtls_ssl_set_hostname       ,   'mbedtls_ssl_set_hostname'       ,\
mbedtls_ssl_setup              ,   'mbedtls_ssl_setup'              ,\
mbedtls_ssl_write              ,   'mbedtls_ssl_write'

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

; Uninitialize data

;exit_code           dd -1       ;?
server_fd       mbedtls_net_context
;flags           dd ?
rcv_buf         rb BUFFER_LENGTH + 1

entropy         mbedtls_entropy_context
ctr_drbg        mbedtls_ctr_drbg_context
ssl             mbedtls_ssl_context
conf            mbedtls_ssl_config
cacert          mbedtls_x509_crt
vrfy_buf        rb 512

I_END:



