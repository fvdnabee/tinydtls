/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include "net/rpl/rpl.h"

#include <string.h>

#include "config.h"

#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/ip/uip-debug.h"

#include "debug.h"
#include "dtls.h"

#ifdef TINYDTLS_ERBIUM
// Erbium includes:
#include "erbium.h"

/* For CoAP-specific example: not required for normal RESTful Web service. */
#if WITH_COAP == 3
#include "er-coap-03.h"
#elif WITH_COAP == 7
#include "er-coap-07.h"
#elif WITH_COAP == 12
#include "er-coap-12.h"
#elif WITH_COAP == 13
#include "er-coap-13.h"
#else
#warning "Erbium example without CoAP-specifc functionality"
#endif /* CoAP-specific example */

// Instead of including the entire er-coap-13-engine file, we just declare the one function we need as an external function
//#include "apps/er-coap-13/er-coap-13-engine.h"
extern void coap_receive_from_tinydtls(uip_ip6addr_t* srcipaddr, uint16_t srcport, uint8_t* data, uint16_t datalen);
#endif

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

#define MAX_PAYLOAD_LEN 120

static struct uip_udp_conn *server_conn;

static dtls_context_t *dtls_context;

static const unsigned char ecdsa_priv_key[] = {
			0xD9, 0xE2, 0x70, 0x7A, 0x72, 0xDA, 0x6A, 0x05,
			0x04, 0x99, 0x5C, 0x86, 0xED, 0xDB, 0xE3, 0xEF,
			0xC7, 0xF1, 0xCD, 0x74, 0x83, 0x8F, 0x75, 0x70,
			0xC8, 0x07, 0x2D, 0x0A, 0x76, 0x26, 0x1B, 0xD4};

static const unsigned char ecdsa_pub_key_x[] = {
			0xD0, 0x55, 0xEE, 0x14, 0x08, 0x4D, 0x6E, 0x06,
			0x15, 0x59, 0x9D, 0xB5, 0x83, 0x91, 0x3E, 0x4A,
			0x3E, 0x45, 0x26, 0xA2, 0x70, 0x4D, 0x61, 0xF2,
			0x7A, 0x4C, 0xCF, 0xBA, 0x97, 0x58, 0xEF, 0x9A};

static const unsigned char ecdsa_pub_key_y[] = {
			0xB4, 0x18, 0xB6, 0x4A, 0xFE, 0x80, 0x30, 0xDA,
			0x1D, 0xDC, 0xF4, 0xF4, 0x2E, 0x2F, 0x26, 0x31,
			0xD0, 0x43, 0xB1, 0xFB, 0x03, 0xE2, 0x2F, 0x4D,
			0x17, 0xDE, 0x43, 0xF9, 0xF9, 0xAD, 0xEE, 0x70};

static int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {
  size_t i;
  PRINTF("\nStart of application data\n"); // fvdabeele
  for (i = 0; i < len; i++)
    PRINTF("%c", data[i]);
  PRINTF("\nEnd of application data\n"); // fvdabeele

  /* echo incoming application data */
  dtls_write(ctx, session, data, len);
  return 0;
}

#ifdef TINYDTLS_ERBIUM
static dtls_context_t* latest_peer_ctx;
static session_t* latest_peer_session;

static int
read_coap_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {
  size_t i;
  PRINTF("\nStart of received application data (CoAP)\n"); // fvdabeele
  for (i = 0; i < len; i++)
    PRINTF("%c", data[i]);
  PRINTF("\nEnd of of received application data (CoAP)\n"); // fvdabeele

  /* store ctx and session for use in write_coap_to_latest_peer */
  latest_peer_ctx = ctx;
  latest_peer_session = session;

  /* pass result to erbium */
  coap_receive_from_tinydtls(&UIP_IP_BUF->srcipaddr, UIP_UDP_BUF->srcport, data, len); // Note this will call write_coap_to_latest peer

  return 0;
}

extern int
write_coap_to_latest_peer(uint8_t *data, size_t len) {
  /* send CoAP message as outgoing application data */
  dtls_write(latest_peer_ctx, latest_peer_session, data, len);

  size_t i;
  PRINTF("\nStart of transmitted application data (CoAP)\n"); // fvdabeele
  for (i = 0; i < len; i++)
    PRINTF("%c", data[i]);
  PRINTF("\nEnd of of transmitted application data (CoAP)\n"); // fvdabeele

  return 0;
}
#endif

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  PRINTF("send to ");
  PRINT6ADDR(&conn->ripaddr);
  PRINTF(":%u\n", uip_ntohs(conn->rport));

  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}

#ifdef DTLS_PSK
static int
get_psk_key(struct dtls_context_t *ctx, 
	    const session_t *session, 
	    const unsigned char *id, size_t id_len, 
	    const dtls_psk_key_t **result) {

  static const dtls_psk_key_t psk = {
    .id = (unsigned char *)"Client_identity", 
    .id_length = 15,
    .key = (unsigned char *)"secretPSK", 
    .key_length = 9
  };

  *result = &psk;
  return 0;
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}
#endif /* DTLS_ECC */

PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
static void
dtls_handle_read(dtls_context_t *ctx) {
  session_t session;

  if(uip_newdata()) {
    uip_debug_ipaddr_print(&UIP_IP_BUF->srcipaddr);
    PRINTF("\n");
    uip_ipaddr_t temp;
    uip_ipaddr_copy(&temp,&UIP_IP_BUF->srcipaddr);
    uip_debug_ipaddr_print(&temp);
    PRINTF("\n");

    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;
    session.size = sizeof(session.addr) + sizeof(session.port);
    
    uint8 r = dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
    PRINTF("dtls_handle_message returned %d\n", r);
  }
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: \n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}

#if UIP_CONF_ROUTER && CONTIKI_TINYDTLS_RPL_DAG
static void
create_rpl_dag(uip_ipaddr_t *ipaddr)
{
  struct uip_ds6_addr *root_if;

  root_if = uip_ds6_addr_lookup(ipaddr);
  if(root_if != NULL) {
    rpl_dag_t *dag;
    uip_ipaddr_t prefix;
    
    rpl_set_root(RPL_DEFAULT_INSTANCE, ipaddr);
    dag = rpl_get_any_dag();
    uip_ip6addr(&prefix, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &prefix, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
}
#endif

void
init_dtls() {
  static dtls_handler_t cb = {
    .write = send_to_peer,
#ifndef TINYDTLS_ERBIUM
    .read  = read_from_peer,
#else
    .read  = read_coap_from_peer,
#endif
    .event = NULL,
#ifdef DTLS_PSK
    .get_psk_key = get_psk_key,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
    .get_ecdsa_key = get_ecdsa_key,
    .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
  };
#if UIP_CONF_ROUTER && CONTIKI_TINYDTLS_RPL_DAG
  uip_ipaddr_t ipaddr;
#endif /* UIP_CONF_ROUTER */

  PRINTF("DTLS server started\n");

#if 0  /* TEST */
  memset(&tmp_addr, 0, sizeof(rimeaddr_t));
  if(get_eui64_from_eeprom(tmp_addr.u8));
#if UIP_CONF_IPV6
  memcpy(&uip_lladdr.addr, &tmp_addr.u8, 8);
#endif
#endif /* TEST */

#if UIP_CONF_ROUTER && CONTIKI_TINYDTLS_RPL_DAG
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  create_rpl_dag(&ipaddr);
#endif /* UIP_CONF_ROUTER */

  server_conn = udp_new(NULL, 0, NULL);
  udp_bind(server_conn, UIP_HTONS(5683));

  dtls_set_log_level(DTLS_LOG_DEBUG);

  dtls_context = dtls_new_context(server_conn);
  if (dtls_context)
    dtls_set_handler(dtls_context, &cb);
}

/******************************************************************************/
#ifdef TINYDTLS_ERBIUM
/*
 * Resources are defined by the RESOURCE macro.
 * Signature: resource name, the RESTful methods it handles, and its URI path (omitting the leading slash).
 */
RESOURCE(helloworld, METHOD_GET, "hello", "title=\"Hello world: ?len=0..\";rt=\"Text\"");

/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
void
helloworld_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  const char *len = NULL;
  /* Some data that has the length up to REST_MAX_CHUNK_SIZE. For more, see the chunk resource. */
  char const * const message = "Hello World! ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy";
  int length = 12; /*           |<-------->| */

  /* The query string can be retrieved by rest_get_query() or parsed for its key-value pairs. */
  if (REST.get_query_variable(request, "len", &len)) {
    length = atoi(len);
    if (length<0) length = 0;
    if (length>REST_MAX_CHUNK_SIZE) length = REST_MAX_CHUNK_SIZE;
    memcpy(buffer, message, length);
  } else {
    memcpy(buffer, message, length);
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  REST.set_header_etag(response, (uint8_t *) &length, 1);
  REST.set_response_payload(response, buffer, length);
}
#endif
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();

  print_local_addresses();

  dtls_init();
  init_dtls();

  if (!dtls_context) {
    dtls_emerg("cannot create context\n");
    PROCESS_EXIT();
  }

#ifdef TINYDTLS_ERBIUM
  /* Initialize the REST engine. */
  rest_init_engine();

  /* Activate the application-specific resources. */
  rest_activate_resource(&resource_helloworld);
#endif

  while(1) {
    PROCESS_WAIT_EVENT();
    if(ev == tcpip_event) {
      dtls_handle_read(dtls_context);
    }
#if 0
    if (bytes_read > 0) {
      /* dtls_handle_message(dtls_context, &the_session, readbuf, bytes_read); */
      read_from_peer(dtls_context, &the_session, readbuf, bytes_read);
    }
    dtls_handle_message(ctx, &session, uip_appdata, bytes_read);
#endif

#ifdef TINYDTLS_ERBIUM
//#if defined (PLATFORM_HAS_BUTTON)
//    if (ev == sensors_event && data == &button_sensor) {
//      PRINTF("BUTTON\n");
//#if REST_RES_EVENT
//      /* Call the event_handler for this application-specific event. */
//      event_event_handler(&resource_event);
//#endif
//#if REST_RES_SEPARATE && WITH_COAP>3
//      /* Also call the separate response example handler. */
//      separate_finalize_handler();
//#endif
//    }
//#endif /* PLATFORM_HAS_BUTTON */
#endif
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
