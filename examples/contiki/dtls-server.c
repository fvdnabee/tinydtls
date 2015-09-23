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

#define SERIAL_BUF_LENGTH 2048

#if UIP_CONF_IPV6_RPL
#include "net/rpl/rpl.h"
#endif /* UIP_CONF_IPV6_RPL */

#include <string.h>

#include "tinydtls.h"

#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif

#define DEBUG_VERBOSE 0

#include "net/ip/uip-debug.h"
#include "net/ipv6/uip-ds6-route.h"

#include "debug.h"
#include "dtls.h"

/* for handling serial-line events: */
#include "dev/serial-line.h"
unsigned long clock_start; // energest
unsigned long cpu_start_time; // energest
unsigned long lpm_start_time; // energest
unsigned long tx_start_time; // energest
unsigned long rx_start_time; // energest
unsigned long irq_start_time; // energest
uint32_t packet_transmitted_start;
uint32_t packets_received_start;

/*---------------------------------------------------------------------------*/
/* Packet sniffer */
#include "rime.h"
static uint32_t packets_received = 0;
static uint32_t packets_transmitted = 0;

void packet_received(void) { packets_received++; }
void packet_transmitted(int mac_status) { packets_transmitted++; }

RIME_SNIFFER(packet_counter, &packet_received, &packet_transmitted);
/*---------------------------------------------------------------------------*/

#ifdef TINYDTLS_ERBIUM
#include "rest-engine.h"
// Instead of including the entire er-coap-engine file, we just declare the one function we need as an external function
extern void coap_receive_from_tinydtls(uip_ip6addr_t* srcipaddr, uint16_t srcport, uint8_t* data, uint16_t datalen);
#endif

#ifdef ENABLE_POWERTRACE
#include "powertrace.h"
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
  if (DEBUG_VERBOSE) {
    size_t i;
    for (i = 0; i < len; i++)
      PRINTF("%c", data[i]);
  }

  /* echo incoming application data */
  dtls_write(ctx, session, data, len);
  return 0;
}

#ifdef TINYDTLS_ERBIUM
static int
read_coap_from_peer(struct dtls_context_t *ctx, 
              session_t *session, uint8 *data, size_t len) {
  if (DEBUG_VERBOSE) {
    size_t i;
    PRINTF("\nStart of received application data (CoAP)\n"); // fvdabeele
    for (i = 0; i < len; i++)
      PRINTF("%c", data[i]);
    PRINTF("\nEnd of of received application data (CoAP)\n"); // fvdabeele
  }

  /* pass result to erbium */
  coap_receive_from_tinydtls(&UIP_IP_BUF->srcipaddr, UIP_UDP_BUF->srcport, data, len); // Note this will call write_coap_to_latest peer

  return 0;
}

extern int
write_coap_to_peer(session_t* session, uint8_t *data, size_t len) {
  /* send CoAP message as outgoing application data */
  dtls_write(dtls_context, session, data, len);

  size_t i;
  if (DEBUG_VERBOSE) {
    PRINTF("\nStart of transmitted application data (CoAP)\n"); // fvdabeele
    for (i = 0; i < len; i++)
      PRINTF("%c", data[i]);
    PRINTF("\nEnd of of transmitted application data (CoAP)\n"); // fvdabeele
  }

  return 0;
}

extern int
dtls_server_know_peer(session_t* session) {
  // Try to find out whether we are connected to the peer via DTLS or plain-text CoAP
  dtls_peer_t* peer = dtls_get_peer(dtls_context, session);

  return peer != NULL;
}
#endif

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  if (DEBUG_VERBOSE) {
    PRINTF("send to ");
    PRINT6ADDR(&conn->ripaddr);
    PRINTF(":%u\n", uip_ntohs(conn->rport));
  }

  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {

  struct keymap_t {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[3] = {
    { (unsigned char *)"Client_identity", 15,
      (unsigned char *)"secretPSK", 9 },
    { (unsigned char *)"default identity", 16,
      (unsigned char *)"\x11\x22\x33", 3 },
    { (unsigned char *)"\0", 2,
      (unsigned char *)"", 1 }
  };

  if (type != DTLS_PSK_KEY) {
    if (type == DTLS_PSK_HINT) {
      // return "Client_identity" PSK hint
      if (result_length < psk[0].id_length) {
        dtls_warn("buffer too small for PSK identity");
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
      }

      memcpy(result, psk[0].id, psk[0].id_length);
      return psk[0].id_length;
    } else {
      return 0;
    }
  }

  if (id) {
    int i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
      if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
	if (result_length < psk[i].key_length) {
	  dtls_warn("buffer too small for PSK");
	  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
	}

	memcpy(result, psk[i].key, psk[i].key_length);
	return psk[i].key_length;
      }
    }
  }

  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
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
PROCESS(serial_comms, "Energest over serialline");
AUTOSTART_PROCESSES(&udp_server_process, &serial_comms);
/*---------------------------------------------------------------------------*/
static void
dtls_handle_read(dtls_context_t *ctx) {
  session_t session;

  if(uip_newdata()) {
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;
    session.size = sizeof(session.addr) + sizeof(session.port);
    
    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
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

#if 0
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
    .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
    .get_ecdsa_key = get_ecdsa_key,
    .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
  };
#if 0
  uip_ipaddr_t ipaddr;
  /* struct uip_ds6_addr *root_if; */
#endif /* UIP_CONF_ROUTER */

  PRINTF("DTLS server started\n");

#if 0  /* TEST */
  memset(&tmp_addr, 0, sizeof(rimeaddr_t));
  if(get_eui64_from_eeprom(tmp_addr.u8));
#if UIP_CONF_IPV6
  memcpy(&uip_lladdr.addr, &tmp_addr.u8, 8);
#endif
#endif /* TEST */

#if 0
/*   uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0); */
/*   uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr); */
/*   uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF); */

/*   create_rpl_dag(&ipaddr); */
/* #else */
  /* uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF); */

  uip_ip6addr(&ipaddr, 0xaaaa, 0,0,0,0x0200,0,0,0x0003);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);

  create_rpl_dag(&ipaddr);
#endif /* UIP_CONF_ROUTER */

  server_conn = udp_new(NULL, 0, NULL);
  udp_bind(server_conn, UIP_HTONS(61617));

  //dtls_set_log_level(DTLS_LOG_DEBUG);
  dtls_set_log_level(DTLS_LOG_CRIT);

  dtls_context = dtls_new_context(server_conn);
  if (dtls_context)
    dtls_set_handler(dtls_context, &cb);
}

#ifdef TINYDTLS_ERBIUM
#include <stdlib.h>
#include <string.h>
#include "rest-engine.h"

// Hello world resource
static void res_hello_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
RESOURCE(res_hello,
         "title=\"Hello world: ?len=0..\";rt=\"Text\"",
         res_hello_get_handler,
         NULL,
         NULL,
         NULL);

static void
res_hello_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  const char *len = NULL;
  /* Some data that has the length up to REST_MAX_CHUNK_SIZE. For more, see the chunk resource. */
  char const *const message = "Hello World! ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy";
  int length = 12; /*           |<-------->| */

  /* The query string can be retrieved by rest_get_query() or parsed for its key-value pairs. */
  if(REST.get_query_variable(request, "len", &len)) {
    length = atoi(len);
    if(length < 0) {
      length = 0;
    }
    if(length > REST_MAX_CHUNK_SIZE) {
      length = REST_MAX_CHUNK_SIZE;
    }
    memcpy(buffer, message, length);
  } else {
    memcpy(buffer, message, length);
  } REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  REST.set_header_etag(response, (uint8_t *)&length, 1);
  REST.set_response_payload(response, buffer, length);
}


// Observable resource
static void res_obs_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
static void res_obs_periodic_handler(void);

PERIODIC_RESOURCE(res_obs,
                  "title=\"Periodic demo\";obs",
                  res_obs_get_handler,
                  NULL,
                  NULL,
                  NULL,
                  5 * CLOCK_SECOND,
                  res_obs_periodic_handler);

/*
 * Use local resource state that is accessed by res_get_handler() and altered by res_periodic_handler() or PUT or POST.
 */
static int32_t event_counter = 0;

static void
res_obs_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  /*
   * For minimal complexity, request query and options should be ignored for GET on observable resources.
   * Otherwise the requests must be stored with the observer list and passed by REST.notify_subscribers().
   * This would be a TODO in the corresponding files in contiki/apps/erbium/!
   */
  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_header_max_age(response, res_obs.periodic->period / CLOCK_SECOND);
  REST.set_response_payload(response, buffer, snprintf((char *)buffer, preferred_size, "VERY LONG EVENT %lu", event_counter));

  /* The REST.subscription_handler() will be called for observable resources by the REST framework. */
}
/*
 * Additionally, a handler function named [resource name]_handler must be implemented for each PERIODIC_RESOURCE.
 * It will be called by the REST manager process with the defined period.
 */

static void
res_obs_periodic_handler()
{
  /* Do a periodic task here, e.g., sampling a sensor. */
  ++event_counter;

  /* Usually a condition is defined under with subscribers are notified, e.g., large enough delta in sensor reading. */
  if(1) {
    /* Notify the registered observers which will trigger the res_get_handler to create the response. */
    REST.notify_subscribers(&res_obs);
  }
}


// Toggle resource
#include "dev/leds.h"

static void res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/* A simple actuator example. Toggles the red led */
RESOURCE(res_toggle,
         "title=\"Red LED\";rt=\"Control\"",
         NULL,
         res_post_handler,
         NULL,
         NULL);

static void
res_post_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  leds_toggle(LEDS_RED);
}
#endif

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();

  dtls_init();
  init_dtls();

  print_local_addresses();

  if (!dtls_context) {
    dtls_emerg("cannot create context\n");
    PROCESS_EXIT();
  }

#ifdef TINYDTLS_ERBIUM
  /* Initialize the REST engine. */
  rest_init_engine();

  /* Activate the application-specific resources. */
  rest_activate_resource(&res_hello, "hello");
  rest_activate_resource(&res_obs, "obs");
#if PLATFORM_HAS_LEDS
/*  rest_activate_resource(&res_leds, "actuators/leds"); */
  rest_activate_resource(&res_toggle, "actuators/toggle");
#endif
#endif

#ifdef ENABLE_POWERTRACE
  powertrace_start(CLOCK_SECOND * 2); 
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
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static char buf[SERIAL_BUF_LENGTH];
static int blen;
#define ADD(...) do {                                                   \
    blen += snprintf(&buf[blen], sizeof(buf) - blen, __VA_ARGS__);      \
  } while(0)
static void
ipaddr_add(const uip_ipaddr_t *addr)
{
  uint16_t a;
  int i, f;
  for(i = 0, f = 0; i < sizeof(uip_ipaddr_t); i += 2) {
    a = (addr->u8[i] << 8) + addr->u8[i + 1];
    if(a == 0 && f >= 0) {
      if(f++ == 0) ADD("::");
    } else {
      if(f > 0) {
        f = -1;
      } else if(i > 0) {
        ADD(":");
      }
      ADD("%x", a);
    }
  }
}
PROCESS_THREAD(serial_comms, ev, data)
{
  static uip_ds6_route_t *r;
  static uip_ds6_nbr_t *nbr;

  PROCESS_BEGIN();

  /* initialize serial line */
  serial_line_init();
#ifdef CONTIKI_TARGET_RM090
  uart1_set_input(serial_line_input_byte);
#endif

	/* Rime sniffer */
  rime_sniffer_add(&packet_counter);

  while(1) {
    PROCESS_WAIT_EVENT();

     if(ev == serial_line_event_message) {
      char *line = (char *)data;
      if (line[0] == '?') {
        if (line[1] == 'E') { // request to print energest values:
          printf("%lu %lu %lu %lu %lu %lu %lu %lu\n",
              clock_time() - clock_start,
              energest_type_time(ENERGEST_TYPE_CPU) - cpu_start_time,
              energest_type_time(ENERGEST_TYPE_LPM) - lpm_start_time ,
              energest_type_time(ENERGEST_TYPE_TRANSMIT) - tx_start_time,
              energest_type_time(ENERGEST_TYPE_LISTEN) - rx_start_time,
              energest_type_time(ENERGEST_TYPE_IRQ) - irq_start_time,
              packets_transmitted - packet_transmitted_start,
              packets_received - packets_received_start);
        } else if (line[1] == 'A') {
          // get a tentative (is this a problem?)link-local address and return:
          blen = 0;
          uip_ds6_addr_t *lladdr;
          int i;
          lladdr = uip_ds6_get_link_local(-1);
          ipaddr_add(&lladdr->ipaddr);

          buf[blen] = '\0';
          printf("%s\n", buf);
        } else if (line[1] == 'N') { // request to print neighbour table
          int i = 0;
          blen = 0;
          for(nbr = nbr_table_head(ds6_neighbors);
              nbr != NULL;
              nbr = nbr_table_next(ds6_neighbors, nbr)) {
            if (i > 0)
              ADD(",");

            ipaddr_add(&nbr->ipaddr);
            i++;
          }

          if (blen < SERIAL_BUF_LENGTH) {
            buf[blen] = '\0';
            printf("%s\n", buf);
          } else {
            // error ...
            printf("ERROR buffer too small for blen=%d\n", blen);
          }
        } else if (line[1] == 'R') { // request to print routing table
          int i = 0;
          blen = 0;
          // lookup next hop for default route:
          //uip_ipaddr_t dummy_address;
          //uip_ip6addr(&dummy_address, 0xfe80, 0, 0, 0, 0, 0, 0, 0); //  hardcoded to aaaa:: for now
          //uip_ds6_defrt_t * defrt =  uip_ds6_defrt_lookup(&dummy_address); // NOTE: this does not work !
          uip_ipaddr_t * dftrt_addr = uip_ds6_defrt_choose();
          // add default route
          ADD("::,"); // ::/0 is default route
          ipaddr_add(dftrt_addr);
          ADD(",0");
          //ADD("%lu", defrt->lifetime.interval);

          for(r = uip_ds6_route_head(); r != NULL; r = uip_ds6_route_next(r)) {
            ADD(";");
            ipaddr_add(&r->ipaddr);
            ADD(",");
            ipaddr_add(uip_ds6_route_nexthop(r));
            ADD(",");
            ADD("%lu", (unsigned long)r->state.lifetime);
            i++;
          }

          if (blen < SERIAL_BUF_LENGTH) {
            buf[blen] = '\0';
            printf("%s\n", buf);
          } else {
            // error ...
            printf("ERROR buffer too small for blen=%d\n", blen);
          }
        }
      } else if(line[0] == '!') {
        if (line[1] == 'S') { // start/stop coap transmitting, n/a for coap server however ...
          // If this is the first time that we will start sending coap requests, then set the energest start and rime sniffer start values
          if (rx_start_time == 0) {
            clock_start = clock_time();
            rx_start_time = energest_type_time(ENERGEST_TYPE_LISTEN);
            lpm_start_time = energest_type_time(ENERGEST_TYPE_LPM);
            cpu_start_time = energest_type_time(ENERGEST_TYPE_CPU);
            tx_start_time = energest_type_time(ENERGEST_TYPE_TRANSMIT);
            irq_start_time = energest_type_time(ENERGEST_TYPE_IRQ);
            packet_transmitted_start = packets_transmitted;
            packets_received_start  = packets_received;

            printf("Energest stats reset.\n");
          } else {
            printf("Warning: Energest stats have already been reset.\n");
          }
        }
      }
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
