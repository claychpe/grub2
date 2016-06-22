/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010,2011  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/net.h>
#include <grub/env.h>
#include <grub/i18n.h>
#include <grub/command.h>
#include <grub/net/ip.h>
#include <grub/net/netbuff.h>
#include <grub/net/udp.h>
#include <grub/datetime.h>
#include <grub/time.h>
#include <grub/list.h>

static void
parse_dhcp_vendor (const char *name, const void *vend, int limit, int *mask)
{
  const grub_uint8_t *ptr, *ptr0;

  ptr = ptr0 = vend;

  if (ptr[0] != GRUB_NET_BOOTP_RFC1048_MAGIC_0
      || ptr[1] != GRUB_NET_BOOTP_RFC1048_MAGIC_1
      || ptr[2] != GRUB_NET_BOOTP_RFC1048_MAGIC_2
      || ptr[3] != GRUB_NET_BOOTP_RFC1048_MAGIC_3)
    return;
  ptr = ptr + sizeof (grub_uint32_t);
  while (ptr - ptr0 < limit)
    {
      grub_uint8_t tagtype;
      grub_uint8_t taglength;

      tagtype = *ptr++;

      /* Pad tag.  */
      if (tagtype == GRUB_NET_BOOTP_PAD)
	continue;

      /* End tag.  */
      if (tagtype == GRUB_NET_BOOTP_END)
	return;

      taglength = *ptr++;

      switch (tagtype)
	{
	case GRUB_NET_BOOTP_NETMASK:
	  if (taglength == 4)
	    {
	      int i;
	      for (i = 0; i < 32; i++)
		if (!(ptr[i / 8] & (1 << (7 - (i % 8)))))
		  break;
	      *mask = i;
	    }
	  break;

	case GRUB_NET_BOOTP_ROUTER:
	  if (taglength == 4)
	    {
	      grub_net_network_level_netaddress_t target;
	      grub_net_network_level_address_t gw;
	      char *rname;
	      
	      target.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
	      target.ipv4.base = 0;
	      target.ipv4.masksize = 0;
	      gw.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
	      grub_memcpy (&gw.ipv4, ptr, sizeof (gw.ipv4));
	      rname = grub_xasprintf ("%s:default", name);
	      if (rname)
		grub_net_add_route_gw (rname, target, gw, NULL);
	      grub_free (rname);
	    }
	  break;
	case GRUB_NET_BOOTP_DNS:
	  {
	    int i;
	    for (i = 0; i < taglength / 4; i++)
	      {
		struct grub_net_network_level_address s;
		s.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
		s.ipv4 = grub_get_unaligned32 (ptr);
		s.option = DNS_OPTION_PREFER_IPV4;
		grub_net_add_dns_server (&s);
		ptr += 4;
	      }
	  }
	  continue;
	case GRUB_NET_BOOTP_HOSTNAME:
          grub_env_set_net_property (name, "hostname", (const char *) ptr,
                                     taglength);
          break;

	case GRUB_NET_BOOTP_DOMAIN:
          grub_env_set_net_property (name, "domain", (const char *) ptr,
                                     taglength);
          break;

	case GRUB_NET_BOOTP_ROOT_PATH:
          grub_env_set_net_property (name, "rootpath", (const char *) ptr,
                                     taglength);
          break;

	case GRUB_NET_BOOTP_EXTENSIONS_PATH:
          grub_env_set_net_property (name, "extensionspath", (const char *) ptr,
                                     taglength);
          break;

	  /* If you need any other options please contact GRUB
	     development team.  */
	}

      ptr += taglength;
    }
}

#define OFFSET_OF(x, y) ((grub_size_t)((grub_uint8_t *)((y)->x) - (grub_uint8_t *)(y)))

struct grub_net_network_level_interface *
grub_net_configure_by_dhcp_ack (const char *name,
				struct grub_net_card *card,
				grub_net_interface_flags_t flags,
				const struct grub_net_bootp_packet *bp,
				grub_size_t size,
				int is_def, char **device, char **path)
{
  grub_net_network_level_address_t addr;
  grub_net_link_level_address_t hwaddr;
  struct grub_net_network_level_interface *inter;
  int mask = -1;

  addr.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
  addr.ipv4 = bp->your_ip;

  if (device)
    *device = 0;
  if (path)
    *path = 0;

  grub_memcpy (hwaddr.mac, bp->mac_addr,
	       bp->hw_len < sizeof (hwaddr.mac) ? bp->hw_len
	       : sizeof (hwaddr.mac));
  hwaddr.type = GRUB_NET_LINK_LEVEL_PROTOCOL_ETHERNET;

  inter = grub_net_add_addr (name, card, &addr, &hwaddr, flags);
  if (!inter)
    return 0;

#if 0
  /* This is likely based on misunderstanding. gateway_ip refers to
     address of BOOTP relay and should not be used after BOOTP transaction
     is complete.
     See RFC1542, 3.4 Interpretation of the 'giaddr' field
   */
  if (bp->gateway_ip)
    {
      grub_net_network_level_netaddress_t target;
      grub_net_network_level_address_t gw;
      char *rname;
	  
      target.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
      target.ipv4.base = bp->server_ip;
      target.ipv4.masksize = 32;
      gw.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
      gw.ipv4 = bp->gateway_ip;
      rname = grub_xasprintf ("%s:gw", name);
      if (rname)
	grub_net_add_route_gw (rname, target, gw);
      grub_free (rname);

      target.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
      target.ipv4.base = bp->gateway_ip;
      target.ipv4.masksize = 32;
      grub_net_add_route (name, target, inter);
    }
#endif

  if (size > OFFSET_OF (boot_file, bp))
    grub_env_set_net_property (name, "boot_file", bp->boot_file,
                               sizeof (bp->boot_file));
  if (is_def)
    grub_net_default_server = 0;
  if (is_def && !grub_net_default_server && bp->server_ip)
    {
      grub_net_default_server = grub_xasprintf ("%d.%d.%d.%d",
						((grub_uint8_t *) &bp->server_ip)[0],
						((grub_uint8_t *) &bp->server_ip)[1],
						((grub_uint8_t *) &bp->server_ip)[2],
						((grub_uint8_t *) &bp->server_ip)[3]);
      grub_print_error ();
    }

  if (is_def)
    {
      grub_env_set ("net_default_interface", name);
      grub_env_export ("net_default_interface");
    }

  if (device && !*device && bp->server_ip)
    {
      *device = grub_xasprintf ("tftp,%d.%d.%d.%d",
				((grub_uint8_t *) &bp->server_ip)[0],
				((grub_uint8_t *) &bp->server_ip)[1],
				((grub_uint8_t *) &bp->server_ip)[2],
				((grub_uint8_t *) &bp->server_ip)[3]);
      grub_print_error ();
    }
  if (size > OFFSET_OF (server_name, bp)
      && bp->server_name[0])
    {
      grub_env_set_net_property (name, "dhcp_server_name", bp->server_name,
                                 sizeof (bp->server_name));
      if (is_def && !grub_net_default_server)
	{
	  grub_net_default_server = grub_strdup (bp->server_name);
	  grub_print_error ();
	}
      if (device && !*device)
	{
	  *device = grub_xasprintf ("tftp,%s", bp->server_name);
	  grub_print_error ();
	}
    }

  if (size > OFFSET_OF (boot_file, bp) && path)
    {
      *path = grub_strndup (bp->boot_file, sizeof (bp->boot_file));
      grub_print_error ();
      if (*path)
	{
	  char *slash;
	  slash = grub_strrchr (*path, '/');
	  if (slash)
	    *slash = 0;
	  else
	    **path = 0;
	}
    }
  if (size > OFFSET_OF (vendor, bp))
    parse_dhcp_vendor (name, &bp->vendor, size - OFFSET_OF (vendor, bp), &mask);
  grub_net_add_ipv4_local (inter, mask);
  
  inter->dhcp_ack = grub_malloc (size);
  if (inter->dhcp_ack)
    {
      grub_memcpy (inter->dhcp_ack, bp, size);
      inter->dhcp_acklen = size;
    }
  else
    grub_errno = GRUB_ERR_NONE;

  return inter;
}

struct grub_dhcpv6_option {
  grub_uint16_t code;
  grub_uint16_t len;
  grub_uint8_t data[0];
} GRUB_PACKED;


struct grub_dhcpv6_iana_option {
  grub_uint32_t iaid;
  grub_uint32_t t1;
  grub_uint32_t t2;
  grub_uint8_t data[0];
} GRUB_PACKED;

struct grub_dhcpv6_iaaddr_option {
  grub_uint8_t addr[16];
  grub_uint32_t preferred_lifetime;
  grub_uint32_t valid_lifetime;
  grub_uint8_t data[0];
} GRUB_PACKED;

struct grub_DUID_LL
{
  grub_uint16_t type;
  grub_uint16_t hw_type;
  grub_uint8_t hwaddr[6];
} GRUB_PACKED;

enum
  {
    GRUB_DHCPv6_SOLICIT = 1,
    GRUB_DHCPv6_ADVERTISE = 2,
    GRUB_DHCPv6_REQUEST = 3,
    GRUB_DHCPv6_REPLY = 7
  };

enum
  {
    GRUB_DHCPv6_OPTION_CLIENTID = 1,
    GRUB_DHCPv6_OPTION_SERVERID = 2,
    GRUB_DHCPv6_OPTION_IA_NA = 3,
    GRUB_DHCPv6_OPTION_IAADDR = 5,
    GRUB_DHCPv6_OPTION_ORO = 6,
    GRUB_DHCPv6_OPTION_ELAPSED_TIME = 8,
    GRUB_DHCPv6_OPTION_DNS_SERVERS = 23,
    GRUB_DHCPv6_OPTION_BOOTFILE_URL = 59
  };

/* The default netbuff size for sending DHCPv6 packets which should be
   large enough to hold the information */

/* TODO: Check MTU ?? */
#define GRUB_DHCPv6_DEFAULT_NETBUFF_ALLOC_SIZE 512

struct grub_dhcp6_info
{
  grub_uint8_t *client_duid;
  grub_uint16_t client_duid_len;
  grub_uint8_t *server_duid;
  grub_uint16_t server_duid_len;
  grub_uint32_t iaid;
  grub_net_network_level_address_t *ia_addr;
  grub_net_network_level_address_t *dns_server_addrs;
  grub_uint16_t num_dns_server;
  char *boot_file_proto; /* aka scheme */
  char *boot_file_server_ip; /* aka authority */
  char *boot_file_path;
  char *device;
  char *path;
};

typedef struct grub_dhcp6_info *grub_dhcp6_info_t;

struct grub_dhcpv6_session
{
  struct grub_dhcpv6_session *next;
  struct grub_dhcpv6_session **prev;
  grub_uint32_t iaid;
  grub_uint32_t transaction_id:24;
  grub_uint64_t start_time;
  struct grub_DUID_LL duid;
  struct grub_net_network_level_interface *iface;

  /* The associated dhcpv6 options */
  /* FIXME: Remove  dhcpv6 ?? */
  grub_dhcp6_info_t dhcp6;
};

typedef grub_err_t (*dhcp6_option_hook_fn) (const struct grub_dhcpv6_option *opt, void *data);

static grub_err_t
foreach_dhcp6_option (const struct grub_dhcpv6_option *opt, grub_size_t size,
 dhcp6_option_hook_fn hook, void *hook_data);

static grub_err_t
parse_dhcp6_iaaddr (const struct grub_dhcpv6_option *opt, void *data)
{
  grub_dhcp6_info_t dhcp6 = (grub_dhcp6_info_t )data;

  grub_uint16_t code = grub_be_to_cpu16 (opt->code);
  grub_uint16_t len = grub_be_to_cpu16 (opt->len);

  if (code == GRUB_DHCPv6_OPTION_IAADDR)
    {
      const struct grub_dhcpv6_iaaddr_option *iaaddr;
      iaaddr = (const struct grub_dhcpv6_iaaddr_option *)opt->data;

      /* FIXME: Is the check really necessary ?? */
      if (len < sizeof (*iaaddr))
	return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("DHCPv6 packet is corrupted"));

      /* FIXEME: This is very ugly ... */
      if (!dhcp6->ia_addr) 
	{
	  dhcp6->ia_addr = grub_malloc (sizeof(*dhcp6->ia_addr));
	  dhcp6->ia_addr->type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
	  dhcp6->ia_addr->ipv6[0] = grub_get_unaligned64 (iaaddr->addr);
	  dhcp6->ia_addr->ipv6[1] = grub_get_unaligned64 (iaaddr->addr + 8);
	}
      /* FIXME ELSE ?? */
    }
  /* TODO: else and error out handling */

  return GRUB_ERR_NONE;
}

static grub_err_t
parse_dhcp6_info (const struct grub_dhcpv6_option *opt, void *data)
{
  grub_dhcp6_info_t dhcp6 = (grub_dhcp6_info_t)data;

  grub_uint16_t code = grub_be_to_cpu16 (opt->code);
  grub_uint16_t len = grub_be_to_cpu16 (opt->len);

  /*TODO: Erro check for len and code value */

  switch (code)
    {
      case GRUB_DHCPv6_OPTION_CLIENTID:
	dhcp6->client_duid = grub_malloc (len);
	grub_memcpy (dhcp6->client_duid, opt->data, len);
	dhcp6->client_duid_len = len;
	break;

      case GRUB_DHCPv6_OPTION_SERVERID:
	dhcp6->server_duid = grub_malloc (len);
	grub_memcpy (dhcp6->server_duid, opt->data, len);
	dhcp6->server_duid_len = len;
	break;

      case GRUB_DHCPv6_OPTION_IA_NA:
	{
	  const struct grub_dhcpv6_iana_option *ia_na;
	  grub_uint16_t data_len;

	  /* FIXME: Is this check really necessary ?? */
	  if (len < sizeof (*ia_na))
	    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("DHCPv6 packet is corrupted"));

	  ia_na = (const struct grub_dhcpv6_iana_option *)opt->data;
	  dhcp6->iaid = grub_be_to_cpu32 (ia_na->iaid);

	  /* TODO: make iaaddr a separate structure */
	  data_len = len - sizeof (*ia_na);
	  if (data_len)
	    foreach_dhcp6_option ((const struct grub_dhcpv6_option *)ia_na->data, data_len, parse_dhcp6_iaaddr, dhcp6);
	}
	break;

      case GRUB_DHCPv6_OPTION_DNS_SERVERS:
	{
	  const grub_uint8_t *po;
	  grub_uint16_t ln;
	  grub_net_network_level_address_t *la;

	  if (len == 0 || len & 0xf)
	    return grub_error (GRUB_ERR_IO, N_("invalid dns address length"));

	  dhcp6->num_dns_server = ln = len >> 4;
	  dhcp6->dns_server_addrs = la = grub_zalloc (ln * sizeof (*la));

	  for (po = opt->data; ln > 0; po += 0x10, la++, ln--)
	    { 
	      la->type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
	      la->ipv6[0] = grub_get_unaligned64 (po);
	      la->ipv6[1] = grub_get_unaligned64 (po + 8);
	      la->option = DNS_OPTION_PREFER_IPV6;
	    }
	}
	break;

      case GRUB_DHCPv6_OPTION_BOOTFILE_URL:
	{
	  grub_uint16_t scheme_len, host_len;
	  const char *scheme, *host, *path;
	  const char *protos[] = {"tftp://", "http://", NULL};
	  const char **pr;

	  /* TODO Put URL Parser in a function */

	  scheme = (const char *)opt->data;
	  for (pr = protos; *pr; pr++)
	    {
	      scheme_len = grub_strlen(*pr);

	      if (len < scheme_len)
		continue;

	      if (grub_memcmp (scheme, *pr, scheme_len) == 0)
		{
		  len -= scheme_len;
		  host = scheme + scheme_len; 
		  break;
		}
	    }

	  if (!*pr)
	    return grub_error (GRUB_ERR_IO, N_("unsupported protcol or invalid url fomat"));

	  for (path = host; len > 0 && *path != '/'; --len, ++path);

	  if (!len)
	    return grub_error (GRUB_ERR_IO, N_("invalid url format"));
      
	  host_len = path - host;

	  dhcp6->boot_file_proto = grub_zalloc (scheme_len - 2);
	  grub_memcpy (dhcp6->boot_file_proto, scheme, scheme_len - 3);

	  if (host_len > 2 && (host[0] == '[' && host[host_len - 1] == ']'))
	    {
	      dhcp6->boot_file_server_ip = grub_zalloc (host_len - 1);
	      grub_memcpy (dhcp6->boot_file_server_ip, host + 1, host_len - 2);
	    }
	  else
	    {
	      dhcp6->boot_file_server_ip = grub_zalloc (host_len + 1);
	      grub_memcpy (dhcp6->boot_file_server_ip, host, host_len);
	    }

	  dhcp6->boot_file_path = grub_zalloc (len + 1);
	  grub_memcpy (dhcp6->boot_file_path, path, len);

	  /* TODO: Error Check */
	  dhcp6->device = grub_xasprintf ("%s,%s", dhcp6->boot_file_proto, dhcp6->boot_file_server_ip);

	  if (dhcp6->boot_file_path)
	    {
	      /* TODO: Explain why we need to workaround the path */
	      /* Workaround path .... */
	      dhcp6->path = grub_strdup (dhcp6->boot_file_path);
	      if (dhcp6->path)
		{
		  char *slash;
		  slash = grub_strrchr (dhcp6->path, '/');
		  if (slash)
		    *slash = 0;
		  else
		    *dhcp6->path = 0;
		}
	    }
	}
	break;

      default:
	break;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
foreach_dhcp6_option (const struct grub_dhcpv6_option *opt, grub_size_t size, dhcp6_option_hook_fn hook, void *hook_data)
{
  while (size > 0)
    {
      grub_uint16_t code, len;

      if (size < sizeof (*opt))
	return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("DHCPv6 option size overflow detected"));

      size -= sizeof (*opt);
      len = grub_be_to_cpu16 (opt->len);
      code = grub_be_to_cpu16 (opt->code);

      if (size < len)
	return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("DHCPv6 option size overflow detected"));

      if (code == 0)
	break;
      else
	{
	  if (hook)
	    hook (opt, hook_data);
	  size -= len;
	  opt = (const struct grub_dhcpv6_option *)((grub_uint8_t *)opt + len + sizeof (*opt));
	}
    }

  return GRUB_ERR_NONE;

  /* TODO: Error Handlng here .. */
}

static grub_err_t
get_dhcp6_info (const struct grub_net_dhcpv6_packet *v6,
		grub_size_t size,
                grub_dhcp6_info_t dhcp6)
{
  if (size < sizeof (*v6))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("DHCPv6 packet size too small"));

  return (foreach_dhcp6_option ((const struct grub_dhcpv6_option *)v6->dhcp_options,
				size - sizeof (*v6), parse_dhcp6_info, dhcp6));
}

static struct grub_dhcpv6_session *grub_dhcpv6_sessions = NULL;
#define FOR_DHCPV6_SESSIONS(var) FOR_LIST_ELEMENTS (var, grub_dhcpv6_sessions)

static void
grub_dhcpv6_session_add (struct grub_dhcpv6_session *session,
    struct grub_net_network_level_interface *iface,
    grub_uint32_t iaid)
{
  struct grub_datetime date;
  grub_err_t err;
  grub_int32_t t = 0;

  err = grub_get_datetime (&date);
  if (err || !grub_datetime2unixtime (&date, &t))
    {
      grub_errno = GRUB_ERR_NONE;
      t = 0;
    }

  session->iface = iface;
  session->iaid = iaid;
  session->transaction_id = t;
  session->start_time = grub_get_time_ms ();
  session->duid.type = grub_cpu_to_be16_compile_time (3) ;
  session->duid.hw_type = grub_cpu_to_be16_compile_time (1);
  grub_memcpy (&session->duid.hwaddr, &iface->hwaddress.mac,
	  sizeof (session->duid.hwaddr));

  session->dhcp6 = NULL;
  grub_list_push (GRUB_AS_LIST_P (&grub_dhcpv6_sessions), GRUB_AS_LIST (session));
}

static void
grub_dhcpv6_sessions_free (void)
{
  struct grub_dhcpv6_session *session;

  FOR_DHCPV6_SESSIONS (session)
    {
      grub_list_remove (GRUB_AS_LIST (session));
      grub_free (session);
      session = grub_dhcpv6_sessions;
    }
}

static grub_err_t
grub_net_configure_by_dhcpv6_adv (const struct grub_net_dhcpv6_packet *v6_adv,
	grub_size_t size __attribute__ ((unused)),
	struct grub_dhcpv6_session *session)
{
  struct grub_net_buff *nb;
  /* TODO: merge opt and popt */
  struct grub_dhcpv6_option *popt;
  struct grub_net_dhcpv6_packet *v6;
  struct udphdr *udph;
  grub_net_network_level_address_t multicast;
  grub_net_link_level_address_t ll_multicast;
  struct grub_net_network_level_interface *inf;
  grub_uint64_t elapsed;
  grub_err_t err = GRUB_ERR_NONE;

  grub_dhcp6_info_t dhcp6;
  struct grub_dhcpv6_option *opt;

  dhcp6 = session->dhcp6;
  inf = session->iface;

  multicast.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
  multicast.ipv6[0] = grub_cpu_to_be64_compile_time (0xff02ULL << 48);
  multicast.ipv6[1] = grub_cpu_to_be64_compile_time (0x10002ULL);

  err = grub_net_link_layer_resolve (inf, &multicast, &ll_multicast);
  if (err)
    return err;

  nb = grub_netbuff_alloc (GRUB_DHCPv6_DEFAULT_NETBUFF_ALLOC_SIZE);

  if (!nb)
    return grub_errno;

  err = grub_netbuff_reserve (nb, GRUB_DHCPv6_DEFAULT_NETBUFF_ALLOC_SIZE);
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  /* CLIENT_ID */
  err = grub_netbuff_push (nb, dhcp6->client_duid_len + sizeof (*opt));
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }
  opt = (struct grub_dhcpv6_option *)nb->data;
  opt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_CLIENTID);
  opt->len = grub_cpu_to_be16 (dhcp6->client_duid_len);
  grub_memcpy (opt->data, dhcp6->client_duid , dhcp6->client_duid_len);

  /* SERVER_ID */
  err = grub_netbuff_push (nb, dhcp6->server_duid_len + sizeof (*opt));
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }
  opt = (struct grub_dhcpv6_option *)nb->data;
  opt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_SERVERID);
  opt->len = grub_cpu_to_be16 (dhcp6->server_duid_len);
  grub_memcpy (opt->data, dhcp6->server_duid , dhcp6->server_duid_len);

  /* IANA */
  /* FIXME: Do we have to send data ?? YES */
  struct grub_dhcpv6_iana_option *ia_na;
  struct grub_dhcpv6_iaaddr_option *iaaddr;

  err = grub_netbuff_push (nb, sizeof (*ia_na) + sizeof (*opt));
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  if (dhcp6->ia_addr)
    {
      err = grub_netbuff_push (nb, sizeof(*iaaddr) + sizeof (*opt));
      if (err)
	{
	  grub_netbuff_free (nb);
	  return err;
	}
    }
  opt = (struct grub_dhcpv6_option *)nb->data;
  opt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_IA_NA);
  opt->len = grub_cpu_to_be16 (sizeof (*ia_na));
  if (dhcp6->ia_addr)
    opt->len += grub_cpu_to_be16 (sizeof(*iaaddr) + sizeof (*opt));

  ia_na = (struct grub_dhcpv6_iana_option *)opt->data; 
  ia_na->iaid = grub_cpu_to_be32 (dhcp6->iaid); 

/* TODO: Do We really care about this t1 t2 .. ?? */
#if 0
  ia_na->t1 = grub_cpu_to_be32 (dhcp6->ia_na->t1); 
  ia_na->t2 = grub_cpu_to_be32 (dhcp6->ia_na->t2); 
#endif
  ia_na->t1 = 0; 
  ia_na->t2 = 0; 

  if (dhcp6->ia_addr)
    {
      opt = (struct grub_dhcpv6_option *)ia_na->data;
      opt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_IAADDR);
      opt->len = grub_cpu_to_be16 (sizeof (*iaaddr));
      iaaddr = (struct grub_dhcpv6_iaaddr_option *)opt->data;
      grub_set_unaligned64 (iaaddr->addr, dhcp6->ia_addr->ipv6[0]);
      grub_set_unaligned64 (iaaddr->addr + 8, dhcp6->ia_addr->ipv6[1]); 

/* TODO: Do We really care about this preferred and valid lifetime .. ?? */
#if 0
      iaaddr->preferred_lifetime = grub_cpu_to_be32 (dhcp6->ia_addr->preferred_lifetime);
      iaaddr->valid_lifetime = grub_cpu_to_be32 (dhcp6->ia_addr->valid_lifetime);
#endif
      iaaddr->preferred_lifetime = 0;
      iaaddr->valid_lifetime = 0;
    }

  /* ORO */
  err = grub_netbuff_push (nb, sizeof (*popt) + 2 * sizeof (grub_uint16_t));
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  popt = (struct grub_dhcpv6_option*) nb->data;
  popt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_ORO);
  popt->len = grub_cpu_to_be16_compile_time (2 * sizeof (grub_uint16_t));
  grub_set_unaligned16 (popt->data, grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_BOOTFILE_URL));
  grub_set_unaligned16 (popt->data + 2, grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_DNS_SERVERS));

  /* ELAPSED_TIME */
  err = grub_netbuff_push (nb, sizeof (*popt) + sizeof (grub_uint16_t));
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }
  popt = (struct grub_dhcpv6_option*) nb->data;
  popt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_ELAPSED_TIME);
  popt->len = grub_cpu_to_be16_compile_time (sizeof (grub_uint16_t));

  /* the time is expressed in hundredths of a second */
  elapsed = grub_divmod64 (grub_get_time_ms () - session->start_time, 10, 0);

  if (elapsed > 0xffff)
    elapsed = 0xffff;

  grub_set_unaligned16 (popt->data,  grub_cpu_to_be16 ((grub_uint16_t)elapsed));

  err = grub_netbuff_push (nb, sizeof (*v6));
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  v6 = (struct grub_net_dhcpv6_packet *) nb->data;
  v6->message_type = GRUB_DHCPv6_REQUEST;
  v6->transaction_id = v6_adv->transaction_id;

  err = grub_netbuff_push (nb, sizeof (*udph));
  if (err)
    {
      grub_netbuff_free (nb);
      return err;
    }

  udph = (struct udphdr *) nb->data;
  udph->src = grub_cpu_to_be16_compile_time (546);
  udph->dst = grub_cpu_to_be16_compile_time (547);
  udph->chksum = 0;
  udph->len = grub_cpu_to_be16 (nb->tail - nb->data);

  udph->chksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_UDP,
						 &inf->address,
						 &multicast);
  err = grub_net_send_ip_packet (inf, &multicast, &ll_multicast, nb,
				 GRUB_NET_IP_UDP);

  grub_netbuff_free (nb);

  return err;
}

static void
grub_net_configure_by_dhcp6_info (const char *name,
	  struct grub_net_card *card,
	  grub_dhcp6_info_t dhcp6,
	  int is_def,
	  int flags,
	  struct grub_net_network_level_interface **ret_inf) 
{
  grub_net_network_level_netaddress_t netaddr;
  struct grub_net_network_level_interface *inf;

  if (dhcp6->ia_addr)
    {
      inf = grub_net_add_addr (name, card, dhcp6->ia_addr, &card->default_address, flags);

      netaddr.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
      netaddr.ipv6.base[0] = dhcp6->ia_addr->ipv6[0];
      netaddr.ipv6.base[1] = 0;
      netaddr.ipv6.masksize = 64;
      grub_net_add_route (name, netaddr, inf);

      /* TODO: ret_inf check */
      if (ret_inf)
	*ret_inf = inf;
    }

  /* TODO: DNS bootfileurl and more ... */

  if (dhcp6->dns_server_addrs)
    {
      grub_uint16_t i;

      for (i = 0; i < dhcp6->num_dns_server; ++i)
	grub_net_add_dns_server (dhcp6->dns_server_addrs + i);
    }

  if (dhcp6->boot_file_path)
    grub_env_set_net_property (name, "boot_file", dhcp6->boot_file_path,
			  grub_strlen (dhcp6->boot_file_path));

  /* TODO is_def ?*/
  if (is_def && dhcp6->boot_file_server_ip)
    {
      grub_net_default_server = grub_strdup (dhcp6->boot_file_server_ip);
      grub_env_set ("net_default_interface", name);
      grub_env_export ("net_default_interface");
    }
}

struct grub_net_network_level_interface *
grub_net_configure_by_dhcpv6_reply (const char *name,
	struct grub_net_card *card,
	grub_net_interface_flags_t flags,
	const struct grub_net_dhcpv6_packet *v6,
	grub_size_t size,
	int is_def,
	char **device, char **path)
{
  struct grub_net_network_level_interface *inf;
  grub_dhcp6_info_t dhcp6;

  dhcp6 = grub_zalloc (sizeof(*dhcp6));
  if (!dhcp6)
    return NULL;

  get_dhcp6_info (v6, size, dhcp6);
  
  grub_net_configure_by_dhcp6_info (name, card, dhcp6, is_def, flags, &inf);

  /* TODO: Error check for device and path */
  if (device && dhcp6->device)
    *device = grub_strdup (dhcp6->device);

  if (path && dhcp6->path)
    *path = grub_strdup (dhcp6->path);

  grub_free (dhcp6);
  return inf;
}

void
grub_net_process_dhcp (struct grub_net_buff *nb,
		       struct grub_net_card *card)
{
  char *name;
  struct grub_net_network_level_interface *inf;

  name = grub_xasprintf ("%s:dhcp", card->name);
  if (!name)
    {
      grub_print_error ();
      return;
    }
  grub_net_configure_by_dhcp_ack (name, card,
				  0, (const struct grub_net_bootp_packet *) nb->data,
				  (nb->tail - nb->data), 0, 0, 0);
  grub_free (name);
  if (grub_errno)
    grub_print_error ();
  else
    {
      FOR_NET_NETWORK_LEVEL_INTERFACES(inf)
	if (grub_memcmp (inf->name, card->name, grub_strlen (card->name)) == 0
	    && grub_memcmp (inf->name + grub_strlen (card->name),
			    ":dhcp_tmp", sizeof (":dhcp_tmp") - 1) == 0)
	  {
	    grub_net_network_level_interface_unregister (inf);
	    break;
	  }
    }
}

grub_err_t
grub_net_process_dhcp6 (struct grub_net_buff *nb,
	struct grub_net_card *card __attribute__ ((unused)))
{
  const struct grub_net_dhcpv6_packet *v6;
  struct grub_dhcpv6_session *session;
  grub_size_t size;
  grub_dhcp6_info_t dhcp6;

  v6 = (const struct grub_net_dhcpv6_packet *) nb->data;
  size = nb->tail - nb->data;

  dhcp6 = grub_zalloc (sizeof(*dhcp6));
  if (!dhcp6)
    return grub_errno;    

  get_dhcp6_info (v6, size, dhcp6);

  if (!dhcp6->client_duid || !dhcp6->server_duid || !dhcp6->ia_addr)
    {
      /* FIXME: DO NOT RETURN ERROR */
      grub_free (dhcp6);
      return grub_error (GRUB_ERR_BAD_ARGUMENT, "XXXXXX\n" );
    }

  FOR_DHCPV6_SESSIONS (session)
    {
      if (session->transaction_id == v6->transaction_id &&
	  grub_memcmp (dhcp6->client_duid, &session->duid, sizeof (session->duid)) == 0 &&
	  session->iaid == dhcp6->iaid)
	{
	  session->dhcp6 = dhcp6;
	  break;
	}
    }

  if (!session)
    {
      grub_dprintf ("bootp", "DHCPv6 session not found\n");
      return GRUB_ERR_NONE;
    }

  if (v6->message_type == GRUB_DHCPv6_ADVERTISE)
    {
      grub_free (dhcp6);
      return (grub_net_configure_by_dhcpv6_adv (v6, size, session));
    }
  else if (v6->message_type == GRUB_DHCPv6_REPLY)
    {
      char *name;
      struct grub_net_network_level_interface *inf;

      inf = session->iface;
      name = grub_xasprintf ("%s:dhcp6", inf->card->name);
      if (!name)
	return grub_errno;

      grub_net_configure_by_dhcp6_info (name, inf->card, dhcp6, 1, 0, 0);

      grub_list_remove (GRUB_AS_LIST (session));
      grub_free (session);
      grub_free (name);
    }

  grub_free (dhcp6);
  return GRUB_ERR_NONE;
}

static char
hexdigit (grub_uint8_t val)
{
  if (val < 10)
    return val + '0';
  return val + 'a' - 10;
}

static grub_err_t
grub_cmd_dhcpopt (struct grub_command *cmd __attribute__ ((unused)),
		  int argc, char **args)
{
  struct grub_net_network_level_interface *inter;
  int num;
  grub_uint8_t *ptr;
  grub_uint8_t taglength;

  if (argc < 4)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("four arguments expected"));

  FOR_NET_NETWORK_LEVEL_INTERFACES (inter)
    if (grub_strcmp (inter->name, args[1]) == 0)
      break;

  if (!inter)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("unrecognised network interface `%s'"), args[1]);

  if (!inter->dhcp_ack)
    return grub_error (GRUB_ERR_IO, N_("no DHCP info found"));

  if (inter->dhcp_acklen <= OFFSET_OF (vendor, inter->dhcp_ack))
    return grub_error (GRUB_ERR_IO, N_("no DHCP options found"));

  num = grub_strtoul (args[2], 0, 0);
  if (grub_errno)
    return grub_errno;

  ptr = inter->dhcp_ack->vendor;

  if (ptr[0] != GRUB_NET_BOOTP_RFC1048_MAGIC_0
      || ptr[1] != GRUB_NET_BOOTP_RFC1048_MAGIC_1
      || ptr[2] != GRUB_NET_BOOTP_RFC1048_MAGIC_2
      || ptr[3] != GRUB_NET_BOOTP_RFC1048_MAGIC_3)
    return grub_error (GRUB_ERR_IO, N_("no DHCP options found"));
  ptr = ptr + sizeof (grub_uint32_t);
  while (1)
    {
      grub_uint8_t tagtype;

      if (ptr >= ((grub_uint8_t *) inter->dhcp_ack) + inter->dhcp_acklen)
	return grub_error (GRUB_ERR_IO, N_("no DHCP option %d found"), num);

      tagtype = *ptr++;

      /* Pad tag.  */
      if (tagtype == 0)
	continue;

      /* End tag.  */
      if (tagtype == 0xff)
	return grub_error (GRUB_ERR_IO, N_("no DHCP option %d found"), num);

      taglength = *ptr++;
	
      if (tagtype == num)
	break;
      ptr += taglength;
    }

  if (grub_strcmp (args[3], "string") == 0)
    {
      grub_err_t err = GRUB_ERR_NONE;
      char *val = grub_malloc (taglength + 1);
      if (!val)
	return grub_errno;
      grub_memcpy (val, ptr, taglength);
      val[taglength] = 0;
      if (args[0][0] == '-' && args[0][1] == 0)
	grub_printf ("%s\n", val);
      else
	err = grub_env_set (args[0], val);
      grub_free (val);
      return err;
    }

  if (grub_strcmp (args[3], "number") == 0)
    {
      grub_uint64_t val = 0;
      int i;
      for (i = 0; i < taglength; i++)
	val = (val << 8) | ptr[i];
      if (args[0][0] == '-' && args[0][1] == 0)
	grub_printf ("%llu\n", (unsigned long long) val);
      else
	{
	  char valn[64];
	  grub_snprintf (valn, sizeof (valn), "%lld\n", (unsigned long long) val);
	  return grub_env_set (args[0], valn);
	}
      return GRUB_ERR_NONE;
    }

  if (grub_strcmp (args[3], "hex") == 0)
    {
      grub_err_t err = GRUB_ERR_NONE;
      char *val = grub_malloc (2 * taglength + 1);
      int i;
      if (!val)
	return grub_errno;
      for (i = 0; i < taglength; i++)
	{
	  val[2 * i] = hexdigit (ptr[i] >> 4);
	  val[2 * i + 1] = hexdigit (ptr[i] & 0xf);
	}
      val[2 * taglength] = 0;
      if (args[0][0] == '-' && args[0][1] == 0)
	grub_printf ("%s\n", val);
      else
	err = grub_env_set (args[0], val);
      grub_free (val);
      return err;
    }

  return grub_error (GRUB_ERR_BAD_ARGUMENT,
		     N_("unrecognised DHCP option format specification `%s'"),
		     args[3]);
}

/* FIXME: allow to specify mac address.  */
static grub_err_t
grub_cmd_bootp (struct grub_command *cmd __attribute__ ((unused)),
		int argc, char **args)
{
  struct grub_net_card *card;
  struct grub_net_network_level_interface *ifaces;
  grub_size_t ncards = 0;
  unsigned j = 0;
  int interval;
  grub_err_t err;

  FOR_NET_CARDS (card)
  {
    if (argc > 0 && grub_strcmp (card->name, args[0]) != 0)
      continue;
    ncards++;
  }

  if (ncards == 0)
    return grub_error (GRUB_ERR_NET_NO_CARD, N_("no network card found"));

  ifaces = grub_zalloc (ncards * sizeof (ifaces[0]));
  if (!ifaces)
    return grub_errno;

  j = 0;
  FOR_NET_CARDS (card)
  {
    if (argc > 0 && grub_strcmp (card->name, args[0]) != 0)
      continue;
    ifaces[j].card = card;
    ifaces[j].next = &ifaces[j+1];
    if (j)
      ifaces[j].prev = &ifaces[j-1].next;
    ifaces[j].name = grub_xasprintf ("%s:dhcp_tmp", card->name);
    card->num_ifaces++;
    if (!ifaces[j].name)
      {
	unsigned i;
	for (i = 0; i < j; i++)
	  grub_free (ifaces[i].name);
	grub_free (ifaces);
	return grub_errno;
      }
    ifaces[j].address.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_DHCP_RECV;
    grub_memcpy (&ifaces[j].hwaddress, &card->default_address, 
		 sizeof (ifaces[j].hwaddress));
    j++;
  }
  ifaces[ncards - 1].next = grub_net_network_level_interfaces;
  if (grub_net_network_level_interfaces)
    grub_net_network_level_interfaces->prev = & ifaces[ncards - 1].next;
  grub_net_network_level_interfaces = &ifaces[0];
  ifaces[0].prev = &grub_net_network_level_interfaces;
  for (interval = 200; interval < 10000; interval *= 2)
    {
      int done = 0;
      for (j = 0; j < ncards; j++)
	{
	  struct grub_net_bootp_packet *pack;
	  struct grub_datetime date;
	  grub_int32_t t = 0;
	  struct grub_net_buff *nb;
	  struct udphdr *udph;
	  grub_net_network_level_address_t target;
	  grub_net_link_level_address_t ll_target;

	  if (!ifaces[j].prev)
	    continue;
	  nb = grub_netbuff_alloc (sizeof (*pack) + 64 + 128);
	  if (!nb)
	    {
	      grub_netbuff_free (nb);
	      return grub_errno;
	    }
	  err = grub_netbuff_reserve (nb, sizeof (*pack) + 64 + 128);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }
	  err = grub_netbuff_push (nb, sizeof (*pack) + 64);
	  if (err)
	    {
	      grub_netbuff_free (nb);
	      return err;
	    }
	  pack = (void *) nb->data;
	  done = 1;
	  grub_memset (pack, 0, sizeof (*pack) + 64);
	  pack->opcode = 1;
	  pack->hw_type = 1;
	  pack->hw_len = 6;
	  err = grub_get_datetime (&date);
	  if (err || !grub_datetime2unixtime (&date, &t))
	    {
	      grub_errno = GRUB_ERR_NONE;
	      t = 0;
	    }
	  pack->ident = grub_cpu_to_be32 (t);
	  pack->seconds = grub_cpu_to_be16 (t);

	  grub_memcpy (&pack->mac_addr, &ifaces[j].hwaddress.mac, 6); 

	  grub_netbuff_push (nb, sizeof (*udph));

	  udph = (struct udphdr *) nb->data;
	  udph->src = grub_cpu_to_be16_compile_time (68);
	  udph->dst = grub_cpu_to_be16_compile_time (67);
	  udph->chksum = 0;
	  udph->len = grub_cpu_to_be16 (nb->tail - nb->data);
	  target.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4;
	  target.ipv4 = 0xffffffff;
	  err = grub_net_link_layer_resolve (&ifaces[j], &target, &ll_target);
	  if (err)
	    return err;

	  udph->chksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_UDP,
							 &ifaces[j].address,
							 &target);

	  err = grub_net_send_ip_packet (&ifaces[j], &target, &ll_target, nb,
					 GRUB_NET_IP_UDP);
	  grub_netbuff_free (nb);
	  if (err)
	    return err;
	}
      if (!done)
	break;
      grub_net_poll_cards (interval, 0);
    }

  err = GRUB_ERR_NONE;
  for (j = 0; j < ncards; j++)
    {
      grub_free (ifaces[j].name);
      if (!ifaces[j].prev)
	continue;
      grub_error_push ();
      grub_net_network_level_interface_unregister (&ifaces[j]);
      err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
			N_("couldn't autoconfigure %s"),
			ifaces[j].card->name);
    }

  grub_free (ifaces);
  return err;
}


static grub_err_t
grub_cmd_bootp6 (struct grub_command *cmd __attribute__ ((unused)),
	int argc, char **args)
{
  struct grub_net_card *card;
  grub_uint32_t j = 0;
  int interval;
  grub_err_t err;
  struct grub_dhcpv6_session *session;

  err = GRUB_ERR_NONE;

  FOR_NET_CARDS (card)
  {
    struct grub_net_network_level_interface *iface;

    if (argc > 0 && grub_strcmp (card->name, args[0]) != 0)
      continue;

    iface = grub_net_ipv6_get_link_local (card, &card->default_address);
    if (!iface)
      {
	grub_dhcpv6_sessions_free ();
	return grub_errno;
      }

    session = grub_malloc (sizeof (*session));
    grub_dhcpv6_session_add (session, iface, j);
    j++;
  }

  for (interval = 200; interval < 10000; interval *= 2)
    {
      int done = 1;

      FOR_DHCPV6_SESSIONS (session)
	{
	  struct grub_net_buff *nb;
	  struct grub_dhcpv6_option *opt;
	  struct grub_net_dhcpv6_packet *v6;
	  struct grub_DUID_LL *duid;
	  struct grub_dhcpv6_iana_option *ia_na;
	  grub_net_network_level_address_t multicast;
	  grub_net_link_level_address_t ll_multicast;
	  struct udphdr *udph;

	  multicast.type = GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6;
	  multicast.ipv6[0] = grub_cpu_to_be64_compile_time (0xff02ULL << 48);
	  multicast.ipv6[1] = grub_cpu_to_be64_compile_time (0x10002ULL);

	  err = grub_net_link_layer_resolve (session->iface,
		    &multicast, &ll_multicast);
	  if (err)
	    {
	      grub_dhcpv6_sessions_free ();
	      return err;
	    }

	  nb = grub_netbuff_alloc (GRUB_DHCPv6_DEFAULT_NETBUFF_ALLOC_SIZE);

	  if (!nb)
	    {
	      grub_dhcpv6_sessions_free ();
	      return grub_errno;
	    }

	  err = grub_netbuff_reserve (nb, GRUB_DHCPv6_DEFAULT_NETBUFF_ALLOC_SIZE);
	  if (err)
	    {
	      grub_dhcpv6_sessions_free ();
	      grub_netbuff_free (nb);
	      return err;
	    }

	  err = grub_netbuff_push (nb, sizeof (*opt) + sizeof (grub_uint16_t));
	  if (err)
	    {
	      grub_dhcpv6_sessions_free ();
	      grub_netbuff_free (nb);
	      return err;
	    }

	  opt = (struct grub_dhcpv6_option *)nb->data;
	  opt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_ELAPSED_TIME);
	  opt->len = grub_cpu_to_be16_compile_time (sizeof (grub_uint16_t));
	  grub_set_unaligned16 (opt->data, 0);

	  err = grub_netbuff_push (nb, sizeof (*opt) + sizeof (*duid));
	  if (err)
	    {
	      grub_dhcpv6_sessions_free ();
	      grub_netbuff_free (nb);
	      return err;
	    }

	  opt = (struct grub_dhcpv6_option *)nb->data;
	  opt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_CLIENTID);
	  opt->len = grub_cpu_to_be16 (sizeof (*duid));

	  duid = (struct grub_DUID_LL *) opt->data;
	  grub_memcpy (duid, &session->duid, sizeof (*duid));

	  err = grub_netbuff_push (nb, sizeof (*opt) + sizeof (*ia_na));
	  if (err)
	    {
	      grub_dhcpv6_sessions_free ();
	      grub_netbuff_free (nb);
	      return err;
	    }

	  opt = (struct grub_dhcpv6_option *)nb->data;
	  opt->code = grub_cpu_to_be16_compile_time (GRUB_DHCPv6_OPTION_IA_NA);
	  opt->len = grub_cpu_to_be16 (sizeof (*ia_na));
	  ia_na = (struct grub_dhcpv6_iana_option *)opt->data;
	  ia_na->iaid = grub_cpu_to_be32 (session->iaid);
	  ia_na->t1 = 0;
	  ia_na->t2 = 0;

	  err = grub_netbuff_push (nb, sizeof (*v6));
	  if (err)
	    {
	      grub_dhcpv6_sessions_free ();
	      grub_netbuff_free (nb);
	      return err;
	    }

	  v6 = (struct grub_net_dhcpv6_packet *)nb->data;
	  v6->message_type = GRUB_DHCPv6_SOLICIT;
	  v6->transaction_id = session->transaction_id;

	  grub_netbuff_push (nb, sizeof (*udph));

	  udph = (struct udphdr *) nb->data;
	  udph->src = grub_cpu_to_be16_compile_time (546);
	  udph->dst = grub_cpu_to_be16_compile_time (547);
	  udph->chksum = 0;
	  udph->len = grub_cpu_to_be16 (nb->tail - nb->data);

	  udph->chksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_UDP,
			    &session->iface->address, &multicast);

	  err = grub_net_send_ip_packet (session->iface, &multicast,
		    &ll_multicast, nb, GRUB_NET_IP_UDP);
	  done = 0;
	  grub_netbuff_free (nb);

	  if (err)
	    {
	      grub_dhcpv6_sessions_free ();
	      return err;
	    }
	}
      if (!done)
	grub_net_poll_cards (interval, 0);
    }

  FOR_DHCPV6_SESSIONS (session)
    {
      grub_error_push ();
      err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
			N_("couldn't autoconfigure %s"),
			session->iface->card->name);
      grub_list_remove (GRUB_AS_LIST (session));
      grub_free (session);
      session = grub_dhcpv6_sessions;
    }

  return err;
}

static grub_command_t cmd_getdhcp, cmd_bootp, cmd_bootp6;

void
grub_bootp_init (void)
{
  cmd_bootp = grub_register_command ("net_bootp", grub_cmd_bootp,
				     N_("[CARD]"),
				     N_("perform a bootp autoconfiguration"));
  cmd_getdhcp = grub_register_command ("net_get_dhcp_option", grub_cmd_dhcpopt,
				       N_("VAR INTERFACE NUMBER DESCRIPTION"),
				       N_("retrieve DHCP option and save it into VAR. If VAR is - then print the value."));
  cmd_bootp6 = grub_register_command ("net_bootp6", grub_cmd_bootp6,
				     N_("[CARD]"),
				     N_("perform a DHCPv6 autoconfiguration"));
}

void
grub_bootp_fini (void)
{
  grub_unregister_command (cmd_getdhcp);
  grub_unregister_command (cmd_bootp);
  grub_unregister_command (cmd_bootp6);
}
