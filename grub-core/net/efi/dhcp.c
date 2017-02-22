#include <grub/mm.h>
#include <grub/command.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/misc.h>
#include <grub/net/efi.h>
#include <grub/charset.h>

#ifdef GRUB_EFI_NET_DEBUG
static void
dhcp4_mode_print (grub_efi_dhcp4_mode_data_t *mode)
{
    switch (mode->state)
      {
	case GRUB_EFI_DHCP4_STOPPED:
	  grub_printf ("STATE: STOPPED\n");
	  break;
	case GRUB_EFI_DHCP4_INIT:
	  grub_printf ("STATE: INIT\n");
	  break;
	case GRUB_EFI_DHCP4_SELECTING:
	  grub_printf ("STATE: SELECTING\n");
	  break;
	case GRUB_EFI_DHCP4_REQUESTING:
	  grub_printf ("STATE: REQUESTING\n");
	  break;
	case GRUB_EFI_DHCP4_BOUND:
	  grub_printf ("STATE: BOUND\n");
	  break;
	case GRUB_EFI_DHCP4_RENEWING:
	  grub_printf ("STATE: RENEWING\n");
	  break;
	case GRUB_EFI_DHCP4_REBINDING:
	  grub_printf ("STATE: REBINDING\n");
	  break;
	case GRUB_EFI_DHCP4_INIT_REBOOT:
	  grub_printf ("STATE: INIT_REBOOT\n");
	  break;
	case GRUB_EFI_DHCP4_REBOOTING:
	  grub_printf ("STATE: REBOOTING\n");
	  break;
	default:
	  grub_printf ("STATE: UNKNOWN\n");
	  break;
      }

    grub_printf ("CLIENT_ADDRESS: %u.%u.%u.%u\n",
      mode->client_address[0],
      mode->client_address[1],
      mode->client_address[2],
      mode->client_address[3]);
    grub_printf ("SERVER_ADDRESS: %u.%u.%u.%u\n",
      mode->server_address[0],
      mode->server_address[1],
      mode->server_address[2],
      mode->server_address[3]);
    grub_printf ("SUBNET_MASK: %u.%u.%u.%u\n",
      mode->subnet_mask[0],
      mode->subnet_mask[1],
      mode->subnet_mask[2],
      mode->subnet_mask[3]);
    grub_printf ("ROUTER_ADDRESS: %u.%u.%u.%u\n",
      mode->router_address[0],
      mode->router_address[1],
      mode->router_address[2],
      mode->router_address[3]);
}
#endif

static grub_efi_ipv4_address_t *
grub_efi_dhcp4_parse_dns (grub_efi_dhcp4_protocol_t *dhcp4, grub_efi_dhcp4_packet_t *reply_packet)
{
  grub_efi_dhcp4_packet_option_t **option_list;
  grub_efi_status_t status;
  grub_efi_uint32_t option_count = 0;
  grub_efi_uint32_t i;

  status = efi_call_4 (dhcp4->parse, dhcp4, reply_packet, &option_count, NULL);

  if (status != GRUB_EFI_BUFFER_TOO_SMALL)
    return NULL;

  option_list = grub_malloc (option_count * sizeof(*option_list));
  if (!option_list)
    return NULL;

  status = efi_call_4 (dhcp4->parse, dhcp4, reply_packet, &option_count, option_list);
  if (status != GRUB_EFI_SUCCESS)
    {
      grub_free (option_list);
      return NULL;
    }

  for (i = 0; i < option_count; ++i)
    {
      if (option_list[i]->op_code == 6)
	{
	  grub_efi_ipv4_address_t *dns_address;

	  if (((option_list[i]->length & 0x3) != 0) || (option_list[i]->length == 0))
	    continue;

	  /* We only contact primary dns */
	  dns_address = grub_malloc (sizeof (*dns_address));
	  if (!dns_address)
	    {
	      grub_free (option_list);
	      return NULL;
	    }
	  grub_memcpy (dns_address, option_list[i]->data, sizeof (dns_address));
	  grub_free (option_list);
	  return dns_address;
	}
    }

  grub_free (option_list);
  return NULL;
}

#if 0
/* Somehow this doesn't work ... */
static grub_err_t
grub_cmd_efi_bootp (struct grub_command *cmd __attribute__ ((unused)),
		    int argc __attribute__ ((unused)),
		    char **args __attribute__ ((unused)))
{
  struct grub_efi_net_device *dev;
  for (dev = net_devices; dev; dev = dev->next)
    {
      grub_efi_pxe_t *pxe = dev->ip4_pxe;
      grub_efi_pxe_mode_t *mode = pxe->mode;
      grub_efi_status_t status;

      if (!mode->started)
	{
	  status = efi_call_2 (pxe->start, pxe, 0);

	  if (status != GRUB_EFI_SUCCESS)
	      grub_printf ("Couldn't start PXE\n");
	}

      status = efi_call_2 (pxe->dhcp, pxe, 0);
      if (status != GRUB_EFI_SUCCESS)
	{
	  grub_printf ("dhcp4 configure failed, %d\n", (int)status);
	  continue;
	}

      dev->prefer_ip6 = 0;
    }

  return GRUB_ERR_NONE;
}
#endif

static grub_err_t
grub_cmd_efi_bootp (struct grub_command *cmd __attribute__ ((unused)),
		    int argc __attribute__ ((unused)),
		    char **args __attribute__ ((unused)))
{
  struct grub_efi_net_device *netdev;

  for (netdev = net_devices; netdev; netdev = netdev->next)
    {
      grub_efi_status_t status;
      grub_efi_dhcp4_mode_data_t mode;
      grub_efi_dhcp4_config_data_t config;
      grub_efi_dhcp4_packet_option_t *options;
      grub_efi_ipv4_address_t *dns_address;

      grub_memset (&config, 0, sizeof(config));

      config.option_count = 1;
      options = grub_malloc (sizeof(*options) + 2);
      /* Parameter request list */
      options->op_code = 55;
      options->length = 3;
      /* subnet mask */
      options->data[0] = 1;
      /* router */
      options->data[1] = 3;
      /* DNS */
      options->data[2] = 6;
      config.option_list = &options;

      /* FIXME: What if the dhcp has bounded */
      status = efi_call_2 (netdev->dhcp4->configure, netdev->dhcp4, &config);
      grub_free (options);
      if (status != GRUB_EFI_SUCCESS)
	{
	  grub_printf ("dhcp4 configure failed, %d\n", (int)status);
	  continue;
	}

      status = efi_call_2 (netdev->dhcp4->start, netdev->dhcp4, NULL);
      if (status != GRUB_EFI_SUCCESS)
	{
	  grub_printf ("dhcp4 start failed, %d\n", (int)status);
	  continue;
	}

      status = efi_call_2 (netdev->dhcp4->get_mode_data, netdev->dhcp4, &mode);
      if (status != GRUB_EFI_SUCCESS)
	{
	  grub_printf ("dhcp4 get mode failed, %d\n", (int)status);
	  continue;
	}

#ifdef GRUB_EFI_NET_DEBUG
      dhcp4_mode_print (&mode);
#endif

      grub_efi_ip4_config2_manual_address_t manual_addr;

      grub_memcpy (manual_addr.address, mode.client_address, sizeof (manual_addr.address));
      grub_memcpy (manual_addr.subnet_mask, mode.subnet_mask, sizeof (manual_addr.subnet_mask));

      status = efi_call_4 (netdev->ip4_config->set_data, netdev->ip4_config,
		    GRUB_EFI_IP4_CONFIG2_DATA_TYPE_MANUAL_ADDRESS,
		    sizeof (manual_addr), &manual_addr);

      status = efi_call_4 (netdev->ip4_config->set_data, netdev->ip4_config,
		    GRUB_EFI_IP4_CONFIG2_DATA_TYPE_GATEWAY,
		    sizeof (mode.router_address), &mode.router_address);

      dns_address = grub_efi_dhcp4_parse_dns (netdev->dhcp4, mode.reply_packet);

      if (dns_address)
	{
	  status = efi_call_4 (netdev->ip4_config->set_data, netdev->ip4_config,
		    GRUB_EFI_IP4_CONFIG2_DATA_TYPE_DNSSERVER,
		    sizeof (*dns_address), dns_address);
	}
    }

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_efi_bootp;

void grub_efi_net_dhcp_init (void)
{
  cmd_efi_bootp = grub_register_command ("net_efi_bootp", grub_cmd_efi_bootp,
				     N_("[CARD]"),
				     N_("perform a bootp autoconfiguration"));
}
void grub_efi_net_dhcp_fini (void)
{
  grub_unregister_command (cmd_efi_bootp);
}

