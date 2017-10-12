
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/misc.h>
#include <grub/net/efi.h>
#include <grub/charset.h>

static void
http_configure (struct grub_efi_net_device *dev, int prefer_ip6)
{
  grub_efi_http_config_data_t http_config;
  grub_efi_httpv4_access_point_t httpv4_node;
  grub_efi_httpv6_access_point_t httpv6_node;
  grub_efi_status_t status;

  grub_efi_http_t *http = dev->http;

  grub_memset (&http_config, 0, sizeof(http_config));
  http_config.http_version = GRUB_EFI_HTTPVERSION11;
  http_config.timeout_millisec = 5000;

  if (prefer_ip6)
    {
      grub_efi_uintn_t sz;
      grub_efi_ip6_config_manual_address_t manual_address;

      http_config.local_address_is_ipv6 = 1;
      sz = sizeof (manual_address);
      status = efi_call_4 (dev->ip6_config->get_data, dev->ip6_config,
			GRUB_EFI_IP6_CONFIG_DATA_TYPE_MANUAL_ADDRESS,
			&sz, &manual_address);

      if (status == GRUB_EFI_NOT_FOUND)
	{
	  grub_printf ("The MANUAL ADDRESS is not found\n");
	}

      /* FIXME: The manual interface would return BUFFER TOO SMALL !!! */
      if (status != GRUB_EFI_SUCCESS)
	{
	  grub_printf ("??? %d\n",(int) status);
	  return;
	}

      grub_memcpy (httpv6_node.local_address, manual_address.address, sizeof (httpv6_node.local_address));
      httpv6_node.local_port = 0;
      http_config.access_point.ipv6_node = &httpv6_node;
    }
  else
    {
      http_config.local_address_is_ipv6 = 0;
      grub_memset (&httpv4_node, 0, sizeof(httpv4_node));
      httpv4_node.use_default_address = 1;

      /* Use random port here */
      /* See TcpBind() in edk2/NetworkPkg/TcpDxe/TcpDispatcher.c */
      httpv4_node.local_port = 0;
      http_config.access_point.ipv4_node = &httpv4_node;
    }

  status = efi_call_2 (http->configure, http, &http_config);

  if (status == GRUB_EFI_ALREADY_STARTED)
    {
      /* XXX: This hangs HTTPS boot */
#if 0
      if (efi_call_2 (http->configure, http, NULL) != GRUB_EFI_SUCCESS)
	{
	  grub_error (GRUB_ERR_IO, N_("couldn't reset http instance"));
	  grub_print_error ();
	  return;
	}
      status = efi_call_2 (http->configure, http, &http_config);
#endif
      return;
    }

  if (status != GRUB_EFI_SUCCESS)
    {
      grub_error (GRUB_ERR_IO, N_("couldn't configure http protocol, reason: %d"), (int)status);
      grub_print_error ();
      return ;
    }
}

static grub_efi_boolean_t request_callback_done;
static grub_efi_boolean_t response_callback_done;

static void
grub_efi_http_request_callback (grub_efi_event_t event __attribute__ ((unused)),
				void *context __attribute__ ((unused)))
{
  request_callback_done = 1;
}

static void
grub_efi_http_response_callback (grub_efi_event_t event __attribute__ ((unused)),
				void *context __attribute__ ((unused)))
{
  response_callback_done = 1;
}

struct grub_efi_http_data
{
  grub_efi_http_request_data_t request_data;
  grub_efi_http_message_t request_message;
  grub_efi_http_token_t request_token;
  grub_efi_http_response_data_t response_data;
  grub_efi_http_message_t response_message;
  grub_efi_http_token_t response_token;
  grub_efi_http_header_t request_headers[3];
};

static grub_err_t
grub_efihttp_open (struct grub_efi_net_device *dev,
		  int prefer_ip6 __attribute__ ((unused)),
		  grub_file_t file,
		  const char *filename __attribute__ ((unused)),
		  int type)
{
  grub_efi_status_t status;
  grub_uint32_t length, i;
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
  grub_efi_http_t *http = dev->http;
  char *url = NULL;

  struct grub_efi_http_data *data = grub_malloc (sizeof (*data));

  grub_memset (data, 0, sizeof (*data));

  data->request_headers[0].field_name = (grub_efi_char8_t *)"Host";
  data->request_headers[0].field_value = (grub_efi_char8_t *)file->device->net->server;
  data->request_headers[1].field_name = (grub_efi_char8_t *)"Accept";
  data->request_headers[1].field_value = (grub_efi_char8_t *)"*/*";
  data->request_headers[2].field_name = (grub_efi_char8_t *)"User-Agent";
  data->request_headers[2].field_value = (grub_efi_char8_t *)"UefiHttpBoot/1.0";

  {
    grub_efi_ipv6_address_t address;
    const char *rest;
    grub_efi_char16_t *ucs2_url;
    grub_size_t url_len, ucs2_url_len;
    const char *protocol = (type == 1) ? "https" : "http";

    if (grub_efi_string_to_ip6_address (file->device->net->server, &address, &rest) && *rest == 0)
      url = grub_xasprintf ("%s://[%s]%s", protocol, file->device->net->server, file->device->net->name);
    else
      url = grub_xasprintf ("%s://%s%s", protocol, file->device->net->server, file->device->net->name);

    if (!url)
      return grub_errno;

    url_len = grub_strlen (url);
    ucs2_url_len = url_len * GRUB_MAX_UTF16_PER_UTF8;
    ucs2_url = grub_malloc ((ucs2_url_len + 1) * sizeof (ucs2_url[0]));

    if (!ucs2_url)
      {
	grub_free (url);
	return grub_errno;
      }

    ucs2_url_len = grub_utf8_to_utf16 (ucs2_url, ucs2_url_len, (grub_uint8_t *)url, url_len, NULL); /* convert string format from ascii to usc2 */
    ucs2_url[ucs2_url_len] = 0;
    grub_free (url);
    data->request_data.url = ucs2_url;
  }

  data->request_data.method = GRUB_EFI_HTTPMETHODGET;

  data->request_message.data.request = &data->request_data;
  data->request_message.header_count = 3;
  data->request_message.headers = data->request_headers;
  data->request_message.body_length = 0;
  data->request_message.body = NULL;

  /* request token */
  data->request_token.event = NULL;
  data->request_token.status = GRUB_EFI_NOT_READY;
  data->request_token.message = &data->request_message;

  request_callback_done = 0;
  status = efi_call_5 (b->create_event,
                       GRUB_EFI_EVT_NOTIFY_SIGNAL,
                       GRUB_EFI_TPL_CALLBACK,
                       grub_efi_http_request_callback,
                       NULL,
                       &data->request_token.event);

  if (status != GRUB_EFI_SUCCESS)
    {
      grub_free (data->request_data.url);
      return grub_error (GRUB_ERR_IO, "Fail to create an event! status=0x%x\n", status);
    }

  status = efi_call_2 (http->request, http, &data->request_token);

  if (status != GRUB_EFI_SUCCESS)
    {
      efi_call_1 (b->close_event, data->request_token.event);
      grub_free (data->request_data.url);
      return grub_error (GRUB_ERR_IO, "Fail to send a request! status=0x%x\n", status);
    }
  /* TODO: Add Timeout */
  while (!request_callback_done)
    efi_call_1(http->poll, http);

  data->response_data.status_code = GRUB_EFI_HTTP_STATUS_UNSUPPORTED_STATUS;
  data->response_message.data.response = &data->response_data;
  /* herader_count will be updated by the HTTP driver on response */
  data->response_message.header_count = 0;
  /* headers will be populated by the driver on response */
  data->response_message.headers = NULL;
  /* use zero BodyLength to only receive the response headers */
  data->response_message.body_length = 0;
  data->response_message.body = NULL;
  data->response_token.event = NULL;

  status = efi_call_5 (b->create_event,
              GRUB_EFI_EVT_NOTIFY_SIGNAL,
              GRUB_EFI_TPL_CALLBACK,
              grub_efi_http_response_callback,
              NULL,
              &data->response_token.event);

  if (status != GRUB_EFI_SUCCESS)
    {
      efi_call_1 (b->close_event, data->request_token.event);
      grub_free (data->request_data.url);
      return grub_error (GRUB_ERR_IO, "Fail to create an event! status=0x%x\n", status);
    }

  data->response_token.status = GRUB_EFI_SUCCESS;
  data->response_token.message = &data->response_message;

  /* wait for HTTP response */
  response_callback_done = 0;
  status = efi_call_2 (http->response, http, &data->response_token);

  if (status != GRUB_EFI_SUCCESS)
    {
      efi_call_1 (b->close_event, data->response_token.event);
      efi_call_1 (b->close_event, data->request_token.event);
      grub_free (data->request_data.url);
      return grub_error (GRUB_ERR_IO, "Fail to receive a response! status=%d\n", (int)status);
    }

  /* TODO: Add Timeout */
  while (!response_callback_done)
    efi_call_1 (http->poll, http);

  /* check the HTTP status code */
  /* parse the length of the file from the ContentLength header */
  for (length = 0, i = 0; i < data->response_message.header_count; ++i)
    {
      if (!grub_strcmp((const char*)data->response_message.headers[i].field_name, "Content-Length"))
	{
	  length = grub_strtoul((const char*)data->response_message.headers[i].field_value, 0, 10);
	  break;
	}
    }

  file->size = (grub_off_t)length;
  file->not_easily_seekable = 0;
  file->data = data;
  file->device->net->offset = 0;

  /* release */
  /* On response, this array is allocated and
    populated by the HTTP driver. It is the responsibility of the caller
    to free this memory on both request and response. */
  if (data->response_message.headers)
    efi_call_1 (b->free_pool, data->response_message.headers);

  efi_call_1 (b->close_event, data->response_token.event);
  efi_call_1 (b->close_event, data->request_token.event);
  grub_free (data->request_data.url);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_efihttp_close (struct grub_efi_net_device *dev __attribute__ ((unused)),
		    int prefer_ip6 __attribute__ ((unused)),
		    grub_file_t file)
{
  struct grub_efi_http_data *data = file->data;

  if (data)
    grub_free (data);

  file->data = 0;
  file->offset = 0;
  file->device->net->offset = 0;
  return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_efihttp_read (struct grub_efi_net_device *dev,
		  int prefer_ip6 __attribute__((unused)),
		  grub_file_t file,
		  char *buf,
		  grub_size_t len)
{
  grub_efi_status_t status;
  grub_size_t sum = 0;
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
  grub_efi_http_t *http = dev->http;
  struct grub_efi_http_data *data = file->data;

  grub_memset (data, 0, sizeof (*data));
  efi_call_5 (b->create_event,
              GRUB_EFI_EVT_NOTIFY_SIGNAL,
              GRUB_EFI_TPL_CALLBACK,
              grub_efi_http_response_callback,
              NULL,
              &data->response_token.event);

  while (len)
    {
      data->response_message.data.response = NULL;
      data->response_message.header_count = 0;
      data->response_message.headers = NULL;
      data->response_message.body_length = len;
      data->response_message.body = buf;

      data->response_token.message = &data->response_message;
      data->response_token.status = GRUB_EFI_NOT_READY;

      response_callback_done = 0;

      status = efi_call_2 (http->response, http, &data->response_token);
      if (status != GRUB_EFI_SUCCESS)
	{
	  efi_call_1 (b->close_event, data->response_token.event);
	  grub_error (GRUB_ERR_IO, "Error! status=%d\n", (int)status);
	  return -1;
	}

      while (!response_callback_done)
	efi_call_1(http->poll, http);

      file->device->net->offset += data->response_message.body_length;
      sum += data->response_message.body_length;
      buf += data->response_message.body_length;
      len -= data->response_message.body_length;
    }

  efi_call_1 (b->close_event, data->response_token.event);

  return sum;
}

struct grub_efi_net_io io_http =
  {
    .configure = http_configure,
    .open = grub_efihttp_open,
    .read = grub_efihttp_read,
    .close = grub_efihttp_close
  };
