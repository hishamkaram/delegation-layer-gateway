# Nginx setup on Ubuntu

`scripts/setup_nginx.py --hostname HOSTNAME` prepares an isolated virtual host
for the supplied hostname. Examples use `gateway.example.com`. The helper was
validated with Ubuntu Nginx 1.24 and Certbot 2.9. It does not start Gateway, enroll devices,
change DNS, install packages, edit existing virtual hosts or configure port 8443.

Nginx owns public port 443. It forwards only `/mcp`, the two OAuth protected
resource metadata routes, and `/v1/enroll` to Gateway HTTPS on
`127.0.0.1:9443`. Nginx verifies the upstream certificate against the system CA
bundle and the public hostname, using TLS 1.3 and SNI. Gateway therefore needs a
valid certificate for that hostname too. No TLS verification bypass is offered.
The connector's device mTLS listener remains direct on port 8443.

## Run

Replace `gateway.example.com` with your own hostname. No operator hostname is
stored in the script. Run from the Gateway repository. A command without
`--apply` prints its candidate
configuration without changing files or running system commands:

```sh
python3 scripts/setup_nginx.py --hostname gateway.example.com --phase https
```

With DNS already pointing here, run these three commands in order:

```sh
sudo python3 scripts/setup_nginx.py --hostname gateway.example.com --phase bootstrap --apply
sudo certbot certonly --webroot \
  --webroot-path /var/lib/delegation-layer-gateway-acme/gateway.example.com \
  --cert-name gateway.example.com \
  -d gateway.example.com
sudo python3 scripts/setup_nginx.py --hostname gateway.example.com --phase https --apply
```

Certbot prompts for its account/contact and terms as needed. The first command
adds only an HTTP challenge route; other requests on that hostname return 503.
The last command enables HTTPS and redirects HTTP to HTTPS, while preserving
the challenge route for renewal. It validates the complete installed Nginx
configuration before and after its change, then reloads Nginx. On a validation,
reload or handled interruption failure it restores its prior config and attempts
to validate/reload it. An unsuccessful rollback is an error requiring operator
inspection. SIGKILL, host failure and power loss cannot run rollback.

The script owns only `/etc/nginx/sites-enabled/zzzz-delegation-layer-gateway-HOSTNAME.conf` and its
ACME webroot. It supports the Ubuntu layout where `conf.d/*.conf` loads before the final
`sites-enabled/*` include. It appends after existing sites and refuses
later-sorting entries; custom include layouts require separate review. It refuses symlink/foreign/edited target configs, duplicate exact
hostname definitions and downgrading HTTPS to bootstrap. Any Nginx-reported
conflicting server name, including one between existing sites, blocks installation. Run the HTTPS phase
again to validate and reload an unchanged generated config. `--upstream-port`
can select another unprivileged loopback port; it must match Gateway's listener.

## Operation and limits

- Keep the Cloudflare DNS record **DNS only** for the intended direct device
  mTLS connection. This script never changes Cloudflare settings.
- Nginx request/error logging is disabled for this virtual host because native
  error messages can contain URLs, query values and upstream details. Gateway
  owns protected metadata-only audit and metrics.
- Proxy buffering and upstream retries are disabled. The application owns MCP
  authentication, authorization, idempotency and task outcomes.
- A successful Nginx reload does not prove Gateway readiness. Until Gateway is
  running with the matching TLS configuration, proxied endpoints return 502.
- Certbot `certonly --webroot` does not install a reload hook here. After renewal,
  rerun the HTTPS phase to reload Nginx. Check the host's renewal timer separately;
  this script does not create or change it. Gateway loads certificates at startup,
  so its private certificate/key copy and controlled restart also need updating.
  Those application service/renewal steps remain separate deployment work.
- The script never reads `.env`, private key contents or bearer tokens. Captured
  Nginx diagnostics are not printed because they may expose other service data.

## Verification

```sh
python3 -m unittest discover -s scripts -p test_setup_nginx.py -v
bin/python-lint/bin/ruff check scripts/setup_nginx.py scripts/test_setup_nginx.py
bin/python-lint/bin/ruff format --check scripts/setup_nginx.py scripts/test_setup_nginx.py
```

Tests cover private config ownership, Nginx-reported duplicate hosts (including
quoted aliases), default-site preservation, handled signals, read-only preview,
validation/reload rollback and unchanged foreign sites. An owned temporary Nginx process also checks
unmatched-host routing. If Nginx and OpenSSL are
installed, both generated phases also undergo actual `nginx -t` using temporary
certificates and unprivileged loopback ports. This is local syntax evidence;
installed-service reload, ACME issuance, upstream TLS and external MCP acceptance
remain unverified until run in their respective environments.

References: [Nginx proxy TLS verification](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify),
[Certbot webroot](https://eff-certbot.readthedocs.io/en/stable/using.html#webroot).
