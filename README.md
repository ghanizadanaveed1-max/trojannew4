# Ghanizada Cloud Run User Manager v11

v11 is an update of v9 focused on the requested mobile UI redesign and QR reliability.

## Changes
- Public page shows only a clean admin password login screen.
- Dashboard and management UI are hidden until successful authentication.
- New professional dashboard layout with sidebar navigation and responsive mobile layout.
- Redesigned user cards, server health, security, backup, and settings pages.
- QR modal redesigned with a fixed square QR frame and no stretching.
- QR endpoint explicitly uses the `qrencode` PNG CLI with stdout output.
- Docker image explicitly installs Alpine's `libqrencode-tools` package, which provides the `qrencode` command.
- Existing Trojan, VLESS, VMess, user management, subscription URLs, backups, Cloud Storage persistence, traffic limits, expiration, and admin authentication are retained.
- Includes a Python 3.13 `server.cpython-313.pyc` cache file.

## Deploy
```bash
unzip ghanizada_cloud_run_user_manager_v11.zip
cd ghanizada_v11
chmod +x deploy.sh
./deploy.sh
```

Use the same Cloud Storage bucket/project as the previous deployment to preserve existing users and admin data.

## SSH/Stunnel VPS Backend
The Settings page now includes an SSH/Stunnel VPS Backend section. Configure a VPS hostname/IP, TLS port, and WebSocket path; the panel writes a dedicated `/ws/ssh` Cloud Run route and reloads Caddy.

Important: the VPS endpoint behind this route must be a WebSocket-capable HTTP(S) bridge that forwards WebSocket connections to SSH (for example, a WebSocket-to-TCP bridge in front of the VPS SSH service). A raw stunnel TLS listener alone does not understand the WebSocket protocol and cannot be used directly as the Cloud Run upstream.


## SSH/Stunnel VPS Backend
The Settings page includes an SSH/Stunnel VPS Backend section. It configures a dedicated Cloud Run WebSocket endpoint at `/ws/ssh` and proxies that WebSocket to the configured VPS HTTPS WebSocket bridge.

The VPS upstream must speak HTTP(S) WebSocket. A raw stunnel TLS listener forwarding directly to SSH is not WebSocket-aware and cannot be used as the upstream by this route.
