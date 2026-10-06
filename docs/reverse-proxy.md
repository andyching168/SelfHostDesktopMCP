# Reverse proxy examples

The gateway listens on `--host/--port` (default `127.0.0.1:8765`) and must be started with `--public-url https://mcp.example.com`.

## Caddy
```
mcp.example.com {
    @gw path /mcp /device /health /api/* /authorize /token /register /pair/* /.well-known/*
    reverse_proxy @gw 127.0.0.1:8765 {
        flush_interval -1
    }
}
```
WebSocket upgrade (`/device`) works out of the box.

## nginx
```
location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;   # map $http_upgrade $connection_upgrade { default upgrade; '' close; }
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s; proxy_send_timeout 3600s; proxy_buffering off;
}
```

## Nginx Proxy Manager
New Proxy Host → your domain → `http` → gateway host:8765, **Websockets Support ON**, request an SSL certificate **for that exact hostname**
(a certificate for another subdomain fails TLS verification), Force SSL, **Access List: Public** (a proxy-level Basic Auth collides with the `Authorization` header).
Advanced tab: `proxy_read_timeout 3600s; proxy_send_timeout 3600s; proxy_buffering off;`

The proxy must send `X-Forwarded-For` (all three do by default); the gateway uses it to hide `/api/*` from the internet.
