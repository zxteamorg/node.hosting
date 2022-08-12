# DEPRECATED
Moved to https://github.com/freemework/hosting/tree/src-typescript


# ZXTeam's Hosting Items like Web Server (http.Server/https.Server wrapper), WebSocket Server, endpoints, adapters.
[![npm version badge](https://img.shields.io/npm/v/@zxteam/hosting.svg)](https://www.npmjs.com/package/@zxteam/hosting)
[![downloads badge](https://img.shields.io/npm/dm/@zxteam/hosting.svg)](https://www.npmjs.org/package/@zxteam/hosting)
[![commit activity badge](https://img.shields.io/github/commit-activity/m/zxteamorg/node.hosting)](https://github.com/zxteamorg/node.hosting/pulse)
[![last commit badge](https://img.shields.io/github/last-commit/zxteamorg/node.hosting)](https://github.com/zxteamorg/node.hosting/graphs/commit-activity)
[![twitter badge](https://img.shields.io/twitter/follow/zxteamorg?style=social&logo=twitter)](https://twitter.com/zxteamorg)

## Usage
### WebSockets
There two endpoints:
* `WebSocketChannelFactoryEndpoint` - this endpoint request your channel implementation (you should provide a channel and be channel's server)
* `WebSocketChannelSupplyEndpoint` - this endpoint provides a channel (you use channel as client)

## Configuration
### Web servers
#### Keys
 * listenHost: IP Address string like 127.0.0.1 or ::1
 * listenPort: integer port number like 8080
 * type: http | https
 * trustProxy: true | false | loopback | linklocal | uniquelocal
 * clientCertificateMode: none | request | trust | xfcc  (see enum [ClientCertificateMode](./src/conf.ts))

#### Example
```
# Define second HTTP server
server.0.type = http
server.0.listenHost = 0.0.0.0
server.0.listenPort = 8080
server.0.trustProxy = true # Optional
server.0.clientCertificateMode = xfcc # Can be "xfcc" only
server.0.caCertificates = /path/to/ca.crt  # Optional, but required when clientCertificateMode presented

# Define second HTTPS server
server.1.type = https
server.1.listenHost = 0.0.0.0
server.1.listenPort = 8443
server.1.trustProxy = false # Optional, default
server.1.clientCertificateMode = none
server.1.caCertificates = /path/to/ca.crt # Optional, required for client validation in modes: "trust" and "xfcc"
server.1.serverCertificate = /path/to/ssl/tls.crt
server.1.serverKey = /path/to/ssl/tls.key
server.1.serverKeyPassword = qwerty # Optional, required only for encrypted serverKey

# Activate both 0 and 1 servers
servers = 0 1
```


## Interfaces

## Classes
