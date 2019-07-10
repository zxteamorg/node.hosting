import * as zxteam from "@zxteam/contract";

export namespace Configuration {
	export type WebServer = UnsecuredWebServer | SecuredWebServer;

	export interface WebServerBase {
		name: string;
		listenHost: string;
		listenPort: number;
		/**
		 * See http://expressjs.com/en/4x/api.html#trust.proxy.options.table
		 */
		trustProxy?: boolean | "loopback" | "linklocal" | "uniquelocal";
	}

	export interface UnsecuredBaseWebServer extends WebServerBase {
		type: "http";
	}
	export interface UnsecuredCommonWebServer extends UnsecuredBaseWebServer {
	}
	export interface UnsecuredXfccWebServer extends UnsecuredBaseWebServer {
		caCertificates: Buffer | string | Array<string | Buffer>;
		clientCertificateMode: SecuredWebServer.ClientCertificateMode.XFCC;
	}
	export type UnsecuredWebServer = UnsecuredCommonWebServer | UnsecuredXfccWebServer;

	export interface SecuredBaseWebServer extends WebServerBase {
		type: "https";
		/**
		 * Certificate's data as Buffer or Path to file
		 */
		serverCertificate: Buffer | string;
		/**
		 * Private Key's data as Buffer or Path to file
		 */
		serverKey: Buffer | string;
		serverKeyPassword?: string;
	}
	export interface SecuredCommonWebServer extends SecuredBaseWebServer {
		/**
		 * Certificate's data as Buffer or Path to file
		 */
		caCertificates?: Buffer | string | Array<string | Buffer>;
		clientCertificateMode:
		SecuredWebServer.ClientCertificateMode.REQUEST |
		SecuredWebServer.ClientCertificateMode.NONE;
	}
	export interface SecuredClientWebServer extends SecuredBaseWebServer {
		/**
		 * Certificate's data as Buffer or Path to file
		 */
		caCertificates: Buffer | string | Array<string | Buffer>;
		clientCertificateMode:
		SecuredWebServer.ClientCertificateMode.TRUST |
		SecuredWebServer.ClientCertificateMode.XFCC;
	}
	export type SecuredWebServer = SecuredCommonWebServer | SecuredClientWebServer;

	export namespace SecuredWebServer {
		export const enum ClientCertificateMode {
			/**
			 * The server will NOT request a certificate from clients that connect WILL NOT validate the certificate.
			 */
			NONE = "none",

			/**
			 * The server WILL request a certificate from clients that connect and WILL NOT validate the certificate.
			 * Validate the certificate by yourself.
			 */
			REQUEST = "request",

			/**
			 * The server WILL request a certificate from clients that connect and validate the certificate
			 * Rejects untrusted certificate
			 */
			TRUST = "trust",

			/**
			 * The server WILL retreive a certificate from the HTTP header X-Forwarded-Client-Cert and validate the certificate.
			 * Rejects untrusted certificate
			 * Hist: Use $ssl_client_escaped_cert NGINX variable to set X-Forwarded-Client-Cert header inside configuration.
			 */
			XFCC = "xfcc"
		}
	}

	export interface ServerEndpoint {
		readonly servers: Array<string>;
	}

	export interface BindEndpoint {
		readonly bindPath: string;
	}

	export function parseWebServer(configuration: zxteam.Configuration, serverName: string): WebServer {
		const serverType = configuration.getString("type");
		switch (serverType) {
			case "http": {
				const serverOpts: UnsecuredWebServer = {
					type: serverType,
					name: serverName,
					listenHost: configuration.getString("listenHost"),
					listenPort: configuration.getInteger("listenPort")
				};
				if (configuration.hasKey("trustProxy")) {
					serverOpts.trustProxy = Configuration.parseTrustProxy(configuration.getString("trustProxy"));
				}
				return serverOpts;
			}
			case "https": {
				let serverOpts: SecuredWebServer;

				const clientCertMode: string = configuration.getString("clientCertificateMode");
				switch (clientCertMode) {
					case SecuredWebServer.ClientCertificateMode.NONE:
					case SecuredWebServer.ClientCertificateMode.REQUEST:
						serverOpts = {
							type: serverType,
							name: serverName,
							listenHost: configuration.getString("listenHost"),
							listenPort: configuration.getInteger("listenPort"),
							serverCertificate: configuration.getString("serverCertificate"),
							serverKey: configuration.getString("serverKey"),
							clientCertificateMode: clientCertMode
						};
						if (configuration.hasKey("caCertificate")) {
							serverOpts.caCertificates = configuration.getString("caCertificate");
						}
						break;
					case SecuredWebServer.ClientCertificateMode.TRUST:
					case SecuredWebServer.ClientCertificateMode.XFCC:
						serverOpts = {
							type: serverType,
							name: serverName,
							listenHost: configuration.getString("listenHost"),
							listenPort: configuration.getInteger("listenPort"),
							caCertificates: configuration.getString("caCertificate"),
							serverCertificate: configuration.getString("serverCertificate"),
							serverKey: configuration.getString("serverKey"),
							clientCertificateMode: clientCertMode
						};
						break;
					default:
						throw new Error(`Unsupported value for clientCertMode: ${clientCertMode}`);
				}

				if (configuration.hasKey("serverKeyPassword")) {
					serverOpts.serverKeyPassword = configuration.getString("serverKeyPassword");
				}
				if (configuration.hasKey("trustProxy")) {
					serverOpts.trustProxy = Configuration.parseTrustProxy(configuration.getString("trustProxy"));
				}
				return serverOpts;
			}
			default:
				throw new Error(`Non supported server type: ${serverType}`);
		}
	}

	export function parseWebServers(configuration: zxteam.Configuration): Array<Configuration.WebServer> {
		const serverIndexes: Array<string> = configuration.getString("servers").split(" ");
		const servers: Array<Configuration.WebServer> = serverIndexes.map(serverName =>
			Configuration.parseWebServer(configuration.getConfiguration(`server.${serverName}`), serverName)
		);
		return servers;
	}

	export function parseTrustProxy(val: string): boolean | "loopback" | "linklocal" | "uniquelocal" {
		switch (val) {
			case "true": return true;
			case "false": return false;
			case "loopback":
			case "linklocal":
			case "uniquelocal":
				return val;
			default:
				throw new Error(`Wrong value for trustProxy: ${val}`);
		}
	}
}
