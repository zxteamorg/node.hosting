import * as zxteam from "@zxteam/contract";

export namespace Configuration {
	export type WebServer = UnsecuredWebServer | SecuredWebServer;

	export interface WebServerBase {
		readonly name: string;
		readonly listenHost: string;
		readonly listenPort: number;
		/**
		 * See http://expressjs.com/en/4x/api.html#trust.proxy.options.table
		 */
		readonly trustProxy?: boolean | "loopback" | "linklocal" | "uniquelocal";
	}

	export interface UnsecuredBaseWebServer extends WebServerBase {
		readonly type: "http";
	}
	export interface UnsecuredCommonWebServer extends UnsecuredBaseWebServer {
	}
	export interface UnsecuredXfccWebServer extends UnsecuredBaseWebServer {
		readonly caCertificates: Buffer | string | Array<string | Buffer>;
		readonly clientCertificateMode: ClientCertificateMode.XFCC;
	}
	export type UnsecuredWebServer = UnsecuredCommonWebServer | UnsecuredXfccWebServer;

	export interface SecuredBaseWebServer extends WebServerBase {
		readonly type: "https";
		/**
		 * Certificate's data as Buffer or Path to file
		 */
		readonly serverCertificate: Buffer | string;
		/**
		 * Private Key's data as Buffer or Path to file
		 */
		readonly serverKey: Buffer | string;
		readonly serverKeyPassword?: string;
	}
	export interface SecuredCommonWebServer extends SecuredBaseWebServer {
		/**
		 * Certificate's data as Buffer or Path to file
		 */
		readonly caCertificates?: Buffer | string | Array<string | Buffer>;
		readonly clientCertificateMode: ClientCertificateMode.REQUEST | ClientCertificateMode.NONE;
	}
	export interface SecuredClientWebServer extends SecuredBaseWebServer {
		/**
		 * Certificate's data as Buffer or Path to file
		 */
		readonly caCertificates: Buffer | string | Array<string | Buffer>;
		readonly clientCertificateMode: ClientCertificateMode.TRUST | ClientCertificateMode.XFCC;
	}
	export type SecuredWebServer = SecuredCommonWebServer | SecuredClientWebServer;

	export enum ClientCertificateMode {
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

	export interface ServerEndpoint {
		readonly servers: Array<string>;
	}

	export interface BindEndpoint {
		readonly bindPath: string;
	}

	export interface WebSocketEndpoint extends BindEndpoint {
		readonly defaultProtocol: string;
		readonly allowedProtocols?: ReadonlyArray<string>;
	}

	export function parseWebServer(configuration: zxteam.Configuration, serverName: string): WebServer {
		const serverType = configuration.getString("type");
		switch (serverType) {
			case "http": {
				let trustProxy: boolean | "loopback" | "linklocal" | "uniquelocal" | undefined = undefined;
				if (configuration.has("trustProxy")) {
					trustProxy = Configuration.parseTrustProxy(configuration.getString("trustProxy"));
				}

				if (configuration.has("clientCertificateMode")) {
					const clientCertificateMode = configuration.getString("clientCertificateMode");
					if (clientCertificateMode !== Configuration.ClientCertificateMode.XFCC) {
						throw new Error(`Unsupported value for clientCertificateMode: ${clientCertificateMode}`);
					}

					const serverOpts: UnsecuredXfccWebServer = {
						type: serverType,
						name: serverName,
						listenHost: configuration.getString("listenHost"),
						listenPort: configuration.getInteger("listenPort"),
						trustProxy,
						clientCertificateMode,
						caCertificates: configuration.getString("caCertificates") // caCertificates requires for validate client certificates
					};

					return serverOpts;
				} else {
					const serverOpts: UnsecuredCommonWebServer = {
						type: serverType,
						name: serverName,
						listenHost: configuration.getString("listenHost"),
						listenPort: configuration.getInteger("listenPort"),
						trustProxy
					};

					return serverOpts;
				}
			}
			case "https": {
				let serverOpts: SecuredWebServer;

				let trustProxy: boolean | "loopback" | "linklocal" | "uniquelocal" | undefined = undefined;
				if (configuration.has("trustProxy")) {
					trustProxy = Configuration.parseTrustProxy(configuration.getString("trustProxy"));
				}

				let serverKeyPassword: string | undefined = undefined;
				if (configuration.has("serverKeyPassword")) {
					serverKeyPassword = configuration.getString("serverKeyPassword");
				}


				const clientCertMode: string = configuration.getString("clientCertificateMode");
				switch (clientCertMode) {
					case ClientCertificateMode.NONE:
					case ClientCertificateMode.REQUEST:
						if (configuration.has("caCertificates")) {
							serverOpts = {
								type: serverType,
								name: serverName,
								listenHost: configuration.getString("listenHost"),
								listenPort: configuration.getInteger("listenPort"),
								serverCertificate: configuration.getString("serverCertificate"),
								serverKey: configuration.getString("serverKey"),
								serverKeyPassword,
								trustProxy,
								clientCertificateMode: clientCertMode,
								caCertificates: configuration.getString("caCertificates")
							};
						} else {
							serverOpts = {
								type: serverType,
								name: serverName,
								listenHost: configuration.getString("listenHost"),
								listenPort: configuration.getInteger("listenPort"),
								serverCertificate: configuration.getString("serverCertificate"),
								serverKey: configuration.getString("serverKey"),
								serverKeyPassword,
								trustProxy,
								clientCertificateMode: clientCertMode
							};
						}
						break;
					case ClientCertificateMode.TRUST:
					case ClientCertificateMode.XFCC:
						serverOpts = {
							type: serverType,
							name: serverName,
							listenHost: configuration.getString("listenHost"),
							listenPort: configuration.getInteger("listenPort"),
							caCertificates: configuration.getString("caCertificates"),
							serverCertificate: configuration.getString("serverCertificate"),
							serverKey: configuration.getString("serverKey"),
							serverKeyPassword,
							trustProxy,
							clientCertificateMode: clientCertMode
						};
						break;
					default:
						throw new Error(`Unsupported value for clientCertificateMode: ${clientCertMode}`);
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
