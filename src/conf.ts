import * as zxteam from "@zxteam/contract";

//import * as _ from "lodash";

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
	export interface UnsecuredWebServer extends WebServerBase {
		type: "http";
	}
	export interface SecuredWebServer extends WebServerBase {
		type: "https";
		/**
		 * Certificate's data as Buffer or Path to file
		 */
		caCertificate: Buffer | string;
		/**
		 * Certificate's data as Buffer or Path to file
		 */
		serverCertificate: Buffer | string;
		/**
		 * Private Key's data as Buffer or Path to file
		 */
		serverKey: Buffer | string;
		serverKeyPassword?: string;
		clientCertificateMode: SecuredWebServer.ClientCertificateMode;
	}

	export namespace SecuredWebServer {
		export const enum ClientCertificateMode {
			/**
			 * the server will NOT request a certificate from clients that connect
			 * { requestCert: false, rejectUnauthorized: false }
			 */
			NONE = "none",

			/**
			 * the server WILL request a certificate from clients that connect
			 * { requestCert: true, rejectUnauthorized: false }
			 */
			REQUEST = "request",

			/**
			 * the server WILL request a certificate from clients that connect and attempt to verify that certificate
			 * { requestCert: true, rejectUnauthorized: true }
			 */
			TRUST = "trust"
		}
	}

	export interface ServerEndpoint {
		readonly servers: Array<string>;
	}

	export interface BindEndpoint extends ServerEndpoint {
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
					listenPort: configuration.getInt("listenPort")
				};
				if (configuration.hasKey("trustProxy")) {
					serverOpts.trustProxy = Configuration.parseTrustProxy(configuration.getString("trustProxy"));
				}
				return serverOpts;
			}
			case "https": {
				const clientCertMode = configuration.getString("clientCertificateMode");
				switch (clientCertMode) {
					case SecuredWebServer.ClientCertificateMode.NONE:
					case SecuredWebServer.ClientCertificateMode.REQUEST:
					case SecuredWebServer.ClientCertificateMode.TRUST:
						break;
					default:
						throw new Error(`Unsupported value for clientCertMode: ${clientCertMode}`);
				}

				const serverOpts: SecuredWebServer = {
					type: serverType,
					name: serverName,
					listenHost: configuration.getString("listenHost"),
					listenPort: configuration.getInt("listenPort"),
					caCertificate: configuration.getString("caCertificate"),
					serverCertificate: configuration.getString("serverCertificate"),
					serverKey: configuration.getString("serverKey"),
					clientCertificateMode: clientCertMode
				};
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
