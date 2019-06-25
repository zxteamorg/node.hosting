const { name, version } = require(require("path").join(__dirname, "..", "package.json"));
const G: any = global || window || {};
const PACKAGE_GUARD: symbol = Symbol.for(name);
if (PACKAGE_GUARD in G) {
	const conflictVersion = G[PACKAGE_GUARD];
	// tslint:disable-next-line: max-line-length
	const msg = `Conflict module version. Look like two different version of package ${name} was loaded inside the process: ${conflictVersion} and ${version}.`;
	if (process !== undefined && process.env !== undefined && process.env.NODE_ALLOW_CONFLICT_MODULES === "1") {
		console.warn(msg + " This treats as warning because NODE_ALLOW_CONFLICT_MODULES is set.");
	} else {
		throw new Error(msg + " Use NODE_ALLOW_CONFLICT_MODULES=\"1\" to treats this error as warning.");
	}
} else {
	G[PACKAGE_GUARD] = version;
}

import * as zxteam from "@zxteam/contract";
import { Initable, Disposable } from "@zxteam/disposable";

import * as express from "express";
import * as fs from "fs";
import * as http from "http";
import * as https from "https";
import { URL } from "url";
import * as WebSocket from "ws";

import { Configuration } from "./conf";

export * from "./conf";

export type WebServerRequestHandler = (req: http.IncomingMessage, res: http.ServerResponse) => boolean;

export interface WebServer extends zxteam.Disposable {
	readonly name: string;
	readonly underlayingServer: http.Server | https.Server;
	expressApplication: express.Application;
	requestHandler: WebServerRequestHandler;
	createWebSocketServer(bindPath: string): WebSocket.Server;
	listen(): Promise<void>;
}

export abstract class AbstractWebServer<TOpts extends Configuration.WebServerBase> extends Disposable implements WebServer {
	public abstract readonly underlayingServer: http.Server | https.Server;
	protected readonly _log: zxteam.Logger;
	protected readonly _opts: TOpts;
	protected readonly _websockets: { [bindPath: string]: WebSocket.Server };
	private _handler: WebServerRequestHandler | null;
	private _expressApplication: express.Application | null;

	public constructor(opts: TOpts, log: zxteam.Logger) {
		super();
		this._opts = opts;
		this._log = log;
		this._websockets = {};
		this._handler = null;
		this._expressApplication = null;
	}

	/**
	 * Lazy create for Express Application
	 */
	public get expressApplication(): express.Application {
		if (this._expressApplication === null) {
			this._expressApplication = express();
			if (this._opts.trustProxy !== undefined) {
				this._expressApplication.set("trust proxy", this._opts.trustProxy);
			}
		}
		return this._expressApplication;
	}

	public set expressApplication(value: express.Application) {
		if (this._expressApplication !== null) {
			throw new Error("Wrong operation at current state. Express application already set. Override is not allowed.");
		}
		this._expressApplication = value;
	}

	public get name(): string { return this._opts.name; }

	public createWebSocketServer(bindPath: string): WebSocket.Server {
		const websocketServer: WebSocket.Server = new WebSocket.Server({ noServer: true });
		this._websockets[bindPath] = websocketServer;
		return websocketServer;
	}

	public listen(): Promise<void> {
		this.underlayingServer.on("upgrade", (request, socket, head) => {
			const urlPath = request.url;
			const wss = this._websockets[urlPath];
			if (wss !== undefined) {
				this._log.debug("Upgrade the server on url path for WebSocket server.", urlPath);
				wss.handleUpgrade(request, socket, head, function (ws) {
					wss.emit("connection", ws, request);
				});
			} else {
				socket.destroy();
			}
		});

		return this.onListen();
	}

	public get requestHandler(): WebServerRequestHandler {
		if (this._handler === null) {
			throw new Error("Wrong operation at current state. Request handler is not set yet.");
		}
		return this._handler;
	}

	public set requestHandler(value: WebServerRequestHandler) {
		if (this._handler !== null) {
			throw new Error("Wrong operation at current state. Request handler already set. Override is not allowed.");
		}
		this._handler = value;
	}

	protected abstract onListen(): Promise<void>;

	protected onRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
		if (this._handler !== null) {
			if (this._handler(req, res)) {
				// The request was processed by a handler
				return;
			}
		}

		if (this._expressApplication !== null) {
			this._expressApplication(req, res);
			return;
		}

		this._log.warn("Request was handled but no listener.");
		res.writeHead(503);
		res.statusMessage = "Service Unavailable";
		res.end();
	}
}

export class UnsecuredWebServer extends AbstractWebServer<Configuration.UnsecuredWebServer> {
	private readonly _httpServer: http.Server;

	public constructor(opts: Configuration.UnsecuredWebServer, log: zxteam.Logger) {
		super(opts, log);

		// Make HTTP server instance
		const serverOpts: https.ServerOptions = {
		};

		this._httpServer = http.createServer(serverOpts, this.onRequest.bind(this));
	}

	public get underlayingServer(): http.Server { return this._httpServer; }

	public onListen(): Promise<void> {
		this._log.debug("UnsecuredWebServer#listen()");
		const opts: Configuration.UnsecuredWebServer = this._opts;
		const server: http.Server = this._httpServer;
		return new Promise((resolve, reject) => {
			this._log.info("Starting Web Server...");
			server
				.on("listening", () => {
					const address = server.address();
					if (address !== null) {
						if (typeof address === "string") {
							this._log.info(`Web Server was started on ${address}`);
						} else {
							this._log.info(address.family + " Web Server was started on http://" + address.address + ":" + address.port);
						}
					}
					resolve();
				})
				.on("error", reject)
				.listen(opts.listenPort, opts.listenHost);
		});
	}

	protected async onDispose() {
		this._log.debug("UnsecuredWebServer#onDispose()");
		const server = this._httpServer;
		const address = server.address();
		if (address !== null) {
			if (typeof address === "string") {
				this._log.info("Stoping Web Server http://" + address + "...");
			} else {
				this._log.info("Stoping " + address.family + " Web Server http://" + address.address + ":" + address.port + "...");
			}
		} else {
			this._log.info("Stoping Web Server...");
		}
		await new Promise((destroyResolve) => {
			server.close((err) => {
				if (err) {
					this._log.warn("The Web Server was stopped with error", err);
				} else {
					this._log.info("The Web Server was stopped");
				}
				destroyResolve();
			});
		});
	}
}

export class SecuredWebServer extends AbstractWebServer<Configuration.SecuredWebServer> {
	private readonly _httpsServer: https.Server;

	public constructor(opts: Configuration.SecuredWebServer, log: zxteam.Logger) {
		super(opts, log);

		// Make HTTPS server instance
		const serverOpts: https.ServerOptions = {
			ca: opts.caCertificate instanceof Buffer ? opts.caCertificate : fs.readFileSync(opts.caCertificate),
			cert: opts.serverCertificate instanceof Buffer ? opts.serverCertificate : fs.readFileSync(opts.serverCertificate),
			key: opts.serverKey instanceof Buffer ? opts.serverKey : fs.readFileSync(opts.serverKey)
		};
		if (opts.serverKeyPassword !== undefined) {
			serverOpts.passphrase = opts.serverKeyPassword;
		}

		serverOpts.requestCert = true;
		serverOpts.rejectUnauthorized = true;

		if (process.env.NODE_ENV === "development" && process.env.COINGET_ALLOW_UNLICENSED_CALLS === "YES") {
			serverOpts.requestCert = false;
			serverOpts.rejectUnauthorized = false;
		}

		this._httpsServer = https.createServer(serverOpts, this.onRequest.bind(this));
	}

	public get underlayingServer(): https.Server { return this._httpsServer; }

	public onListen(): Promise<void> {
		this._log.debug("SecuredWebServer#listen()");
		const opts: Configuration.SecuredWebServer = this._opts;
		const server: https.Server = this._httpsServer;
		return new Promise((resolve, reject) => {
			this._log.info("Starting Web Server...");
			server
				.on("listening", () => {
					const address = server.address();
					if (address !== null) {
						if (typeof address === "string") {
							this._log.info(`Web Server was started on ${address}`);
						} else {
							this._log.info(address.family + " Web Server was started on https://" + address.address + ":" + address.port);
						}
					}
					resolve();
				})
				.on("error", reject)
				.listen(opts.listenPort, opts.listenHost);
		});
	}

	protected async onDispose() {
		this._log.debug("SecuredWebServer#onDispose()");
		const server = this._httpsServer;
		const address = server.address();
		if (address !== null) {
			if (typeof address === "string") {
				this._log.info("Stoping Web Server http://" + address + "...");
			} else {
				this._log.info("Stoping " + address.family + " Web Server http://" + address.address + ":" + address.port + "...");
			}
		} else {
			this._log.info("Stoping Web Server...");
		}
		await new Promise((destroyResolve) => {
			server.close((err) => {
				if (err) {
					this._log.warn("The Web Server was stopped with error", err);
				} else {
					this._log.info("The Web Server was stopped");
				}
				destroyResolve();
			});
		});
	}
}

export function instanceofWebServer(server: any): server is WebServer {
	if (server instanceof UnsecuredWebServer) { return true; }
	if (server instanceof SecuredWebServer) { return true; }
	return false;
}

export function createWebServer(serverOpts: Configuration.WebServer, log: zxteam.Logger): WebServer {
	switch (serverOpts.type) {
		case "http":
			return new UnsecuredWebServer(serverOpts, log);
		case "https":
			return new SecuredWebServer(serverOpts, log);
		default: {
			const { type } = serverOpts;
			throw new Error(`Not supported server type '${type}'`);
		}
	}
}

export function createWebServers(
	serversOpts: ReadonlyArray<Configuration.WebServer>, log: zxteam.Logger
): ReadonlyArray<WebServer> {
	return serversOpts.map(serverOpts => createWebServer(serverOpts, log));
}
