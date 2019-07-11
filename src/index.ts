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
import * as net from "net";
import * as http from "http";
import * as https from "https";
import { unescape as urlDecode } from "querystring";
import { parse as parseURL } from "url";
import * as WebSocket from "ws";
import * as _ from "lodash";
import { pki } from "node-forge";

import { Configuration } from "./conf";

export * from "./conf";

export type WebServerRequestHandler = http.RequestListener;

export interface WebServer extends zxteam.Disposable {
	readonly name: string;
	readonly underlayingServer: http.Server | https.Server;
	rootExpressApplication: express.Application;
	bindRequestHandler(bindPath: string, handler: WebServerRequestHandler): void;
	createWebSocketServer(bindPath: string): WebSocket.Server;
	listen(): Promise<void>;
}

export abstract class AbstractWebServer<TOpts extends Configuration.WebServerBase | Configuration.WebServer>
	extends Disposable implements WebServer {
	public abstract readonly underlayingServer: http.Server | https.Server;
	protected readonly _log: zxteam.Logger;
	protected readonly _opts: TOpts;
	protected readonly _websockets: { [bindPath: string]: WebSocket.Server };
	private readonly _onUpgrade: (request: http.IncomingMessage, socket: net.Socket, head: Buffer) => void;
	private readonly _onRequestImpl: http.RequestListener;
	private readonly _handlers: Map</*bindPath: */string, WebServerRequestHandler>;
	private readonly _caCertificates: Array<[pki.Certificate, Buffer]>;
	private _rootExpressApplication: express.Application | null;

	public constructor(opts: TOpts, log: zxteam.Logger) {
		super();
		this._opts = opts;
		this._log = log;
		this._websockets = {};
		this._handlers = new Map();
		this._rootExpressApplication = null;


		let onXfccRequest: http.RequestListener | null = null;
		let onXfccUpgrade: ((request: http.IncomingMessage, socket: net.Socket, head: Buffer) => void) | null = null;
		if ("type" in opts) {
			const friendlyOpts = opts as Configuration.WebServer;
			if (
				"clientCertificateMode" in friendlyOpts &&
				friendlyOpts.clientCertificateMode === Configuration.ClientCertificateMode.XFCC
			) {
				if (
					friendlyOpts.caCertificates === undefined ||
					!(
						_.isString(friendlyOpts.caCertificates)
						|| friendlyOpts.caCertificates instanceof Buffer
						|| _.isArray(friendlyOpts.caCertificates)
					)
				) {
					throw new Error("ClientCertificateMode.XFCC required at least one CA certificate");
				}

				this._caCertificates = parseCertificates(friendlyOpts.caCertificates);

				onXfccRequest = this.onRequestXFCC.bind(this);
				onXfccUpgrade = this.onUpgradeXFCC.bind(this);
			} else {
				if (
					friendlyOpts.type === "https" &&
					friendlyOpts.caCertificates !== undefined &&
					(
						_.isString(friendlyOpts.caCertificates)
						|| friendlyOpts.caCertificates instanceof Buffer
						|| _.isArray(friendlyOpts.caCertificates)
					)
				) {
					this._caCertificates = parseCertificates(friendlyOpts.caCertificates);
				}
			}
		}

		this._onRequestImpl = onXfccRequest !== null ? onXfccRequest : this.onRequestCommon.bind(this);
		this._onUpgrade = onXfccUpgrade !== null ? onXfccUpgrade : this.onUpgradeCommon.bind(this);
	}

	/**
	 * Lazy create for Express Application
	 */
	public get rootExpressApplication(): express.Application {
		if (this._rootExpressApplication === null) {
			this._rootExpressApplication = express();
			const trustProxy = this._opts.trustProxy;
			if (trustProxy !== undefined) {
				this._log.debug("Setup 'trust proxy':", trustProxy);
				this._rootExpressApplication.set("trust proxy", trustProxy);
			}
		}
		return this._rootExpressApplication;
	}

	public set rootExpressApplication(value: express.Application) {
		if (this._rootExpressApplication !== null) {
			throw new Error("Wrong operation at current state. Express application already set. Override is not allowed.");
		}
		this._rootExpressApplication = value;
	}

	public get name(): string { return this._opts.name; }

	public bindRequestHandler(bindPath: string, value: WebServerRequestHandler): void {
		if (this._handlers.has(bindPath)) {
			throw new Error(`Wrong operation. Path '${bindPath}' already binded`);
		}
		this._handlers.set(bindPath, value);
	}

	public createWebSocketServer(bindPath: string): WebSocket.Server {
		const websocketServer: WebSocket.Server = new WebSocket.Server({ noServer: true });
		this._websockets[bindPath] = websocketServer;
		return websocketServer;
	}

	public listen(): Promise<void> {
		this.underlayingServer.on("upgrade", this._onUpgrade);
		return this.onListen();
	}

	protected get caCertificatesAsPki(): Array<pki.Certificate> {
		if (this._caCertificates === undefined) {
			throw new Error("Wrong operation at current state.");
		}
		return this._caCertificates.map(tuple => tuple[0]);
	}

	protected get caCertificatesAsBuffer(): Array<Buffer> {
		if (this._caCertificates === undefined) {
			throw new Error("Wrong operation at current state.");
		}
		return this._caCertificates.map(tuple => tuple[1]);
	}

	protected abstract onListen(): Promise<void>;

	protected onRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
		this._onRequestImpl(req, res);
	}

	private onRequestCommon(req: http.IncomingMessage, res: http.ServerResponse): void {
		if (this._handlers.size > 0 && req.url !== undefined) {
			const { pathname } = parseURL(req.url);
			if (pathname !== undefined) {
				for (const bindPath of this._handlers.keys()) {
					if (pathname.startsWith(bindPath)) {
						const handler = this._handlers.get(bindPath) as WebServerRequestHandler;
						handler(req, res);
						return;
					}
				}
			}
		}

		// A proper handler was not found, fallback to rootExpressApplication
		if (this._rootExpressApplication !== null) {
			this._rootExpressApplication(req, res);
			return;
		}

		this._log.warn("Request was handled but no listener.");
		res.writeHead(503);
		res.statusMessage = "Service Unavailable";
		res.end();
	}

	private onRequestXFCC(req: http.IncomingMessage, res: http.ServerResponse): void {
		if (this.validateXFCC(req)) {
			this.onRequestCommon(req, res);
			return;
		}

		res.statusMessage = "Client certificate is required.";
		res.writeHead(401);
		res.end();
	}

	private onUpgradeCommon(req: http.IncomingMessage, socket: net.Socket, head: Buffer): void {
		const urlPath = req.url;
		if (urlPath !== undefined) {
			const wss = this._websockets[urlPath];
			if (wss !== undefined) {
				this._log.debug("Upgrade the server on url path for WebSocket server.", urlPath);
				wss.handleUpgrade(req, socket, head, function (ws) {
					wss.emit("connection", ws, req);
				});
			} else {
				socket.destroy();
			}
		} else {
			socket.destroy();
		}
	}

	private onUpgradeXFCC(req: http.IncomingMessage, socket: net.Socket, head: Buffer): void {
		if (this.validateXFCC(req)) {
			this.onUpgradeCommon(req, socket, head);
			return;
		}

		socket.write("HTTP/1.1 401 Client certificate is required.\r\n\r\n");
		socket.end();
	}

	private validateXFCC(req: http.IncomingMessage): boolean {
		const xfccHeaderData = req && req.headers && req.headers["x-forwarded-client-cert"];
		if (_.isString(xfccHeaderData)) {
			this._log.trace("X-Forwarded-Client-Cert header:", xfccHeaderData);

			const clientCertPem = urlDecode(xfccHeaderData);
			const clientCert = pki.certificateFromPem(clientCertPem);

			for (const caCert of this.caCertificatesAsPki) {
				try {
					if (caCert.verify(clientCert)) {
						return true;
					}
				} catch (e) {
					this._log.trace("Verify failed.", e);
				}
			}
		} else {
			this._log.debug("Request with no X-Forwarded-Client-Cert header.");
		}

		return false;
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
			cert: opts.serverCertificate instanceof Buffer ? opts.serverCertificate : fs.readFileSync(opts.serverCertificate),
			key: opts.serverKey instanceof Buffer ? opts.serverKey : fs.readFileSync(opts.serverKey)
		};

		if (opts.caCertificates !== undefined) {
			if (_.isString(opts.caCertificates)) {
				serverOpts.ca = fs.readFileSync(opts.caCertificates);
			}
			//serverOpts.ca = this.caCertificatesAsBuffer;
		}
		if (opts.serverKeyPassword !== undefined) {
			serverOpts.passphrase = opts.serverKeyPassword;
		}

		switch (opts.clientCertificateMode) {
			case Configuration.ClientCertificateMode.NONE:
			case Configuration.ClientCertificateMode.XFCC: // XFCC handled by AbstractWebServer
				serverOpts.requestCert = false;
				serverOpts.rejectUnauthorized = false;
				break;
			case Configuration.ClientCertificateMode.REQUEST:
				serverOpts.requestCert = true;
				serverOpts.rejectUnauthorized = false;
				break;
			default:
				// By default use Configuration.SecuredWebServer.ClientCertMode.TRUST mode
				serverOpts.requestCert = true;
				serverOpts.rejectUnauthorized = true;
				break;
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

export interface ProtocolAdapterNext<T> {
	(cancellationToken: zxteam.CancellationToken, data: T): zxteam.Task<T>;
}
export interface ProtocolAdapter {
	handleBinaryMessage(
		cancellationToken: zxteam.CancellationToken, data: ArrayBuffer, next?: ProtocolAdapterNext<ArrayBuffer>
	): zxteam.Task<ArrayBuffer>;
	handleTextMessage(
		cancellationToken: zxteam.CancellationToken, data: string, next?: ProtocolAdapterNext<string>
	): zxteam.Task<string>;
}

export type ProtocolAdapterFactory = () => Promise<ProtocolAdapter>;

export abstract class ServerEndpoint extends Initable {
	protected readonly _servers: ReadonlyArray<WebServer>;
	protected readonly _log: zxteam.Logger;

	public constructor(
		servers: ReadonlyArray<WebServer>,
		log: zxteam.Logger
	) {
		super();

		this._servers = servers;
		this._log = log;
	}
}

export abstract class BindEndpoint extends ServerEndpoint {
	protected readonly _bindPath: string;

	public constructor(
		servers: ReadonlyArray<WebServer>,
		opts: Configuration.BindEndpoint,
		log: zxteam.Logger
	) {
		super(servers, log);

		this._bindPath = opts.bindPath;
	}
}

export abstract class RestEndpoint<TService> extends BindEndpoint {
	protected readonly _service: TService;

	public constructor(
		servers: ReadonlyArray<WebServer>,
		service: TService,
		opts: Configuration.BindEndpoint,
		log: zxteam.Logger
	) {
		super(servers, opts, log);

		this._service = service;
	}
}

export interface WebSocketBinderEndpoint {
	use(protocol: string, protocolAdapter: ProtocolAdapter): void;
}

export class WebSocketEndpoint extends BindEndpoint implements WebSocketBinderEndpoint {
	private readonly _webSocketServers: Array<WebSocket.Server>;
	private readonly _protocolAdaptersMap: Map</* protocol: */string, Array<ProtocolAdapter>>;
	private _defaultProtocol: string;
	private _connectionCounter: number;

	public constructor(
		servers: ReadonlyArray<WebServer>,
		opts: Configuration.WebSocketEndpoint,
		log: zxteam.Logger
	) {
		super(servers, opts, log);
		this._webSocketServers = [];
		this._protocolAdaptersMap = new Map();
		this._defaultProtocol = opts.defaultProtocol;
		this._connectionCounter = 0;
	}

	public use(protocol: string, protocolAdapter: ProtocolAdapter): void {
		let items = this._protocolAdaptersMap.get(protocol);
		if (items === undefined) {
			items = [];
			this._protocolAdaptersMap.set(protocol, items);
		}
		items.push(protocolAdapter);
	}

	protected onInit(): void {
		for (const server of this._servers) {
			const webSocketServer = server.createWebSocketServer(this._bindPath); // new WebSocket.Server({ noServer: true });
			this._webSocketServers.push(webSocketServer);
			webSocketServer.on("connection", this.onConnection.bind(this));
		}
	}

	protected async onDispose() {
		const webSocketServers = this._webSocketServers.splice(0).reverse();
		for (const webSocketServer of webSocketServers) {
			await new Promise((resolve) => {
				webSocketServer.close((err) => {
					if (err !== undefined) {
						if (this._log.isWarnEnabled) {
							this._log.warn(`Web Socket Server was closed with error.Inner message: ${err.message} `);
						}
						this._log.trace("Web Socket Server was closed with error.", err);
					}

					// dispose never raise any errors
					resolve();
				});
			});
		}
	}

	protected onConnection(webSocket: WebSocket, request: http.IncomingMessage): void {
		if (this._connectionCounter === Number.MAX_SAFE_INTEGER) { this._connectionCounter = 0; }
		const connectionNumber: number = this._connectionCounter++;
		const ipAddress = request.connection.remoteAddress;
		if (ipAddress !== undefined && this._log.isTraceEnabled) {
			this._log.trace(`Connection #${connectionNumber} was established from ${ipAddress} `);
		}
		if (this._log.isInfoEnabled) {
			this._log.info(`Connection #${connectionNumber} was established`);
		}

		const protocol = webSocket.protocol || this._defaultProtocol;
		const protocolAdapters = (() => {
			const items = this._protocolAdaptersMap.get(protocol);
			return items !== undefined ? items.slice(0) : [];
		})();
		if (protocolAdapters.length === 0) {
			this._log.warn(`Connection #${connectionNumber} dropped. No any adapters to handle protocol: ${protocol}`);
			// https://tools.ietf.org/html/rfc6455#section-7.4.1
			webSocket.close(1007, `Wrong sub-protocol: ${protocol}`);
			webSocket.terminate();
			return;
		}
		(webSocket as any).protocolAdapters = protocolAdapters;

		webSocket.binaryType = "arraybuffer";
		webSocket.onmessage = ({ data }) => {
			Promise.resolve().then(() => this.onMessage(webSocket, data))
				.catch(e => {
					if (this._log.isInfoEnabled) {
						this._log.info(`Connection #${connectionNumber} onMessage failed: ${e.message} `);
					}
					if (this._log.isTraceEnabled) {
						this._log.trace(`Connection #${connectionNumber} onMessage failed: `, e);
					}
				});
		};
		webSocket.onclose = ({ code, reason }) => {
			if (this._log.isTraceEnabled) {
				this._log.trace(`Connection #${connectionNumber} was closed: ${JSON.stringify({ code, reason })} `);
			}
			if (this._log.isInfoEnabled) {
				this._log.info(`Connection #${connectionNumber} was closed`);
			}
		};
	}

	protected async onMessage(webSocket: WebSocket, data: WebSocket.Data): Promise<void> {
		const protocolAdapters: Array<ProtocolAdapter> = (webSocket as any).protocolAdapters.slice();
		let nextProtocolAdapter: ProtocolAdapter = protocolAdapters.shift() as ProtocolAdapter;
		if (data instanceof ArrayBuffer) {
			const next: ProtocolAdapterNext<ArrayBuffer> = (cancellationToken: zxteam.CancellationToken, nextData: ArrayBuffer) => {
				const currentProtocolAdapter = nextProtocolAdapter;
				let nextFunc;
				if (protocolAdapters.length > 0) {
					nextFunc = next;
					nextProtocolAdapter = protocolAdapters.shift() as ProtocolAdapter;
				} else {
					nextFunc = undefined;
				}
				return currentProtocolAdapter.handleBinaryMessage(cancellationToken, nextData, nextFunc);
			};
			const response = await next(DUMMY_CANCELLATION_TOKEN, data).promise;
			webSocket.send(response);
		} else if (_.isString(data)) {
			const next: ProtocolAdapterNext<string> = (cancellationToken: zxteam.CancellationToken, nextData: string) => {
				const currentProtocolAdapter = nextProtocolAdapter;
				let nextFunc;
				if (protocolAdapters.length > 0) {
					nextFunc = next;
					nextProtocolAdapter = protocolAdapters.shift() as ProtocolAdapter;
				} else {
					nextFunc = undefined;
				}
				return currentProtocolAdapter.handleTextMessage(cancellationToken, nextData, nextFunc);
			};
			const response = await next(DUMMY_CANCELLATION_TOKEN, data).promise;
			webSocket.send(response);
		} else {
			throw new Error("Bad message");
		}
	}
}


export function instanceofWebServer(server: any): server is WebServer {
	if (server instanceof UnsecuredWebServer) { return true; }
	if (server instanceof SecuredWebServer) { return true; }

	if (
		process.env.NODE_ENV === "development" &&
		"name" in server &&
		"underlayingServer" in server &&
		"rootExpressApplication" in server &&
		"bindRequestHandler" in server &&
		"createWebSocketServer" in server &&
		"listen" in server
	) {
		// Look like the server is WebServer like. Allow it only in development
		return true;
	}

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


function parseCertificate(certificate: Buffer | string): [pki.Certificate, Buffer] {
	let cert: pki.Certificate;
	let data: Buffer;

	if (_.isString(certificate)) {
		data = fs.readFileSync(certificate);
		cert = pki.certificateFromPem(data.toString("ascii"));
	} else {
		data = certificate;
		cert = pki.certificateFromPem(certificate.toString("ascii"));
	}

	return [cert, data];
}
function parseCertificates(certificates: Buffer | string | Array<string | Buffer>): Array<[pki.Certificate, Buffer]> {
	if (certificates instanceof Buffer || _.isString(certificates)) {
		return [parseCertificate(certificates)];
	} else {
		return certificates.map(parseCertificate);
	}
}

const DUMMY_CANCELLATION_TOKEN: zxteam.CancellationToken = Object.freeze({
	get isCancellationRequested() { return false; },
	addCancelListener(cb: Function) { /***/ },
	removeCancelListener(cb: Function) { /***/ },
	throwIfCancellationRequested() { /***/ }
});
