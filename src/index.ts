const { name: packageName, version: packageVersion } = require("../package.json");
const G: any = global || window || {};
const PACKAGE_GUARD: symbol = Symbol.for(packageName);
if (PACKAGE_GUARD in G) {
	const conflictVersion = G[PACKAGE_GUARD];
	// tslint:disable-next-line: max-line-length
	const msg = `Conflict module version. Look like two different version of package ${packageName} was loaded inside the process: ${conflictVersion} and ${packageVersion}.`;
	if (process !== undefined && process.env !== undefined && process.env.NODE_ALLOW_CONFLICT_MODULES === "1") {
		console.warn(msg + " This treats as warning because NODE_ALLOW_CONFLICT_MODULES is set.");
	} else {
		throw new Error(msg + " Use NODE_ALLOW_CONFLICT_MODULES=\"1\" to treats this error as warning.");
	}
} else {
	G[PACKAGE_GUARD] = packageVersion;
}

import { CancellationToken, Logger, PublisherChannel, SubscriberChannel } from "@zxteam/contract";
import { ManualCancellationTokenSource, DUMMY_CANCELLATION_TOKEN } from "@zxteam/cancellation";
import { Initable, Disposable } from "@zxteam/disposable";
import { InvalidOperationError, wrapErrorIfNeeded, AggregateError } from "@zxteam/errors";

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

export interface WebServer extends Initable {
	readonly name: string;
	readonly underlayingServer: http.Server | https.Server;
	rootExpressApplication: express.Application;
	bindRequestHandler(bindPath: string, handler: WebServerRequestHandler): void;
	createWebSocketServer(bindPath: string): WebSocket.Server;
}

export abstract class AbstractWebServer<TOpts extends Configuration.WebServerBase | Configuration.WebServer>
	extends Initable implements WebServer {
	public abstract readonly underlayingServer: http.Server | https.Server;
	protected readonly _log: Logger;
	protected readonly _opts: TOpts;
	protected readonly _websockets: { [bindPath: string]: WebSocket.Server };
	private readonly _onUpgrade: (request: http.IncomingMessage, socket: net.Socket, head: Buffer) => void;
	private readonly _onRequestImpl: http.RequestListener;
	private readonly _handlers: Map</*bindPath: */string, WebServerRequestHandler>;
	private readonly _caCertificates: ReadonlyArray<[pki.Certificate, Buffer]>;
	private _rootExpressApplication: express.Application | null;

	public constructor(opts: TOpts, log: Logger) {
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
				} else {
					this._caCertificates = [];
				}
			}
		} else {
			this._caCertificates = [];
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

	protected onInit(): Promise<void> {
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

	public constructor(opts: Configuration.UnsecuredWebServer, log: Logger) {
		super(opts, log);

		// Make HTTP server instance
		const serverOpts: https.ServerOptions = {
		};

		this._httpServer = http.createServer(serverOpts, this.onRequest.bind(this));
	}

	public get underlayingServer(): http.Server { return this._httpServer; }

	protected onListen(): Promise<void> {
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

	public constructor(opts: Configuration.SecuredWebServer, log: Logger) {
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

	protected onListen(): Promise<void> {
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

export abstract class BindEndpoint extends Initable {
	protected readonly _log: Logger;
	protected readonly _bindPath: string;

	public constructor(
		opts: Configuration.BindEndpoint,
		log: Logger
	) {
		super();
		this._log = log;
		this._bindPath = opts.bindPath;
	}
}

export abstract class ServersBindEndpoint extends BindEndpoint {
	protected readonly _servers: ReadonlyArray<WebServer>;

	public constructor(
		servers: ReadonlyArray<WebServer>,
		opts: Configuration.BindEndpoint,
		log: Logger
	) {
		super(opts, log);
		this._servers = servers;
	}
}

export type WebSocketBinaryChannel = PublisherChannel<Uint8Array> & SubscriberChannel<Uint8Array>;
export type WebSocketTextChannel = PublisherChannel<string> & SubscriberChannel<string>;
export class WebSocketChannelsEndpoint extends ServersBindEndpoint {
	private readonly _webSocketServers: Array<WebSocket.Server>;
	private readonly _connections: Set<WebSocket>;
	private _defaultProtocol: string;
	private _allowedProtocols: Set<string>;
	private _connectionCounter: number;

	public constructor(
		servers: ReadonlyArray<WebServer>,
		opts: Configuration.WebSocketEndpoint,
		log: Logger
	) {
		super(servers, opts, log);
		this._webSocketServers = [];
		this._connections = new Set();
		this._defaultProtocol = opts.defaultProtocol;
		this._allowedProtocols = new Set([this._defaultProtocol]);
		if (opts.allowedProtocols !== undefined) {
			opts.allowedProtocols.forEach((allowedProtocol: string): void => {
				this._allowedProtocols.add(allowedProtocol);
			});
		}
		this._connectionCounter = 0;
	}

	protected onInit(): void {
		for (const server of this._servers) {
			const webSocketServer = server.createWebSocketServer(this._bindPath); // new WebSocket.Server({ noServer: true });
			this._webSocketServers.push(webSocketServer);
			webSocketServer.on("connection", this.onConnection.bind(this));
		}
	}

	protected async onDispose() {
		const connections = [...this._connections.values()];
		this._connections.clear();
		for (const webSocket of connections) {
			webSocket.close(1001, "going away");
			webSocket.terminate();
		}

		const webSocketServers = this._webSocketServers.splice(0).reverse();
		for (const webSocketServer of webSocketServers) {
			await new Promise((resolve) => {
				webSocketServer.close((err) => {
					if (err !== undefined) {
						if (this._log.isWarnEnabled) {
							this._log.warn(`Web Socket Server was closed with error. Inner message: ${err.message} `);
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
		if (this.disposing) {
			// https://tools.ietf.org/html/rfc6455#section-7.4.1
			webSocket.close(1001, "going away");
			webSocket.terminate();
			return;
		}

		if (this._connectionCounter === Number.MAX_SAFE_INTEGER) { this._connectionCounter = 0; }
		const connectionNumber: number = this._connectionCounter++;
		const ipAddress: string | undefined = request.connection.remoteAddress;
		if (ipAddress !== undefined && this._log.isTraceEnabled) {
			this._log.trace(`Connection #${connectionNumber} was established from ${ipAddress} `);
		}
		if (this._log.isInfoEnabled) {
			this._log.info(`Connection #${connectionNumber} was established`);
		}

		const subProtocol: string = webSocket.protocol || this._defaultProtocol;
		if (webSocket.protocol !== undefined) {
			if (!this._allowedProtocols.has(subProtocol)) {
				this._log.warn(`Connection #${connectionNumber} dropped. Not supported sub-protocol: ${subProtocol}`);
				// https://tools.ietf.org/html/rfc6455#section-7.4.1
				webSocket.close(1007, `Wrong sub-protocol: ${subProtocol}`);
				webSocket.terminate();
				return;
			}
		}

		const cancellationTokenSource = new ManualCancellationTokenSource();

		webSocket.binaryType = "nodebuffer";

		const channels: Map</*protocol:*/ string, {
			binaryChannel?: WebSocketChannelsEndpointHelpers.WebSocketBinaryChannelImpl,
			textChannel?: WebSocketChannelsEndpointHelpers.WebSocketTextChannelImpl
		}> = new Map();

		webSocket.onmessage = async ({ data }) => {
			try {
				let channelsTuple = channels.get(subProtocol);
				if (channelsTuple === undefined) {
					channelsTuple = {};
					channels.set(subProtocol, channelsTuple);
				}

				if (data instanceof Buffer) {
					if (channelsTuple.binaryChannel === undefined) {
						const binaryChannel = new WebSocketChannelsEndpointHelpers.WebSocketBinaryChannelImpl(webSocket);
						try {
							this.onOpenBinaryChannel(webSocket, subProtocol, binaryChannel);
						} catch (e) {
							// https://tools.ietf.org/html/rfc6455#section-7.4.1
							webSocket.close(1011, wrapErrorIfNeeded(e).message);
							webSocket.terminate();
							return;
						}
						channelsTuple.binaryChannel = binaryChannel;
					}
					await channelsTuple.binaryChannel.onMessage(cancellationTokenSource.token, data);
				} else if (_.isString(data)) {
					if (channelsTuple.textChannel === undefined) {
						const textChannel = new WebSocketChannelsEndpointHelpers.WebSocketTextChannelImpl(webSocket);
						try {
							this.onOpenTextChannel(webSocket, subProtocol, textChannel);
						} catch (e) {
							// https://tools.ietf.org/html/rfc6455#section-7.4.1
							const friendlyError: Error = wrapErrorIfNeeded(e);
							webSocket.close(1011, friendlyError.message);
							webSocket.terminate();
							return;
						}
						channelsTuple.textChannel = textChannel;
					}
					await channelsTuple.textChannel.onMessage(cancellationTokenSource.token, data);
				} else {
					if (this._log.isDebugEnabled) {
						this._log.debug(
							`Connection #${connectionNumber} cannot handle a message due not supported type. Terminate socket...`
						);
					}
					// https://tools.ietf.org/html/rfc6455#section-7.4.1
					webSocket.close(1003, `Not supported message type`);
					webSocket.terminate();
					return;
				}
			} catch (e) {
				if (this._log.isInfoEnabled) {
					this._log.info(`Connection #${connectionNumber} onMessage failed: ${e.message}`);
				}
				if (this._log.isTraceEnabled) {
					this._log.trace(`Connection #${connectionNumber} onMessage failed:`, e);
				}
			}
		};
		webSocket.onclose = ({ code, reason }) => {
			if (this._log.isTraceEnabled) {
				this._log.trace(`Connection #${connectionNumber} was closed: ${JSON.stringify({ code, reason })} `);
			}
			if (this._log.isInfoEnabled) {
				this._log.info(`Connection #${connectionNumber} was closed`);
			}

			cancellationTokenSource.cancel();
			this._connections.delete(webSocket);

			const closedError = new Error(`WebSocket was closed: ${code} ${reason}`);
			for (const channelsTuple of channels.values()) {
				if (channelsTuple.binaryChannel !== undefined) {
					channelsTuple.binaryChannel.onClose(closedError).catch(console.error);
				}
				if (channelsTuple.textChannel !== undefined) {
					channelsTuple.textChannel.onClose(closedError).catch(console.error);
				}
			}
			channels.clear();
		};

		this._connections.add(webSocket);
	}

	/**
	 * The method should be overriden. The method called by the endpoint,
	 * when WSClient sent first binary message for specified sub-protocol.
	 * @param webSocket WebSocket instance
	 * @param subProtocol These strings are used to indicate sub-protocols,
	 * so that a single server can implement multiple WebSocket sub-protocols (for example,
	 * you might want one server to be able to handle different types of interactions
	 * depending on the specified protocol).
	 * @param channel Binary channel instance to be user in inherited class
	 */
	protected onOpenBinaryChannel(webSocket: WebSocket, subProtocol: string, channel: WebSocketBinaryChannel): void {
		throw new InvalidOperationError(`Binary messages are not supported by the sub-protocol: ${subProtocol}`);
	}

	/**
	 * The method should be overriden. The method called by the endpoint,
	 * when WSClient sent first text message for specified sub-protocol.
	 * @param webSocket WebSocket instance
	 * @param subProtocol These strings are used to indicate sub-protocols,
	 * so that a single server can implement multiple WebSocket sub-protocols (for example,
	 * you might want one server to be able to handle different types of interactions
	 * depending on the specified protocol).
	 * @param channel Text channel instance to be user in inherited class
	 */
	protected onOpenTextChannel(webSocket: WebSocket, subProtocol: string, channel: WebSocketTextChannel): void {
		throw new InvalidOperationError(`Text messages are not supported by the sub-protocol: ${subProtocol}`);
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

export function createWebServer(serverOpts: Configuration.WebServer, log: Logger): WebServer {
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
	serversOpts: ReadonlyArray<Configuration.WebServer>, log: Logger
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

namespace WebSocketChannelsEndpointHelpers {
	export class WebSocketChannelBase<TData> {
		protected readonly _webSocket: WebSocket;
		protected readonly _callbacks: Array<SubscriberChannel.Callback<TData>>;
		protected _isBroken: boolean;

		public constructor(webSocket: WebSocket) {
			this._webSocket = webSocket;
			this._callbacks = [];
			this._isBroken = false;
		}

		public async onClose(error: Error): Promise<void> {
			if (this._isBroken) {
				// Already sent error-based callback, nothing to do
				return;
			}
			await Promise.all(this._callbacks.map(async (callback) => {
				try {
					// Notify that channel brokes
					await callback(DUMMY_CANCELLATION_TOKEN, error);
				} catch (e) {
					// Nothing to do any more with fucking client's callback. Just log STDERR.
					console.error(e);
				}
			}));
		}

		public async onMessage(cancellationToken: CancellationToken, data: TData): Promise<void> {
			if (this._isBroken) {
				console.error("Skip received messages due channel is broken");
				return;
			}
			const errors: Array<Error> = [];
			const safePromises = this._callbacks.map(async (callback) => {
				try {
					await callback(cancellationToken, { data });
				} catch (e) {
					errors.push(wrapErrorIfNeeded(e));
				}
			});
			await Promise.all(safePromises);
			if (errors.length > 0) {
				// The callback supplier is shitcoder. Closing channel and socket to prevent flowing shit...
				this._isBroken = true;

				// https://tools.ietf.org/html/rfc6455#section-7.4.1
				this._webSocket.close(1011, "A server is terminating the connection because it encountered an unexpected condition that prevented it from fulfilling the request.");
				this._webSocket.terminate();

				const aggregatedError = new AggregateError(errors);
				await Promise.all(this._callbacks.map(async (callback) => {
					try {
						// Notify that channel brokes
						await callback(DUMMY_CANCELLATION_TOKEN, aggregatedError);
					} catch (e) {
						// Nothing to do any more with fucking client's callback. Just log STDERR.
						console.error(e);
					}
				}));
			}
		}

		public addHandler(cb: SubscriberChannel.Callback<TData>): void {
			this._callbacks.push(cb);
		}

		public removeHandler(cb: SubscriberChannel.Callback<TData>): void {
			const index = this._callbacks.indexOf(cb);
			if (index !== -1) {
				this._callbacks.splice(index, 1);
			}
		}

		public send(cancellationToken: CancellationToken, data: TData): Promise<void> {
			if (this._isBroken) {
				throw new InvalidOperationError("Cannot send message on broken channel");
			}
			return new Promise(sendResolve => this._webSocket.send(data, () => sendResolve()));
		}
	}
	export class WebSocketBinaryChannelImpl extends WebSocketChannelBase<Uint8Array> implements WebSocketBinaryChannel { }
	export class WebSocketTextChannelImpl extends WebSocketChannelBase<string> implements WebSocketTextChannel { }
}
