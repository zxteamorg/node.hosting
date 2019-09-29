import * as zxteam from "@zxteam/contract";
import { SubscriberChannel, CancellationToken, InvokeChannel } from "@zxteam/contract";
import { Disposable } from "@zxteam/disposable";
import { logger } from "@zxteam/logger";
import { DUMMY_CANCELLATION_TOKEN } from "@zxteam/cancellation";

import * as http from "http";
import * as _ from "lodash";
//import * as WebSocket from "ws";

import * as THE from "../src/index";

type Channel<T> = InvokeChannel<T, T> & SubscriberChannel<T>;

class BinaryEchoChannel extends Disposable implements Channel<ArrayBuffer> {
	private readonly _timeout: number;
	private readonly _handlers: Set<zxteam.SubscriberChannel.Callback<ArrayBuffer, zxteam.SubscriberChannel.Event<ArrayBuffer>>>;
	private _timer?: NodeJS.Timeout;

	public constructor(timeout: number) {
		super();
		this._timeout = timeout;
		this._handlers = new Set();
	}

	public addHandler(cb: zxteam.SubscriberChannel.Callback<ArrayBuffer, zxteam.SubscriberChannel.Event<ArrayBuffer>>): void {
		if (this._timer === undefined) {
			this._timer = setInterval(this.onTimer.bind(this), this._timeout);
		}
		this._handlers.add(cb);
	}

	public invoke(cancellationToken: zxteam.CancellationToken, data: ArrayBuffer): Promise<ArrayBuffer> {
		console.log("data instanceof ArrayBuffer: ", data instanceof ArrayBuffer);
		this._handlers.forEach(h => h(DUMMY_CANCELLATION_TOKEN, { data })); // Broadcast
		return Promise.resolve(Buffer.from("Broadcast done"));
	}

	public removeHandler(cb: zxteam.SubscriberChannel.Callback<ArrayBuffer, zxteam.SubscriberChannel.Event<ArrayBuffer>>): void {
		this._handlers.delete(cb);
		if (this._timer !== undefined) {
			clearInterval(this._timer);
			delete this._timer;
		}
	}

	protected onDispose() {
		if (this._timer !== undefined) {
			clearInterval(this._timer);
			delete this._timer;
		}
		this._handlers.clear();
	}

	private onTimer() {
		const now = new Date();
		this._handlers.forEach(h => h(DUMMY_CANCELLATION_TOKEN, { data: ArrayBufferUtils.fromBuffer(Buffer.from(now.toISOString())) }));
	}
}

class StringEchoChannel extends Disposable implements Channel<string> {
	private readonly _timeout: number;
	private readonly _handlers: Set<zxteam.SubscriberChannel.Callback<string, zxteam.SubscriberChannel.Event<string>>>;
	private _timer?: NodeJS.Timeout;

	public constructor(timeout: number) {
		super();
		this._timeout = timeout;
		this._handlers = new Set();
	}

	public addHandler(cb: zxteam.SubscriberChannel.Callback<string, zxteam.SubscriberChannel.Event<string>>): void {
		if (this._timer === undefined) {
			this._timer = setInterval(this.onTimer.bind(this), this._timeout);
		}
		this._handlers.add(cb);
	}

	public invoke(cancellationToken: zxteam.CancellationToken, data: string): Promise<string> {
		this._handlers.forEach(h => h(DUMMY_CANCELLATION_TOKEN, { data })); // Broadcast
		return Promise.resolve("Broadcast done");
	}

	public removeHandler(cb: zxteam.SubscriberChannel.Callback<string, zxteam.SubscriberChannel.Event<string>>): void {
		this._handlers.delete(cb);
		if (this._timer !== undefined) {
			clearInterval(this._timer);
			delete this._timer;
		}
	}
	protected onDispose() {
		if (this._timer !== undefined) {
			clearInterval(this._timer);
			delete this._timer;
		}
		this._handlers.clear();
	}

	private onTimer() {
		const now = new Date();
		this._handlers.forEach(h => h(DUMMY_CANCELLATION_TOKEN, { data: now.toISOString() }));
	}
}

async function main() {
	const server = new THE.UnsecuredWebServer({
		type: "http",
		listenHost: "0.0.0.0",
		listenPort: 8080,
		name: "Unsecured Server"
	}, logger.getLogger("Unsecured Server"));

	const wsEndpoint = new THE.WebSocketChannelEndpoint(
		[server],
		{
			bindPath: "/",
			defaultProtocol: "text"
		},
		logger.getLogger("wsEndpoint")
	);

	const binaryEchoChannel = new BinaryEchoChannel(450);
	const stringEchoChannel = new StringEchoChannel(750);

	wsEndpoint.useChannelBinary("bin", binaryEchoChannel);
	wsEndpoint.useChannelText("text", stringEchoChannel);

	await wsEndpoint.init(DUMMY_CANCELLATION_TOKEN);
	await server.init(DUMMY_CANCELLATION_TOKEN);

	let destroyRequestCount = 0;
	async function gracefulShutdown(signal: string) {
		if (destroyRequestCount++ === 0) {
			console.log(`Interrupt signal received: ${signal}`);
			await wsEndpoint.dispose();
			await sleep(2000);
			await server.dispose();
			await sleep(2000);
			await binaryEchoChannel.dispose();
			await stringEchoChannel.dispose();
			process.exit(0);
		} else {
			console.log(`Interrupt signal (${destroyRequestCount}) received: ${signal}`);
		}
	}

	(["SIGTERM", "SIGINT"] as Array<NodeJS.Signals>).forEach(signal => process.on(signal, () => gracefulShutdown(signal)));
}

main().catch(e => {
	console.error(e);
	process.exit(1);
});


function sleep(ms: number): Promise<void> {
	return new Promise(r => setTimeout(r, ms));
}

namespace ArrayBufferUtils {
	export function fromBuffer(buf: Uint8Array): ArrayBuffer {
		const ab = new ArrayBuffer(buf.length);
		const view = new Uint8Array(ab);
		for (let i = 0; i < buf.length; ++i) {
			view[i] = buf[i];
		}
		return ab;
	}

	export function toBuffer(ab: ArrayBuffer): Buffer {
		const buf = Buffer.alloc(ab.byteLength);
		const view = new Uint8Array(ab);
		for (let i = 0; i < buf.length; ++i) {
			buf[i] = view[i];
		}
		return buf;
	}
}
