import { SubscriberChannel, CancellationToken } from "@zxteam/contract";
import { logger } from "@zxteam/logger";
import { DUMMY_CANCELLATION_TOKEN } from "@zxteam/cancellation";

import * as _ from "lodash";
import * as WebSocket from "ws";

import * as THE from "../src/index";

class TestWebSocketChannelsEndpoint extends THE.WebSocketChannelsEndpoint {
	protected onOpenBinaryChannel(webSocket: WebSocket, subProtocol: string, channel: THE.WebSocketBinaryChannel) {
		let timer: NodeJS.Timeout | null = null;
		let echoMessage: string;
		const messageHandler = (cancellationToken: CancellationToken, event: SubscriberChannel.Event<Uint8Array> | Error) => {
			if (event instanceof Error) {
				if (timer !== null) {
					clearTimeout(timer);
				}
			} else {
				const friendlyData = event.data.toString();
				console.log(subProtocol, "Receive:", friendlyData);
				if (friendlyData === "stop") {
					if (timer !== null) {
						clearTimeout(timer);
					}
				} else {
					echoMessage = friendlyData;
					if (timer === null) {
						timer = setInterval(() => {
							const now = new Date();
							channel.send(cancellationToken, Buffer.from(JSON.stringify({
								subProtocol,
								format: "binary",
								data: now.toISOString(),
								echoMessage
							})));
						}, 500);
					}
				}
			}
		};
		channel.addHandler(messageHandler);
	}
	protected onOpenTextChannel(webSocket: WebSocket, subProtocol: string, channel: THE.WebSocketTextChannel) {
		let timer: NodeJS.Timeout | null = null;
		let echoMessage: string;
		const messageHandler = (cancellationToken: CancellationToken, event: SubscriberChannel.Event<string> | Error) => {
			if (event instanceof Error) {
				if (timer !== null) {
					clearTimeout(timer);
				}
			} else {
				console.log(subProtocol, "Receive:", event.data);
				if (event.data === "stop") {
					if (timer !== null) {
						clearTimeout(timer);
					}
				} else {
					echoMessage = event.data;
					if (timer === null) {
						timer = setInterval(() => {
							const now = new Date();
							channel.send(cancellationToken, JSON.stringify({
								subProtocol,
								format: "text",
								data: now.toISOString(),
								echoMessage
							}));
						}, 500);
					}
				}
			}
		};
		channel.addHandler(messageHandler);
	}
}

async function main() {
	const server = new THE.UnsecuredWebServer({
		type: "http",
		listenHost: "0.0.0.0",
		listenPort: 8080,
		name: "Unsecured Server"
	}, logger.getLogger("Unsecured Server"));

	const wsEndpoint = new TestWebSocketChannelsEndpoint(
		[server],
		{
			bindPath: "/ws",
			defaultProtocol: "text",
			allowedProtocols: ["bin" /*, "text" - will be included automatically*/]
		},
		logger.getLogger("wsEndpoint")
	);

	await wsEndpoint.init(DUMMY_CANCELLATION_TOKEN);
	await server.init(DUMMY_CANCELLATION_TOKEN);

	let destroyRequestCount = 0;
	async function gracefulShutdown(signal: string) {
		if (destroyRequestCount++ === 0) {
			console.log(`Interrupt signal received: ${signal}`);
			await wsEndpoint.dispose();
			await sleep(500);
			await server.dispose();
			await sleep(500);
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
