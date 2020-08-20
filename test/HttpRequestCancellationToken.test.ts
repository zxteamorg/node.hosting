import { CancellationToken } from "@zxteam/contract";
import { DUMMY_CANCELLATION_TOKEN } from "@zxteam/cancellation";
import { logger, LoggerProvider } from "@zxteam/logger";

import { assert } from "chai";

import * as http from "http";
import * as net from "net";


import * as THE from "../";

describe("HttpRequestCancellationToken tests", function () {
	let webServer: THE.UnsecuredWebServer | null = null;

	beforeEach(async function () {
		webServer = new THE.UnsecuredWebServer(
			{
				type: "http",
				name: "Test Web Server",
				listenHost: "127.0.0.1",
				listenPort: 65499
			},
			logger
		);
		await webServer.init(DUMMY_CANCELLATION_TOKEN);
	});

	afterEach(async function () {
		if (webServer !== null && (webServer.initialized || webServer.initializing)) {
			await webServer.dispose();
		}
		webServer = null;
	});


	it("5 requests should signal disconnect via CancellationToken", async function () {
		let onClientDisconnectCallCounter: number = 0;
		const defer: { resolve?: () => void, promise?: Promise<void> } = {};
		defer.promise = new Promise(function (resolve) { defer.resolve = resolve; });
		const timeout: NodeJS.Timeout = setTimeout(function () { defer.resolve!(); }, 1000);

		webServer!.rootExpressApplication.get("/", async function (request: http.IncomingMessage, response: http.OutgoingMessage) {
			const cancellationToken: CancellationToken = THE.AbstractWebServer.createCancellationToken(request);
			function onClientDisconnect() {
				onClientDisconnectCallCounter++;
				if (onClientDisconnectCallCounter === 5) {
					clearTimeout(timeout);
					defer.resolve!();
				}
			}
			cancellationToken.addCancelListener(onClientDisconnect);
		});

		function hangupRequest() {
			const socket: net.Socket = net.connect({
				port: 65499,
				family: 4,
				host: "127.0.0.1",
				readable: true,
				writable: true,
				allowHalfOpen: false
			});
			socket.on("connect", function () {
				socket.write(Buffer.from("GET / HTTP/1.0\n\n", "utf-8"), function () {
					socket.destroy();
				});
			});
		}

		process.nextTick(hangupRequest); // 1
		process.nextTick(hangupRequest); // 2
		process.nextTick(hangupRequest); // 3
		process.nextTick(hangupRequest); // 4
		process.nextTick(hangupRequest); // 5

		await defer.promise!;

		assert.equal(onClientDisconnectCallCounter, 5, "Expected 5 disconnects");
	});
});
