import * as zxteam from "@zxteam/contract";
import { logger } from "@zxteam/logger";
import { DUMMY_CANCELLATION_TOKEN } from "@zxteam/cancellation";

import * as http from "http";

import * as THE from "../src/index";
import { Disposable } from "@zxteam/disposable";

const masterKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`;

const serverCertificate = `-----BEGIN CERTIFICATE-----
MIID/zCCAmcCCQCeg6C9anBLzDANBgkqhkiG9w0BAQUFADBXMQswCQYDVQQGEwJV
QTEdMBsGA1UEAwwUb25YZmNjUmVxdWVzdEFwcFRlc3QxKTAnBgkqhkiG9w0BCQEW
GmFkbWluQG9uWGZjY1JlcXVlc3RBcHBUZXN0MB4XDTE5MDcxMDEwMzQxNVoXDTIw
MDcwOTEwMzQxNVowLDELMAkGA1UEBhMCVUExHTAbBgNVBAMMFG9uWGZjY1JlcXVl
c3RBcHBUZXN0MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAo217jokG
ik9mtuXKVRehYN+iVvn5EukUpfislCJZnSAbiqffz1jRAzn882H1kpNtvpSk46jY
PDZAvJn9rJQ4jm4igphNApP0OvMrE21falaFIdwGPTubco4aQsgUSP2bBPQtFBaN
BrG/YpY7XDZzJQgXPIkMMBIAJllTNk4EiNpgdVLGqqXUNWI15FDDZzshhMzvoeep
LWcohVs2Ns5hgLCNn3SCjP4C2NVIOSNlfIXHQfSw8yvAtBmNCCBodFrysnsTXF2q
tg0M/0p+t/aVeRZHVIkEacSLOtLETpEkkwGhW2Q0wvEa8ayjRyk6E3A4KKY85gOu
6Oy71CMwAI0aSGLBs2r+vn8cpxt9yTjNRtu1IUeuWVoun6MN41NeGgEBrG6hi+kD
Q5EaroY4TiLClVJfJClz1IxzOHAqC7461QyNUB7eG6zDY1XESHAkQOIsPbiejoIq
jh0mTAuD7kG7FzN9SzFkdG04YMzvOjUKb71Y0jEaYFwOG72Q/ImnswEVAgMBAAEw
DQYJKoZIhvcNAQEFBQADggGBAAwWZBE70KMWHajvG2iOeB/0jEOapfxv2giBprKQ
ZTFUlG2tywQ2J4NMwJVAe3CAGjAYY2s5CBuRQhtuvSE0OwDwVjn6qpmpOC3DbA9j
pogUbH8M7/1qOFgZ78EpNbUJZVE+HrpwTOTdVxN+seVfObi1P9KpwNVii4AR0La1
Hvqgx3RHnRMqU3vZIR3A1qe8Y6LKqEuq7IP/1Ohutysl+NAiuPLb0vDgTP/ReNEG
a/axuzKiYfRP1lThn/HrXRagEXwQ34MBshGKdiXTXTftBvIDL60Lq4qmdEauGTD7
H9VLbtV1ukvYdlL1c2V/qvZi7cDrYY4YtA8XA0GubBaEUtvegiCSeO32CSm5so8Q
u3jEUX9M7kC4gQZ/JsmhKhytMZzdN+7HJWbA/n9kAh1SHGOuRtcZlh7zV954dc0u
IrkW5obxwoK0Lg7yVXJSZJC818w8+SC0Bt9qoYr3jWx2Yrf0+Wu6cDylPbtGW5nc
JG20M2ioCGh1ivYIRKM7ORnsjA==
-----END CERTIFICATE-----
`;

const caCertificate1 = `-----BEGIN CERTIFICATE-----
MIIEKjCCApICCQCjZvM2xvkIZjANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJV
QTEdMBsGA1UEAwwUb25YZmNjUmVxdWVzdEFwcFRlc3QxKTAnBgkqhkiG9w0BCQEW
GmFkbWluQG9uWGZjY1JlcXVlc3RBcHBUZXN0MB4XDTE5MDcxMDEwMzIwNFoXDTI5
MDcwNzEwMzIwNFowVzELMAkGA1UEBhMCVUExHTAbBgNVBAMMFG9uWGZjY1JlcXVl
c3RBcHBUZXN0MSkwJwYJKoZIhvcNAQkBFhphZG1pbkBvblhmY2NSZXF1ZXN0QXBw
VGVzdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKNte46JBopPZrbl
ylUXoWDfolb5+RLpFKX4rJQiWZ0gG4qn389Y0QM5/PNh9ZKTbb6UpOOo2Dw2QLyZ
/ayUOI5uIoKYTQKT9DrzKxNtX2pWhSHcBj07m3KOGkLIFEj9mwT0LRQWjQaxv2KW
O1w2cyUIFzyJDDASACZZUzZOBIjaYHVSxqql1DViNeRQw2c7IYTM76HnqS1nKIVb
NjbOYYCwjZ90goz+AtjVSDkjZXyFx0H0sPMrwLQZjQggaHRa8rJ7E1xdqrYNDP9K
frf2lXkWR1SJBGnEizrSxE6RJJMBoVtkNMLxGvGso0cpOhNwOCimPOYDrujsu9Qj
MACNGkhiwbNq/r5/HKcbfck4zUbbtSFHrllaLp+jDeNTXhoBAaxuoYvpA0ORGq6G
OE4iwpVSXyQpc9SMczhwKgu+OtUMjVAe3husw2NVxEhwJEDiLD24no6CKo4dJkwL
g+5BuxczfUsxZHRtOGDM7zo1Cm+9WNIxGmBcDhu9kPyJp7MBFQIDAQABMA0GCSqG
SIb3DQEBCwUAA4IBgQBnLgbBvq9sEINoeL21ax57Hip2Y2X5/MBisKtNJrsSImp/
OVMRCnaKSfnJVqiRdReqKhGDrIFgvUF4ytbZ7Vy8MSxX5x9OP76ZmzD25et1xn7P
QSfa0GTEZ8dmI6yNAe4ryDWKgteDYRgd+G0LsS8GpZmUm6SLRZxhWBM57hC0zE1B
xJoPBAiIN6K4fQlzCAF/nPwAjcFsvarL+EMopDES6UMw+l6GqlJHHFGz4cS8ndsR
vY/HjOP4Fif+xhwTPKzrN5/Vgs/xo1Rs/Q1uU9IDp0nciCiTnRUxbsWQ5puOXrxO
DRN2hlyG/6Pd1qGnvRTE9BmRznnXj6CP/DyD3EoB1jp9GI59tzdve3aJN7FKgRDT
zs2Wdn6DXcr6c1J0p3vbKiCaRNF3vfwq2+gRNwragSMi7XJjzaukKraUyXSAJzFY
SAW4WTjMh43gBoOeEF9yyTpkmSWjTjcbH9MtibF9gLH8XNtjwkiYU0hGFfWCN8fu
Gk8emp3WDtMzqwq8v8U=
-----END CERTIFICATE-----
`;

const caCertificate2 = `-----BEGIN CERTIFICATE-----
MIIDDzCCAfcCFDv4TbGUY6/7jRqlDlbZcDkhlCXhMA0GCSqGSIb3DQEBCwUAMEQx
ITAfBgNVBAMMGENvaW5HZXRUZXN0Um9vdEF1dGhvdGl0eTEfMB0GCSqGSIb3DQEJ
ARYQYWRtaW5AY29pbmdldC5pbzAeFw0xOTA1MjYxOTUzMjNaFw0zMDA1MDgxOTUz
MjNaMEQxITAfBgNVBAMMGENvaW5HZXRUZXN0Um9vdEF1dGhvdGl0eTEfMB0GCSqG
SIb3DQEJARYQYWRtaW5AY29pbmdldC5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAKs74kf1qqFFd1487AKJN9V+jreF3ht+/uAyZqlgFx+ESV9NJVLg
T6ETA9pQkv5t2OdWt50JbMM8HiWSXCPSW3Ifik3+gosHAySHW/KsbYmhFIcmaS14
+/l1wpdJJq9LUAx5sLb77mM8fnVCblWeq59skWzERhcEFMJysaaDY07mTo630rT3
S9yCMfZfuMqPpTuOoAVVR4/bZiYwY6IDIKCAmafjDli/CsGMCd4quFahKD8Sbwyh
kuV8LXR8JQCDq8TmItCu/fr1qGjq02jNHbNa7ZneIwHJh/awDZVMsADJW/8PE14r
roFkbkYhF0UAPM2ik4rvvZ02xKGAQZcxa88CAwEAATANBgkqhkiG9w0BAQsFAAOC
AQEAC3oWphsc7aTr7PbFVtA2FqSSe/u0OHNlfBmNdmC4+IRMtZaFntoP7/lIJ+yF
a1sx5JjFxu3wCXK8Xjs2FLjBsEM8V80DcUywciBaVKU3PNNf7YTi7POzkpxGlh+6
5ldzMFswH1/DbBTp/9xdxFGGLwL5BHEYW7EGT0bGlFRug7u5x4GYTifk7Pz5sUeI
/BBpOiDVGVi8wC9RT1Hg9SriRlqREDZxNCGKU3mLsSbpIBQ8IPYjb0Zh2X1e/IHu
eaQL6j8QkpPHC7tuo4Q/qIqlSX3K5bZihSDhwggcY/Lj5wIGxjF+MfkV8R8YzRNE
rOgEbvrU9VHU1UkWSoCXefFQyw==
-----END CERTIFICATE-----
`;

let server1: THE.SecuredWebServer;
let server2: THE.UnsecuredWebServer;

class TimerSubsciberChannel extends Disposable implements zxteam.SubscriberChannel<Date> {
	private readonly _timeout: number;
	private readonly _handlers: Set<zxteam.SubscriberChannel.Callback<Date, zxteam.SubscriberChannel.Event<Date>>>;
	private _timer?: NodeJS.Timeout;

	public constructor(timeout: number) {
		super();
		this._timeout = timeout;
		this._handlers = new Set();
	}

	public addHandler(cb: zxteam.SubscriberChannel.Callback<Date, zxteam.SubscriberChannel.Event<Date>>): void {
		if (this._timer === undefined) {
			this._timer = setInterval(this.onTimer.bind(this), this._timeout);
		}
		this._handlers.add(cb);
	}
	public removeHandler(cb: zxteam.SubscriberChannel.Callback<Date, zxteam.SubscriberChannel.Event<Date>>): void {
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
		this._handlers.forEach(h => h(DUMMY_CANCELLATION_TOKEN, { data: now }));
	}
}

const subscriptionChannel = new TimerSubsciberChannel(250);

class MyRestEndpoint extends THE.RestEndpoint<undefined> {
	protected onInit(): void {
		this._servers.map(server => {
			server.bindRequestHandler("/", this._helloWorldHandler.bind(this));
		});
	}
	protected onDispose(): void {
		//
	}

	private _helloWorldHandler(req: http.IncomingMessage, res: http.ServerResponse) {
		//
		res.end("Hello, World!!!");
	}
}

class SubsciberHandle {
	private readonly _timerSubsciberChannel: TimerSubsciberChannel;
	private readonly _publisherChannel: zxteam.PublisherChannel<string>;
	private readonly _event: zxteam.SubscriberChannel.Callback<Date, zxteam.SubscriberChannel.Event<Date>>;
	private readonly _token: string;

	public constructor(timerSubsciberChannel: TimerSubsciberChannel, publisherChannel: zxteam.PublisherChannel<string>) {
		this._timerSubsciberChannel = timerSubsciberChannel;
		this._publisherChannel = publisherChannel;
		this._event = this.onEvent.bind(this);
		this._token = Date.now().toString();

		this._timerSubsciberChannel.addHandler(this._event);
	}

	public get token(): string { return this._token; }

	public destroy() {
		this._timerSubsciberChannel.removeHandler(this._event);
	}

	private onEvent(cancellationToken: zxteam.CancellationToken, ev: zxteam.SubscriberChannel.Event<Date> | Error): void {
		if (ev instanceof Error) {
			this._publisherChannel.send(cancellationToken, `[${this._token}] Failed: ${ev.message}`);
			return;
		}
		this._publisherChannel.send(cancellationToken, `[${this._token}] Now: ${ev.data}`);
	}
}

class MyTextProtocolAdapter extends THE.AbstractProtocolAdapter<string> {
	private readonly _subscribers: Map<string, SubsciberHandle>;

	public constructor(callbackChannel: THE.ProtocolAdapter.CallbackChannel<string>, log: zxteam.Logger) {
		super(callbackChannel, log);
		this._subscribers = new Map();
	}

	public handleMessage(
		ct: zxteam.CancellationToken, data: string, next?: THE.ProtocolAdapter.Next<string>
	) {
		if (data === "Hello") {
			return Promise.resolve("World!!!");
		} else if (data === "subscribe") {
			const handle = new SubsciberHandle(subscriptionChannel, this._callbackChannel);
			this._subscribers.set(handle.token, handle);
		}

		if (next !== undefined) {
			return next(ct, data);
		}
		return Promise.reject(new Error("Next was not provided"));
	}

	protected onDispose() {
		for (const s of this._subscribers.values()) {
			s.destroy();
		}
		this._subscribers.clear();
	}
}
class MyTextProtocolAdapter2 extends THE.AbstractProtocolAdapter<string> {
	public handleMessage(
		ct: zxteam.CancellationToken, data: string, next?: THE.ProtocolAdapter.Next<string>
	) {
		return Promise.resolve(data);
	}
	protected onDispose() {
		//nop
	}
}

class MyBinaryProtocolAdapter extends THE.AbstractProtocolAdapter<ArrayBuffer> {
	public handleMessage(
		ct: zxteam.CancellationToken, data: ArrayBuffer, next?: THE.ProtocolAdapter.Next<ArrayBuffer>
	) {
		if (next !== undefined) {
			return next(ct, data);
		}
		return Promise.reject(new Error("Next was not provided"));
	}

	protected onDispose() {
		//nop
	}
}
class MyBinaryProtocolAdapter2 extends THE.AbstractProtocolAdapter<ArrayBuffer> {
	public handleMessage(
		ct: zxteam.CancellationToken, data: ArrayBuffer, next?: THE.ProtocolAdapter.Next<ArrayBuffer>
	) {
		return Promise.resolve(data);
	}
	protected onDispose() {
		//nop
	}
}

async function main() {

	server1 = new THE.SecuredWebServer({
		caCertificates: [Buffer.from(caCertificate1), Buffer.from(caCertificate2)],
		clientCertificateMode: THE.Configuration.ClientCertificateMode.XFCC,
		//clientCertificateMode: THE.Configuration.ClientCertificateMode.REQUEST,
		serverCertificate: Buffer.from(serverCertificate),
		serverKey: Buffer.from(masterKey),
		type: "https",
		listenHost: "0.0.0.0",
		listenPort: 8443,
		name: "onXfccRequestAppTest Secured"
	}, logger.getLogger("Secured Server"));

	server2 = new THE.UnsecuredWebServer({
		// caCertificates: [Buffer.from(caCertificate1), Buffer.from(caCertificate2)],
		// clientCertificateMode: THE.Configuration.ClientCertificateMode.XFCC,
		type: "http",
		listenHost: "0.0.0.0",
		listenPort: 8440,
		name: "onXfccRequestAppTest Unsecured"
	}, logger.getLogger("Unsecured Server"));

	const restEndpoint = new MyRestEndpoint(
		[server1, server2],
		undefined,
		{
			bindPath: "/"
		},
		logger.getLogger("restEndpoint")
	);

	const wsEndpoint = new THE.WebSocketAdapterEndpoint(
		[server1, server2],
		{
			bindPath: "/ws",
			defaultProtocol: "text"
		},
		logger.getLogger("wsEndpoint")
	);
	wsEndpoint.useTextAdapter("text", (ch) => new MyTextProtocolAdapter(ch, logger.getLogger("MyTextProtocolAdapter")));
	wsEndpoint.useTextAdapter("text", (ch) => new MyTextProtocolAdapter2(ch, logger.getLogger("MyTextProtocolAdapter2")));

	wsEndpoint.useBinaryAdapter("bin", (ch) => new MyBinaryProtocolAdapter(ch, logger.getLogger("MyBinaryProtocolAdapter")));
	wsEndpoint.useBinaryAdapter("bin", (ch) => new MyBinaryProtocolAdapter2(ch, logger.getLogger("MyBinaryProtocolAdapter2")));

	await restEndpoint.init(DUMMY_CANCELLATION_TOKEN);
	await wsEndpoint.init(DUMMY_CANCELLATION_TOKEN);

	await server1.init(DUMMY_CANCELLATION_TOKEN);
	await server2.init(DUMMY_CANCELLATION_TOKEN);

	let destroyRequestCount = 0;
	async function gracefulShutdown(signal: string) {
		if (destroyRequestCount++ === 0) {
			console.log(`Interrupt signal received: ${signal}`);
			await wsEndpoint.dispose();
			await restEndpoint.dispose();
			await server2.dispose();
			await server1.dispose();
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
