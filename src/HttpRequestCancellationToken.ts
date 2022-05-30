import { CancellationToken } from "@zxteam/contract";
import { CancelledError, wrapErrorIfNeeded, AggregateError } from "@zxteam/errors";

import * as http from "http";

export class HttpRequestCancellationToken implements CancellationToken {
	private readonly _onClientDisconnectBound: () => void;
	private readonly _cancelListeners: Array<Function> = [];
	private readonly _request: http.IncomingMessage;
	private _isCancellationRequested: boolean;

	public constructor(request: http.IncomingMessage) {
		this._isCancellationRequested = false;
		this._onClientDisconnectBound = this._onClientDisconnect.bind(this);
		this._request = request;
		// According to https://nodejs.org/api/http.html
		// v16.0.0	The close event is now emitted when the request has been completed and not when the underlying socket is closed.
		//
		// So We switch to listen "close" event on underlaying socket
		this._request.socket.on("close", this._onClientDisconnectBound);
		// this._request.on("end", this._onClientDisconnectBound);
	}

	public get isCancellationRequested(): boolean { return this._isCancellationRequested; }

	public addCancelListener(cb: Function): void {
		this._cancelListeners.push(cb);
	}

	public removeCancelListener(cb: Function): void {
		const cbIndex = this._cancelListeners.indexOf(cb);
		if (cbIndex !== -1) {
			this._cancelListeners.splice(cbIndex, 1);
		}
	}

	public throwIfCancellationRequested(): void {
		if (this.isCancellationRequested) {
			throw new CancelledError();
		}
	}

	private _onClientDisconnect() {
		this._request.socket.removeListener("close", this._onClientDisconnectBound);
		// this._request.removeListener("end", this._onClientDisconnectBound);

		this._isCancellationRequested = true;

		let errors: Array<Error> | null = null;
		if (this._cancelListeners.length > 0) {
			// Release callback. We do not need its anymore
			const cancelListeners = this._cancelListeners.splice(0);
			for (const cancelListener of cancelListeners) {
				try {
					cancelListener();
				} catch (e) {
					if (errors === null) { errors = []; }
					errors.push(wrapErrorIfNeeded(e));
				}
			}
		}
		if (errors !== null && errors.length > 0) {
			throw new AggregateError(errors);
		}
	}
}


