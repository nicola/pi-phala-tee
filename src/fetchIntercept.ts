/**
 * Scoped global-fetch interceptor for api.redpill.ai.
 *
 * We patch `globalThis.fetch` narrowly:
 *   - requests whose URL does NOT start with `https://api.redpill.ai/` pass
 *     through unchanged to whatever `fetch` was present before us
 *     (i.e. we chain under any other extension's wrappers).
 *   - requests whose URL DOES match are tee'd: we capture the exact outgoing
 *     request body bytes and the exact response body bytes, parse `chat_id`
 *     from the response, and stash a TurnRecord in an in-memory ring.
 *
 * Why not `streamSimple`?  Because registering as `openai-completions`
 * preserves full pi-ai feature parity (tool calling, image inputs,
 * cross-provider handoff, abort, compat flags) for free.  The interceptor
 * is the smallest amount of code that adds observability without
 * reimplementing the streaming protocol.
 *
 * Security notes:
 *   - API key is never read from `init.headers` into the record.
 *   - Records are held in-memory only. If the process dies, they're lost.
 *   - Max 32 records kept; oldest is evicted. This prevents unbounded growth
 *     if the user has a runaway agent loop.
 *   - Only `chat/completions` bodies are retained in the record; signature
 *     and attestation fetches we make ourselves do not pollute the ring.
 */

const HOST_PREFIX = "https://api.redpill.ai/";
const COMPLETIONS_PATH = "/v1/chat/completions";
const MAX_RECORDS = 32;

export interface TurnRecord {
	startedAt: number;
	endedAt: number;
	chatId?: string;
	model?: string;
	streamed: boolean;
	requestBytes: Uint8Array;
	responseBytes?: Uint8Array;
	/** For streamed responses: parsed chunks, preserved in order. */
	streamedChunks?: unknown[];
	/** Assembled content as text (convenience, not trust-critical). */
	assembledContent?: string;
	httpStatus: number;
}

type Fetch = typeof globalThis.fetch;

let installed = false;
const records: TurnRecord[] = [];

export function installInterceptor(): void {
	if (installed) return;
	installed = true;

	const prior: Fetch = globalThis.fetch.bind(globalThis);

	const wrapped: Fetch = async (input, init) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
		if (!url.startsWith(HOST_PREFIX)) return prior(input, init);

		// We only snapshot the completions endpoint for later verification.
		// Attestation/signature fetches we issue ourselves use a fresh fetch
		// reference captured below, so they don't recurse into us.
		const isCompletions = url.includes(COMPLETIONS_PATH);
		if (!isCompletions) return prior(input, init);

		const startedAt = Date.now();
		const reqBytes = bodyToBytes(init?.body);

		const resp = await prior(input, init);
		const contentType = resp.headers.get("content-type") || "";
		const streamed = contentType.includes("text/event-stream");

		if (!resp.body) {
			// No body to tee — record what we have and return the response as-is.
			record({
				startedAt,
				endedAt: Date.now(),
				streamed,
				requestBytes: reqBytes ?? new Uint8Array(0),
				httpStatus: resp.status,
			});
			return resp;
		}

		// Tee the body stream: one side flows to the caller, the other to us.
		const [callerStream, ourStream] = resp.body.tee();

		// Consume our side in the background.
		void consumeForRecord(ourStream, streamed, startedAt, reqBytes ?? new Uint8Array(0), resp.status);

		return new Response(callerStream, {
			status: resp.status,
			statusText: resp.statusText,
			headers: resp.headers,
		});
	};

	// Expose an unwrapped fetch for our own verification calls (so they don't
	// recurse through the interceptor and pollute the ring).
	(globalThis as { __phalaTeeRawFetch?: Fetch }).__phalaTeeRawFetch = prior;
	globalThis.fetch = wrapped;
}

export function rawFetch(): Fetch {
	const f = (globalThis as { __phalaTeeRawFetch?: Fetch }).__phalaTeeRawFetch;
	if (!f) throw new Error("phala-tee: raw fetch not available (interceptor not installed)");
	return f;
}

async function consumeForRecord(
	stream: ReadableStream<Uint8Array>,
	streamed: boolean,
	startedAt: number,
	requestBytes: Uint8Array,
	httpStatus: number,
): Promise<void> {
	try {
		const reader = stream.getReader();
		const chunks: Uint8Array[] = [];
		let total = 0;
		const HARD_LIMIT = 8 * 1024 * 1024; // 8 MiB safety cap
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			if (value) {
				total += value.length;
				if (total > HARD_LIMIT) break;
				chunks.push(value);
			}
		}
		const responseBytes = concat(chunks);

		let chatId: string | undefined;
		let model: string | undefined;
		let streamedChunks: unknown[] | undefined;
		let assembledContent: string | undefined;

		if (streamed) {
			const parsed = parseSse(responseBytes);
			streamedChunks = parsed.chunks;
			const first = parsed.chunks[0] as Record<string, unknown> | undefined;
			chatId = typeof first?.id === "string" ? first.id : undefined;
			model = typeof first?.model === "string" ? first.model : undefined;
			assembledContent = parsed.assembledContent;
		} else {
			try {
				const obj = JSON.parse(new TextDecoder().decode(responseBytes)) as Record<string, unknown>;
				if (typeof obj.id === "string") chatId = obj.id;
				if (typeof obj.model === "string") model = obj.model;
			} catch {
				/* ignore parse error */
			}
		}

		record({
			startedAt,
			endedAt: Date.now(),
			chatId,
			model,
			streamed,
			requestBytes,
			responseBytes,
			streamedChunks,
			assembledContent,
			httpStatus,
		});
	} catch {
		// If teeing fails, we just won't have a record for this turn; fine.
	}
}

function bodyToBytes(body: BodyInit | null | undefined): Uint8Array | undefined {
	if (body == null) return undefined;
	if (body instanceof Uint8Array) return body;
	if (typeof body === "string") return new TextEncoder().encode(body);
	if (body instanceof ArrayBuffer) return new Uint8Array(body);
	if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
	// Blob / FormData / stream / etc. are not used by pi-ai's openai-completions path.
	// If we ever see one, we skip content-hash binding rather than guess.
	return undefined;
}

function concat(chunks: Uint8Array[]): Uint8Array {
	let n = 0;
	for (const c of chunks) n += c.length;
	const out = new Uint8Array(n);
	let o = 0;
	for (const c of chunks) {
		out.set(c, o);
		o += c.length;
	}
	return out;
}

function parseSse(bytes: Uint8Array): { chunks: unknown[]; assembledContent: string } {
	const text = new TextDecoder().decode(bytes);
	const chunks: unknown[] = [];
	let assembledContent = "";
	for (const line of text.split("\n")) {
		const t = line.trim();
		if (!t.startsWith("data: ")) continue;
		const payload = t.slice(6);
		if (payload === "[DONE]") break;
		try {
			const obj = JSON.parse(payload) as {
				choices?: Array<{ delta?: { content?: string } }>;
			};
			chunks.push(obj);
			const delta = obj?.choices?.[0]?.delta?.content;
			if (typeof delta === "string") assembledContent += delta;
		} catch {
			/* malformed chunk, skip */
		}
	}
	return { chunks, assembledContent };
}

function record(r: TurnRecord): void {
	records.push(r);
	while (records.length > MAX_RECORDS) records.shift();
}

/**
 * Find the turn record matching a given chat_id, or the most recent
 * completions record if chat_id is not known yet.
 */
export function findRecord(chatId?: string): TurnRecord | undefined {
	if (chatId) {
		for (let i = records.length - 1; i >= 0; i--) {
			if (records[i].chatId === chatId) return records[i];
		}
	}
	return records[records.length - 1];
}

/** Return the most recent record (for /tee on the last turn). */
export function lastRecord(): TurnRecord | undefined {
	return records[records.length - 1];
}
