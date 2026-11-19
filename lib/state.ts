import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { errors, type Adapter, type AdapterFactory, type AdapterPayload } from "oidc-provider";

import type { AccessEntry } from "./config.js";
import { openStateStorage, type S3Storage } from "./state-storage.js";

export const oauthClockTolerance = 15;

function generateKeys() {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = randomBytes(12).toString("hex");
  return {
    kid,
    cookieKey: randomBytes(32).toString("base64url"),
    jwks: { keys: [{ ...privateKey.export({ format: "jwk" }), kid, use: "sig", alg: "RS256" }] },
  };
}

export async function openOAuthState(
  issuer: string,
  users: AccessEntry[],
  cwd = process.cwd(),
  s3?: S3Storage,
) {
  const store = await openStateStorage(cwd, s3);
  const identity = createHash("sha256")
    .update(
      JSON.stringify([issuer, [...new Set(users.map((entry) => JSON.stringify(entry)))].sort()]),
    )
    .digest("hex");
  let closed = false;
  let failure: Error | undefined;
  let tail = Promise.resolve();
  function run<T>(operation: () => T | Promise<T>): Promise<T> {
    if (closed) return Promise.reject(new Error("OAuth state is closed."));
    const next = tail.then(() => {
      if (failure) throw failure;
      return operation();
    });
    tail = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }
  async function close() {
    if (closed) return;
    closed = true;
    await tail;
    store.close();
  }

  try {
    const text = await store.read();
    const snapshot = text === undefined ? undefined : readSnapshot(text);
    const reuse = snapshot?.identity === identity;
    const keys = reuse ? snapshot.keys : generateKeys();
    let records = reuse ? snapshot.records : [];
    async function save(next: Row[]) {
      try {
        // A fresh revision changes the S3 ETag even if all OAuth records stayed the same.
        const snapshot: Snapshot = {
          version: 1,
          identity,
          keys,
          records: next,
          revision: randomBytes(16).toString("hex"),
        };
        await store.write(JSON.stringify(snapshot));
        records = next;
      } catch (cause) {
        failure = new Error(
          `Could not save OAuth state. ${cause instanceof Error ? cause.message : "Restart the provider."}`,
          { cause },
        );
        throw failure;
      }
    }
    if (!reuse || store.remote) await save(records);
    return { ...keys, adapter: jsonAdapter(() => records, save, run), close };
  } catch (error) {
    await close();
    throw error;
  }
}

interface Row {
  model: string;
  id: string;
  payload: AdapterPayload;
  expires?: number;
}

interface Snapshot {
  version: 1;
  identity: string;
  keys: ReturnType<typeof generateKeys>;
  records: Row[];
  revision?: string;
}

function readSnapshot(text: string): Snapshot {
  try {
    const snapshot: Snapshot = JSON.parse(text);
    if (
      snapshot.version !== 1 ||
      typeof snapshot.identity !== "string" ||
      typeof snapshot.keys?.kid !== "string" ||
      typeof snapshot.keys.cookieKey !== "string" ||
      snapshot.keys.jwks?.keys?.[0]?.kid !== snapshot.keys.kid ||
      !Array.isArray(snapshot.records) ||
      snapshot.records.some(
        (row) =>
          !row ||
          typeof row.model !== "string" ||
          typeof row.id !== "string" ||
          !row.payload ||
          typeof row.payload !== "object" ||
          Array.isArray(row.payload) ||
          (row.expires !== undefined && !Number.isSafeInteger(row.expires)),
      )
    )
      throw new Error("Invalid snapshot.");
    return snapshot;
  } catch (cause) {
    throw new Error("Cannot read OAuth state. Restore a valid snapshot before restarting.", {
      cause,
    });
  }
}

function jsonAdapter(
  read: () => Row[],
  save: (rows: Row[]) => Promise<void>,
  run: <T>(operation: () => T | Promise<T>) => Promise<T>,
): AdapterFactory {
  const now = () => Math.floor(Date.now() / 1000);
  const live = (row: Row, time: number) => row.expires === undefined || row.expires > time;
  return (model): Adapter => {
    function find(match: (row: Row) => boolean) {
      const time = now();
      return read().findLast((row) => row.model === model && live(row, time) && match(row));
    }
    function remove(match: (row: Row) => boolean) {
      const rows = read();
      const remaining = rows.filter((row) => row.model !== model || !match(row));
      if (remaining.length !== rows.length) return save(remaining);
    }
    const payload = (row?: Row) => row && structuredClone(row.payload);
    return {
      upsert: (id, data, expiresIn) =>
        run(() => {
          const time = now();
          if (model === "ReplayDetection" && find((row) => row.id === id))
            throw new errors.InvalidGrant("Replay detected.");
          let rows = read().filter(
            (row) => live(row, time) && (row.model !== model || row.id !== id),
          );
          // Clients and interactions can be created before Google sign-in.
          if (model === "Client" || model === "Interaction") {
            const oldest = rows.filter((row) => row.model === model).at(-1000);
            if (oldest) rows = rows.filter((row) => row !== oldest);
          }
          rows.push({
            model,
            id,
            payload: structuredClone(data),
            ...(expiresIn === undefined ? {} : { expires: time + expiresIn + oauthClockTolerance }),
          });
          return save(rows);
        }),
      find: (id) => run(() => payload(find((row) => row.id === id))),
      findByUid: (uid) => run(() => payload(find((row) => row.payload.uid === uid))),
      findByUserCode: (code) => run(() => payload(find((row) => row.payload.userCode === code))),
      consume: (id) =>
        run(() => {
          const row = find((record) => record.id === id);
          if (!row || row.payload.consumed !== undefined)
            throw new errors.InvalidGrant("Credential has expired or already been used.");
          return save(
            read().map((record) =>
              record === row
                ? { ...record, payload: { ...record.payload, consumed: now() } }
                : record,
            ),
          );
        }),
      destroy: (id) => run(() => remove((row) => row.id === id)),
      revokeByGrantId: (id) => run(() => remove((row) => row.payload.grantId === id)),
    };
  };
}
