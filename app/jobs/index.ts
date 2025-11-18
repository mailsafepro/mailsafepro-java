// sdk/node/index.ts
import crypto from "crypto";

export type JobCreate = {
  source: "list" | "upload";
  emails?: string[];
  file_token?: string;
  checksmtp?: boolean;
  includerawdns?: boolean;
  callback_url?: string;
  sandbox?: boolean;
  metadata?: Record<string, any>;
};

export class EmailValidationAPI {
  constructor(private baseUrl: string, private apiKey: string) {}

  private headers(extra: Record<string, string> = {}) {
    return {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${this.apiKey}`,
      ...extra,
    };
  }

  async createJob(body: JobCreate, idemKey?: string) {
    const res = await fetch(`${this.baseUrl}/v1/jobs`, {
      method: "POST",
      headers: this.headers(idemKey ? { "X-Idempotency-Key": idemKey } : {}),
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`Create job failed: ${res.status}`);
    return res.json();
  }

  async getJob(jobId: string) {
    const res = await fetch(`${this.baseUrl}/v1/jobs/${jobId}`, {
      headers: this.headers(),
    });
    if (!res.ok) throw new Error(`Get job failed: ${res.status}`);
    return res.json();
  }

  async getResults(jobId: string, page = 1, size = 500) {
    const res = await fetch(`${this.baseUrl}/v1/jobs/${jobId}/results?page=${page}&size=${size}`, {
      headers: this.headers(),
    });
    if (!res.ok) throw new Error(`Get results failed: ${res.status}`);
    return res.json();
  }

  static verifyWebhook(opts: {
    secret: string;
    signatureHeader: string; // e.g., "sha256=BASE64..."
    timestampHeader: string; // unix seconds string
    rawBody: Buffer | string;
    toleranceSec?: number;   // default 300
  }): boolean {
    const { secret, signatureHeader, timestampHeader, rawBody } = opts;
    const tolerance = opts.toleranceSec ?? 300;
    const now = Math.floor(Date.now() / 1000);
    const ts = parseInt(timestampHeader, 10);
    if (!Number.isFinite(ts) || Math.abs(now - ts) > tolerance) return false;

    const expected = crypto
      .createHmac("sha256", Buffer.from(secret, "utf-8"))
      .update(`${timestampHeader}.`)
      .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf-8"))
      .digest("base64");

    const parts = signatureHeader.split("=");
    if (parts.length !== 2 || parts[0] !== "sha256") return false;

    const received = parts[1];
    const a = Buffer.from(expected, "utf-8");
    const b = Buffer.from(received, "utf-8");
    return crypto.timingSafeEqual(a, b);
  }
}
