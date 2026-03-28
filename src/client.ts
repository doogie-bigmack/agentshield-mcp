/**
 * AgentShield API Client
 * Handles authentication and HTTP calls to AgentShield API.
 */

export interface AgentShieldConfig {
  baseUrl: string;
  apiKey?: string;
  email?: string;
  password?: string;
}

export class AgentShieldClient {
  private baseUrl: string;
  private apiKey?: string;
  private email?: string;
  private password?: string;
  private accessToken?: string;

  constructor(config: AgentShieldConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.email = config.email;
    this.password = config.password;
  }

  private async getAuthHeaders(): Promise<Record<string, string>> {
    if (this.apiKey) {
      return { "X-API-Key": this.apiKey };
    }

    if (!this.accessToken && this.email && this.password) {
      await this.login();
    }

    if (this.accessToken) {
      return { Authorization: `Bearer ${this.accessToken}` };
    }

    return {};
  }

  private async login(): Promise<void> {
    const res = await fetch(`${this.baseUrl}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: this.email, password: this.password }),
    });

    if (!res.ok) {
      throw new Error(`Login failed: ${res.status} ${await res.text()}`);
    }

    const data = (await res.json()) as { access_token?: string };
    this.accessToken = data.access_token;
  }

  async request(
    method: string,
    path: string,
    body?: unknown,
    query?: Record<string, string>
  ): Promise<unknown> {
    const url = new URL(`${this.baseUrl}${path}`);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== "") url.searchParams.set(k, v);
      }
    }

    const headers: Record<string, string> = {
      ...(await this.getAuthHeaders()),
    };

    if (body) {
      headers["Content-Type"] = "application/json";
    }

    const res = await fetch(url.toString(), {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`AgentShield API error ${res.status}: ${text}`);
    }

    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return res.json();
    }
    return res.text();
  }
}
