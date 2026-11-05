const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
export const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  role: string = "SUPER_ADMIN",
  user: string = "sinan.mohammed"
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-NetSentinel-Role": role,
    "X-NetSentinel-User": user,
    ...((options.headers as Record<string, string>) || {}),
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    cache: "no-store",
  });

  if (!res.ok) {
    let errText = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      errText = data.detail || JSON.stringify(data);
    } catch {
      errText = await res.text();
    }
    throw new Error(errText);
  }

  return res.json() as Promise<T>;
}

export function getReportUrl(format: "csv" | "json" | "html"): string {
  return `${API_BASE}/reports/${format}`;
}

