const dateFmt = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", year: "numeric" });
const dateTimeFmt = new Intl.DateTimeFormat(undefined, {
  day: "numeric",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
});
const money = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" });

export const fmtDate = (ts: number | null | undefined) => (ts ? dateFmt.format(new Date(ts * 1000)) : "—");
export const fmtDateTime = (ts: number | null | undefined) => (ts ? dateTimeFmt.format(new Date(ts * 1000)) : "—");
export const fmtMoney = (n: number) => money.format(n);

export function relative(ts: number): string {
  const diff = ts * 1000 - Date.now();
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (abs < 60_000) return "just now";
  if (abs < 3_600_000) return rtf.format(Math.round(diff / 60_000), "minute");
  if (abs < 86_400_000) return rtf.format(Math.round(diff / 3_600_000), "hour");
  if (abs < 30 * 86_400_000) return rtf.format(Math.round(diff / 86_400_000), "day");
  return fmtDate(ts);
}

export function daysLeftLabel(days: number | null): string {
  if (days === null) return "";
  if (days < 0) return `${Math.abs(days)} day${days === -1 ? "" : "s"} overdue`;
  if (days === 0) return "Due today";
  if (days === 1) return "Due tomorrow";
  return `${days} days left`;
}

export function monthLabel(key: string): string {
  const [y, m] = key.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, 1)).toLocaleString(undefined, { month: "short", timeZone: "UTC" });
}

export const humanize = (s: string) => s.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
