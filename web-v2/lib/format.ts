export function formatTimestamp(value?: string | null) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not available" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function shortId(value: string) { return value.length > 12 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value; }
export function titleCase(value: string) { return value.replaceAll("_", " ").toLowerCase().replace(/\b\w/g, letter => letter.toUpperCase()); }
