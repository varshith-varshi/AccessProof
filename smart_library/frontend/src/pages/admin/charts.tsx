import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { BarChart3 } from "lucide-react";
import type { ReactNode } from "react";
import { Card, EmptyState, Skeleton } from "../../components/ui";
import { monthLabel } from "../../lib/format";

export interface Reports {
  monthly: { month: string; borrowed: number; returned: number }[];
  reservations: { month: string; placed: number; fulfilled: number; cancelled: number }[];
  loan_status: { status: string; count: number }[];
  categories: { category: string; loans: number }[];
  top_books: { book_id: string; title: string; author: string; loans: number }[];
  decisions: { allow: number; deny: number; info: number };
}

const AXIS = { fontSize: 12, fill: "#5b6896" };
const tooltipStyle = { borderRadius: 12, border: "1px solid #d9deec", boxShadow: "0 8px 24px -8px rgb(12 22 54 / .2)", fontSize: 13 };

export function ChartCard({ title, subtitle, children, loading, empty }: { title: string; subtitle?: string; children: ReactNode; loading?: boolean; empty?: boolean }) {
  return (
    <Card className="p-5">
      <h3 className="font-semibold text-ink-950">{title}</h3>
      {subtitle && <p className="mt-0.5 text-xs text-ink-500">{subtitle}</p>}
      <div className="mt-4 h-64">
        {loading ? (
          <Skeleton className="h-full" />
        ) : empty ? (
          <EmptyState icon={BarChart3} title="No data yet">Charts appear once there is circulation in the database.</EmptyState>
        ) : (
          children
        )}
      </div>
    </Card>
  );
}

export function BorrowingChart({ data }: { data: Reports["monthly"] }) {
  return (
    <ResponsiveContainer>
      <AreaChart data={data.map((d) => ({ ...d, label: monthLabel(d.month) }))} margin={{ left: -20, right: 8, top: 8 }}>
        <defs>
          <linearGradient id="gBorrow" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#3b5cf5" stopOpacity={0.35} />
            <stop offset="1" stopColor="#3b5cf5" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gReturn" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#8b5cf6" stopOpacity={0.25} />
            <stop offset="1" stopColor="#8b5cf6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#eceff7" vertical={false} />
        <XAxis dataKey="label" tick={AXIS} axisLine={false} tickLine={false} />
        <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
        <Area type="monotone" dataKey="borrowed" name="Borrowed" stroke="#2346e0" strokeWidth={2.5} fill="url(#gBorrow)" />
        <Area type="monotone" dataKey="returned" name="Returned" stroke="#7c3aed" strokeWidth={2} fill="url(#gReturn)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function CategoryChart({ data }: { data: Reports["categories"] }) {
  return (
    <ResponsiveContainer>
      <BarChart data={data.slice(0, 8)} layout="vertical" margin={{ left: 10, right: 16 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#eceff7" horizontal={false} />
        <XAxis type="number" tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="category" tick={AXIS} axisLine={false} tickLine={false} width={120} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#f1f4ff" }} />
        <Bar dataKey="loans" name="Loans" radius={[0, 6, 6, 0]} fill="#3b5cf5" barSize={16} />
      </BarChart>
    </ResponsiveContainer>
  );
}

const STATUS_COLORS: Record<string, string> = { active: "#3b5cf5", due_soon: "#f59e0b", overdue: "#e11d48", returned: "#b4bcd6" };
const STATUS_LABEL: Record<string, string> = { active: "Active", due_soon: "Due soon", overdue: "Overdue", returned: "Returned" };

export function StatusChart({ data }: { data: Reports["loan_status"] }) {
  const rows = data.filter((d) => d.count > 0).map((d) => ({ ...d, name: STATUS_LABEL[d.status] ?? d.status }));
  return (
    <ResponsiveContainer>
      <PieChart>
        <Pie data={rows} dataKey="count" nameKey="name" innerRadius="55%" outerRadius="85%" paddingAngle={3} stroke="none">
          {rows.map((r) => (
            <Cell key={r.status} fill={STATUS_COLORS[r.status]} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
        <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function ReservationChart({ data }: { data: Reports["reservations"] }) {
  return (
    <ResponsiveContainer>
      <BarChart data={data.map((d) => ({ ...d, label: monthLabel(d.month) }))} margin={{ left: -20, right: 8, top: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#eceff7" vertical={false} />
        <XAxis dataKey="label" tick={AXIS} axisLine={false} tickLine={false} />
        <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#f6f7fb" }} />
        <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
        <Bar dataKey="placed" name="Placed" fill="#8b5cf6" radius={[6, 6, 0, 0]} barSize={14} />
        <Bar dataKey="fulfilled" name="Fulfilled" fill="#10b981" radius={[6, 6, 0, 0]} barSize={14} />
        <Bar dataKey="cancelled" name="Cancelled" fill="#b4bcd6" radius={[6, 6, 0, 0]} barSize={14} />
      </BarChart>
    </ResponsiveContainer>
  );
}
