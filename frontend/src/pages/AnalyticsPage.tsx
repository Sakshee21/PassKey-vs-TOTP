import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { getAnalyticsSummary } from "../lib/analytics";
import { ApiError } from "../lib/api";
import type { AnalyticsSummary, User } from "../lib/types";

// Validated categorical palette (see dataviz skill), light/dark pairs, fixed
// order — slot 0 is always "passkey", slot 1 always "totp_password".
const PALETTE_LIGHT = ["#2a78d6", "#eb6834", "#1baf7a"];
const PALETTE_DARK = ["#3987e5", "#d95926", "#199e70"];
const OTHER_COLOR = "#898781"; // mode-invariant muted/neutral, for the pie's "Other" fold
// Reserved status color (dataviz skill), never reused as a categorical hue -
// flags simulated-attack traffic as a state, not a series identity.
const CRITICAL_COLOR = "#d03b3b";

const METHOD_LABEL: Record<string, string> = {
  passkey: "Passkey",
  totp_password: "Password + TOTP",
};

const FAILURE_LABEL: Record<string, string> = {
  invalid_totp_code: "Invalid TOTP code",
  invalid_backup_code: "Invalid backup code",
  invalid_password: "Invalid password",
  unknown_account: "Unknown account",
  unknown_passkey: "Unknown passkey",
  no_passkeys_registered: "No passkey set up",
  ceremony_failed: "Passkey ceremony failed",
  unknown: "Unknown",
};

function useIsDarkMode(): boolean {
  const [isDark, setIsDark] = useState(
    () => window.matchMedia("(prefers-color-scheme: dark)").matches,
  );
  useEffect(() => {
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (e: MediaQueryListEvent) => setIsDark(e.matches);
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }, []);
  return isDark;
}

const tooltipStyle = {
  background: "canvas",
  border: "1px solid rgba(127,127,127,0.25)",
  borderRadius: 8,
  fontSize: 13,
};

interface Props {
  user: User;
}

export function AnalyticsPage({ user }: Props) {
  const [data, setData] = useState<AnalyticsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const isDark = useIsDarkMode();
  const palette = isDark ? PALETTE_DARK : PALETTE_LIGHT;
  const muted = "#898781";
  const grid = isDark ? "#2c2c2a" : "#e1e0d9";

  useEffect(() => {
    getAnalyticsSummary()
      .then(setData)
      .catch((err) =>
        setError(err instanceof ApiError ? err.message : "Failed to load analytics"),
      );
  }, []);

  if (error) {
    return (
      <div className="card">
        <h2>Analytics</h2>
        <p className="hint">
          Viewing as {user.email} — <strong>admin</strong>
        </p>
        <p className="error">{error}</p>
        <Link to="/dashboard">Back to dashboard</Link>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="card">
        <p className="hint">Loading analytics…</p>
      </div>
    );
  }

  if (data.total_events === 0) {
    return (
      <div className="card">
        <h2>Analytics</h2>
        <p className="hint">
          Viewing as {user.email} — <strong>admin</strong>
        </p>
        <p className="hint">
          No login attempts recorded yet. Sign in a few times — with a passkey and with
          password+TOTP — to see charts here.
        </p>
        <Link to="/dashboard">Back to dashboard</Link>
      </div>
    );
  }

  const byMethod = data.by_method.map((m) => ({
    method: METHOD_LABEL[m.method] ?? m.method,
    successRate: m.success_rate,
    avgLatency: m.avg_latency_ms ?? 0,
    totalAttempts: m.total_attempts,
    hasLatency: m.avg_latency_ms !== null,
  }));

  const timeSeries = data.attempts_over_time.map((t) => ({
    time: new Date(t.bucket).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "numeric",
    }),
    attempts: t.attempts,
    simulated: t.simulated_attempts,
  }));
  const hasSimulatedData = timeSeries.some((t) => t.simulated > 0);

  // Pie is an all-pairs-adjacent context (every slice sits beside every other),
  // so cap at 3 explicit categorical colors and fold the rest into "Other".
  const topReasons = data.failure_reasons.slice(0, 3);
  const otherCount = data.failure_reasons.slice(3).reduce((sum, f) => sum + f.count, 0);
  const failureSlices = [
    ...topReasons.map((f, i) => ({
      name: FAILURE_LABEL[f.reason] ?? f.reason,
      value: f.count,
      color: palette[i],
    })),
    ...(otherCount > 0 ? [{ name: "Other", value: otherCount, color: OTHER_COLOR }] : []),
  ];

  return (
    <div>
      <div className="card">
        <h2>Analytics</h2>
        <p className="hint">
          Viewing as {user.email} — <strong>admin</strong>
        </p>
        <p className="hint">
          {data.total_events} logged login attempts
          {data.simulated_events > 0 && (
            <>
              {" "}
              (<strong style={{ color: CRITICAL_COLOR }}>{data.simulated_events} simulated</strong>
              , from security-demos/attack_sim.py)
            </>
          )}
          .
        </p>
        <Link to="/dashboard">Back to dashboard</Link>
      </div>

      <div className="card">
        <h2>Success rate by method</h2>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={byMethod} margin={{ left: -10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={grid} vertical={false} />
            <XAxis
              dataKey="method"
              tick={{ fill: muted, fontSize: 12 }}
              axisLine={{ stroke: grid }}
              tickLine={false}
            />
            <YAxis
              unit="%"
              domain={[0, 100]}
              tick={{ fill: muted, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: grid }}
              contentStyle={tooltipStyle}
              formatter={(value, _name, props) =>
                props.payload.totalAttempts === 0
                  ? ["No attempts yet", "Success rate"]
                  : [`${value}%`, "Success rate"]
              }
            />
            <Bar dataKey="successRate" radius={[4, 4, 0, 0]} isAnimationActive={false}>
              {byMethod.map((_, i) => (
                <Cell key={i} fill={palette[i % palette.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h2>Average latency by method</h2>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={byMethod} margin={{ left: -10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={grid} vertical={false} />
            <XAxis
              dataKey="method"
              tick={{ fill: muted, fontSize: 12 }}
              axisLine={{ stroke: grid }}
              tickLine={false}
            />
            <YAxis
              unit="ms"
              tick={{ fill: muted, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: grid }}
              contentStyle={tooltipStyle}
              formatter={(value, _name, props) =>
                props.payload.hasLatency
                  ? [`${Math.round(Number(value))} ms`, "Avg latency"]
                  : ["No data", "Avg latency"]
              }
            />
            <Bar dataKey="avgLatency" radius={[4, 4, 0, 0]} isAnimationActive={false}>
              {byMethod.map((_, i) => (
                <Cell key={i} fill={palette[i % palette.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h2>Login attempts over time</h2>
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={timeSeries} margin={{ left: -10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={grid} vertical={false} />
            <XAxis
              dataKey="time"
              tick={{ fill: muted, fontSize: 11 }}
              axisLine={{ stroke: grid }}
              tickLine={false}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: muted, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip contentStyle={tooltipStyle} />
            {hasSimulatedData && <Legend wrapperStyle={{ fontSize: 13 }} />}
            <Line
              type="monotone"
              dataKey="attempts"
              name="All attempts"
              stroke={palette[0]}
              strokeWidth={2}
              dot={{ r: 4, fill: palette[0] }}
              activeDot={{ r: 5 }}
              isAnimationActive={false}
            />
            {hasSimulatedData && (
              <Line
                type="monotone"
                dataKey="simulated"
                name="Simulated (attack_sim.py)"
                stroke={CRITICAL_COLOR}
                strokeWidth={2}
                dot={{ r: 4, fill: CRITICAL_COLOR }}
                activeDot={{ r: 5 }}
                isAnimationActive={false}
              />
            )}
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h2>Failure reason breakdown</h2>
        {failureSlices.length === 0 ? (
          <p className="hint">No failed attempts recorded.</p>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={failureSlices}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={90}
                label={({ percent }) => `${Math.round((percent ?? 0) * 100)}%`}
                labelLine={false}
                isAnimationActive={false}
              >
                {failureSlices.map((slice, i) => (
                  <Cell key={i} fill={slice.color} />
                ))}
              </Pie>
              <Legend wrapperStyle={{ fontSize: 13 }} />
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
