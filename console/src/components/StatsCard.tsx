import React from "react";

const COLOR_MAP = {
  emerald: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
  red: "text-red-400 bg-red-400/10 border-red-400/20",
  orange: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  blue: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  yellow: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  purple: "text-purple-400 bg-purple-400/10 border-purple-400/20",
};

interface StatsCardProps {
  title: string;
  value: number;
  total?: number;
  icon: React.ReactNode;
  color: keyof typeof COLOR_MAP;

  blink?: boolean;
}

export default function StatsCard({ title, value, total, icon, color, blink }: StatsCardProps) {
  const colors = COLOR_MAP[color];
  return (
    <div className={`rounded-xl border p-4 ${colors} ${blink && value > 0 ? "animate-pulse" : ""}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium uppercase tracking-wider opacity-70">{title}</span>
        <span className="opacity-60">{icon}</span>
      </div>
      <div className="text-3xl font-bold">
        {value}
        {total !== undefined && (
          <span className="text-base font-normal opacity-50 ml-1">/ {total}</span>
        )}
      </div>
    </div>
  );
}
