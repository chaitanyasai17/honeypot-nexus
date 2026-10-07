// Honeypot Nexus - Data Formatting Utilities
// Source of Truth for frontend timezone conversion to Asia/Kolkata (IST)

export const DISPLAY_TIMEZONE = "Asia/Kolkata";

/**
 * Safely parses any timestamp or ISO string into a JavaScript Date object.
 * If the string does not have a timezone offset (e.g., SQLite naive UTC output),
 * it is explicitly treated as UTC per Honeypot Nexus architecture rules.
 */
export function parseUtcDate(input) {
  if (!input) return null;
  if (input instanceof Date) return isNaN(input.getTime()) ? null : input;

  if (typeof input === 'number') {
    return new Date(input);
  }

  let str = String(input).trim();
  if (!str) return null;

  // Standardize SQL format "YYYY-MM-DD HH:MM:SS" -> "YYYY-MM-DDTHH:MM:SS"
  if (str.includes(' ') && !str.includes('T')) {
    str = str.replace(' ', 'T');
  }

  // If no timezone suffix (Z or +/-offset), treat as UTC
  if (!str.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(str)) {
    str += 'Z';
  }

  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d;
}

// Pre-compiled Intl.DateTimeFormat instances for performance
const timeOnlyFormatter = new Intl.DateTimeFormat('en-IN', {
  timeZone: DISPLAY_TIMEZONE,
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: true
});

const dateTimeFormatter = new Intl.DateTimeFormat('en-IN', {
  timeZone: DISPLAY_TIMEZONE,
  day: '2-digit',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: true
});

/**
 * Formats timestamp to HH:MM:SS AM/PM in Asia/Kolkata (IST).
 * Example: "09:49:18 PM"
 */
export function formatTime(isoStr, includeTz = false) {
  const d = parseUtcDate(isoStr);
  if (!d) return '--:--:--';
  const timeStr = timeOnlyFormatter.format(d);
  return includeTz ? `${timeStr} IST` : timeStr;
}

/**
 * Legacy alias for formatTime returning "HH:MM:SS AM/PM" in IST.
 */
export function formatDate(isoStr) {
  return formatTime(isoStr, false);
}

/**
 * Formats timestamp to "06 Oct 2026, 09:49:18 PM" or "06 Oct 2026, 09:49:18 PM IST".
 */
export function formatDateTime(isoStr, includeTz = false) {
  const d = parseUtcDate(isoStr);
  if (!d) return '---';
  const formatted = dateTimeFormatter.format(d);
  return includeTz ? `${formatted} IST` : formatted;
}

/**
 * Single centralized frontend timestamp formatter fulfilling Requirement 7.
 * Supports format: 'time' | 'datetime' | 'detailed'
 */
export function formatTimestamp(isoStr, options = {}) {
  const d = parseUtcDate(isoStr);
  if (!d) return '--:--:--';

  const fmt = options.format || 'time';
  if (fmt === 'detailed' || fmt === 'full') {
    return `${dateTimeFormatter.format(d)} IST`;
  }
  if (fmt === 'datetime') {
    return formatDateTime(isoStr, options.includeTz);
  }
  return formatTime(isoStr, options.includeTz);
}

export function formatSeverityBadge(sev) {
  const s = (sev || 'NORMAL').toUpperCase();
  let icon = '●';
  if (s === 'ELEVATED') icon = '▲';
  else if (s === 'HIGH') icon = '◆';
  else if (s === 'CRITICAL') icon = '✖';

  return `<span class="hn-badge hn-badge-${s.toLowerCase()}">${icon} ${s}</span>`;
}

export function formatRiskMeter(score) {
  const val = Math.max(0, Math.min(100, score || 0));
  let color = 'var(--hn-sev-normal)';
  if (val >= 75) color = 'var(--hn-sev-critical)';
  else if (val >= 50) color = 'var(--hn-sev-high)';
  else if (val >= 25) color = 'var(--hn-sev-elevated)';

  return `
    <div class="hn-risk-meter">
      <div class="hn-risk-track">
        <div class="hn-risk-fill" style="width:${val}%; background:${color};"></div>
      </div>
      <div class="hn-risk-val" style="color:${color};">${val}</div>
    </div>
  `;
}
