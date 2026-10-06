// Honeypot Nexus - Data Formatting Utilities

export function formatDate(isoStr) {
  if (!isoStr) return '--:--:--';
  const d = new Date(isoStr);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDateTime(isoStr) {
  if (!isoStr) return '---';
  const d = new Date(isoStr);
  return d.toLocaleString([], {
    month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
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
