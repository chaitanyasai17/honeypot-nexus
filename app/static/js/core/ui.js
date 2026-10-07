// Honeypot Nexus - UI Utilities and Drawer / Toast Manager
import { formatTime, formatDateTime, formatSeverityBadge } from './format.js';

export function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function showToast(title, message, severity = 'normal') {
  const container = document.getElementById('hnToastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  const sevLower = (severity || 'normal').toLowerCase();
  toast.className = `hn-toast hn-toast-${sevLower}`;

  toast.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <strong style="font-size:12px; text-transform:uppercase; color:var(--hn-text);">${esc(title)}</strong>
      <span style="font-size:10px; color:var(--hn-text-faint);">${formatTime(new Date())}</span>
    </div>
    <div style="font-size:13px; color:var(--hn-text-dim);">${esc(message)}</div>
  `;

  container.appendChild(toast);

  const duration = sevLower === 'critical' ? 12000 : 6000;
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(40px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

export function openDrawer(title, contentHtml) {
  const drawer = document.getElementById('hnDrawer');
  const backdrop = document.getElementById('hnDrawerBackdrop');
  const titleEl = document.getElementById('hnDrawerTitle');
  const bodyEl = document.getElementById('hnDrawerBody');

  if (!drawer || !backdrop) return;

  if (titleEl) titleEl.textContent = title;
  if (bodyEl) bodyEl.innerHTML = contentHtml;

  backdrop.classList.add('active');
  drawer.classList.add('active');
}

export function closeDrawer() {
  const drawer = document.getElementById('hnDrawer');
  const backdrop = document.getElementById('hnDrawerBackdrop');
  if (drawer) drawer.classList.remove('active');
  if (backdrop) backdrop.classList.remove('active');
}

// Global Escape listener to close drawer
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeDrawer();
});

/**
 * Telemetry Event Inspection Drawer (Requirement 9)
 * Fetches full event record and displays formatted IST timestamps and forensic telemetry.
 */
export async function openEventDetail(id) {
  try {
    const res = await fetch(`/api/events/${encodeURIComponent(id)}`);
    if (!res.ok) throw new Error('Event record not found');
    const ev = await res.json();

    const geoStr = ev.geo ? `${ev.geo.city || 'Unknown'}, ${ev.geo.country || 'Unknown'}` : 'Unknown';

    const content = `
      <div style="display:flex; flex-direction:column; gap:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>${formatSeverityBadge(ev.severity)}</div>
          <div class="mono" style="font-size:12px; color:var(--hn-text-faint);">${esc(ev.event_id)}</div>
        </div>

        <!-- Timestamps Inspection Box (Requirement 9) -->
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; background:var(--hn-bg-2); padding:12px; border-radius:6px; border:1px solid var(--hn-border);">
          <div>
            <div style="font-size:11px; font-weight:700; color:var(--hn-text-faint); text-transform:uppercase;">Event Time</div>
            <div class="mono" style="font-size:13px; font-weight:600; color:var(--hn-text); margin-top:4px;">${formatDateTime(ev.timestamp, true)}</div>
          </div>
          <div>
            <div style="font-size:11px; font-weight:700; color:var(--hn-text-faint); text-transform:uppercase;">Received At</div>
            <div class="mono" style="font-size:13px; font-weight:600; color:var(--hn-text); margin-top:4px;">${formatDateTime(ev.received_at || ev.timestamp, true)}</div>
          </div>
        </div>

        <div style="background:var(--hn-bg-2); padding:12px; border-radius:6px; border:1px solid var(--hn-border);">
          <div style="font-size:11px; font-weight:700; color:var(--hn-text-faint); text-transform:uppercase;">Request Target</div>
          <div class="mono" style="font-size:14px; margin-top:4px;"><strong>${esc(ev.http_method)}</strong> ${esc(ev.endpoint)}</div>
          <div style="font-size:12px; color:var(--hn-text-dim); margin-top:4px;">Surface: ${esc(ev.surface)} • Event Type: ${esc(ev.event_type)}</div>
          <div style="font-size:12px; color:var(--hn-text-dim); margin-top:2px;">Origin: <span class="mono" style="color:var(--hn-accent);">${esc(ev.source_ip)}</span> (${esc(geoStr)})</div>
        </div>

        <div>
          <div style="font-size:11px; font-weight:700; color:var(--hn-text-faint); text-transform:uppercase; margin-bottom:6px;">Captured Payload</div>
          <div class="hn-code-block">${esc(ev.payload || '(None)')}</div>
        </div>

        <div>
          <div style="font-size:11px; font-weight:700; color:var(--hn-text-faint); text-transform:uppercase; margin-bottom:6px;">Detection Rules Triggered</div>
          ${ev.detections && ev.detections.length ? ev.detections.map(d => `
            <div style="background:rgba(239,70,85,0.08); border:1px solid rgba(239,70,85,0.2); padding:10px; border-radius:6px; margin-bottom:8px;">
              <div style="font-weight:700; font-size:13px; color:var(--hn-critical);">${esc(d.rule_id)}: ${esc(d.attack_type)} (+${d.points} pts)</div>
              <div style="font-size:12px; color:var(--hn-text-dim); margin-top:2px;">${esc(d.reason)}</div>
            </div>
          `).join('') : '<div style="font-size:12px; color:var(--hn-text-faint);">No threat rules fired on this request.</div>'}
        </div>

        <div style="display:flex; gap:10px; margin-top:12px;">
          <a href="/dashboard/sessions/${encodeURIComponent(ev.session_summary ? ev.session_summary.session_id : '')}" class="hn-btn hn-btn-secondary hn-btn-sm" style="flex:1;">View Session</a>
          <a href="/dashboard/attackers/${encodeURIComponent(ev.source_ip)}" class="hn-btn hn-btn-secondary hn-btn-sm" style="flex:1;">Attacker Profile</a>
        </div>
      </div>
    `;
    openDrawer('Telemetry Event Inspection', content);
  } catch (err) {
    showToast('Inspection Error', err.message, 'critical');
  }
}

if (typeof window !== 'undefined') {
  window.openEventDetail = openEventDetail;
}
