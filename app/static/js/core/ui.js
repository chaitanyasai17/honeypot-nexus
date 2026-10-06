// Honeypot Nexus - UI Utilities and Drawer / Toast Manager

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
      <span style="font-size:10px; color:var(--hn-text-faint);">${new Date().toLocaleTimeString()}</span>
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
