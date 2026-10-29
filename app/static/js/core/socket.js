// Honeypot Nexus - Real-Time WebSocket Telemetry Client (/soc)
import { showToast } from './ui.js';

class SocketManager {
  constructor() {
    this.socket = null;
    this.handlers = new Map();
  }

  init() {
    if (this.socket) {
      return; // Already initialized
    }

    if (typeof io === 'undefined') {
      console.warn('Socket.IO client library not loaded. Real-time updates paused.');
      this.setStatus('offline', 'OFFLINE (No SocketIO)');
      return;
    }

    this.socket = io('/soc', {
      transports: ['polling'],
      upgrade: false,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 10000
    });

    this.socket.on('connect', () => {
      this.setStatus('live', 'LIVE');
    });

    this.socket.on('disconnect', () => {
      this.setStatus('offline', 'OFFLINE');
    });

    this.socket.on('reconnect_attempt', () => {
      this.setStatus('reconnecting', 'RECONNECTING');
    });

    this.socket.on('connect_error', () => {
      this.setStatus('reconnecting', 'RECONNECTING');
    });

    // Default global handlers
    this.socket.on('new_alert', (alert) => {
      showToast(
        `${alert.severity} Alert: ${alert.title}`,
        `${alert.description || ''} (Source: ${alert.source_ip})`,
        alert.severity
      );
      this._dispatch('new_alert', alert);
    });

    const eventNames = [
      'new_event', 'new_attack', 'alert_update', 'risk_update',
      'session_update', 'threat_level_update', 'system_health', 'kpi_update'
    ];

    eventNames.forEach(evt => {
      this.socket.on(evt, (data) => this._dispatch(evt, data));
    });
  }

  setStatus(state, label) {
    const statusEl = document.getElementById('hnLiveIndicator');
    const statusTextEl = document.getElementById('hnLiveText');
    if (statusEl) {
      statusEl.className = `hn-dot hn-dot-${state}`;
    }
    if (statusTextEl) {
      statusTextEl.textContent = label;
      statusTextEl.style.color = state === 'live' ? 'var(--hn-ok)' :
                                 state === 'reconnecting' ? 'var(--hn-warn)' : 'var(--hn-down)';
    }
  }

  on(eventName, callback) {
    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    const list = this.handlers.get(eventName);
    if (!list.includes(callback)) {
      list.push(callback);
    }
  }

  off(eventName, callback) {
    if (!this.handlers.has(eventName)) return;
    if (!callback) {
      this.handlers.delete(eventName);
    } else {
      const list = this.handlers.get(eventName).filter(cb => cb !== callback);
      this.handlers.set(eventName, list);
    }
  }

  _dispatch(eventName, data) {
    const callbacks = this.handlers.get(eventName) || [];
    callbacks.forEach(cb => {
      try {
        cb(data);
      } catch (err) {
        console.error(`Error in socket handler for ${eventName}:`, err);
      }
    });
  }
}

export const SocketBus = new SocketManager();
