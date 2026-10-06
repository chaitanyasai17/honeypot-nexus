// Honeypot Nexus - Real-Time WebSocket Telemetry Client (/soc)
import { showToast } from './ui.js';

class SocketManager {
  constructor() {
    this.socket = null;
    this.handlers = new Map();
    this.statusEl = document.getElementById('hnLiveIndicator');
    this.statusTextEl = document.getElementById('hnLiveText');
  }

  init() {
    if (typeof io === 'undefined') {
      console.warn('Socket.IO client library not loaded. Real-time updates paused.');
      this.setStatus('offline', 'OFFLINE (No SocketIO)');
      return;
    }

    this.socket = io('/soc', {
      transports: ['polling', 'websocket'],
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
    if (this.statusEl) {
      this.statusEl.className = `hn-dot hn-dot-${state}`;
    }
    if (this.statusTextEl) {
      this.statusTextEl.textContent = label;
    }
  }

  on(eventName, callback) {
    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    this.handlers.get(eventName).push(callback);
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
