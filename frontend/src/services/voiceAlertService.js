/**
 * Voice Alert Service for PS-08 Step 6.
 * Manages browser Web Speech API (window.speechSynthesis) for real-time security alerts.
 * Features:
 * - Autoplay policy compliance with explicit user toggle
 * - De-duplication using composite signature (incident_id + severity + approval_state)
 * - Safe sanitization to avoid speaking sensitive raw tokens
 * - Manual voice replay
 */

class VoiceAlertService {
  constructor() {
    this.enabled = true;
    this.playedAlerts = new Set();
    this.isSupported = typeof window !== 'undefined' && 'speechSynthesis' in window;
    
    // Load persisted enabled preference if available
    try {
      const saved = localStorage.getItem('ps08_voice_alerts_enabled');
      if (saved !== null) {
        this.enabled = saved === 'true';
      }
    } catch (e) {
      // localStorage may be unavailable in some sandboxes
    }
  }

  /**
   * Checks if browser supports Speech Synthesis
   */
  hasSpeechSupport() {
    return this.isSupported;
  }

  /**
   * Toggles or sets voice alert enabled status
   */
  setEnabled(val) {
    this.enabled = !!val;
    try {
      localStorage.setItem('ps08_voice_alerts_enabled', String(this.enabled));
    } catch (e) {}
    if (!this.enabled) {
      this.cancel();
    }
  }

  isEnabled() {
    return this.enabled && this.isSupported;
  }

  /**
   * Generate composite key to prevent duplicate voice loops on polling
   */
  getAlertSignature(alert) {
    if (!alert) return null;
    const incId = alert.incident_id || alert.alert_id || 'unknown';
    const sev = alert.risk_level || alert.severity || 'UNKNOWN';
    const state = alert.approval_state || alert.status || 'active';
    return `${incId}_${sev}_${state}`;
  }

  /**
   * Speaks alert if voice is enabled and has not already been spoken
   */
  speakAlert(alert) {
    if (!this.isEnabled() || !alert) return false;
    
    // Only speak for HIGH or CRITICAL severity
    const level = (alert.risk_level || alert.severity || '').toUpperCase();
    if (level !== 'HIGH' && level !== 'CRITICAL') return false;

    // Check duplicate signature
    const sig = this.getAlertSignature(alert);
    if (sig && this.playedAlerts.has(sig)) {
      return false; // Already spoken for this severity/state cycle
    }

    const voiceText = alert.voice_message || alert.message || `${level} security alert detected.`;
    const spoken = this._speakText(voiceText, level === 'CRITICAL' ? 1.05 : 1.0);
    if (spoken && sig) {
      this.playedAlerts.add(sig);
    }
    return spoken;
  }

  /**
   * Forces replay of alert announcement regardless of duplicate cache
   */
  replayAlert(alert) {
    if (!this.isSupported || !alert) return false;
    const level = (alert.risk_level || alert.severity || '').toUpperCase();
    const voiceText = alert.voice_message || alert.message || `${level} security alert detected.`;
    return this._speakText(voiceText, level === 'CRITICAL' ? 1.05 : 1.0);
  }

  /**
   * Speaks raw test message to verify browser speech
   */
  testSpeech() {
    if (!this.isSupported) return false;
    return this._speakText("High security alert system online. Browser voice alerts are active.", 1.0);
  }

  /**
   * Cancels active speech utterances
   */
  cancel() {
    if (this.isSupported) {
      try {
        window.speechSynthesis.cancel();
      } catch (e) {}
    }
  }

  /**
   * Internal Web Speech API caller
   */
  _speakText(text, rate = 1.0) {
    if (!this.isSupported) return false;
    try {
      this.cancel(); // Stop current speech
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = rate;
      utterance.pitch = 1.0;
      utterance.volume = 1.0;

      // Select natural English voice if available
      const voices = window.speechSynthesis.getVoices();
      if (voices && voices.length > 0) {
        const engVoice = voices.find(v => v.lang.startsWith('en') && (v.name.includes('Natural') || v.name.includes('Online') || v.name.includes('Google') || v.name.includes('Microsoft')));
        if (engVoice) {
          utterance.voice = engVoice;
        }
      }

      window.speechSynthesis.speak(utterance);
      return true;
    } catch (err) {
      console.warn("Speech synthesis invocation failed:", err);
      return false;
    }
  }
}

export const voiceAlertService = new VoiceAlertService();
export default voiceAlertService;
