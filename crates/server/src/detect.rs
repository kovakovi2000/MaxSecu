//! Pure anomaly-detection analyzer over the audit-event stream (DESIGN §16.5,
//! Phase 6). The authoritative audit trail lives on the **external append-only
//! sink** (`audit.rs`/§11.4); this module is the *detection logic* that turns a
//! stream of security-relevant events into the typed [`Alert`]s §16.5's "alert on
//! anomalies" bullet calls for. It is deliberately **pure** — no I/O, no async, no
//! clock — so each rule is deterministic and individually testable; the
//! dashboard/SIEM wiring (feeding it from the real event sources and forwarding
//! alerts) is the documented integration (runbook, P6.11), not coded here.
//!
//! The input is a self-contained typed [`AuditEvent`] (it reuses [`GrantAction`]
//! from the grant-edge sink where natural). [`analyze`] is a batch function over a
//! slice; [`AlertSink`] is the emit seam, with a dropping [`NullAlertSink`] and a
//! recording [`MemoryAlertSink`] for tests/wiring.
//!
//! Thresholds are in [`Thresholds`], whose [`Default`] mirrors the values recorded
//! in `docs/parameters.md` §10.

use crate::audit::GrantAction;
use std::collections::HashMap;
use std::sync::Mutex;

/// One security-relevant event as fed to the analyzer (a self-contained, redacted
/// projection of what the external sink records, §16.5). Times are epoch-ms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    /// A challenge-response proof was denied (§9.2/§9.3).
    AuthDenied { user_id: [u8; 16], at_ms: u64 },
    /// A sharing-graph grant edge was recorded (§12.3a/§12.4b; mirrors `GrantEdge`).
    Grant {
        granted_by: [u8; 16],
        recipient_id: [u8; 16],
        action: GrantAction,
        file_id: [u8; 16],
        at_ms: u64,
    },
    /// A user was revoked (a `*`/role tombstone naming them was anchored, §12.9b).
    UserRevoked { user_id: [u8; 16], at_ms: u64 },
    /// A client reported a tombstone-set gap below the sink-anchored head (D22/§7.6).
    TombstoneGapReported { reported_by: [u8; 16], at_ms: u64 },
    /// A file version was finalized; `recovery_present` reflects its manifest (§12.3a).
    VersionFinalized {
        file_id: [u8; 16],
        version: u64,
        recovery_present: bool,
        at_ms: u64,
    },
    /// A directory binding was (re-)signed/changed for a user (§7.1/§12.1).
    DirectoryBindingChanged {
        user_id: [u8; 16],
        key_version: u64,
        at_ms: u64,
    },
}

/// A typed anomaly the analyzer raises (§16.5 "alert on anomalies").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    /// A spike in auth failures: a sliding window held more than the threshold.
    AuthFailureSpike { count: u64, window_ms: u64 },
    /// Unusually high re-share fan-out by one granter within a window (§14.5).
    HighReshareFanout {
        granted_by: [u8; 16],
        count: u64,
        window_ms: u64,
    },
    /// A grant by a user revoked shortly afterwards — a planted-recipient signal (§14.5).
    GrantBySoonRevoked {
        granted_by: [u8; 16],
        recipient_id: [u8; 16],
        file_id: [u8; 16],
    },
    /// A reported tombstone-set gap below the sink-anchored head (D22).
    TombstoneGap { reported_by: [u8; 16] },
    /// A finalized version missing a valid recovery grant (§12.3a).
    MissingRecoveryGrant { file_id: [u8; 16], version: u64 },
    /// A directory-binding change outside any allowed ceremony window (§12.1).
    DirectoryChangeOffCeremony { user_id: [u8; 16], at_ms: u64 },
}

/// Detection tunables (defaults recorded in `docs/parameters.md` §10).
#[derive(Clone, Debug)]
pub struct Thresholds {
    /// Emit `AuthFailureSpike` when a sliding window holds **more than** this many
    /// `AuthDenied` events.
    pub auth_failures_per_window: u64,
    /// Width of the auth-failure sliding window (ms).
    pub auth_window_ms: u64,
    /// Emit `HighReshareFanout` when one granter's `Reshare` count in a sliding
    /// window **exceeds** this.
    pub reshare_fanout_per_window: u64,
    /// Width of the re-share fan-out sliding window (ms).
    pub reshare_window_ms: u64,
    /// A grant by `G` followed by `UserRevoked{G}` within this span (ms) after the
    /// grant is flagged `GrantBySoonRevoked`.
    pub soon_revoked_window_ms: u64,
    /// Allowed `[start_ms, end_ms]` (inclusive) windows for directory-binding
    /// changes; a change outside every window is off-ceremony.
    pub ceremony_windows: Vec<(u64, u64)>,
}

impl Default for Thresholds {
    fn default() -> Self {
        // parameters.md §10. Conservative closed-deployment defaults: a handful of
        // failed proofs/minute is normal fat-fingering, but >20/min is a spike; a
        // human re-sharing >10 files/hour is unusual; a grant by a user revoked
        // within a day is suspicious; ceremony windows are deployment-specific and
        // start empty (every change is off-ceremony until windows are configured).
        Thresholds {
            auth_failures_per_window: 20,
            auth_window_ms: 60_000, // 1 minute
            reshare_fanout_per_window: 10,
            reshare_window_ms: 3_600_000,       // 1 hour
            soon_revoked_window_ms: 86_400_000, // 24 hours
            ceremony_windows: Vec::new(),
        }
    }
}

/// Analyze a batch of audit events and return every anomaly found, deterministically.
///
/// The input need not be time-sorted; each rule sorts its own projection. Alerts
/// are grouped by rule in a fixed order (auth spike, fan-out, soon-revoked,
/// tombstone gap, missing recovery, off-ceremony) so the output is stable.
pub fn analyze(events: &[AuditEvent], t: &Thresholds) -> Vec<Alert> {
    let mut out = Vec::new();
    out.extend(auth_failure_spike(events, t));
    out.extend(high_reshare_fanout(events, t));
    out.extend(grant_by_soon_revoked(events, t));
    out.extend(tombstone_gaps(events));
    out.extend(missing_recovery_grants(events));
    out.extend(directory_off_ceremony(events, t));
    out
}

/// `AuthFailureSpike`: if any sliding `auth_window_ms` window contains **more
/// than** `auth_failures_per_window` `AuthDenied` events, emit once with the peak
/// window count. A window is `[ts, ts + window_ms)` anchored at each event.
fn auth_failure_spike(events: &[AuditEvent], t: &Thresholds) -> Vec<Alert> {
    let mut times: Vec<u64> = events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::AuthDenied { at_ms, .. } => Some(*at_ms),
            _ => None,
        })
        .collect();
    times.sort_unstable();
    // Sliding window: for each left edge, count events within [t, t+window).
    let mut peak: u64 = 0;
    let mut right = 0usize;
    for left in 0..times.len() {
        if right < left {
            right = left;
        }
        while right < times.len() && times[right] < times[left] + t.auth_window_ms {
            right += 1;
        }
        peak = peak.max((right - left) as u64);
    }
    if peak > t.auth_failures_per_window {
        vec![Alert::AuthFailureSpike {
            count: peak,
            window_ms: t.auth_window_ms,
        }]
    } else {
        Vec::new()
    }
}

/// `HighReshareFanout`: per `granted_by`, if `Grant{action: Reshare}` count within
/// any `reshare_window_ms` window **exceeds** `reshare_fanout_per_window`, emit for
/// that granter (with the peak window count). Granters are reported in ascending
/// id order for stable output.
fn high_reshare_fanout(events: &[AuditEvent], t: &Thresholds) -> Vec<Alert> {
    let mut by_granter: HashMap<[u8; 16], Vec<u64>> = HashMap::new();
    for e in events {
        if let AuditEvent::Grant {
            granted_by,
            action: GrantAction::Reshare,
            at_ms,
            ..
        } = e
        {
            by_granter.entry(*granted_by).or_default().push(*at_ms);
        }
    }
    let mut hits: Vec<([u8; 16], u64)> = Vec::new();
    for (granter, mut times) in by_granter {
        times.sort_unstable();
        let mut peak: u64 = 0;
        let mut right = 0usize;
        for left in 0..times.len() {
            if right < left {
                right = left;
            }
            while right < times.len() && times[right] < times[left] + t.reshare_window_ms {
                right += 1;
            }
            peak = peak.max((right - left) as u64);
        }
        if peak > t.reshare_fanout_per_window {
            hits.push((granter, peak));
        }
    }
    hits.sort_by_key(|a| a.0);
    hits.into_iter()
        .map(|(granted_by, count)| Alert::HighReshareFanout {
            granted_by,
            count,
            window_ms: t.reshare_window_ms,
        })
        .collect()
}

/// `GrantBySoonRevoked`: a `Grant` (Author or Reshare) by `G` followed by a
/// `UserRevoked{G}` within `soon_revoked_window_ms` *after* the grant → emit
/// (granted_by, recipient, file). A soft-revoke denial is not itself a grant of
/// possession, so it is excluded. Grants are reported in event order.
fn grant_by_soon_revoked(events: &[AuditEvent], t: &Thresholds) -> Vec<Alert> {
    // Earliest revocation time per user.
    let mut revoked_at: HashMap<[u8; 16], u64> = HashMap::new();
    for e in events {
        if let AuditEvent::UserRevoked { user_id, at_ms } = e {
            revoked_at
                .entry(*user_id)
                .and_modify(|t| *t = (*t).min(*at_ms))
                .or_insert(*at_ms);
        }
    }
    let mut out = Vec::new();
    for e in events {
        if let AuditEvent::Grant {
            granted_by,
            recipient_id,
            action,
            file_id,
            at_ms,
        } = e
        {
            if matches!(action, GrantAction::SoftRevoke) {
                continue;
            }
            if let Some(&rev) = revoked_at.get(granted_by) {
                if rev >= *at_ms && rev - *at_ms <= t.soon_revoked_window_ms {
                    out.push(Alert::GrantBySoonRevoked {
                        granted_by: *granted_by,
                        recipient_id: *recipient_id,
                        file_id: *file_id,
                    });
                }
            }
        }
    }
    out
}

/// `TombstoneGap`: every `TombstoneGapReported` is security-critical (D22) and is
/// emitted immediately, with no threshold.
fn tombstone_gaps(events: &[AuditEvent]) -> Vec<Alert> {
    events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::TombstoneGapReported { reported_by, .. } => Some(Alert::TombstoneGap {
                reported_by: *reported_by,
            }),
            _ => None,
        })
        .collect()
}

/// `MissingRecoveryGrant`: every finalized version without a recovery grant (§12.3a).
fn missing_recovery_grants(events: &[AuditEvent]) -> Vec<Alert> {
    events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::VersionFinalized {
                file_id,
                version,
                recovery_present: false,
                ..
            } => Some(Alert::MissingRecoveryGrant {
                file_id: *file_id,
                version: *version,
            }),
            _ => None,
        })
        .collect()
}

/// `DirectoryChangeOffCeremony`: a `DirectoryBindingChanged` whose `at_ms` lies in
/// no `[start, end]` ceremony window → emit.
fn directory_off_ceremony(events: &[AuditEvent], t: &Thresholds) -> Vec<Alert> {
    events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::DirectoryBindingChanged { user_id, at_ms, .. } => {
                let in_window = t
                    .ceremony_windows
                    .iter()
                    .any(|&(start, end)| *at_ms >= start && *at_ms <= end);
                if in_window {
                    None
                } else {
                    Some(Alert::DirectoryChangeOffCeremony {
                        user_id: *user_id,
                        at_ms: *at_ms,
                    })
                }
            }
            _ => None,
        })
        .collect()
}

/// The alert-forwarding seam (§16.5): in production an adapter ships to the SIEM /
/// dashboard; here we provide a dropping and a recording implementation.
pub trait AlertSink {
    fn emit(&self, alert: &Alert);
}

/// Drops every alert — for paths that run the analyzer without a forwarding target.
pub struct NullAlertSink;

impl AlertSink for NullAlertSink {
    fn emit(&self, _alert: &Alert) {}
}

/// Records alerts in memory (for tests / local mirroring), behind an interior
/// `Mutex` so it is shareable by `&self`.
#[derive(Default)]
pub struct MemoryAlertSink {
    alerts: Mutex<Vec<Alert>>,
}

impl MemoryAlertSink {
    pub fn new() -> MemoryAlertSink {
        MemoryAlertSink::default()
    }

    /// A snapshot of the recorded alerts, in emission order.
    pub fn alerts(&self) -> Vec<Alert> {
        self.alerts.lock().unwrap().clone()
    }
}

impl AlertSink for MemoryAlertSink {
    fn emit(&self, alert: &Alert) {
        self.alerts.lock().unwrap().push(alert.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: [u8; 16] = [0xAA; 16];
    const G: [u8; 16] = [0xBB; 16];
    const R: [u8; 16] = [0xCC; 16];
    const F: [u8; 16] = [0xDD; 16];
    const T: u64 = 1_000_000;

    fn denied(user: [u8; 16], at_ms: u64) -> AuditEvent {
        AuditEvent::AuthDenied {
            user_id: user,
            at_ms,
        }
    }

    fn grant(action: GrantAction, at_ms: u64) -> AuditEvent {
        AuditEvent::Grant {
            granted_by: G,
            recipient_id: R,
            action,
            file_id: F,
            at_ms,
        }
    }

    #[test]
    fn quiet_stream_no_alerts() {
        let t = Thresholds::default();
        // A benign, allowed mix: a couple of failures, a finalized version WITH
        // recovery, an in-window directory change, a grant with no revoke.
        let t2 = Thresholds {
            ceremony_windows: vec![(T, T + 1000)],
            ..Thresholds::default()
        };
        let events = vec![
            denied(U, T),
            denied(U, T + 100),
            grant(GrantAction::Reshare, T),
            AuditEvent::VersionFinalized {
                file_id: F,
                version: 1,
                recovery_present: true,
                at_ms: T,
            },
            AuditEvent::DirectoryBindingChanged {
                user_id: U,
                key_version: 1,
                at_ms: T + 500,
            },
        ];
        assert_eq!(analyze(&events, &t2), Vec::new());
        assert_eq!(analyze(&[], &t), Vec::new());
    }

    #[test]
    fn auth_failure_spike_alerts() {
        let t = Thresholds::default(); // 20 / 60_000ms
                                       // 21 failures inside one minute → spike with peak 21.
        let mut events: Vec<AuditEvent> = (0..21).map(|i| denied(U, T + i * 100)).collect();
        match analyze(&events, &t).as_slice() {
            [Alert::AuthFailureSpike { count, window_ms }] => {
                assert_eq!(*count, 21);
                assert_eq!(*window_ms, 60_000);
            }
            other => panic!("expected one spike, got {other:?}"),
        }
        // Spread the same 21 out over >1min each → no window exceeds 20.
        events = (0..21).map(|i| denied(U, T + i * 60_000)).collect();
        assert_eq!(analyze(&events, &t), Vec::new());
    }

    #[test]
    fn reshare_fanout_alerts() {
        let t = Thresholds::default(); // 10 / hour
                                       // 11 re-shares by G within the hour → fan-out alert for G with count 11.
        let events: Vec<AuditEvent> = (0..11)
            .map(|i| grant(GrantAction::Reshare, T + i * 1000))
            .collect();
        match analyze(&events, &t).as_slice() {
            [Alert::HighReshareFanout {
                granted_by,
                count,
                window_ms,
            }] => {
                assert_eq!(*granted_by, G);
                assert_eq!(*count, 11);
                assert_eq!(*window_ms, 3_600_000);
            }
            other => panic!("expected one fan-out, got {other:?}"),
        }
        // Author grants do not count toward re-share fan-out.
        let authors: Vec<AuditEvent> = (0..11)
            .map(|i| grant(GrantAction::Author, T + i * 1000))
            .collect();
        assert_eq!(analyze(&authors, &t), Vec::new());
    }

    #[test]
    fn grant_by_soon_revoked_alerts() {
        let t = Thresholds::default(); // 24h window
        let events = vec![
            grant(GrantAction::Reshare, T),
            AuditEvent::UserRevoked {
                user_id: G,
                at_ms: T + 1000, // within a day
            },
        ];
        assert_eq!(
            analyze(&events, &t),
            vec![Alert::GrantBySoonRevoked {
                granted_by: G,
                recipient_id: R,
                file_id: F,
            }]
        );
        // A revoke far in the future (>24h) does not flag the grant.
        let late = vec![
            grant(GrantAction::Reshare, T),
            AuditEvent::UserRevoked {
                user_id: G,
                at_ms: T + 86_400_001,
            },
        ];
        assert_eq!(analyze(&late, &t), Vec::new());
        // A revoke BEFORE the grant is not "soon-revoked after".
        let before = vec![
            AuditEvent::UserRevoked {
                user_id: G,
                at_ms: T,
            },
            grant(GrantAction::Reshare, T + 1000),
        ];
        assert_eq!(analyze(&before, &t), Vec::new());
    }

    #[test]
    fn tombstone_gap_alerts() {
        let t = Thresholds::default();
        let events = vec![AuditEvent::TombstoneGapReported {
            reported_by: U,
            at_ms: T,
        }];
        assert_eq!(
            analyze(&events, &t),
            vec![Alert::TombstoneGap { reported_by: U }]
        );
    }

    #[test]
    fn missing_recovery_grant_alerts() {
        let t = Thresholds::default();
        let events = vec![
            AuditEvent::VersionFinalized {
                file_id: F,
                version: 3,
                recovery_present: false,
                at_ms: T,
            },
            AuditEvent::VersionFinalized {
                file_id: F,
                version: 4,
                recovery_present: true,
                at_ms: T + 1,
            },
        ];
        assert_eq!(
            analyze(&events, &t),
            vec![Alert::MissingRecoveryGrant {
                file_id: F,
                version: 3
            }]
        );
    }

    #[test]
    fn directory_change_off_ceremony_alerts() {
        let t = Thresholds {
            ceremony_windows: vec![(T, T + 1000)],
            ..Thresholds::default()
        };
        let events = vec![
            // In-window: allowed.
            AuditEvent::DirectoryBindingChanged {
                user_id: U,
                key_version: 1,
                at_ms: T + 500,
            },
            // Outside every window: flagged.
            AuditEvent::DirectoryBindingChanged {
                user_id: U,
                key_version: 2,
                at_ms: T + 5000,
            },
        ];
        assert_eq!(
            analyze(&events, &t),
            vec![Alert::DirectoryChangeOffCeremony {
                user_id: U,
                at_ms: T + 5000
            }]
        );
    }

    #[test]
    fn memory_alert_sink_records() {
        let sink = MemoryAlertSink::new();
        assert!(sink.alerts().is_empty());
        let a = Alert::TombstoneGap { reported_by: U };
        sink.emit(&a);
        sink.emit(&Alert::MissingRecoveryGrant {
            file_id: F,
            version: 1,
        });
        assert_eq!(sink.alerts().len(), 2);
        assert_eq!(sink.alerts()[0], a);
        // The null sink drops without panicking.
        NullAlertSink.emit(&a);
    }
}
