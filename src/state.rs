//! Pure local state: session admission and the one release predicate.
//! Time is Unix seconds passed in by the caller; nothing here reads a clock
//! or a store. Aggregate states (activation, threshold) belong to the client.

use crate::wire::{Code, TrusteePolicy};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentStatus {
    Accepted,
    Superseded,
    Revoked,
    Closed,
}

impl EnrollmentStatus {
    const ALL: [Self; 4] = [
        Self::Accepted,
        Self::Superseded,
        Self::Revoked,
        Self::Closed,
    ];

    /// The stored name of this local state.
    pub fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Closed => "closed",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|status| status.name() == name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    CoolingDown,
    Released,
    Finalized,
    /// Cancelled by the candidate.
    Cancelled,
    /// Cancelled by the holder.
    Vetoed,
    Refused,
}

impl SessionStatus {
    const ALL: [Self; 6] = [
        Self::CoolingDown,
        Self::Released,
        Self::Finalized,
        Self::Cancelled,
        Self::Vetoed,
        Self::Refused,
    ];

    /// The stored name of this local state.
    pub fn name(self) -> &'static str {
        match self {
            Self::CoolingDown => "cooling_down",
            Self::Released => "released",
            Self::Finalized => "finalized",
            Self::Cancelled => "cancelled",
            Self::Vetoed => "vetoed",
            Self::Refused => "refused",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|status| status.name() == name)
    }
}

/// Stored facts about one enrollment sequence. Expiry is computed, not stored.
#[derive(Clone, Copy, Debug)]
pub struct EnrollmentState {
    pub status: EnrollmentStatus,
    pub sequence: u64,
    pub expires_at: i64,
}

/// Stored facts about one session, deadlines as fixed at admission.
#[derive(Clone, Copy, Debug)]
pub struct SessionState {
    pub status: SessionStatus,
    pub sequence: u64,
    pub cooldown_ends_at: i64,
    pub expires_at: i64,
}

/// Deadlines fixed once, when a session is admitted; persisted as given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    pub cooldown_ends_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// Seal and persist a new contribution.
    Emit,
    /// Return the contribution already persisted for this session.
    Resend,
}

/// Admit a verified session whose bindings match `enrollment`. The cooldown
/// starts at `now`, the trustee's clock, never at the candidate's
/// `requestedAt`; the session must outlive the cooldown and stay inside both
/// the policy's lifetime and the enrollment's term.
pub fn admit(
    enrollment: &EnrollmentState,
    policy: &TrusteePolicy,
    attempts_used: u32,
    requested_at: i64,
    expires_at: i64,
    now: i64,
    skew_secs: i64,
) -> Result<Admission, Code> {
    usable(enrollment, now)?;
    if attempts_used >= policy.maximum_attempts {
        return Err(Code::RecoveryRateLimited);
    }
    if (requested_at - now).abs() > skew_secs {
        return Err(Code::InvalidRequest);
    }
    if expires_at <= now {
        return Err(Code::RecoveryExpired);
    }
    let cooldown_ends_at = now + policy.cooldown_secs;
    let within_bounds = expires_at > cooldown_ends_at
        && expires_at <= now + policy.session_lifetime_secs
        && expires_at <= enrollment.expires_at;
    if !within_bounds {
        return Err(Code::RecoveryRefused);
    }
    Ok(Admission {
        cooldown_ends_at,
        expires_at,
    })
}

/// The release predicate. Every route that could hand out a contribution
/// asks this first, inside the transaction that persists the answer.
/// `clock_floor` is the highest time the store has seen; a clock behind it
/// means the clock moved backwards, and nothing is released.
pub fn release(
    enrollment: &EnrollmentState,
    session: &SessionState,
    now: i64,
    clock_floor: i64,
) -> Result<Release, Code> {
    if now < clock_floor {
        return Err(Code::TemporarilyUnavailable);
    }
    usable(enrollment, now)?;
    if session.sequence != enrollment.sequence {
        return Err(Code::StaleEnrollmentSequence);
    }
    match session.status {
        SessionStatus::CoolingDown | SessionStatus::Released => {}
        SessionStatus::Vetoed => return Err(Code::RecoveryVetoed),
        // Terminal states win over re-serving anything already persisted.
        SessionStatus::Cancelled | SessionStatus::Refused | SessionStatus::Finalized => {
            return Err(Code::RecoveryRefused);
        }
    }
    if now >= session.expires_at {
        return Err(Code::RecoveryExpired);
    }
    if now < session.cooldown_ends_at {
        return Err(Code::RecoveryCoolingDown);
    }
    Ok(match session.status {
        SessionStatus::Released => Release::Resend,
        _ => Release::Emit,
    })
}

fn usable(enrollment: &EnrollmentState, now: i64) -> Result<(), Code> {
    match enrollment.status {
        EnrollmentStatus::Revoked | EnrollmentStatus::Closed => Err(Code::EnrollmentRevoked),
        EnrollmentStatus::Superseded => Err(Code::StaleEnrollmentSequence),
        EnrollmentStatus::Accepted if now >= enrollment.expires_at => Err(Code::EnrollmentExpired),
        EnrollmentStatus::Accepted => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn enrollment() -> EnrollmentState {
        EnrollmentState {
            status: EnrollmentStatus::Accepted,
            sequence: 2,
            expires_at: NOW + 365 * DAY,
        }
    }

    fn session() -> SessionState {
        SessionState {
            status: SessionStatus::CoolingDown,
            sequence: 2,
            cooldown_ends_at: NOW - 1,
            expires_at: NOW + DAY,
        }
    }

    fn policy() -> TrusteePolicy {
        TrusteePolicy {
            factor_key: [0; 32],
            cooldown_secs: 2 * DAY,
            session_lifetime_secs: 7 * DAY,
            maximum_attempts: 3,
        }
    }

    /// The store's CHECK constraints spell these names.
    #[test]
    fn stored_names_round_trip() {
        for status in EnrollmentStatus::ALL {
            assert_eq!(EnrollmentStatus::from_name(status.name()), Some(status));
        }
        for status in SessionStatus::ALL {
            assert_eq!(SessionStatus::from_name(status.name()), Some(status));
        }
        assert_eq!(SessionStatus::from_name("active"), None);
    }

    #[test]
    fn release_emits_once_and_then_resends() {
        assert_eq!(
            release(&enrollment(), &session(), NOW, NOW),
            Ok(Release::Emit)
        );
        let released = SessionState {
            status: SessionStatus::Released,
            ..session()
        };
        assert_eq!(
            release(&enrollment(), &released, NOW, NOW),
            Ok(Release::Resend)
        );
    }

    #[test]
    fn release_refuses_every_blocked_case() {
        let e = enrollment();
        let s = session();
        let with_enrollment = |status| EnrollmentState { status, ..e };
        let with_session = |status| SessionState { status, ..s };
        let cases = [
            (
                "clock moved backwards",
                release(&e, &s, NOW, NOW + 1),
                Code::TemporarilyUnavailable,
            ),
            (
                "revoked",
                release(&with_enrollment(EnrollmentStatus::Revoked), &s, NOW, NOW),
                Code::EnrollmentRevoked,
            ),
            (
                "closed",
                release(&with_enrollment(EnrollmentStatus::Closed), &s, NOW, NOW),
                Code::EnrollmentRevoked,
            ),
            (
                "superseded",
                release(&with_enrollment(EnrollmentStatus::Superseded), &s, NOW, NOW),
                Code::StaleEnrollmentSequence,
            ),
            (
                "enrollment expired",
                release(
                    &EnrollmentState {
                        expires_at: NOW,
                        ..e
                    },
                    &s,
                    NOW,
                    NOW,
                ),
                Code::EnrollmentExpired,
            ),
            (
                "session for another sequence",
                release(&e, &SessionState { sequence: 1, ..s }, NOW, NOW),
                Code::StaleEnrollmentSequence,
            ),
            (
                "vetoed",
                release(&e, &with_session(SessionStatus::Vetoed), NOW, NOW),
                Code::RecoveryVetoed,
            ),
            (
                "cancelled",
                release(&e, &with_session(SessionStatus::Cancelled), NOW, NOW),
                Code::RecoveryRefused,
            ),
            (
                "refused",
                release(&e, &with_session(SessionStatus::Refused), NOW, NOW),
                Code::RecoveryRefused,
            ),
            (
                "finalized",
                release(&e, &with_session(SessionStatus::Finalized), NOW, NOW),
                Code::RecoveryRefused,
            ),
            (
                "session expired",
                release(
                    &e,
                    &SessionState {
                        expires_at: NOW,
                        ..s
                    },
                    NOW,
                    NOW,
                ),
                Code::RecoveryExpired,
            ),
            (
                "released but now expired",
                release(
                    &e,
                    &SessionState {
                        status: SessionStatus::Released,
                        expires_at: NOW,
                        ..s
                    },
                    NOW,
                    NOW,
                ),
                Code::RecoveryExpired,
            ),
            (
                "cooling down",
                release(
                    &e,
                    &SessionState {
                        cooldown_ends_at: NOW + 1,
                        ..s
                    },
                    NOW,
                    NOW,
                ),
                Code::RecoveryCoolingDown,
            ),
        ];
        for (name, outcome, expected) in cases {
            assert_eq!(outcome, Err(expected), "{name}");
        }
    }

    #[test]
    fn admission_starts_the_cooldown_at_trustee_time() {
        // A backdated requestedAt inside the skew does not shorten the cooldown.
        let admitted = admit(
            &enrollment(),
            &policy(),
            0,
            NOW - 60,
            NOW + 3 * DAY,
            NOW,
            300,
        );
        assert_eq!(
            admitted,
            Ok(Admission {
                cooldown_ends_at: NOW + 2 * DAY,
                expires_at: NOW + 3 * DAY
            })
        );
    }

    #[test]
    fn admission_refuses_every_blocked_case() {
        let e = enrollment();
        let p = policy();
        let later = NOW + 3 * DAY;
        let cases = [
            (
                "enrollment revoked",
                admit(
                    &EnrollmentState {
                        status: EnrollmentStatus::Revoked,
                        ..e
                    },
                    &p,
                    0,
                    NOW,
                    later,
                    NOW,
                    300,
                ),
                Code::EnrollmentRevoked,
            ),
            (
                "attempts used up",
                admit(&e, &p, 3, NOW, later, NOW, 300),
                Code::RecoveryRateLimited,
            ),
            (
                "stale request",
                admit(&e, &p, 0, NOW - 301, later, NOW, 300),
                Code::InvalidRequest,
            ),
            (
                "request from the future",
                admit(&e, &p, 0, NOW + 301, later, NOW, 300),
                Code::InvalidRequest,
            ),
            (
                "already expired",
                admit(&e, &p, 0, NOW, NOW, NOW, 300),
                Code::RecoveryExpired,
            ),
            (
                "expires within the cooldown",
                admit(&e, &p, 0, NOW, NOW + 2 * DAY, NOW, 300),
                Code::RecoveryRefused,
            ),
            (
                "longer than the policy allows",
                admit(&e, &p, 0, NOW, NOW + 7 * DAY + 1, NOW, 300),
                Code::RecoveryRefused,
            ),
            (
                "outlives the enrollment",
                admit(
                    &EnrollmentState {
                        expires_at: NOW + 3 * DAY - 1,
                        ..e
                    },
                    &p,
                    0,
                    NOW,
                    later,
                    NOW,
                    300,
                ),
                Code::RecoveryRefused,
            ),
        ];
        for (name, outcome, expected) in cases {
            assert_eq!(outcome, Err(expected), "{name}");
        }
    }
}
