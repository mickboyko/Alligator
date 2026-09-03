use std::time::{Duration, Instant};

use crate::vault::{UnlockedVault, Vault, VaultError};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UnlockMethod {
    Password,
    Passkey { credential_id: String },
}

#[derive(Debug)]
pub enum AuthError {
    RateLimited { retry_after: Duration },
    Vault(VaultError),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::RateLimited { retry_after } => {
                write!(f, "too many failed attempts, retry in {retry_after:?}")
            }
            AuthError::Vault(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<VaultError> for AuthError {
    fn from(value: VaultError) -> Self {
        Self::Vault(value)
    }
}

#[derive(Debug)]
enum LockState {
    Locked {
        failed_attempts: u32,
        cooldown_until: Option<Instant>,
    },
    Unlocked {
        method: UnlockMethod,
        unlocked: UnlockedVault,
        last_activity: Instant,
    },
}

#[derive(Debug)]
pub struct AuthManager {
    max_failed_attempts: u32,
    cooldown: Duration,
    inactivity_timeout: Duration,
    state: LockState,
    audit_log: Vec<String>,
}

impl AuthManager {
    pub fn new(max_failed_attempts: u32, cooldown: Duration, inactivity_timeout: Duration) -> Self {
        Self {
            max_failed_attempts,
            cooldown,
            inactivity_timeout,
            state: LockState::Locked {
                failed_attempts: 0,
                cooldown_until: None,
            },
            audit_log: vec!["app_started_locked".to_string()],
        }
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, LockState::Unlocked { .. })
    }

    pub fn unlock_with_password(&mut self, vault: &Vault, password: &str) -> Result<(), AuthError> {
        self.ensure_not_rate_limited()?;
        match vault.unlock_with_password(password) {
            Ok(unlocked) => {
                self.audit_log.push("unlock_password_success".to_string());
                self.state = LockState::Unlocked {
                    method: UnlockMethod::Password,
                    unlocked,
                    last_activity: Instant::now(),
                };
                Ok(())
            }
            Err(err) => {
                self.record_failed_attempt();
                self.audit_log.push("unlock_password_failure".to_string());
                Err(err.into())
            }
        }
    }

    pub fn unlock_with_passkey(
        &mut self,
        vault: &Vault,
        credential_id: &str,
        passkey_secret: &str,
    ) -> Result<(), AuthError> {
        let _ = (vault, credential_id, passkey_secret);
        self.audit_log.push("unlock_passkey_disabled".to_string());
        Err(AuthError::Vault(VaultError::InvalidInput(
            "hardware-key unlock is disabled until secure device-backed verification is implemented"
                .to_string(),
        )))
    }

    pub fn lock(&mut self, reason: &str) {
        self.audit_log.push(format!("locked:{reason}"));
        self.state = LockState::Locked {
            failed_attempts: 0,
            cooldown_until: None,
        };
    }

    pub fn unlock_method(&self) -> Option<&UnlockMethod> {
        match &self.state {
            LockState::Unlocked { method, .. } => Some(method),
            LockState::Locked { .. } => None,
        }
    }

    pub fn unlocked(&self) -> Option<&UnlockedVault> {
        match &self.state {
            LockState::Unlocked { unlocked, .. } => Some(unlocked),
            LockState::Locked { .. } => None,
        }
    }

    pub fn unlocked_mut(&mut self) -> Option<&mut UnlockedVault> {
        match &mut self.state {
            LockState::Unlocked { unlocked, .. } => Some(unlocked),
            LockState::Locked { .. } => None,
        }
    }

    pub fn mark_activity(&mut self) {
        if let LockState::Unlocked { last_activity, .. } = &mut self.state {
            *last_activity = Instant::now();
        }
    }

    pub fn should_auto_lock(&self) -> bool {
        match &self.state {
            LockState::Unlocked { last_activity, .. } => {
                last_activity.elapsed() >= self.inactivity_timeout
            }
            LockState::Locked { .. } => false,
        }
    }

    pub fn cooldown_remaining(&self) -> Option<Duration> {
        match &self.state {
            LockState::Locked {
                cooldown_until: Some(until),
                ..
            } => {
                if Instant::now() >= *until {
                    None
                } else {
                    Some(until.duration_since(Instant::now()))
                }
            }
            _ => None,
        }
    }

    pub fn audit_events(&self) -> &[String] {
        self.audit_log.as_slice()
    }

    fn ensure_not_rate_limited(&self) -> Result<(), AuthError> {
        if let Some(remaining) = self.cooldown_remaining() {
            return Err(AuthError::RateLimited {
                retry_after: remaining,
            });
        }
        Ok(())
    }

    fn record_failed_attempt(&mut self) {
        let (failed_attempts, cooldown_until) = match &self.state {
            LockState::Locked {
                failed_attempts,
                cooldown_until,
            } => (*failed_attempts, *cooldown_until),
            LockState::Unlocked { .. } => (0, None),
        };

        let mut next_failed_attempts = failed_attempts + 1;
        let mut next_cooldown = cooldown_until;

        if next_failed_attempts >= self.max_failed_attempts {
            next_cooldown = Some(Instant::now() + self.cooldown);
            next_failed_attempts = 0;
        }

        self.state = LockState::Locked {
            failed_attempts: next_failed_attempts,
            cooldown_until: next_cooldown,
        };
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::vault::Vault;

    fn temp_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "alligator-auth-{label}-{}.json",
            rand::random::<u64>()
        ));
        path
    }

    #[test]
    fn state_transitions_unlock_and_auto_lock() {
        let password = format!("password-{}", rand::random::<u64>());
        let path = temp_path("state");
        let vault = Vault::create(&path, Some(password.as_str()), &[]).expect("create vault");

        let mut auth = AuthManager::new(3, Duration::from_secs(30), Duration::from_millis(1));
        auth.unlock_with_password(&vault, password.as_str())
            .expect("unlock");
        assert!(auth.is_unlocked());

        std::thread::sleep(Duration::from_millis(2));
        assert!(auth.should_auto_lock());

        auth.lock("timeout");
        assert!(!auth.is_unlocked());
    }

    #[test]
    fn unlock_rate_limit_enforced_after_failures() {
        let password = format!("password-{}", rand::random::<u64>());
        let path = temp_path("ratelimit");
        let vault = Vault::create(&path, Some(password.as_str()), &[]).expect("create vault");

        let mut auth = AuthManager::new(2, Duration::from_secs(60), Duration::from_secs(60));
        assert!(auth.unlock_with_password(&vault, "bad").is_err());
        assert!(auth.unlock_with_password(&vault, "bad").is_err());

        let err = auth
            .unlock_with_password(&vault, password.as_str())
            .expect_err("should be rate-limited");
        assert!(matches!(err, AuthError::RateLimited { .. }));
    }
}
