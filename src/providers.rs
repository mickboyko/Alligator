use std::collections::HashMap;

use crate::Source;
use crate::vault::{UnlockedVault, VaultError};

pub trait CredentialProvider: Send + Sync {
    fn access_token_for_source(&self, source: Source) -> Option<&str>;
}

#[derive(Clone, Debug, Default)]
pub struct SessionCredentialProvider {
    tokens_by_provider: HashMap<String, String>,
}

impl SessionCredentialProvider {
    pub fn from_unlocked(unlocked: &UnlockedVault) -> Self {
        let mut tokens = HashMap::new();
        for provider in unlocked.providers() {
            if let Some(secret) = unlocked.secret_for(provider) {
                tokens.insert(provider.to_string(), secret.access_token.clone());
            }
        }

        Self {
            tokens_by_provider: tokens,
        }
    }
}

impl CredentialProvider for SessionCredentialProvider {
    fn access_token_for_source(&self, source: Source) -> Option<&str> {
        self.tokens_by_provider
            .get(source.provider_key())
            .map(String::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshResult {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_epoch_secs: Option<u64>,
}

pub trait OAuthRefresher {
    fn refresh(
        &self,
        provider: &str,
        refresh_token: &str,
        now_epoch_secs: u64,
    ) -> Option<RefreshResult>;
}

#[derive(Debug)]
pub struct OAuthSessionManager<R: OAuthRefresher> {
    refresher: R,
}

impl<R: OAuthRefresher> OAuthSessionManager<R> {
    pub fn new(refresher: R) -> Self {
        Self { refresher }
    }

    pub fn refresh_expiring_tokens(
        &self,
        unlocked: &mut UnlockedVault,
        now_epoch_secs: u64,
    ) -> Result<usize, VaultError> {
        let provider_ids = unlocked
            .providers()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        let mut updated = 0usize;
        for provider in provider_ids {
            let should_refresh = unlocked
                .metadata_for(&provider)
                .and_then(|meta| meta.expires_at_epoch_secs)
                .is_some_and(|expires_at| expires_at <= now_epoch_secs);
            if !should_refresh {
                continue;
            }

            let refresh_token = unlocked
                .secret_for(&provider)
                .map(|secret| secret.refresh_token.clone())
                .ok_or(VaultError::InvalidData(
                    "metadata exists without matching secret",
                ))?;

            if let Some(refreshed) =
                self.refresher
                    .refresh(&provider, &refresh_token, now_epoch_secs)
            {
                let scopes = unlocked
                    .metadata_for(&provider)
                    .map(|meta| meta.scopes.clone())
                    .unwrap_or_default();
                unlocked.upsert_token(
                    provider,
                    scopes,
                    refreshed.expires_at_epoch_secs,
                    refreshed.access_token,
                    refreshed.refresh_token,
                );
                updated += 1;
            }
        }

        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::vault::Vault;

    #[derive(Debug)]
    struct MockRefresher;

    impl OAuthRefresher for MockRefresher {
        fn refresh(
            &self,
            provider: &str,
            refresh_token: &str,
            now_epoch_secs: u64,
        ) -> Option<RefreshResult> {
            Some(RefreshResult {
                access_token: format!("{provider}-new-access"),
                refresh_token: format!("{refresh_token}-next"),
                expires_at_epoch_secs: Some(now_epoch_secs + 120),
            })
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "alligator-provider-{label}-{}.json",
            rand::random::<u64>()
        ));
        path
    }

    #[test]
    fn refresh_updates_and_persists_tokens() {
        let password = format!("password-{}", rand::random::<u64>());
        let path = temp_path("refresh");
        let mut vault = Vault::create(&path, Some(password.as_str()), &[]).expect("create vault");

        let mut unlocked = vault
            .unlock_with_password(password.as_str())
            .expect("unlock vault");
        unlocked.upsert_token(
            "slack",
            vec!["channels:history".to_string(), "channels:read".to_string()],
            Some(10),
            "old-access",
            "old-refresh",
        );
        vault.commit(&unlocked).expect("commit initial token");

        let manager = OAuthSessionManager::new(MockRefresher);
        let updated = manager
            .refresh_expiring_tokens(&mut unlocked, 10)
            .expect("refresh tokens");
        assert_eq!(updated, 1);

        vault.commit(&unlocked).expect("persist refreshed token");

        let reopened = Vault::open(&path).expect("reopen vault");
        let unlocked = reopened
            .unlock_with_password(password.as_str())
            .expect("unlock reopened");
        assert_eq!(
            unlocked
                .secret_for("slack")
                .map(|secret| secret.access_token.as_str()),
            Some("slack-new-access")
        );
        assert_eq!(
            unlocked
                .metadata_for("slack")
                .map(|meta| meta.scopes.clone())
                .unwrap_or_default(),
            vec!["channels:history".to_string(), "channels:read".to_string()]
        );
    }

    #[test]
    fn refresh_skips_unexpired_tokens() {
        let password = format!("password-{}", rand::random::<u64>());
        let path = temp_path("no-refresh");
        let vault = Vault::create(&path, Some(password.as_str()), &[]).expect("create vault");

        let mut unlocked = vault
            .unlock_with_password(password.as_str())
            .expect("unlock vault");
        unlocked.upsert_token(
            "slack",
            vec!["channels:read".to_string()],
            Some(1_000),
            "unchanged-access",
            "unchanged-refresh",
        );

        let manager = OAuthSessionManager::new(MockRefresher);
        let updated = manager
            .refresh_expiring_tokens(&mut unlocked, 999)
            .expect("refresh should succeed");
        assert_eq!(updated, 0);
        assert_eq!(
            unlocked
                .secret_for("slack")
                .map(|secret| secret.access_token.as_str()),
            Some("unchanged-access")
        );
        assert_eq!(
            unlocked
                .metadata_for("slack")
                .map(|meta| meta.scopes.clone())
                .unwrap_or_default(),
            vec!["channels:read".to_string()]
        );
    }
}
