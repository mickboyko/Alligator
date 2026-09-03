use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const VAULT_VERSION: u32 = 1;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Crypto(&'static str),
    InvalidData(&'static str),
    InvalidInput(String),
}

impl Display for VaultError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(err) => write!(f, "io error: {err}"),
            VaultError::Serde(err) => write!(f, "serialization error: {err}"),
            VaultError::Crypto(msg) => write!(f, "crypto error: {msg}"),
            VaultError::InvalidData(msg) => write!(f, "invalid data: {msg}"),
            VaultError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenMetadata {
    pub provider: String,
    pub scopes: Vec<String>,
    pub expires_at_epoch_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthSecret {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Clone)]
pub struct UnlockedVault {
    master_key: Zeroizing<Vec<u8>>,
    metadata: HashMap<String, TokenMetadata>,
    secrets: HashMap<String, OAuthSecret>,
}

impl UnlockedVault {
    pub fn metadata_for(&self, provider: &str) -> Option<&TokenMetadata> {
        self.metadata.get(provider)
    }

    pub fn secret_for(&self, provider: &str) -> Option<&OAuthSecret> {
        self.secrets.get(provider)
    }

    pub fn providers(&self) -> impl Iterator<Item = &str> {
        self.metadata.keys().map(|provider| provider.as_str())
    }

    pub fn upsert_token(
        &mut self,
        provider: impl Into<String>,
        scopes: Vec<String>,
        expires_at_epoch_secs: Option<u64>,
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
    ) {
        let provider = provider.into();
        self.metadata.insert(
            provider.clone(),
            TokenMetadata {
                provider: provider.clone(),
                scopes,
                expires_at_epoch_secs,
            },
        );
        self.secrets.insert(
            provider,
            OAuthSecret {
                access_token: access_token.into(),
                refresh_token: refresh_token.into(),
            },
        );
    }

    fn key(&self) -> &[u8] {
        self.master_key.as_slice()
    }
}

#[derive(Debug)]
pub struct Vault {
    path: PathBuf,
    disk: VaultDisk,
}

impl Vault {
    pub fn create(
        path: impl AsRef<Path>,
        password: Option<&str>,
        passkeys: &[(String, String)],
    ) -> Result<Self, VaultError> {
        if password.is_some_and(|value| value.trim().is_empty()) {
            return Err(VaultError::InvalidInput(
                "password must not be empty".to_string(),
            ));
        }
        validate_recovery_policy(password.is_some(), passkeys.len())?;

        let mut master_key = vec![0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut master_key);

        let password_envelope = match password {
            Some(password) => Some(wrap_key_with_secret(password, &master_key, default_kdf())?),
            None => None,
        };

        let mut passkey_envelopes = Vec::with_capacity(passkeys.len());
        for (credential_id, passkey_secret) in passkeys {
            passkey_envelopes.push(PasskeyEnvelope {
                credential_id: credential_id.clone(),
                wrapped_master_key: wrap_key_with_secret(
                    passkey_secret,
                    &master_key,
                    default_kdf(),
                )?,
            });
        }

        let empty_payload = VaultPayload::default();
        let payload = encrypt_payload(&empty_payload, &master_key)?;
        let disk = VaultDisk {
            version: VAULT_VERSION,
            owner_user: Some(Self::current_os_user()),
            password_envelope,
            passkey_envelopes,
            token_metadata: Vec::new(),
            encrypted_payload: payload,
        };

        let vault = Self {
            path: path.as_ref().to_path_buf(),
            disk,
        };
        vault.persist()?;
        Ok(vault)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, VaultError> {
        let contents = fs::read_to_string(path.as_ref())?;
        let mut disk: VaultDisk = serde_json::from_str(&contents)?;
        if disk.version != VAULT_VERSION {
            return Err(VaultError::InvalidData("unsupported vault version"));
        }
        let current_user = Self::current_os_user();
        let owner_user = disk
            .owner_user
            .clone()
            .unwrap_or_else(|| current_user.clone());
        if owner_user != current_user {
            return Err(VaultError::InvalidInput(
                "vault belongs to a different OS user".to_string(),
            ));
        }
        disk.owner_user = Some(owner_user);
        validate_recovery_policy(
            disk.password_envelope.is_some(),
            disk.passkey_envelopes.len(),
        )?;

        Ok(Self {
            path: path.as_ref().to_path_buf(),
            disk,
        })
    }

    pub fn current_os_user() -> String {
        std::env::var("USER")
            .ok()
            .or_else(|| std::env::var("USERNAME").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "unknown-user".to_string())
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn has_password(&self) -> bool {
        self.disk.password_envelope.is_some()
    }

    pub fn passkey_ids(&self) -> impl Iterator<Item = &str> {
        self.disk
            .passkey_envelopes
            .iter()
            .map(|entry| entry.credential_id.as_str())
    }

    pub fn unlock_with_password(&self, password: &str) -> Result<UnlockedVault, VaultError> {
        let envelope = self
            .disk
            .password_envelope
            .as_ref()
            .ok_or(VaultError::InvalidInput(
                "password login is not configured".to_string(),
            ))?;
        let master_key = unwrap_key_with_secret(password, envelope)?;
        self.unlock_with_master_key(master_key)
    }

    pub fn unlock_with_passkey(
        &self,
        credential_id: &str,
        passkey_secret: &str,
    ) -> Result<UnlockedVault, VaultError> {
        let envelope = self
            .disk
            .passkey_envelopes
            .iter()
            .find(|entry| entry.credential_id == credential_id)
            .ok_or_else(|| VaultError::InvalidInput("unknown passkey credential id".to_string()))?;

        let master_key = unwrap_key_with_secret(passkey_secret, &envelope.wrapped_master_key)?;
        self.unlock_with_master_key(master_key)
    }

    pub fn commit(&mut self, unlocked: &UnlockedVault) -> Result<(), VaultError> {
        let payload = VaultPayload {
            secrets: unlocked.secrets.clone(),
        };
        self.disk.token_metadata = unlocked.metadata.values().cloned().collect();
        self.disk.encrypted_payload = encrypt_payload(&payload, unlocked.key())?;
        self.persist()
    }

    pub fn rotate_password(
        &mut self,
        unlocked: &UnlockedVault,
        new_password: &str,
    ) -> Result<(), VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::InvalidInput(
                "new password must not be empty".to_string(),
            ));
        }

        self.disk.password_envelope = Some(wrap_key_with_secret(
            new_password,
            unlocked.key(),
            default_kdf(),
        )?);
        validate_recovery_policy(true, self.disk.passkey_envelopes.len())?;
        self.persist()
    }

    pub fn enroll_passkey(
        &mut self,
        unlocked: &UnlockedVault,
        credential_id: &str,
        passkey_secret: &str,
    ) -> Result<(), VaultError> {
        if credential_id.is_empty() {
            return Err(VaultError::InvalidInput(
                "credential_id must not be empty".to_string(),
            ));
        }
        if passkey_secret.is_empty() {
            return Err(VaultError::InvalidInput(
                "passkey secret must not be empty".to_string(),
            ));
        }

        self.disk
            .passkey_envelopes
            .retain(|entry| entry.credential_id != credential_id);
        self.disk.passkey_envelopes.push(PasskeyEnvelope {
            credential_id: credential_id.to_string(),
            wrapped_master_key: wrap_key_with_secret(
                passkey_secret,
                unlocked.key(),
                default_kdf(),
            )?,
        });

        validate_recovery_policy(
            self.disk.password_envelope.is_some(),
            self.disk.passkey_envelopes.len(),
        )?;
        self.persist()
    }

    pub fn revoke_passkey(&mut self, credential_id: &str) -> Result<(), VaultError> {
        let before = self.disk.passkey_envelopes.len();
        self.disk
            .passkey_envelopes
            .retain(|entry| entry.credential_id != credential_id);
        if before == self.disk.passkey_envelopes.len() {
            return Err(VaultError::InvalidInput(
                "passkey credential id not found".to_string(),
            ));
        }

        validate_recovery_policy(
            self.disk.password_envelope.is_some(),
            self.disk.passkey_envelopes.len(),
        )?;
        self.persist()
    }

    fn unlock_with_master_key(&self, master_key: Vec<u8>) -> Result<UnlockedVault, VaultError> {
        let payload = decrypt_payload(&self.disk.encrypted_payload, &master_key)?;
        let metadata = self
            .disk
            .token_metadata
            .iter()
            .cloned()
            .map(|entry| (entry.provider.clone(), entry))
            .collect();

        Ok(UnlockedVault {
            master_key: Zeroizing::new(master_key),
            metadata,
            secrets: payload.secrets,
        })
    }

    fn persist(&self) -> Result<(), VaultError> {
        let contents = serde_json::to_string_pretty(&self.disk)?;
        #[cfg(unix)]
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.path)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&self.path, contents)?;
        }
        Ok(())
    }
}

fn validate_recovery_policy(has_password: bool, passkey_count: usize) -> Result<(), VaultError> {
    if has_password || passkey_count >= 2 {
        return Ok(());
    }
    Err(VaultError::InvalidData(
        "vault must have password unlock or at least two passkeys for recovery",
    ))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct KdfConfig {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WrappedKey {
    kdf: KdfConfig,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyEnvelope {
    credential_id: String,
    wrapped_master_key: WrappedKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedPayload {
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VaultPayload {
    secrets: HashMap<String, OAuthSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultDisk {
    version: u32,
    #[serde(default)]
    owner_user: Option<String>,
    password_envelope: Option<WrappedKey>,
    passkey_envelopes: Vec<PasskeyEnvelope>,
    token_metadata: Vec<TokenMetadata>,
    encrypted_payload: EncryptedPayload,
}

fn default_kdf() -> KdfConfig {
    KdfConfig {
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    }
}

fn wrap_key_with_secret(
    secret: &str,
    plaintext_key: &[u8],
    kdf: KdfConfig,
) -> Result<WrappedKey, VaultError> {
    let salt: [u8; 16] = rand::random();

    let derived_key = derive_key(secret, &salt, kdf)?;
    let encrypted = encrypt_bytes(plaintext_key, &derived_key)?;

    Ok(WrappedKey {
        kdf,
        salt_b64: STANDARD.encode(salt),
        nonce_b64: encrypted.nonce_b64,
        ciphertext_b64: encrypted.ciphertext_b64,
    })
}

fn unwrap_key_with_secret(secret: &str, wrapped_key: &WrappedKey) -> Result<Vec<u8>, VaultError> {
    let salt = decode_fixed("salt", &wrapped_key.salt_b64, 16)?;
    let derived_key = derive_key(secret, &salt, wrapped_key.kdf)?;
    let encrypted = EncryptedPayload {
        nonce_b64: wrapped_key.nonce_b64.clone(),
        ciphertext_b64: wrapped_key.ciphertext_b64.clone(),
    };

    decrypt_bytes(&encrypted, &derived_key)
}

fn derive_key(secret: &str, salt: &[u8], kdf: KdfConfig) -> Result<Vec<u8>, VaultError> {
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::Crypto("invalid argon2 params"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(secret.as_bytes(), salt, &mut out)
        .map_err(|_| VaultError::Crypto("argon2 derivation failed"))?;

    Ok(out)
}

fn encrypt_payload(payload: &VaultPayload, key: &[u8]) -> Result<EncryptedPayload, VaultError> {
    let plaintext = serde_json::to_vec(payload)?;
    encrypt_bytes(&plaintext, key)
}

fn decrypt_payload(payload: &EncryptedPayload, key: &[u8]) -> Result<VaultPayload, VaultError> {
    let plaintext = decrypt_bytes(payload, key)?;
    serde_json::from_slice::<VaultPayload>(&plaintext).map_err(VaultError::Serde)
}

fn encrypt_bytes(plaintext: &[u8], key: &[u8]) -> Result<EncryptedPayload, VaultError> {
    if key.len() != KEY_LEN {
        return Err(VaultError::Crypto("invalid key length"));
    }

    let nonce: [u8; NONCE_LEN] = rand::random();

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| VaultError::Crypto("failed to initialize cipher"))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| VaultError::Crypto("encryption failed"))?;

    Ok(EncryptedPayload {
        nonce_b64: STANDARD.encode(nonce),
        ciphertext_b64: STANDARD.encode(ciphertext),
    })
}

fn decrypt_bytes(payload: &EncryptedPayload, key: &[u8]) -> Result<Vec<u8>, VaultError> {
    if key.len() != KEY_LEN {
        return Err(VaultError::Crypto("invalid key length"));
    }

    let nonce = decode_fixed("nonce", &payload.nonce_b64, NONCE_LEN)?;
    let ciphertext = STANDARD
        .decode(payload.ciphertext_b64.as_bytes())
        .map_err(|_| VaultError::InvalidData("ciphertext is not valid base64"))?;

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| VaultError::Crypto("failed to initialize cipher"))?;
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| VaultError::Crypto("decryption failed"))
}

fn decode_fixed(
    name: &'static str,
    value_b64: &str,
    expected_len: usize,
) -> Result<Vec<u8>, VaultError> {
    let bytes = STANDARD
        .decode(value_b64.as_bytes())
        .map_err(|_| VaultError::InvalidData("invalid base64 value"))?;
    if bytes.len() != expected_len {
        return Err(VaultError::InvalidData(match name {
            "salt" => "invalid salt length",
            "nonce" => "invalid nonce length",
            _ => "invalid field length",
        }));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!("alligator-{label}-{}.json", rand::random::<u64>());
        path.push(unique);
        path
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_token_data() {
        let password = format!("password-{}", rand::random::<u64>());
        let passkey_secret = format!("passkey-{}", rand::random::<u64>());
        let path = temp_path("roundtrip");
        let mut vault = Vault::create(
            &path,
            Some(password.as_str()),
            &[("key-1".into(), passkey_secret)],
        )
        .expect("create vault");

        let mut unlocked = vault
            .unlock_with_password(password.as_str())
            .expect("unlock vault");
        unlocked.upsert_token(
            "slack",
            vec!["chat:read".to_string()],
            Some(1_700_000_000),
            "access-a",
            "refresh-a",
        );
        vault.commit(&unlocked).expect("commit vault");

        let reopened = Vault::open(&path).expect("open vault");
        let unlocked = reopened
            .unlock_with_password(password.as_str())
            .expect("unlock reopened vault");

        assert_eq!(
            unlocked
                .secret_for("slack")
                .map(|entry| entry.access_token.as_str()),
            Some("access-a")
        );
        assert_eq!(
            unlocked
                .metadata_for("slack")
                .and_then(|entry| entry.expires_at_epoch_secs),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let password = format!("password-{}", rand::random::<u64>());
        let passkey_secret = format!("passkey-{}", rand::random::<u64>());
        let path = temp_path("tamper");
        let vault = Vault::create(
            &path,
            Some(password.as_str()),
            &[("key-1".into(), passkey_secret)],
        )
        .expect("create vault");
        let mut disk: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(vault.path()).expect("read persisted vault"))
                .expect("parse json");

        disk["encrypted_payload"]["ciphertext_b64"] = serde_json::Value::String("AAAA".into());
        fs::write(
            vault.path(),
            serde_json::to_string_pretty(&disk).expect("serialize tampered"),
        )
        .expect("write tampered vault");

        let reopened = Vault::open(vault.path()).expect("reopen tampered vault");
        assert!(reopened.unlock_with_password(password.as_str()).is_err());
    }

    #[test]
    fn recovery_policy_requires_password_or_two_passkeys() {
        let path = temp_path("recovery");
        let err = Vault::create(&path, None, &[("key-1".into(), "secret-1".into())])
            .expect_err("expected recovery-policy error");
        assert!(matches!(err, VaultError::InvalidData(_)));
    }

    #[test]
    fn recovery_policy_allows_password_only() {
        let password = format!("password-{}", rand::random::<u64>());
        let path = temp_path("password-only");
        let vault = Vault::create(&path, Some(password.as_str()), &[]).expect("create vault");
        let unlocked = vault
            .unlock_with_password(password.as_str())
            .expect("unlock password-only vault");
        assert_eq!(unlocked.providers().count(), 0);
    }

    #[test]
    fn open_rejects_vault_owned_by_different_user() {
        let password = format!("password-{}", rand::random::<u64>());
        let path = temp_path("owner-mismatch");
        let _vault = Vault::create(&path, Some(password.as_str()), &[]).expect("create vault");

        let mut disk: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read vault json"))
                .expect("parse vault json");
        let current = Vault::current_os_user();
        disk["owner_user"] = serde_json::Value::String(format!("{current}-other"));
        fs::write(
            &path,
            serde_json::to_string_pretty(&disk).expect("serialize tampered owner"),
        )
        .expect("write tampered vault");

        let err = Vault::open(&path).expect_err("expected owner mismatch");
        assert!(matches!(err, VaultError::InvalidInput(_)));
    }
}
