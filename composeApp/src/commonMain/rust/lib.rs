use argon2::Argon2;
use chacha20poly1305::aead::generic_array::{ArrayLength, GenericArray};
use chacha20poly1305::{AeadInPlace, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rand::prelude::{Rng, ThreadRng};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use typenum::Unsigned;

uniffi::setup_scaffolding!();

trait WithLength<T> {
    type Length: ArrayLength<T>;
}

impl<T, N: ArrayLength<T>> WithLength<T> for GenericArray<T, N> {
    type Length = N;
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("identity not initialized")]
    IdentityMissing,

    #[error("session not found")]
    SessionMissing,

    #[error("kdf failure")]
    KdfFailed,

    #[error("encryption failure")]
    EncryptionFailed,

    #[error("decryption failure")]
    DecryptionFailed,

    #[error("secret not found")]
    SecretNotFound,
}

const X_NONCE_LENGTH: usize = <XNonce as WithLength<u8>>::Length::USIZE;
const KEY_LENGTH: usize = <Key as WithLength<u8>>::Length::USIZE;
const TAG_LENGTH: usize = <Tag as WithLength<u8>>::Length::USIZE;
const ENCRYPTED_DEK_LENGTH: usize = X_NONCE_LENGTH + KEY_LENGTH + TAG_LENGTH;

#[derive(uniffi::Object)]
pub struct VaultMetadata {
    password_salt: [u8; 32],
    encrypted_dek: [u8; ENCRYPTED_DEK_LENGTH],
}

impl VaultMetadata {
    /// Internal helper to derive the Key Encryption Key (KEK) from a password and salt.
    async fn derive_kek(password: String, salt: [u8; 32]) -> Result<Key, VaultError> {
        let (send, recv) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let mut kek = Key::default();
            let result = Argon2::default()
                .hash_password_into(password.as_bytes(), &salt, &mut kek)
                .map(|_| kek)
                .map_err(|_| VaultError::KdfFailed);
            send.send(result).unwrap();
        });
        Ok(recv.await.map_err(|_| VaultError::KdfFailed)??)
    }

    /// Splits the encrypted_dek buffer into its constituent parts: (Nonce, Encrypted Key, Tag).
    fn unpack_dek(&self) -> (&XNonce, &Key, &Tag) {
        let (nonce, rest) = self.encrypted_dek.split_at(X_NONCE_LENGTH);
        let (encrypted_key, tag) = rest.split_at(KEY_LENGTH);
        (
            XNonce::from_slice(nonce),
            Key::from_slice(encrypted_key),
            Tag::from_slice(tag),
        )
    }
}

#[uniffi::export]
impl VaultMetadata {
    #[uniffi::constructor]
    pub async fn temporary(password: String) -> Result<Self, VaultError> {
        let (salt, mut dek, nonce) = {
            let mut rng = ThreadRng::default();
            let mut salt = [0u8; 32];
            let mut dek = Key::default();
            let mut nonce = XNonce::default();
            rng.fill_bytes(&mut salt);
            rng.fill_bytes(&mut dek);
            rng.fill_bytes(&mut nonce);
            (salt, dek, nonce)
        };

        let kek = Self::derive_kek(password, salt).await?;

        let tag = XChaCha20Poly1305::new(&kek)
            .encrypt_in_place_detached(&nonce, &[], &mut dek)
            .map_err(|_| VaultError::EncryptionFailed)?;

        let mut combined = [0u8; ENCRYPTED_DEK_LENGTH];
        let (n_slice, rest) = combined.split_at_mut(X_NONCE_LENGTH);
        let (d_slice, t_slice) = rest.split_at_mut(KEY_LENGTH);

        n_slice.copy_from_slice(&nonce);
        d_slice.copy_from_slice(&dek);
        t_slice.copy_from_slice(&tag);

        Ok(Self {
            password_salt: salt,
            encrypted_dek: combined,
        })
    }

    pub async fn unlock(self: Arc<Self>, password: String) -> Result<Vault, VaultError> {
        let kek = Self::derive_kek(password, self.password_salt).await?;

        let (nonce, dek, tag) = self.unpack_dek();
        let mut dek = dek.to_owned();
        XChaCha20Poly1305::new(&kek)
            .decrypt_in_place_detached(nonce, &[], &mut dek, tag)
            .map_err(|_| VaultError::DecryptionFailed)?;

        Ok(Vault {
            metadata: self,
            dek,
            secrets: Mutex::new(Default::default()),
        })
    }
}

#[derive(Clone)]
struct EncryptedStore {
    nonce: [u8; X_NONCE_LENGTH],
    ciphertext: Vec<u8>,
}

#[derive(uniffi::Object)]
#[allow(unused)]
pub struct Vault {
    metadata: Arc<VaultMetadata>,
    dek: Key,
    secrets: Mutex<HashMap<String, EncryptedStore>>,
}

#[uniffi::export]
impl Vault {
    pub async fn insert_secret(&self, key: String, mut value: Vec<u8>) -> Result<(), VaultError> {
        let mut rng = ThreadRng::default();
        let mut nonce_bytes = [0u8; X_NONCE_LENGTH];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let cipher = XChaCha20Poly1305::new(&self.dek);
        cipher
            .encrypt_in_place(nonce, &[], &mut value)
            .map_err(|_| VaultError::EncryptionFailed)?;

        let mut secrets = self.secrets.lock().unwrap();
        secrets.insert(
            key,
            EncryptedStore {
                nonce: nonce_bytes,
                ciphertext: value,
            },
        );

        Ok(())
    }

    pub async fn get_secret(&self, key: String) -> Result<Vec<u8>, VaultError> {
        let secrets = self.secrets.lock().unwrap();
        let stored = secrets.get(&key).ok_or(VaultError::SecretNotFound)?;

        let nonce = XNonce::from_slice(&stored.nonce);

        if stored.ciphertext.len() < TAG_LENGTH {
            return Err(VaultError::DecryptionFailed);
        }

        let mut buffer = stored.ciphertext.clone();

        let cipher = XChaCha20Poly1305::new(&self.dek);
        cipher
            .decrypt_in_place(nonce, &[], &mut buffer)
            .map_err(|_| VaultError::DecryptionFailed)?;

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const PASSWORD: &str = "correct horse battery staple";

    #[tokio::test]
    async fn temporary_metadata_can_be_created() {
        let metadata = VaultMetadata::temporary(PASSWORD.to_string()).await;
        assert!(metadata.is_ok());
    }

    #[tokio::test]
    async fn unlock_with_correct_password_succeeds() {
        let metadata = VaultMetadata::temporary(PASSWORD.to_string())
            .await
            .unwrap();
        let metadata = Arc::new(metadata);

        let vault = metadata.clone().unlock(PASSWORD.to_string()).await;
        assert!(vault.is_ok());
    }

    #[tokio::test]
    async fn unlock_with_wrong_password_fails() {
        let metadata = VaultMetadata::temporary(PASSWORD.to_string())
            .await
            .unwrap();
        let metadata = Arc::new(metadata);

        let vault = metadata.clone().unlock("wrong_password".to_string()).await;
        assert!(vault.is_err());
    }

    async fn setup_vault() -> Arc<Vault> {
        let metadata = Arc::new(
            VaultMetadata::temporary("password123".to_string())
                .await
                .unwrap(),
        );
        metadata
            .unlock("password123".to_string())
            .await
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn insert_and_get_secret() {
        let vault = setup_vault().await;
        let key = "apiKey".to_string();
        let value = b"secret-value-123".to_vec();

        vault
            .insert_secret(key.clone(), value.clone())
            .await
            .unwrap();
        let retrieved = vault.get_secret(key).await.unwrap();

        assert_eq!(retrieved, value);
    }

    #[tokio::test]
    async fn get_non_existent_secret_fails() {
        let vault = setup_vault().await;
        let result = vault.get_secret("ghost".to_string()).await;

        assert!(matches!(result, Err(VaultError::SecretNotFound)));
    }
}
