use argon2::Argon2;
use chacha20poly1305::{AeadInPlace, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rand::RngExt;
use rand::prelude::{Rng, ThreadRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Encrypted<T>
where
    T: AsMut<[u8]>,
{
    nonce: XNonce,
    ciphertext: T,
    tag: Tag,
}

impl<T> Encrypted<T>
where
    T: AsMut<[u8]>,
{
    pub fn encrypt(
        cipher: &XChaCha20Poly1305,
        mut data: T,
    ) -> Result<Encrypted<T>, chacha20poly1305::Error> {
        let mut nonce = XNonce::default();
        ThreadRng::default().fill(&mut nonce);
        let tag = cipher.encrypt_in_place_detached(&nonce, &[], data.as_mut())?;
        Ok(Self {
            nonce,
            ciphertext: data,
            tag,
        })
    }
    pub fn decrypt(self, cipher: &XChaCha20Poly1305) -> Result<T, chacha20poly1305::Error> {
        let mut data = self.ciphertext;
        cipher.decrypt_in_place_detached(&self.nonce, &[], data.as_mut(), &self.tag)?;
        Ok(data)
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("identity not initialized")]
    IdentityMissing,

    #[error("session not found")]
    SessionMissing,

    #[error("kdf failure")]
    Kdf,

    #[error("encryption failure")]
    Encryption,

    #[error("decryption failure")]
    Decryption,

    #[error("serialization failure")]
    Serialization,

    #[error("deserialization failure")]
    Deserialization,

    #[error("secret not found")]
    SecretNotFound,
}

#[derive(uniffi::Object, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    password_salt: [u8; 32],
    encrypted_dek: Encrypted<Key>,
}

impl VaultMetadata {
    /// Internal helper to derive the Key Encryption Key (KEK) from a password and salt.
    ///
    /// This uses `std::thread` rather than `tokio::task::spawn_blocking` to remain
    /// runtime-agnostic. This allows the library to function in environments where
    /// a Tokio executor might not be fully configured.
    async fn derive_kek(password: String, salt: [u8; 32]) -> Result<Key, VaultError> {
        let (send, recv) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let mut kek = Key::default();
            let result = Argon2::default()
                .hash_password_into(password.as_bytes(), &salt, &mut kek)
                .map(|_| kek)
                .map_err(|_| VaultError::Kdf);
            send.send(result).unwrap();
        });
        Ok(recv.await.map_err(|_| VaultError::Kdf)??)
    }
}

#[uniffi::export]
impl VaultMetadata {
    #[uniffi::constructor]
    pub async fn temporary(password: String) -> Result<Self, VaultError> {
        let (password_salt, dek) = {
            let mut rng = ThreadRng::default();
            let mut salt = [0u8; 32];
            let mut dek = Key::default();
            rng.fill_bytes(&mut salt);
            rng.fill_bytes(&mut dek);
            (salt, dek)
        };

        let kek = Self::derive_kek(password, password_salt).await?;
        let kek_cipher = XChaCha20Poly1305::new(&kek);
        let encrypted_dek =
            Encrypted::encrypt(&kek_cipher, dek).map_err(|_| VaultError::Encryption)?;

        Ok(Self {
            password_salt,
            encrypted_dek,
        })
    }

    pub async fn unlock(self: Arc<Self>, password: String) -> Result<Vault, VaultError> {
        let kek = Self::derive_kek(password, self.password_salt).await?;
        let kek_cipher = XChaCha20Poly1305::new(&kek);

        let dek = self
            .encrypted_dek
            .clone()
            .decrypt(&kek_cipher)
            .map_err(|_| VaultError::Decryption)?;

        Ok(Vault {
            metadata: self,
            dek: Zeroizing::new(dek),
            secrets: RwLock::new(Default::default()),
        })
    }
}

#[derive(uniffi::Object)]
#[allow(unused)]
pub struct Vault {
    metadata: Arc<VaultMetadata>,
    dek: Zeroizing<Key>,
    secrets: RwLock<HashMap<String, Encrypted<Vec<u8>>>>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct VaultStorage {
    metadata: VaultMetadata,
    secrets: HashMap<String, Encrypted<Vec<u8>>>,
}

#[uniffi::export]
impl Vault {
    pub async fn insert_secret(&self, key: String, value: Vec<u8>) -> Result<(), VaultError> {
        let cipher = XChaCha20Poly1305::new(&self.dek);
        let value = Encrypted::encrypt(&cipher, value).map_err(|_| VaultError::Encryption)?;

        let mut secrets = self.secrets.write().unwrap();
        secrets.insert(key, value);

        Ok(())
    }

    pub async fn get_secret(&self, key: String) -> Result<Vec<u8>, VaultError> {
        let secrets = self.secrets.read().unwrap();
        let stored = secrets.get(&key).ok_or(VaultError::SecretNotFound)?;

        let cipher = XChaCha20Poly1305::new(&self.dek);
        let value = stored
            .clone()
            .decrypt(&cipher)
            .map_err(|_| VaultError::Decryption)?;

        Ok(value)
    }

    pub fn save(&self) -> Result<Vec<u8>, VaultError> {
        let secrets = self.secrets.read().unwrap();
        let storage = VaultStorage {
            metadata: (*self.metadata).clone(),
            secrets: secrets.clone(),
        };
        postcard::to_stdvec(&storage).map_err(|_| VaultError::Serialization)
    }

    #[uniffi::constructor]
    pub async fn load(bytes: Vec<u8>, password: String) -> Result<Self, VaultError> {
        let storage: VaultStorage =
            postcard::from_bytes(&bytes).map_err(|_| VaultError::Deserialization)?;

        let metadata = Arc::new(storage.metadata);
        let mut vault = metadata.unlock(password).await?;

        *vault.secrets.get_mut().unwrap() = storage.secrets;

        Ok(vault)
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

    #[tokio::test]
    async fn vault_save_and_load_round_trip() {
        // 1. Setup initial vault and data
        let initial_vault = setup_vault().await;
        let key = "persistence_test".to_string();
        let value = b"this data should survive serialization".to_vec();

        initial_vault
            .insert_secret(key.clone(), value.clone())
            .await
            .unwrap();

        // 2. Serialize to bytes (Postcard)
        let serialized_data = initial_vault
            .save()
            .expect("Should be able to serialize vault");
        assert!(
            !serialized_data.is_empty(),
            "Serialized data should not be empty"
        );

        // 3. Load into a completely new instance
        let loaded_vault = Vault::load(serialized_data, "password123".to_string())
            .await
            .expect("Should be able to load vault with correct password");

        // 4. Verify data integrity
        let retrieved = loaded_vault.get_secret(key).await.unwrap();
        assert_eq!(retrieved, value, "Retrieved data must match original data");
    }

    #[tokio::test]
    async fn load_fails_with_incorrect_password() {
        let vault = setup_vault().await;
        vault
            .insert_secret("secret".into(), b"data".into())
            .await
            .unwrap();

        let bytes = vault.save().unwrap();

        // Attempt to load with a typo/wrong password
        let result = Vault::load(bytes, "wrong_password".to_string()).await;

        assert!(result.is_err(), "Loading with wrong password must fail");
        // Specifically, it should fail during the DEK decryption in metadata.unlock()
    }

    #[tokio::test]
    async fn load_fails_on_corrupted_bytes() {
        let corrupted_bytes = vec![0u8; 100];
        // Even with the "correct" password, deserialization of the storage structure should fail
        let result = Vault::load(corrupted_bytes, "password123".to_string()).await;

        assert!(matches!(result, Err(VaultError::Deserialization)));
    }

    #[tokio::test]
    async fn vault_metadata_remains_consistent_after_load() {
        let metadata = Arc::new(
            VaultMetadata::temporary(PASSWORD.to_string())
                .await
                .unwrap(),
        );
        let original_salt = metadata.password_salt;

        let vault = metadata.unlock(PASSWORD.to_string()).await.unwrap();
        let bytes = vault.save().unwrap();

        let loaded_vault = Vault::load(bytes, PASSWORD.to_string()).await.unwrap();

        assert_eq!(
            loaded_vault.metadata.password_salt, original_salt,
            "Salt must persist across save/load"
        );
    }
}
