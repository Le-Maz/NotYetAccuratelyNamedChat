pub mod database;

use crate::database::{Database, DatabaseError};
use chacha20poly1305::{AeadInPlace, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rand::prelude::{Rng, ThreadRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Encrypted<T> {
    nonce: XNonce,
    ciphertext: T,
    tag: Tag,
}

impl<T> Encrypted<T>
where
    T: AsMut<[u8]>,
{
    fn encrypt(
        cipher: &XChaCha20Poly1305,
        mut data: T,
    ) -> Result<Encrypted<T>, chacha20poly1305::Error> {
        let mut nonce = XNonce::default();
        ThreadRng::default().fill_bytes(&mut nonce);
        let tag = cipher.encrypt_in_place_detached(&nonce, &[], data.as_mut())?;
        Ok(Self {
            nonce,
            ciphertext: data,
            tag,
        })
    }

    fn decrypt(self, cipher: &XChaCha20Poly1305) -> Result<T, chacha20poly1305::Error> {
        let mut data = self.ciphertext;
        cipher.decrypt_in_place_detached(&self.nonce, &[], data.as_mut(), &self.tag)?;
        Ok(data)
    }
}

/// Internal structure used for database storage, hidden from UniFFI
#[derive(Serialize, Deserialize)]
struct VaultMetadata {
    password_salt: [u8; 16],
    encrypted_dek: Encrypted<Key>,
}

#[derive(uniffi::Object)]
pub struct Vault {
    database: Arc<Database>,
    vault_id: String,
    dek: Zeroizing<Key>,
    secrets: RwLock<HashMap<String, Encrypted<Vec<u8>>>>,
}

#[uniffi::export]
impl Vault {
    #[uniffi::constructor]
    pub async fn create(
        database: Arc<Database>,
        vault_id: String,
        password: String,
    ) -> Result<Self, VaultError> {
        let mut salt = [0u8; 16];
        let mut dek = Key::default();

        {
            let mut rng = ThreadRng::default();
            rng.fill_bytes(&mut salt);
            rng.fill_bytes(&mut dek);
        }

        let kek = derive_kek(Zeroizing::new(password), salt).await?;
        let kek_cipher = XChaCha20Poly1305::new(&kek);
        let encrypted_dek =
            Encrypted::encrypt(&kek_cipher, dek).map_err(|_| VaultError::Encryption)?;

        let metadata = VaultMetadata {
            password_salt: salt,
            encrypted_dek,
        };

        database
            .save_metadata(
                vault_id.clone(),
                postcard::to_stdvec(&metadata).map_err(|_| VaultError::Serialization)?,
            )
            .await?;

        Ok(Self {
            database,
            vault_id,
            dek: Zeroizing::new(dek),
            secrets: RwLock::new(HashMap::new()),
        })
    }

    #[uniffi::constructor]
    pub async fn load(
        database: Arc<Database>,
        vault_id: String,
        password: String,
    ) -> Result<Self, VaultError> {
        let meta_bytes = database.load_metadata(vault_id.clone()).await?;
        let metadata: VaultMetadata =
            postcard::from_bytes(&meta_bytes).map_err(|_| VaultError::Deserialization)?;

        let kek = derive_kek(Zeroizing::new(password), metadata.password_salt).await?;
        let dek = metadata
            .encrypted_dek
            .decrypt(&XChaCha20Poly1305::new(&kek))
            .map_err(|_| VaultError::Decryption)?;

        let secret_rows = database.load_secrets(vault_id.clone()).await?;
        let mut secrets = HashMap::new();
        for (k, v) in secret_rows {
            secrets.insert(
                k,
                postcard::from_bytes(&v).map_err(|_| VaultError::Deserialization)?,
            );
        }

        Ok(Self {
            database,
            vault_id,
            dek: Zeroizing::new(dek),
            secrets: RwLock::new(secrets),
        })
    }

    pub async fn insert_secret(&self, key: String, value: Vec<u8>) -> Result<(), VaultError> {
        let encrypted = Encrypted::encrypt(&XChaCha20Poly1305::new(&self.dek), value)
            .map_err(|_| VaultError::Encryption)?;
        let bytes = postcard::to_stdvec(&encrypted).map_err(|_| VaultError::Serialization)?;

        self.database
            .save_secret(self.vault_id.clone(), key.clone(), bytes)
            .await?;
        self.secrets.write().unwrap().insert(key, encrypted);
        Ok(())
    }

    pub async fn get_secret(&self, key: String) -> Result<Vec<u8>, VaultError> {
        let secrets = self.secrets.read().unwrap();
        let stored = secrets
            .get(&key)
            .cloned()
            .ok_or(VaultError::SecretNotFound)?;
        stored
            .decrypt(&XChaCha20Poly1305::new(&self.dek))
            .map_err(|_| VaultError::Decryption)
    }
}

/// Internal helper for KDF logic
async fn derive_kek(password: Zeroizing<String>, salt: [u8; 16]) -> Result<Key, VaultError> {
    let (send, recv) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        use argon2::*;
        let mut kek = Key::default();
        #[cfg(not(test))]
        let m_cost = 64 * 1024;
        #[cfg(test)]
        let m_cost = 8 * 1024;
        let params = Params::new(m_cost, 3, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let result = argon2
            .hash_password_into(password.as_bytes(), &salt, &mut kek)
            .map(|_| kek)
            .map_err(|_| VaultError::Kdf);
        let _ = send.send(result);
    });
    recv.await.map_err(|_| VaultError::Kdf)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    async fn setup_db() -> Arc<Database> {
        let tmp = NamedTempFile::new().unwrap();
        Database::new(tmp.path().to_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn vault_lifecycle() {
        let db = setup_db().await;
        let vault_id = "test_vault".to_string();
        let password = "password123".to_string();

        let vault = Vault::create(db.clone(), vault_id.clone(), password.clone())
            .await
            .unwrap();
        vault
            .insert_secret("foo".into(), b"bar".to_vec())
            .await
            .unwrap();

        let loaded = Vault::load(db, vault_id, password).await.unwrap();
        assert_eq!(loaded.get_secret("foo".into()).await.unwrap(), b"bar");
    }

    #[tokio::test]
    async fn wrong_password() {
        let db = setup_db().await;
        let vault_id = "test_vault".to_string();
        Vault::create(db.clone(), vault_id.clone(), "correct".into())
            .await
            .unwrap();
        let res = Vault::load(db, vault_id, "wrong".into()).await;
        assert!(res.is_err());
    }
}
