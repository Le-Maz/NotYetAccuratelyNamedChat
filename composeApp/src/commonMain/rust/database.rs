use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DatabaseError {
    #[error("failed to perform database operation")]
    QueryFailure,
    #[error("internal communication error")]
    Internal,
}

pub enum DatabaseCommand {
    SaveMetadata {
        vault_id: String,
        data: Vec<u8>,
        resp: oneshot::Sender<Result<(), DatabaseError>>,
    },
    LoadMetadata {
        vault_id: String,
        resp: oneshot::Sender<Result<Vec<u8>, DatabaseError>>,
    },
    SaveSecret {
        vault_id: String,
        key: String,
        data: Vec<u8>,
        resp: oneshot::Sender<Result<(), DatabaseError>>,
    },
    LoadSecrets {
        vault_id: String,
        resp: oneshot::Sender<Result<HashMap<String, Vec<u8>>, DatabaseError>>,
    },
}

#[derive(uniffi::Object, Clone)]
pub struct Database {
    tx: mpsc::Sender<DatabaseCommand>,
}

#[uniffi::export]
impl Database {
    #[uniffi::constructor]
    pub fn new(path: String) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<DatabaseCommand>(100);

        std::thread::spawn(move || {
            let conn = Connection::open(&path).expect("Failed to open database");

            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS vault_metadata (
                    vault_id TEXT PRIMARY KEY,
                    data BLOB
                );
                CREATE TABLE IF NOT EXISTS vault_secrets (
                    vault_id TEXT,
                    key TEXT,
                    data BLOB,
                    PRIMARY KEY (vault_id, key)
                );",
            )
                .expect("Failed to initialize tables");

            while let Some(msg) = rx.blocking_recv() {
                match msg {
                    DatabaseCommand::SaveMetadata { vault_id, data, resp } => {
                        let res = conn.execute(
                            "INSERT OR REPLACE INTO vault_metadata (vault_id, data) VALUES (?1, ?2)",
                            params![vault_id, data],
                        ).map(|_| ()).map_err(|_| DatabaseError::QueryFailure);
                        let _ = resp.send(res);
                    }
                    DatabaseCommand::LoadMetadata { vault_id, resp } => {
                        let res = conn.query_row(
                            "SELECT data FROM vault_metadata WHERE vault_id = ?1",
                            params![vault_id],
                            |row| row.get::<_, Vec<u8>>(0),
                        ).map_err(|_| DatabaseError::QueryFailure);
                        let _ = resp.send(res);
                    }
                    DatabaseCommand::SaveSecret { vault_id, key, data, resp } => {
                        let res = conn.execute(
                            "INSERT OR REPLACE INTO vault_secrets (vault_id, key, data) VALUES (?1, ?2, ?3)",
                            params![vault_id, key, data],
                        ).map(|_| ()).map_err(|_| DatabaseError::QueryFailure);
                        let _ = resp.send(res);
                    }
                    DatabaseCommand::LoadSecrets { vault_id, resp } => {
                        let res = (|| {
                            let mut stmt = conn.prepare("SELECT key, data FROM vault_secrets WHERE vault_id = ?1")
                                .map_err(|_| DatabaseError::QueryFailure)?;
                            let rows = stmt.query_map(params![vault_id], |row| {
                                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                            }).map_err(|_| DatabaseError::QueryFailure)?;

                            let mut map = HashMap::new();
                            for row in rows {
                                let (k, v) = row.map_err(|_| DatabaseError::QueryFailure)?;
                                map.insert(k, v);
                            }
                            Ok(map)
                        })();
                        let _ = resp.send(res);
                    }
                }
            }
        });

        Arc::new(Self { tx })
    }

    pub async fn save_metadata(&self, vault_id: String, data: Vec<u8>) -> Result<(), DatabaseError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(DatabaseCommand::SaveMetadata {
                vault_id,
                data,
                resp: resp_tx,
            })
            .await
            .map_err(|_| DatabaseError::Internal)?;
        resp_rx.await.map_err(|_| DatabaseError::Internal)?
    }

    pub async fn load_metadata(&self, vault_id: String) -> Result<Vec<u8>, DatabaseError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(DatabaseCommand::LoadMetadata {
                vault_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| DatabaseError::Internal)?;
        resp_rx.await.map_err(|_| DatabaseError::Internal)?
    }

    pub async fn save_secret(
        &self,
        vault_id: String,
        key: String,
        data: Vec<u8>,
    ) -> Result<(), DatabaseError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(DatabaseCommand::SaveSecret {
                vault_id,
                key,
                data,
                resp: resp_tx,
            })
            .await
            .map_err(|_| DatabaseError::Internal)?;
        resp_rx.await.map_err(|_| DatabaseError::Internal)?
    }

    pub async fn load_secrets(
        &self,
        vault_id: String,
    ) -> Result<HashMap<String, Vec<u8>>, DatabaseError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(DatabaseCommand::LoadSecrets {
                vault_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| DatabaseError::Internal)?;
        resp_rx.await.map_err(|_| DatabaseError::Internal)?
    }
}
