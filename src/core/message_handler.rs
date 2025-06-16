//! High-level handler for user registration, login, messaging, and queries
#![allow(dead_code)]
use crate::core::crypto::{Crypto, Encrypted};
use crate::core::db::Db;
use crate::core::mixnet_client::{Incoming, MixnetService};
use anyhow::{Result, anyhow};
use chrono::Utc;
use hex;
use serde_json::{Value, json};
use tokio::sync::mpsc::Receiver;

/// Handles user state, persistence, and mixnet interactions
pub struct MessageHandler {
    /// Crypto utilities
    pub crypto: Crypto,
    /// Underlying mixnet service client
    pub service: MixnetService,
    /// Incoming message receiver
    pub incoming_rx: Receiver<Incoming>,
    /// Database for persistence
    pub db: Db,
    /// Currently logged-in username
    pub current_user: Option<String>,
    /// Our own nym address
    pub nym_address: Option<String>,
    /// Optional user's private key PKCS#8 DER for signing and decryption
    pub private_key: Option<Vec<u8>>,
    /// Optional user's public key SPKI DER for encryption and verification
    pub public_key: Option<Vec<u8>>,
}

impl MessageHandler {
    /// Create a new handler by wrapping the mixnet service and DB
    pub async fn new(
        service: MixnetService,
        incoming_rx: Receiver<Incoming>,
        db_path: &str,
    ) -> anyhow::Result<Self> {
        let db = Db::open(db_path).await?;
        db.init_global().await?;
        Ok(Self {
            crypto: Crypto,
            service,
            incoming_rx,
            db,
            current_user: None,
            nym_address: None,
            private_key: None,
            public_key: None,
        })
    }

    /// Register a new user via the mixnet service, awaiting server responses
    pub async fn register_user(&mut self, username: &str) -> anyhow::Result<bool> {
        // Generate keypair (PEM-encoded private & public keys)
        let (sk_pem, pub_pem) = Crypto::generate_keypair()?;
        // Store keys in handler for signing/encryption
        self.private_key = Some(sk_pem.clone());
        self.public_key = Some(pub_pem.clone());
        // Convert public key PEM to UTF-8 string
        let public_key_pem = String::from_utf8(pub_pem.clone())?;
        // Persist and send the public key in PEM (SubjectPublicKeyInfo) format
        self.db.register_user(username, &public_key_pem).await?;
        self.service
            .send_registration_request(username, &public_key_pem)
            .await?;
        // Await server challenge and responses
        while let Some(incoming) = self.incoming_rx.recv().await {
            let env = incoming.envelope;
            let action = env.action.as_str();
            let ctx = env.context.as_deref();
            match (action, ctx) {
                ("challenge", Some("registration")) => {
                    if let Some(content) = env.content.as_deref() {
                        self.process_register_challenge(username, content).await?;
                    }
                }
                ("challengeResponse", Some("registration")) => {
                    if let Some(result) = env.content.as_deref() {
                        return self.process_register_response(username, result).await;
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }

    /// Login an existing user via the mixnet service, awaiting server response
    pub async fn login_user(&mut self, username: &str) -> anyhow::Result<bool> {
        // Ensure current user is set and load key files
        self.current_user = Some(username.to_string());
        // Load keys from storage
        let sk_pem = self
            .crypto
            .load_private_key_from_file("storage", username)?;
        let pk_pem = self.crypto.load_public_key_from_file("storage", username)?;
        self.private_key = Some(sk_pem.clone());
        self.public_key = Some(pk_pem.clone());

        // Send initial login request
        self.service.send_login_request(username).await?;
        // Await server challenge and responses
        while let Some(incoming) = self.incoming_rx.recv().await {
            let env = incoming.envelope;
            let action = env.action.as_str();
            let ctx = env.context.as_deref();
            match (action, ctx) {
                ("challenge", Some("login")) => {
                    if let Some(content) = env.content.as_deref() {
                        self.process_login_challenge(content).await?;
                    }
                }
                ("challengeResponse", Some("login")) => {
                    if let Some(result) = env.content.as_deref() {
                        return self.process_login_response(username, result).await;
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }

    /// Query for a user's public key via the mixnet service, awaiting server response
    pub async fn query_user(&mut self, username: &str) -> anyhow::Result<Option<(String, String)>> {
        // Send query request
        self.service.send_query_request(username).await?;
        // Await server's query response
        while let Some(incoming) = self.incoming_rx.recv().await {
            let env = incoming.envelope;
            let action = env.action.as_str();
            let ctx = env.context.as_deref();
            match (action, ctx) {
                ("queryResponse", Some("query")) => {
                    if let Some(content) = env.content {
                        if let Ok(v) = serde_json::from_str::<Value>(&content) {
                            if let (Some(user), Some(pk)) = (
                                v.get("username").and_then(|u| u.as_str()),
                                v.get("publicKey").and_then(|k| k.as_str()),
                            ) {
                                let res = (user.to_string(), pk.to_string());
                                if let Some(me) = &self.current_user {
                                    let _ = self.db.add_contact(me, user, pk).await;
                                }
                                return Ok(Some(res));
                            }
                        }
                    }
                    return Ok(None);
                }
                _ => {}
            }
        }
        Ok(None)
    }

    /// Send a direct (encrypted) message to a contact
    pub async fn send_direct_message(
        &self,
        recipient: &str,
        message_content: &str,
    ) -> anyhow::Result<()> {
        // Persist the outgoing plaintext message locally
        let user = self.current_user.as_deref().unwrap_or("");
        self.db
            .save_message(user, recipient, true, message_content, Utc::now())
            .await?;

        // Load recipient's public key from DB
        let contact = self.db.get_contact(user, recipient).await?;
        let recipient_pk_pem = match contact {
            Some((_, pk)) => pk,
            None => return Ok(()),
        };

        // Wrap plaintext in type/message JSON
        let wrapped = json!({"type": 0, "message": message_content});
        let wrapped_str = wrapped.to_string();

        // Encrypt wrapped message via ECDH + AES-GCM
        let enc = Crypto::encrypt(recipient_pk_pem.as_bytes(), wrapped_str.as_bytes())?;
        let encrypted_body = json!({
            "iv": enc.iv,
            "ciphertext": enc.ciphertext,
            "tag": enc.tag,
        });
        let nested = json!({
            "ephemeralPublicKey": enc.ephemeral_pk,
            "salt": enc.salt,
            "encryptedBody": encrypted_body,
        });

        // Sign the encrypted payload
        let sk = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("Missing private key"))?;
        let nested_str = nested.to_string();
        let inner_sig = hex::encode(Crypto::sign(sk, nested_str.as_bytes())?);

        // Build body with encryptedPayload + payloadSignature
        let body = json!({
            "encryptedPayload": nested,
            "payloadSignature": inner_sig,
        });

        // Prepare the overall payload
        let mut payload = json!({
            "sender": user,
            "recipient": recipient,
            "body": body,
            "encrypted": true,
        });

        // If first message, include sender's public key
        let history = self.db.load_messages(user, recipient).await?;
        if history.is_empty() {
            let pk_pem = String::from_utf8(self.public_key.as_ref().unwrap().clone())?;
            payload["senderPublicKey"] = serde_json::Value::String(pk_pem);
        }

        // Sign the full payload for server
        let payload_str = payload.to_string();
        let outer_sig = hex::encode(Crypto::sign(sk, payload_str.as_bytes())?);

        // Send as direct or via server based on handshake status
        // Send the encrypted message (direct if handshake known)
        self.service
            .send_direct_message(recipient, &payload_str, &outer_sig)
            .await?;
        Ok(())
    }

    /// Send a handshake (type=1) encrypted message to establish p2p routing
    pub async fn send_handshake(&self, recipient: &str) -> anyhow::Result<()> {
        let user = self.current_user.as_deref().unwrap_or("");
        // Ensure our own nym address is set
        let nym_addr = self.nym_address.clone().unwrap_or_default();
        // Load our private key
        let sk = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("Missing private key"))?;
        // Fetch recipient's long-term public key
        let contact = self.db.get_contact(user, recipient).await?;
        let recipient_pk = match contact {
            Some((_, pk)) => pk,
            None => return Ok(()),
        };
        // Construct inner handshake payload with type=1
        let handshake = json!({"type": 1, "message": nym_addr});
        let handshake_str = handshake.to_string();
        // Encrypt and derive shared secret
        let enc = Crypto::encrypt(recipient_pk.as_bytes(), handshake_str.as_bytes())?;
        let encrypted_body = json!({
            "iv": enc.iv,
            "ciphertext": enc.ciphertext,
            "tag": enc.tag,
        });
        let nested = json!({
            "ephemeralPublicKey": enc.ephemeral_pk,
            "salt": enc.salt,
            "encryptedBody": encrypted_body,
        });
        // Sign inner encrypted payload
        let inner_sig = hex::encode(Crypto::sign(sk, nested.to_string().as_bytes())?);
        // Build outer payload
        let payload = json!({
            "sender": user,
            "recipient": recipient,
            "body": {"encryptedPayload": nested, "payloadSignature": inner_sig},
            "encrypted": true
        });
        // Sign full payload
        let payload_str = payload.to_string();
        let outer_sig = hex::encode(Crypto::sign(sk, payload_str.as_bytes())?);
        // Send encrypted handshake
        self.service
            .send_direct_message(recipient, &payload_str, &outer_sig)
            .await?;
        Ok(())
    }

    // Helpers to keep the match arms clean:
    async fn process_register_challenge(
        &mut self,
        username: &str,
        content: &str,
    ) -> anyhow::Result<()> {
        if let Ok(v) = serde_json::from_str::<Value>(content) {
            if let Some(nonce) = v.get("nonce").and_then(|n| n.as_str()) {
                let sk = self.private_key.as_ref().unwrap();
                let sig_bytes = Crypto::sign(sk, nonce.as_bytes())?;
                let signature = hex::encode(&sig_bytes);
                self.service
                    .send_registration_response(username, &signature)
                    .await?;
            }
        }
        Ok(())
    }

    async fn process_register_response(
        &mut self,
        username: &str,
        result: &str,
    ) -> anyhow::Result<bool> {
        if result == "success" {
            let sk = self.private_key.as_ref().unwrap();
            let pk = self.public_key.as_ref().unwrap();
            self.crypto.save_keys("storage", username, sk, pk)?;
            self.db.init_user(username).await?;
            self.current_user = Some(username.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn process_login_challenge(&mut self, content: &str) -> anyhow::Result<()> {
        if let Ok(v) = serde_json::from_str::<Value>(content) {
            if let Some(nonce) = v.get("nonce").and_then(|n| n.as_str()) {
                let sk = self.private_key.as_ref().unwrap();
                let sig_bytes = Crypto::sign(sk, nonce.as_bytes())?;
                let signature = hex::encode(&sig_bytes);
                self.service
                    .send_login_response(self.current_user.as_deref().unwrap(), &signature)
                    .await?;
            }
        }
        Ok(())
    }

    async fn process_login_response(
        &mut self,
        username: &str,
        result: &str,
    ) -> anyhow::Result<bool> {
        if result == "success" {
            self.db.init_user(username).await?;
            self.current_user = Some(username.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Handle the queryResponse "action" from the server (context = "query").
    async fn process_query_response(
        &mut self,
        content: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        if let Ok(v) = serde_json::from_str::<Value>(content) {
            if let (Some(user), Some(pk)) = (
                v.get("username").and_then(|u| u.as_str()),
                v.get("publicKey").and_then(|k| k.as_str()),
            ) {
                if let Some(me) = &self.current_user {
                    let _ = self.db.add_contact(me, user, pk).await;
                }
                return Ok(Some((user.to_string(), pk.to_string())));
            }
        }
        Ok(None)
    }

    /// Dispatch a single incoming envelope and return decrypted chat messages.
    pub async fn process_received_message(&mut self, incoming: Incoming) -> Vec<(String, String)> {
        let ts = incoming.ts;
        match self.decrypt_and_verify(incoming).await {
            Ok(Some((sender, ChatMsg::Text(msg)))) => {
                let user = self.current_user.as_deref().unwrap_or("");
                let _ = self.db.save_message(user, &sender, false, &msg, ts).await;
                vec![(sender, msg)]
            }
            Ok(Some((_sender, ChatMsg::Handshake(addr)))) => {
                self.nym_address = Some(addr);
                vec![]
            }
            _ => vec![],
        }
    }

    async fn decrypt_and_verify(
        &mut self,
        incoming: Incoming,
    ) -> Result<Option<(String, ChatMsg)>> {
        let env = incoming.envelope;
        if env.action.as_str() != "incomingMessage" || env.context.as_deref() != Some("chat") {
            return Ok(None);
        }

        let payload_str = env.content.ok_or_else(|| anyhow!("Missing content"))?;
        let payload: Value = serde_json::from_str(&payload_str)?;

        let sender = payload["sender"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing sender"))?
            .to_string();
        let body = &payload["body"];

        let encrypted_val = body["encryptedPayload"].clone();
        let sig_str = body["payloadSignature"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing signature"))?;

        let contact = self
            .db
            .get_contact(self.current_user.as_deref().unwrap_or(""), &sender)
            .await?;
        let pk_bytes = contact
            .map(|(_, pk)| pk.into_bytes())
            .ok_or_else(|| anyhow!("Unknown sender public key"))?;

        let enc_json = encrypted_val.to_string();
        let sig_bytes = hex::decode(sig_str)?;
        if !Crypto::verify(&pk_bytes, enc_json.as_bytes(), &sig_bytes) {
            return Ok(None);
        }

        let encrypted: Encrypted = serde_json::from_value(encrypted_val)?;
        let sk = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("Missing private key"))?;
        let decrypted = Crypto::decrypt(sk, &encrypted)?;

        let text = String::from_utf8(decrypted)?;
        let msg_val: Value = serde_json::from_str(&text)?;

        if let Some(msg_type) = msg_val["type"].as_i64() {
            let content = msg_val["message"].as_str().unwrap_or("").to_string();
            let chat_msg = match msg_type {
                0 => ChatMsg::Text(content),
                1 => ChatMsg::Handshake(content),
                _ => return Ok(None),
            };
            Ok(Some((sender, chat_msg)))
        } else {
            Ok(None)
        }
    }
}

enum ChatMsg {
    Text(String),
    Handshake(String),
}
