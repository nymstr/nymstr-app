//! High-level handler for user registration, login, messaging, and queries
#![allow(dead_code)]
use crate::core::crypto::Crypto;
use crate::core::db::Db;
use crate::core::mixnet_client::{Incoming, MixnetService};
use anyhow::anyhow;
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
            // Handle challenge to sign
            if env.action == "challenge" && env.context.as_deref() == Some("registration") {
                if let Some(content) = env.content {
                    if let Ok(v) = serde_json::from_str::<Value>(&content) {
                        if let Some(nonce) = v.get("nonce").and_then(|n| n.as_str()) {
                            let sk = self.private_key.as_ref().unwrap();
                            let sig_bytes = Crypto::sign(sk, nonce.as_bytes())?;
                            let signature = hex::encode(&sig_bytes);
                            self.service
                                .send_registration_response(username, &signature)
                                .await?;
                        }
                    }
                }
            }
            // Final challenge response from server
            else if env.action == "challengeResponse"
                && env.context.as_deref() == Some("registration")
            {
                if let Some(result) = env.content {
                    if result == "success" {
                        // Save key files and create per-user tables
                        let sk = self.private_key.as_ref().unwrap();
                        let pk = self.public_key.as_ref().unwrap();
                        self.crypto.save_keys("storage", username, sk, pk)?;
                        self.db.init_user(username).await?;
                        self.current_user = Some(username.to_string());
                        return Ok(true);
                    } else {
                        return Ok(false);
                    }
                }
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
            // Handle login challenge (nonce signing)
            if env.action == "challenge" && env.context.as_deref() == Some("login") {
                if let Some(content) = env.content {
                    if let Ok(v) = serde_json::from_str::<Value>(&content) {
                        if let Some(nonce) = v.get("nonce").and_then(|n| n.as_str()) {
                            let sk = self.private_key.as_ref().unwrap();
                            let sig_bytes = Crypto::sign(sk, nonce.as_bytes())?;
                            let signature = hex::encode(&sig_bytes);
                            self.service
                                .send_login_response(username, &signature)
                                .await?;
                        }
                    }
                }
            }
            // Handle final login response
            else if env.action == "challengeResponse" && env.context.as_deref() == Some("login") {
                if let Some(result) = env.content {
                    if result == "success" {
                        self.db.init_user(username).await?;
                        self.current_user = Some(username.to_string());
                        return Ok(true);
                    } else {
                        return Ok(false);
                    }
                }
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
            if env.action == "queryResponse" && env.context.as_deref() == Some("query") {
                if let Some(content) = env.content {
                    if let Ok(v) = serde_json::from_str::<Value>(&content) {
                        if let (Some(user), Some(pk)) = (
                            v.get("username").and_then(|u| u.as_str()),
                            v.get("publicKey").and_then(|k| k.as_str()),
                        ) {
                            let res = (user.to_string(), pk.to_string());
                            // Persist contact
                            if let Some(me) = &self.current_user {
                                let _ = self.db.add_contact(me, user, pk).await;
                            }
                            return Ok(Some(res));
                        }
                    }
                }
                return Ok(None);
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

    /// Drain incoming chat messages: returns Vec of (from, content)
    pub async fn drain_incoming(&mut self) -> Vec<(String, String)> {
        let mut msgs = Vec::new();
        while let Ok(incoming) = self.incoming_rx.try_recv() {
            let env = incoming.envelope;
            if env.action == "incomingMessage" && env.context.as_deref() == Some("chat") {
                if let Some(content_str) = env.content {
                    if let Ok(payload) = serde_json::from_str::<Value>(&content_str) {
                        if let (Some(sender), Some(body)) = (
                            payload.get("sender").and_then(|v| v.as_str()),
                            payload.get("body"),
                        ) {
                            // Body should have encryptedPayload and payloadSignature
                            if let (Some(enc_val), Some(sig_val)) = (
                                body.get("encryptedPayload"),
                                body.get("payloadSignature").and_then(|v| v.as_str()),
                            ) {
                                // Deserialize encrypted payload
                                if let Ok(enc) = serde_json::from_value::<
                                    crate::core::crypto::Encrypted,
                                >(enc_val.clone())
                                {
                                    // Verify inner signature
                                    if let Ok(Some((_, pk))) = self
                                        .db
                                        .get_contact(
                                            self.current_user.as_deref().unwrap_or(""),
                                            sender,
                                        )
                                        .await
                                    {
                                        let pk_bytes = pk.as_bytes();
                                        if Crypto::verify(
                                            pk_bytes,
                                            enc_val.to_string().as_bytes(),
                                            &hex::decode(sig_val).unwrap_or_default(),
                                        ) {
                                            // Decrypt
                                            if let Some(sk_pem) = self.private_key.as_ref() {
                                                if let Ok(decrypted) = Crypto::decrypt(sk_pem, &enc)
                                                {
                                                    if let Ok(text) = String::from_utf8(decrypted) {
                                                        if let Ok(obj) =
                                                            serde_json::from_str::<Value>(&text)
                                                        {
                                                            if let Some(msg_type) = obj
                                                                .get("type")
                                                                .and_then(|v| v.as_i64())
                                                            {
                                                                if msg_type == 1 {
                                                                    if let Some(addr) = obj
                                                                        .get("message")
                                                                        .and_then(|v| v.as_str())
                                                                    {
                                                                        // store handshake address
                                                                        self.nym_address =
                                                                            Some(addr.to_string());
                                                                    }
                                                                    continue;
                                                                } else if msg_type == 0 {
                                                                    if let Some(msg_txt) = obj
                                                                        .get("message")
                                                                        .and_then(|v| v.as_str())
                                                                    {
                                                                        // Persist incoming
                                                                        let user = self
                                                                            .current_user
                                                                            .as_deref()
                                                                            .unwrap_or("");
                                                                        let _ = self
                                                                            .db
                                                                            .save_message(
                                                                                user,
                                                                                sender,
                                                                                false,
                                                                                msg_txt,
                                                                                incoming.ts,
                                                                            )
                                                                            .await;
                                                                        msgs.push((
                                                                            sender.to_string(),
                                                                            msg_txt.to_string(),
                                                                        ));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        msgs
    }
}
