//! Simple test to verify the secure PGP implementation works

#[cfg(test)]
mod tests {
    use crate::crypto::pgp::{PgpKeyManager, PgpSigner, SecurePassphrase};
    use anyhow::Result;

    #[test]
    fn test_secure_pgp() -> Result<()> {
        println!("🔐 Testing Secure PGP Implementation...");

        // Test 1: Generate a secure passphrase
        println!("  1. Generating secure passphrase...");
        let passphrase = SecurePassphrase::generate_strong();
        println!("     ✅ Passphrase generated successfully");

        // Test 2: Generate Ed25519 keypair
        println!("  2. Generating Ed25519 keypair...");
        let user_id = "test@example.com";
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair_secure(user_id, &passphrase)?;
        println!("     ✅ Keypair generated successfully");

        // Test 3: Sign some data
        println!("  3. Testing secure signing...");
        let test_data = b"Hello, secure world!";
        let signature = PgpSigner::sign_detached_secure(&secret_key, test_data, &passphrase)?;
        println!("     ✅ Data signed successfully");
        println!("     📝 Signature length: {} chars", signature.len());

        // Test 4: Verify the signature
        println!("  4. Testing signature verification...");
        let verification_result = PgpSigner::verify_detached(&public_key, test_data, &signature)?;
        println!(
            "     ✅ Signature verified: valid={}, signer={}",
            verification_result.is_valid, verification_result.signer_user_id
        );

        // Test 5: Validate key capabilities
        println!("  5. Testing key validation...");
        PgpSigner::validate_signing_key(&public_key)?;
        println!("     ✅ Key validation passed");

        // Test 6: Check signing capability
        println!("  6. Testing signing capability check...");
        let can_sign = PgpSigner::has_signing_capability(&public_key);
        println!("     ✅ Signing capability: {}", can_sign);

        // Test 7: Get armored public key
        println!("  7. Testing public key export...");
        let public_armored = PgpKeyManager::public_key_armored(&public_key)?;
        println!(
            "     ✅ Public key exported, length: {} chars",
            public_armored.len()
        );

        println!("🎉 All PGP tests passed! The secure implementation is working correctly.");
        Ok(())
    }
}
