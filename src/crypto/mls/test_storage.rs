//! Test-only in-memory storage providers for MLS testing

#[cfg(test)]
pub mod test_providers {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::vec::Vec;
    use core::convert::Infallible;
    use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
    use mls_rs_core::key_package::{KeyPackageStorage, KeyPackageData};
    use mls_rs_core::psk::{PreSharedKeyStorage, ExternalPskId, PreSharedKey};

    #[derive(Debug, Clone)]
    pub struct TestGroupStateStorage {
        storage: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    }

    impl TestGroupStateStorage {
        pub fn new() -> Self {
            Self {
                storage: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl GroupStateStorage for TestGroupStateStorage {
        type Error = Infallible;

        fn max_epoch_id(&self, _group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
            // For testing, just return None (no epoch tracking)
            Ok(None)
        }

        fn state(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            let storage = self.storage.lock().unwrap();
            Ok(storage.get(group_id).cloned())
        }

        fn epoch(&self, group_id: &[u8], _epoch_id: u64) -> Result<Option<Vec<u8>>, Self::Error> {
            // For testing, just return current state
            let storage = self.storage.lock().unwrap();
            Ok(storage.get(group_id).cloned())
        }

        fn write(
            &mut self,
            state: GroupState,
            _epoch_inserts: Vec<EpochRecord>,
            _epoch_updates: Vec<EpochRecord>,
        ) -> Result<(), Self::Error> {
            let mut storage = self.storage.lock().unwrap();
            storage.insert(state.id, state.data);
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    pub struct TestKeyPackageStorage {
        storage: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData>>>,
    }

    impl TestKeyPackageStorage {
        pub fn new() -> Self {
            Self {
                storage: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl KeyPackageStorage for TestKeyPackageStorage {
        type Error = Infallible;

        fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
            let mut storage = self.storage.lock().unwrap();
            storage.insert(id, pkg);
            Ok(())
        }

        fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
            let storage = self.storage.lock().unwrap();
            Ok(storage.get(id).cloned())
        }

        fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
            let mut storage = self.storage.lock().unwrap();
            storage.remove(id);
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    pub struct TestPreSharedKeyStorage {
        storage: Arc<Mutex<HashMap<Vec<u8>, PreSharedKey>>>,
    }

    impl TestPreSharedKeyStorage {
        pub fn new() -> Self {
            Self {
                storage: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        // Test helper method to insert PSKs
        pub fn insert_psk(&self, id: &ExternalPskId, psk: PreSharedKey) {
            let mut storage = self.storage.lock().unwrap();
            storage.insert(id.as_ref().to_vec(), psk);
        }
    }

    impl PreSharedKeyStorage for TestPreSharedKeyStorage {
        type Error = Infallible;

        fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
            let storage = self.storage.lock().unwrap();
            Ok(storage.get(id.as_ref()).cloned())
        }
    }

    #[derive(Debug, Clone)]
    pub struct TestStorageProvider {
        pub group_storage: TestGroupStateStorage,
        pub key_package_storage: TestKeyPackageStorage,
        pub psk_storage: TestPreSharedKeyStorage,
    }

    impl TestStorageProvider {
        pub fn new() -> Self {
            Self {
                group_storage: TestGroupStateStorage::new(),
                key_package_storage: TestKeyPackageStorage::new(),
                psk_storage: TestPreSharedKeyStorage::new(),
            }
        }
    }
}