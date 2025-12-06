use near_sdk::json_types::{Base58CryptoHash, Base64VecU8};
use near_sdk::{env, ext_contract, near, AccountId, CryptoHash, Promise, PromiseError, NearToken};
use near_sdk::state_init::{StateInit, StateInitV1};
use near_sdk::GlobalContractId;
use std::collections::BTreeMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[derive(Default)]
#[near(contract_state)]
pub struct GlobalFactoryContract {
    /// Store the hash of deployed global contracts for reference
    pub global_contracts_registered_by_code_hash: std::collections::HashMap<String, CryptoHash>,
    /// Store account IDs that have deployed global contracts
    pub global_contracts_registered_by_account_id: std::collections::HashMap<String, AccountId>,
}

// Example contract interface that we'll deploy as a global contract
#[ext_contract]
pub trait ExtStatusMessage {
    fn set_status(&mut self, message: String);
    fn get_status(&self, account_id: AccountId) -> Option<String>;
}

#[near]
impl GlobalFactoryContract {
    /// Deploy a global contract with the given bytecode, identifiable by its code hash
    #[payable]
    pub fn deploy_global_contract(&mut self, name: String, code: Base64VecU8) -> Promise {
        let code_hash = env::sha256_array(&code);
        self.global_contracts_registered_by_code_hash.insert(name.clone(), code_hash);

        Promise::new(env::current_account_id()).deploy_global_contract(code)
    }

    /// Deploy a global contract, identifiable by the predecessor's account ID
    #[payable]
    pub fn deploy_global_contract_by_account_id(
        &mut self,
        name: String,
        code: Base64VecU8,
        account_id: AccountId,
    ) -> Promise {
        self.global_contracts_registered_by_account_id.insert(name, account_id.clone());

        Promise::new(account_id)
            .create_account()
            .transfer(env::attached_deposit())
            .add_full_access_key(env::signer_account_pk())
            .deploy_global_contract_by_account_id(code)
    }

    /// Use an existing global contract by its code hash
    pub fn use_global_contract_by_hash(
        &self,
        code_hash: Base58CryptoHash,
        account_id: AccountId,
    ) -> Promise {
        Promise::new(account_id)
            .create_account()
            .transfer(env::attached_deposit())
            .add_full_access_key(env::signer_account_pk())
            .use_global_contract(code_hash)
    }

    /// Use an existing global contract by referencing the account that deployed it
    pub fn use_global_contract_by_account(
        &self,
        deployer_account_id: AccountId,
        account_id: AccountId,
    ) -> Promise {
        Promise::new(account_id)
            .create_account()
            .transfer(env::attached_deposit())
            .add_full_access_key(env::signer_account_pk())
            .use_global_contract_by_account_id(deployer_account_id)
    }

    /// Get the code hash of a deployed global contract by name
    pub fn get_global_contract_hash(&self, name: String) -> Option<Base58CryptoHash> {
        self.global_contracts_registered_by_code_hash.get(&name).cloned().map(|hash| hash.into())
    }

    /// Get the deployer account ID of a global contract by name
    pub fn get_global_contract_deployer(&self, name: String) -> Option<AccountId> {
        self.global_contracts_registered_by_account_id.get(&name).cloned()
    }

    /// Get all global contracts registered by code hash
    pub fn get_global_contracts_registered_by_code_hash(&self) -> Vec<(String, Base58CryptoHash)> {
        self.global_contracts_registered_by_code_hash
            .iter()
            .map(|(name, hash)| (name.clone(), (*hash).into()))
            .collect()
    }

    /// Get all global contracts registered by deployer account ID
    pub fn get_global_contracts_registered_by_account_id(&self) -> Vec<(String, AccountId)> {
        self.global_contracts_registered_by_account_id
            .iter()
            .map(|(name, account_id)| (name.clone(), account_id.clone()))
            .collect()
    }

    /// Example of calling a status message contract that was deployed as global
    pub fn call_global_status_contract(&mut self, account_id: AccountId, message: String) {
        ext_status_message::ext(account_id).set_status(message).detach();
    }

    /// Example of complex call using global contracts
    pub fn complex_global_call(&mut self, account_id: AccountId, message: String) -> Promise {
        // 1) call global status_message to record a message from the signer.
        // 2) call global status_message to retrieve the message of the signer.
        // 3) return that message as its own result.
        ext_status_message::ext(account_id.clone())
            .set_status(message)
            .then(Self::ext(env::current_account_id()).get_result(account_id))
    }

    #[handle_result]
    pub fn get_result(
        &self,
        account_id: AccountId,
        #[callback_result] set_status_result: Result<(), PromiseError>,
    ) -> Result<Promise, &'static str> {
        match set_status_result {
            Ok(_) => Ok(ext_status_message::ext(account_id).get_status(env::signer_account_id())),
            Err(_) => Err("Failed to set status"),
        }
    }

    /// Compute the deterministic account ID for a contract deployed with state_init by code hash.
    /// This is a view function that allows predicting the deployment address before actual deployment.
    ///
    /// # Arguments
    /// * `code_hash` - The hash of the global contract code
    /// * `state_data` - Key-value pairs for initial state (base64-encoded strings)
    ///
    /// # Returns
    /// The deterministic AccountId where the contract will be deployed
    pub fn compute_state_init_address_by_hash(
        &self,
        code_hash: Base58CryptoHash,
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> AccountId {

        // Create StateInit structure
        let state_init = StateInit::V1(StateInitV1 {
            code: GlobalContractId::CodeHash(code_hash.into()),
            data,
        });

        // Return the derived account ID
        state_init.derive_account_id()
    }

    /// Compute the deterministic account ID for a contract deployed with state_init by deployer account.
    /// This is a view function that allows predicting the deployment address before actual deployment.
    ///
    /// # Arguments
    /// * `deployer_account_id` - The account that deployed the global contract
    /// * `state_data` - Key-value pairs for initial state (base64-encoded strings)
    ///
    /// # Returns
    /// The deterministic AccountId where the contract will be deployed
    pub fn compute_state_init_address_by_account(
        &self,
        deployer_account_id: AccountId,
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> AccountId {
        // Convert base64 strings to bytes

        // Create StateInit structure
        let state_init = StateInit::V1(StateInitV1 {
            code: GlobalContractId::AccountId(deployer_account_id),
            data
        });

        // Return the derived account ID
        state_init.derive_account_id()
    }

    /// Deploy a global contract instance with state_init using a code hash.
    /// This creates a deterministic account address based on the code hash and initial state.
    ///
    /// # Arguments
    /// * `code_hash` - The hash of the global contract code
    /// * `state_data` - Key-value pairs for initial state (base64-encoded strings)
    /// * `deposit` - Amount to deposit to the new account
    ///
    /// # Returns
    /// Promise for the deployment operation
    #[payable]
    pub fn deploy_global_contract_with_state_init_by_hash(
        &mut self,
        code_hash: Base58CryptoHash,
        state_data: BTreeMap<String, String>,
        deposit: NearToken,
    ) -> Promise {
        // Convert base64 strings to bytes
        let data: BTreeMap<Vec<u8>, Vec<u8>> = state_data
            .into_iter()
            .map(|(k, v)| {
                let key = BASE64.decode(&k).expect("Invalid base64 key");
                let value = BASE64.decode(&v).expect("Invalid base64 value");
                (key, value)
            })
            .collect();

        // Create StateInit
        let state_init = StateInit::V1(StateInitV1 {
            code: GlobalContractId::CodeHash(code_hash.into()),
            data,
        });

        // Derive deterministic account ID
        let target_account_id = state_init.derive_account_id();

        // Deploy
        Promise::new(target_account_id)
            .create_account()
            .add_full_access_key(env::signer_account_pk())
            .state_init(state_init, deposit)
    }

    /// Deploy a global contract instance with state_init using a deployer account ID.
    /// This creates a deterministic account address based on the deployer account and initial state.
    ///
    /// # Arguments
    /// * `deployer_account_id` - The account that deployed the global contract
    /// * `state_data` - Key-value pairs for initial state (base64-encoded strings)
    /// * `deposit` - Amount to deposit to the new account
    ///
    /// # Returns
    /// Promise for the deployment operation
    #[payable]
    pub fn deploy_global_contract_with_state_init_by_account(
        &mut self,
        deployer_account_id: AccountId,
        state_data: BTreeMap<String, String>,
        deposit: NearToken,
    ) -> Promise {
        // Convert base64 strings to bytes
        let data: BTreeMap<Vec<u8>, Vec<u8>> = state_data
            .into_iter()
            .map(|(k, v)| {
                let key = BASE64.decode(&k).expect("Invalid base64 key");
                let value = BASE64.decode(&v).expect("Invalid base64 value");
                (key, value)
            })
            .collect();

        // Create StateInit with AccountId variant
        let state_init = StateInit::V1(StateInitV1 {
            code: GlobalContractId::AccountId(deployer_account_id),
            data,
        });

        let target_account_id = state_init.derive_account_id();

        // Deploy
        Promise::new(target_account_id)
            .create_account()
            .add_full_access_key(env::signer_account_pk())
            .state_init(state_init, deposit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, AccountId};

    fn get_context(predecessor_account_id: AccountId) -> near_sdk::VMContext {
        VMContextBuilder::new()
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id)
            .build()
    }

    #[test]
    fn test_deploy_global_contract() {
        let context = get_context(accounts(1));
        testing_env!(context);

        let mut contract = GlobalFactoryContract::default();
        let code = vec![0u8; 100]; // Mock bytecode

        contract.deploy_global_contract("test_contract".to_string(), code.clone().into()).detach();

        // Check that the contract was recorded
        let stored_hash = contract.get_global_contract_hash("test_contract".to_string());
        assert!(stored_hash.is_some());

        let expected_hash = near_sdk::env::sha256_array(&code);
        assert_eq!(stored_hash.unwrap(), expected_hash.into());
    }

    #[test]
    fn test_list_global_contracts() {
        let context = get_context(accounts(1));
        testing_env!(context);

        let mut contract = GlobalFactoryContract::default();
        let code = vec![0u8; 100];

        contract.deploy_global_contract("test_contract".to_string(), code.clone().into()).detach();

        let contracts = contract.get_global_contracts_registered_by_code_hash();

        let expected_hash: Base58CryptoHash =
            "EoFMvgbdQttJ3vLsVBcgZaWbhEGrJnpqda85qtbu7LbL".parse().unwrap();
        assert_eq!(contracts.len(), 1);
        assert_eq!(contracts[0].0, "test_contract");
        assert_eq!(contracts[0].1, expected_hash);
    }

    #[test]
    fn test_compute_state_init_address_deterministic() {
        let context = get_context(accounts(1));
        testing_env!(context);

        let contract = GlobalFactoryContract::default();
        let code_hash: Base58CryptoHash =
            "EoFMvgbdQttJ3vLsVBcgZaWbhEGrJnpqda85qtbu7LbL".parse().unwrap();

        let mut state_data = BTreeMap::new();
        state_data.insert(
            BASE64.encode(b"key1"),
            BASE64.encode(b"value1"),
        );

        // Same inputs should produce same output (deterministic)
        let addr1 = contract.compute_state_init_address_by_hash(
            code_hash.clone(),
            state_data.clone(),
        );
        let addr2 = contract.compute_state_init_address_by_hash(
            code_hash.clone(),
            state_data.clone(),
        );

        assert_eq!(addr1, addr2, "Addresses should be deterministic");

        // Different state should produce different address
        let mut different_data = BTreeMap::new();
        different_data.insert(
            BASE64.encode(b"key1"),
            BASE64.encode(b"value2"),  // Different value
        );

        let addr3 = contract.compute_state_init_address_by_hash(code_hash, different_data);

        assert_ne!(addr1, addr3, "Different state should produce different addresses");
    }

    #[test]
    fn test_compute_state_init_hash_vs_account() {
        let context = get_context(accounts(1));
        testing_env!(context);

        let contract = GlobalFactoryContract::default();
        let code_hash: Base58CryptoHash =
            "EoFMvgbdQttJ3vLsVBcgZaWbhEGrJnpqda85qtbu7LbL".parse().unwrap();
        let deployer: AccountId = "deployer.near".parse().unwrap();

        let state_data = BTreeMap::new();

        // Same state data with different GlobalContractId variants should differ
        let addr_hash = contract.compute_state_init_address_by_hash(
            code_hash,
            state_data.clone(),
        );
        let addr_account = contract.compute_state_init_address_by_account(
            deployer,
            state_data,
        );

        assert_ne!(
            addr_hash, addr_account,
            "Hash and Account variants should produce different addresses"
        );
    }
}
