use strum::{EnumDiscriminants, EnumIter, EnumMessage};

mod access_key_type;
mod autogenerate_new_keypair;
mod use_manually_provided_seed_phrase;
mod use_public_key;

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct AddKeyCommand {
    ///Which account should You add an access key to?
    owner_account_id: crate::types::account_id::AccountId,
    #[interactive_clap(subcommand)]
    permission: AccessKeyPermission,
}

impl AddKeyCommand {
    pub async fn process(&self, config: crate::config::Config) -> crate::CliResult {
        let prepopulated_unsigned_transaction = near_primitives::transaction::Transaction {
            signer_id: self.owner_account_id.clone().into(),
            public_key: near_crypto::PublicKey::empty(near_crypto::KeyType::FALCON512),
            nonce: 0,
            receiver_id: self.owner_account_id.clone().into(),
            block_hash: Default::default(),
            actions: vec![],
        };
        match self.permission.clone() {
            AccessKeyPermission::GrantFullAccess(full_access_type) => {
                full_access_type
                    .process(config, prepopulated_unsigned_transaction)
                    .await
            }
            AccessKeyPermission::GrantFunctionCallAccess(function_call_type) => {
                function_call_type
                    .process(config, prepopulated_unsigned_transaction)
                    .await
            }
        }
    }
}

#[derive(Debug, Clone, EnumDiscriminants, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
#[strum_discriminants(derive(EnumMessage, EnumIter))]
///Select a permission that you want to add to the access key
pub enum AccessKeyPermission {
    #[strum_discriminants(strum(
        message = "grant-full-access           - A permission with full access"
    ))]
    ///Provide data for a full access key
    GrantFullAccess(self::access_key_type::FullAccessType),
    #[strum_discriminants(strum(
        message = "grant-function-call-access  - A permission with function call"
    ))]
    ///Provide data for a function-call access key
    GrantFunctionCallAccess(self::access_key_type::FunctionCallType),
}

#[derive(Debug, Clone, EnumDiscriminants, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
#[strum_discriminants(derive(EnumMessage, EnumIter))]
///Add an access key for this account
pub enum AccessKeyMode {
    #[strum_discriminants(strum(
        message = "autogenerate-new-keypair-ed25519         - Automatically generate an Ed25519 key pair"
    ))]
    ///Automatically generate an Ed25519 key pair
    AutogenerateNewKeypairEd25519(self::autogenerate_new_keypair::GenerateKeypair),
    #[strum_discriminants(strum(
        message = "autogenerate-new-keypair-falcon512        - Automatically generate a Falcon512 key pair"
    ))]
    ///Automatically generate a Falcon512 key pair
    AutogenerateNewKeypairFalcon512(self::autogenerate_new_keypair::GenerateKeypair),
    #[strum_discriminants(strum(
        message = "use-manually-provided-seed-prase-ed25519  - Use the provided seed phrase manually to generate an Ed25519 keypair"
    ))]
    ///Use the provided seed phrase manually
    UseManuallyProvidedSeedPhraseEd25519(
        self::use_manually_provided_seed_phrase::AddAccessWithSeedPhraseAction,
    ),
    #[strum_discriminants(strum(
        message = "use-manually-provided-seed-prase-falcon512  - Use the provided seed phrase manually to generate a Falcon512 keypair"
    ))]
    ///Use the provided seed phrase manually
    UseManuallyProvidedSeedPhraseFalcon512(
        self::use_manually_provided_seed_phrase::AddAccessWithSeedPhraseAction,
    ),
    #[strum_discriminants(strum(
        message = "use-manually-provided-public-key  - Use the provided public key manually"
    ))]
    ///Use the provided public key manually
    UseManuallyProvidedPublicKey(self::use_public_key::AddAccessKeyAction),
}

impl AccessKeyMode {
    pub async fn process(
        &self,
        config: crate::config::Config,
        prepopulated_unsigned_transaction: near_primitives::transaction::Transaction,
        permission: near_primitives::account::AccessKeyPermission,
    ) -> crate::CliResult {
        match self {
            AccessKeyMode::UseManuallyProvidedPublicKey(add_access_key_action) => {
                add_access_key_action
                    .process(config, prepopulated_unsigned_transaction, permission)
                    .await
            }
            AccessKeyMode::AutogenerateNewKeypairEd25519(generate_keypair) => {
                generate_keypair
                    .process(config, prepopulated_unsigned_transaction, permission, near_crypto::KeyType::ED25519)
                    .await
            }
            AccessKeyMode::AutogenerateNewKeypairFalcon512(generate_keypair) => {
                generate_keypair
                    .process(config, prepopulated_unsigned_transaction, permission, near_crypto::KeyType::FALCON512)
                    .await
            }
            AccessKeyMode::UseManuallyProvidedSeedPhraseEd25519(add_access_with_seed_phrase_action) => {
                add_access_with_seed_phrase_action
                    .process(config, prepopulated_unsigned_transaction, permission, near_crypto::KeyType::ED25519)
                    .await
            }
            AccessKeyMode::UseManuallyProvidedSeedPhraseFalcon512(add_access_with_seed_phrase_action) => {
                add_access_with_seed_phrase_action
                    .process(config, prepopulated_unsigned_transaction, permission, near_crypto::KeyType::FALCON512)
                    .await
            }
        }
    }
}
