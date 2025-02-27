#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct DeleteAccount {
    ///What Account ID to be deleted
    account_id: crate::types::account_id::AccountId,
    #[interactive_clap(named_arg)]
    ///Enter the beneficiary ID to delete this account ID
    beneficiary: BeneficiaryAccount,
}

impl DeleteAccount {
    pub async fn process(&self, config: crate::config::Config) -> crate::CliResult {
        self.beneficiary
            .process(config, self.account_id.clone().into())
            .await
    }
}

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct BeneficiaryAccount {
    ///Specify a beneficiary
    beneficiary_account_id: crate::types::account_id::AccountId,
    #[interactive_clap(named_arg)]
    ///Select network
    network_config: crate::network_for_transaction::NetworkForTransactionArgs,
}

impl BeneficiaryAccount {
    pub async fn process(
        &self,
        config: crate::config::Config,
        account_id: near_primitives::types::AccountId,
    ) -> crate::CliResult {
        let beneficiary_id: near_primitives::types::AccountId =
            self.beneficiary_account_id.clone().into();
        let prepopulated_unsigned_transaction = near_primitives::transaction::Transaction {
            signer_id: account_id.clone(),
            public_key: near_crypto::PublicKey::empty(near_crypto::KeyType::ED25519),
            nonce: 0,
            receiver_id: account_id,
            block_hash: Default::default(),
            actions: vec![near_primitives::transaction::Action::DeleteAccount(
                near_primitives::transaction::DeleteAccountAction { beneficiary_id },
            )],
        };
        crate::transaction_signature_options::sign_with(
            self.network_config.clone(),
            prepopulated_unsigned_transaction,
            config,
        )
        .await
    }
}
