#[derive(Debug, Clone, interactive_clap_derive::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct SaveKeypairToKeychain {
    #[interactive_clap(named_arg)]
    ///Select network
    network_config: crate::network_for_transaction::NetworkForTransactionArgs,
}

impl SaveKeypairToKeychain {
    pub async fn process(
        &self,
        config: crate::config::Config,
        key_pair_properties: crate::common::KeyPairProperties,
        prepopulated_unsigned_transaction: near_primitives::transaction::Transaction,
    ) -> crate::CliResult {
        let network_config = self.network_config.get_network_config(config.clone());
        crate::common::save_access_key_to_keychain(
            network_config,
            config.credentials_home_dir.clone(),
            key_pair_properties,
            &prepopulated_unsigned_transaction.receiver_id,
        )
        .await
        .map_err(|err| {
            color_eyre::Report::msg(format!("Failed to save a file with access key: {}", err))
        })?;
        crate::transaction_signature_options::sign_with(
            self.network_config.clone(),
            prepopulated_unsigned_transaction,
            config,
        )
        .await
    }
}
