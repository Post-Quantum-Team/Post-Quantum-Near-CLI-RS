use dialoguer::Input;
use serde_json::json;

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct SendNftCommand {
    ///What is the nft-contract account ID?
    nft_contract_account_id: crate::types::account_id::AccountId,
    ///What is the receiver account ID?
    receiver_account_id: crate::types::account_id::AccountId,
    ///Enter an token_id for NFT
    token_id: String,
    #[interactive_clap(long = "prepaid-gas")]
    #[interactive_clap(skip_default_input_arg)]
    ///Enter gas for function call
    gas: crate::common::NearGas,
    #[interactive_clap(long = "attached-deposit")]
    #[interactive_clap(skip_default_input_arg)]
    ///Enter deposit for a function call
    deposit: crate::common::NearBalance,
    #[interactive_clap(named_arg)]
    ///Select network
    network_config: crate::network_for_transaction::NetworkForTransactionArgs,
}

impl SendNftCommand {
    fn input_gas(
        _context: &crate::GlobalContext,
    ) -> color_eyre::eyre::Result<crate::common::NearGas> {
        println!();
        let gas: u64 = loop {
            let input_gas: crate::common::NearGas = Input::new()
                .with_prompt("Enter gas for function call")
                .with_initial_text("100 TeraGas")
                .interact_text()?;
            let crate::common::NearGas { inner: num } = input_gas;
            let gas = num;
            if gas <= 300000000000000 {
                break gas;
            } else {
                println!("You need to enter a value of no more than 300 TERAGAS")
            }
        };
        Ok(gas.into())
    }

    fn input_deposit(
        _context: &crate::GlobalContext,
    ) -> color_eyre::eyre::Result<crate::common::NearBalance> {
        println!();
        let deposit: crate::common::NearBalance = Input::new()
            .with_prompt(
                "Enter deposit for a function call (example: 10NEAR or 0.5near or 10000yoctonear).",
            )
            .with_initial_text("1 yoctoNEAR")
            .interact_text()?;
        Ok(deposit)
    }

    pub async fn process(
        &self,
        config: crate::config::Config,
        owner_account_id: near_primitives::types::AccountId,
    ) -> crate::CliResult {
        let method_name = "nft_transfer".to_string();
        let args = json!({
            "receiver_id": self.receiver_account_id.to_string(),
            "token_id": self.token_id
        })
        .to_string()
        .into_bytes();
        let prepopulated_unsigned_transaction = near_primitives::transaction::Transaction {
            signer_id: owner_account_id,
            public_key: near_crypto::PublicKey::empty(near_crypto::KeyType::ED25519),
            nonce: 0,
            receiver_id: self.nft_contract_account_id.clone().into(),
            block_hash: Default::default(),
            actions: vec![near_primitives::transaction::Action::FunctionCall(
                near_primitives::transaction::FunctionCallAction {
                    method_name,
                    args,
                    gas: self.gas.clone().inner,
                    deposit: self.deposit.clone().to_yoctonear(),
                },
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
