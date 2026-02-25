use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    keccak,
    msg,
    pubkey::Pubkey,
    rent::Rent,
    program::{invoke_signed},
    sysvar::{clock::Clock, Sysvar},
};
use solana_system_interface::instruction as system_instruction;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum SolwannaInstructions {
    Init,
    GetPresentToken,
    ClaimPresentToken { present: String, signature: [u8; 32] },
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct SolwannaState {
    pub santa_pubkey: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct UserState {
    pub has_flag: bool,
}

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

#[cfg(not(feature = "no-entrypoint"))]
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let instruction = SolwannaInstructions::try_from_slice(data)?;

    match instruction {
        SolwannaInstructions::Init => process_init(program_id, accounts),
        SolwannaInstructions::GetPresentToken => process_get_present(program_id, accounts),
        SolwannaInstructions::ClaimPresentToken { present, signature } => process_claim_present(program_id, accounts, present, signature),
    }
}

fn process_init(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let payer = next_account_info(account_info_iter)?;
    let santa_state_account = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    let (pda, bump) = Pubkey::find_program_address(&[b"santa_state"], program_id);
    if pda != *santa_state_account.key {
        return Err(solana_program::program_error::ProgramError::InvalidAccountData);
    }

    let rent = Rent::get()?;
    let space = 32; // Pubkey size
    let lamports = rent.minimum_balance(space);

    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            santa_state_account.key,
            lamports,
            space as u64,
            program_id,
        ),
        &[payer.clone(), santa_state_account.clone(), system_program.clone()],
        &[&[b"santa_state", &[bump]]],
    )?;

    let state = SolwannaState {
        santa_pubkey: *payer.key, // The initializer is Santa
    };
    state.serialize(&mut &mut santa_state_account.data.borrow_mut()[..])?;

    Ok(())
}

fn process_get_present(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let santa_state_account = next_account_info(account_info_iter)?;
    
    let state = SolwannaState::try_from_slice(&santa_state_account.data.borrow())?;
    
    // Generate random present
    let clock = Clock::get()?;
    let presents = ["Toy Train", "Doll", "Bicycle", "Socks", "Candy Cane"];
    let idx = (clock.unix_timestamp as usize) % presents.len();
    let present = presents[idx];

    // Sign the present to ensure authenticity
    let mut data_to_sign = present.as_bytes().to_vec();
    data_to_sign.extend_from_slice(state.santa_pubkey.as_ref());
    data_to_sign.reverse();
    let signature = keccak::hash(&data_to_sign);

    msg!("Here is your voucher for a {}: {:?}", present, signature.to_bytes());

    Ok(())
}

fn process_claim_present(program_id: &Pubkey, accounts: &[AccountInfo], present: String, signature: [u8; 32]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let payer = next_account_info(account_info_iter)?;
    let santa_state_account = next_account_info(account_info_iter)?;
    let user_state_account = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    let state = SolwannaState::try_from_slice(&santa_state_account.data.borrow())?;

    // Verify signature
    let mut data_to_verify = present.as_bytes().to_vec();
    data_to_verify.extend_from_slice(state.santa_pubkey.as_ref());
    data_to_verify.reverse();
    let expected_signature = keccak::hash(&data_to_verify);

    if signature != expected_signature.to_bytes() {
        msg!("Invalid voucher! You get a big lump of coal!");
        return Ok(());
    }

    if present == "FLAG" {
        msg!("Ho ho ho! You got the flag! Congratulations!");
        
        // Create user state to mark flag captured
        let (pda, bump) = Pubkey::find_program_address(&[b"user_state", payer.key.as_ref()], program_id);
        if pda != *user_state_account.key {
             return Err(solana_program::program_error::ProgramError::InvalidAccountData);
        }
        
        if user_state_account.data_is_empty() {
             let rent = Rent::get()?;
             let space = 1; // bool
             let lamports = rent.minimum_balance(space);
             
             invoke_signed(
                &system_instruction::create_account(
                    payer.key,
                    user_state_account.key,
                    lamports,
                    space as u64,
                    program_id,
                ),
                &[payer.clone(), user_state_account.clone(), system_program.clone()],
                &[&[b"user_state", payer.key.as_ref(), &[bump]]],
            )?;
        }
        
        let mut user_data = UserState { has_flag: true };
        user_data.serialize(&mut &mut user_state_account.data.borrow_mut()[..])?;
    } else {
        msg!("Enjoy your {}!", present);
    }

    Ok(())
}