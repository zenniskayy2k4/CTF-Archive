use sol_ctf_framework::ChallengeBuilder;

use solana_sdk::{
    account::Account, message::{AccountMeta, Instruction}, pubkey::Pubkey, signature::{Keypair, Signer}
};
use solana_system_interface::program as system_program;

use std::{
    fs,
    io::Write,
    error::Error,
    net::{
        TcpListener,
        TcpStream
    },
};

use borsh::{BorshDeserialize, BorshSerialize};

use solwanna::{SolwannaState, SolwannaInstructions, UserState};

#[tokio::main]  
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:5001")?;
    loop {
        let (stream, _) = listener.accept()?;
        // move each socket to a Tokio task
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("handler error: {e}");
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut builder = ChallengeBuilder::try_from(socket.try_clone().unwrap()).unwrap();

    // load programs
    let solve_pubkey = match builder.input_program() {
        Ok(pubkey) => pubkey,
        Err(e) => {
            writeln!(socket, "Error: cannot add solve program → {e}")?;
            return Ok(());
        }
    };
    let program_key = Pubkey::new_unique();
    let program_pubkey = builder.add_program(&"../challenge/solwanna.so", Some(program_key)).expect("Duplicate pubkey supplied");

    let user = Keypair::new();
    let admin = Keypair::new();
    writeln!(socket, "program: {}", program_pubkey)?;
    writeln!(socket, "user: {}", user.pubkey())?;

    const INIT_BAL: u64 = 1_000_000_000;

    builder
        .builder
        .add_account(user.pubkey(), Account::new(INIT_BAL, 0, &system_program::ID));

    builder.builder.add_account(admin.pubkey(), Account::new(INIT_BAL, 0, &system_program::ID));

    let (santa_state_pda, _) = Pubkey::find_program_address(&[b"santa_state"], &program_pubkey);

    let mut challenge = builder.build().await;

    let mut data = vec![];

    SolwannaInstructions::Init.serialize(&mut data).unwrap();
    let init_ix = Instruction {
        program_id: program_pubkey,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(santa_state_pda, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: data,
    };

    // Init Santa
    challenge.run_ixs_full(
        &[init_ix],
        &[&admin],
        &admin.pubkey(),
    ).await?;

    // Run solve
    let ixs = challenge.read_instruction(solve_pubkey).unwrap();
    challenge.run_ixs_full(
        &[ixs],
        &[&user],
        &user.pubkey(),
    ).await?;

    // Check if user got the flag
    let (user_state_pda, _) = Pubkey::find_program_address(&[b"user_state", user.pubkey().as_ref()], &program_pubkey);
    
    let user_state_account = challenge.ctx.banks_client.get_account(user_state_pda).await?;
    
    if let Some(account) = user_state_account {
        if let Ok(state) = UserState::deserialize(&mut &account.data[..]) {
            if state.has_flag {
                let flag = fs::read_to_string("flag.txt").unwrap();
                writeln!(socket, "Flag: {}", flag)?;
                return Ok(());
            }
        }
    }

    writeln!(socket, "No flag for you!")?;

    Ok(())
}
