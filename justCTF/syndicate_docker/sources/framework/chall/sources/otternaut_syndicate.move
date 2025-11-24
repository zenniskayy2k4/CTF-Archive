module challenge::otternaut_syndicate {

    use sui::object::new;
    use sui::coin::{ TreasuryCap, Coin };
    use sui::bag::{ Self, Bag, add, remove, contains };
    use std::type_name::{ TypeName, get };
    use sui::balance::{ Self, Balance, Supply, create_supply };

    use challenge::cryon_credits::{ CRYON_CREDITS };

    const NOT_SOLVED: u64 = 1335;
    const WRONG_ACCOUNT: u64 = 1336;
    const NOT_ENOUGH_FUNDS: u64 = 1337;
    const INCORRECT_CAP: u64 = 1338;
    const ACCOUNT_WITH_DEBT: u64 = 1339;
    const REQUIRED_AMOUNT: u64 = 3_333;

    public struct UnderbankAccount<phantom X> has key, store {
        id: UID,
        owner: address,
        dx: u64,
        debt_bag: Bag,
    }

    public struct CryonUnderbank<phantom X, phantom SX> has key, store {
        id: UID,
        supply: Supply<SX>,
        bal: Balance<X>,
        share_price: u128,
    }

    public struct BankCap has key, store {
        id: UID,
        bank_id: ID,
    }

    public struct CouncilGuard has key {
        id: UID,
        bal: Balance<CRYON_CREDITS>,
        is_corrupted: bool
    }

    public struct LendReceipt<phantom X> {
        account_id: ID
    }

    public struct S_CRYON_CREDITS has drop {}

    fun init(ctx: &mut TxContext) {
        let supply = create_supply(S_CRYON_CREDITS {});
        let share_price = 5 << 64;
        let (bank, bank_cap) = new_underbank<CRYON_CREDITS, S_CRYON_CREDITS>(
            supply, share_price, ctx
        );

        transfer::share_object(bank);
        transfer::share_object(CouncilGuard {
            id: new(ctx),
            bal: balance::zero(),
            is_corrupted: false,
        });
        transfer::transfer(bank_cap, ctx.sender());
    }

    public fun new_underbank<X, SX>(
        supply      : Supply<SX>,
        share_price : u128,
        ctx         : &mut TxContext,
    ): (CryonUnderbank<X, SX>, BankCap) {
        let bank_id = new(ctx);
        let bank_cap = BankCap {
            id: new(ctx),
            bank_id: bank_id.to_inner(),
        };
        let underbank = CryonUnderbank<X, SX> {
            id: bank_id,
            supply,
            share_price,
            bal: balance::zero(),
        };
        return (underbank, bank_cap)
    }

    public fun open_account<X>(
        ctx         : &mut TxContext,
    ): UnderbankAccount<X> {
        let owner = ctx.sender();
        UnderbankAccount<X> {
            id: new(ctx),
            owner,
            dx: 0,
            debt_bag: bag::new(ctx),
        }
    }

    public fun add_funds<X, SX>(
        bank_cap    : &BankCap,
        bank        : &mut CryonUnderbank<X, SX>,
        cap         : &mut TreasuryCap<X>,
        amount      : u64,
        ctx         : &mut TxContext,
    ) {
        let coin = cap.mint(amount, ctx);
        assert!(bank_cap.bank_id == bank.id.to_inner(), INCORRECT_CAP);
        bank.bal.join(coin.into_balance());
    }

    public fun lend<X, SX>(
        account     : &mut UnderbankAccount<X>,
        bank        : &mut CryonUnderbank<X, SX>,
        amount      : u64,
        ctx         : &mut TxContext,
    ): (Coin<X>, LendReceipt<X>){
        assert!(account.dx == 0, ACCOUNT_WITH_DEBT);
        assert!(amount <= bank.bal.value(), NOT_ENOUGH_FUNDS);
        let bal = bank.bal.split(amount);
        let debt_shares = bank.calculate_coin_to_shares(amount);
        account.add_shares(bank.mint_shares(debt_shares));
        account.dx = amount;
        return (
            bal.into_coin(ctx),
            LendReceipt { account_id: account.id.to_inner() }
        )
    }

    public fun repay<X, SX>(
        account     : &mut UnderbankAccount<X>,
        bank        : &mut CryonUnderbank<X, SX>,
        coin        : Coin<X>,
    ) {
        let debt_shares = account.take_all<X, SX>();
        let amount = bank.calculate_shares_to_coin(debt_shares.value());
        assert!(coin.value() == amount, NOT_ENOUGH_FUNDS);
        bank.bal.join(coin.into_balance());
        bank.burn_shares(debt_shares);
        account.dx = 0;
    }

    public fun consume_receipt<X>(
        account     : &mut UnderbankAccount<X>,
        receipt     : LendReceipt<X>,
    ) {
        let LendReceipt { account_id } = receipt;
        assert!(account_id == account.id.to_inner(), WRONG_ACCOUNT);
        assert!(account.dx == 0, ACCOUNT_WITH_DEBT);
    }

    fun calculate_coin_to_shares<X, SX>(
        _bank       : &CryonUnderbank<X, SX>,
        amount      : u64
    ): u64 {
        amount
    }

    fun calculate_shares_to_coin<X, SX>(
        bank        : &CryonUnderbank<X, SX>,
        amount      : u64
    ): u64 {
        let coin_amt = (amount as u128) * bank.share_price;
        (coin_amt >> 64) as u64
    }

    fun mint_shares<X, SX>(
        bank        : &mut CryonUnderbank<X, SX>,
        amount      : u64,
    ): Balance<SX> {
        bank.supply.increase_supply(amount)
    }

    fun burn_shares<X, SX>(
        bank        : &mut CryonUnderbank<X, SX>,
        shares      : Balance<SX>
    ) {
        bank.supply.decrease_supply(shares);
    }

    fun add_shares<X, SX>(
        account     : &mut UnderbankAccount<X>,
        shares      : Balance<SX>,
    ) {
        let tname = get<SX>();
        if (account.debt_bag.contains(tname)) {
            account.debt_bag.borrow_mut<TypeName, Balance<SX>>(tname).join(shares);
        } else {
            account.debt_bag.add(tname, shares);
        }
    }

    fun take_all<X, SX>(
        account     : &mut UnderbankAccount<X>,
    ): Balance<SX> {
        let tname = get<SX>();
        if (account.debt_bag.contains(tname)) {
            return account.debt_bag.remove(tname)
        } else {
            return balance::zero()
        }
    }

    public fun bribe_guard(
        guard       : &mut CouncilGuard,
        coins       : Coin<CRYON_CREDITS>,
    ) {
        assert!(coins.value() >= REQUIRED_AMOUNT, NOT_ENOUGH_FUNDS);
        guard.bal.join(coins.into_balance());
        guard.is_corrupted = true;
    }

    public fun is_solved(
        guard       : &CouncilGuard,
    ) {
        assert!(guard.is_corrupted, NOT_SOLVED);
    }

}
