module challenge::fuel_cell {

    use sui::coin::{
        Self,
        Coin,
        TreasuryCap,
    };

    public struct FUEL_CELL has drop {}

    fun init(witness: FUEL_CELL, ctx: &mut TxContext) {
        let (treasury, deny_cap, metadata) = coin::create_regulated_currency_v2(
            witness,
            9,
            b"FC",
            b"FuelCell",
            b"",
            option::none(),
            false,
            ctx,
        );
        transfer::public_freeze_object(metadata);
        transfer::public_transfer(treasury, ctx.sender());
        transfer::public_transfer(deny_cap, ctx.sender());
    }

    public(package) fun mint_fuel_cell(
        treasury_cap    : &mut TreasuryCap<FUEL_CELL>,
        receiver        : address,
        amount          : u64,
        ctx             : &mut TxContext
    ) {
        let fuel_cell = treasury_cap.mint(amount, ctx);
        transfer::public_transfer(fuel_cell, receiver);
    }

    public(package) fun burn_fuel_cell(
        treasury_cap    : &mut TreasuryCap<FUEL_CELL>,
        coin            : Coin<FUEL_CELL>,
    ) {
        coin::burn(treasury_cap, coin);
    }

}
