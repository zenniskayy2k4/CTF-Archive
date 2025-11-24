module challenge::cryon_credits {

    use sui::coin::{ Self, TreasuryCap, Coin };

    public struct CRYON_CREDITS has drop {}

    fun init(witness: CRYON_CREDITS, ctx: &mut TxContext) {
	      let (mut treasury, metadata) = coin::create_currency(
            witness,
            6,
            b"CC",
            b"CryonCredits",
            b"",
            option::none(),
            ctx,
        );
        transfer::public_freeze_object(metadata);
        treasury.mint_and_transfer(3_333, ctx.sender(), ctx);
        transfer::public_transfer(treasury, ctx.sender())
    }

}
