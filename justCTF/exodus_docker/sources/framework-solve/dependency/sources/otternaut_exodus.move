module challenge::otternaut_exodus {

    use sui::coin::{
        Self,
        Coin,
        TreasuryCap,
        DenyCapV2,
    };
    use sui::balance::{
        Self,
        Balance
    };
    use sui::deny_list::DenyList;
    use challenge::fuel_cell::{
        FUEL_CELL,
        mint_fuel_cell,
        burn_fuel_cell,
    };
    use fun burn_fuel_cell as TreasuryCap.burn_fuel_cell;
    use fun mint_fuel_cell as TreasuryCap.mint_fuel_cell;

    /// the vault prepared to store the forbidden fuel cells
    public struct CouncilVault has key {
        id: object::UID,
        forbidden_vault: Balance<FUEL_CELL>,
    }

    /// capability to issue the forbidded fuel cells
    public struct CouncilCap has key {
        id: object::UID,
    }

    /// the otternaut's capsule
    public struct OtternautCapsule has key {
        id: object::UID,
        fuel_vault: Balance<FUEL_CELL>
    }

    /// error thrown if capsule's tank is empty
    const TANK_EMPTY: u64 = 1337;

    fun init(ctx: &mut TxContext) {
        transfer::transfer(
            CouncilCap { id: object::new(ctx) },
            ctx.sender()
        );
        transfer::share_object(
            CouncilVault {
                id: object::new(ctx),
                forbidden_vault: balance::zero<FUEL_CELL>(),
            }
        );
        transfer::share_object(
            OtternautCapsule {
                id: object::new(ctx),
                fuel_vault: balance::zero<FUEL_CELL>(),
            }
        );
    }

    /// **DANGEROUS**
    /// steal the Forbidden Fuel Cell
    public fun steal_forbidden_fuel_cell(
        _               : &CouncilCap,
        receiver        : address,
        treasury_cap    : &mut TreasuryCap<FUEL_CELL>,
        deny_cap        : &mut DenyCapV2<FUEL_CELL>,
        deny_list       : &mut DenyList,
        ctx             : &mut TxContext
    ) {
        treasury_cap.mint_fuel_cell(receiver, 1, ctx);

        coin::deny_list_v2_add(deny_list, deny_cap, receiver, ctx);
    }

    /// fuel the capsule
    public fun fuel_capsule(
        fuel_cell       : Coin<FUEL_CELL>,
        capsule         : &mut OtternautCapsule,
    ) {
        let fuel_balance = fuel_cell.into_balance();
        capsule.fuel_vault.join(fuel_balance);
    }

    /// **DANGEROUS**
    /// burn the fuel
    public fun burn_fuel(
        fuel_cell       : Coin<FUEL_CELL>,
        treasury_cap    : &mut TreasuryCap<FUEL_CELL>,
    ) {
        treasury_cap.burn_fuel_cell(fuel_cell);
    }

    /// check if capsule is ready for exodus
    public fun verify_tank(capsule: &OtternautCapsule) {
        let fuel_cells = capsule.fuel_vault.value();
        assert!(fuel_cells > 0, TANK_EMPTY);
    }

}

