module solution::solution {
    use challenge::otternaut_exodus::{OtternautCapsule, fuel_capsule};
    use sui::coin::Coin;
    use challenge::fuel_cell::FUEL_CELL;

    public entry fun solve(
        fuel_cell: Coin<FUEL_CELL>,
        capsule: &mut OtternautCapsule,
    ) {
        fuel_capsule(fuel_cell, capsule);
    }
}