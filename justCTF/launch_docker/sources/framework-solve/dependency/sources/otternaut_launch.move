module challenge::otternaut_launch {

    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;

    //
    // ENUMS
    //
    public enum CapsuleStatus has store, drop {
        ASSEMBLY_STARTED,
        READY_FOR_LAUNCH
    }

    //
    // OBJECTS
    //
    public struct LaunchCapsule has key {
        id: UID,
        status: CapsuleStatus,
        flight_software_version: u8,
        safety_rating: u8,
    }

    public struct OtternautLab has key {
        id: UID,
    }

    public struct LaunchInspectionLab has key {
        id: UID,
        required_safety: u8,
    }

    public struct MicroWrench has key {
        id: UID,
    }

    public struct AvionicsCalibrator has key {
        id: UID,
    }

    public struct HullFrame has key {
        id: UID,
    }

    public struct Boosters {
        thrust_rating: u8,
    }

    public struct OtterFlightOS {
        version: u8,
    }

    //
    // CONSTANTS
    //
    const REQUIRED_OS_VERSION: u8 = 42;
    const REQUIRED_SAFETY_RATING: u8 = 9;

    const CAPSULE_NOT_READY: u64 = 4200;
    const INVALID_OS_VERSION: u64 = 4201;
    const INSUFFICIENT_SAFETY: u64 = 4202;

    //
    // INITIALIZATION
    //
    fun init(ctx: &mut TxContext) {
        transfer::share_object(LaunchCapsule {
            id: object::new(ctx),
            status: CapsuleStatus::ASSEMBLY_STARTED,
            flight_software_version: 0,
            safety_rating: 0,
        });
        transfer::share_object(OtternautLab { id: object::new(ctx) });
        transfer::share_object(LaunchInspectionLab {
            id: object::new(ctx),
            required_safety: REQUIRED_SAFETY_RATING,
        });
    }

    //
    // TOOL PREPARATION
    //
    public fun prepare_tools(
        _lab: &OtternautLab,
        user: address,
        ctx: &mut TxContext,
    ) {
        transfer::transfer(MicroWrench { id: object::new(ctx) }, user);
        transfer::transfer(AvionicsCalibrator { id: object::new(ctx) }, user);
        transfer::transfer(HullFrame { id: object::new(ctx) }, user);
    }

    //
    // BUILD LOGIC
    //
    public fun assemble_launch_capsule(
        capsule: &mut LaunchCapsule,
        _lab: &OtternautLab,
        lab: &LaunchInspectionLab,
        wrench: MicroWrench,
        calibrator: AvionicsCalibrator,
        frame: HullFrame,
        boosters: Boosters,
        os: OtterFlightOS,
    ) {
        let OtterFlightOS { version } = os;
        assert!(version == REQUIRED_OS_VERSION, INVALID_OS_VERSION);
        install_frame(frame);
        tighten_bolts(wrench);
        calibrate_avionics(calibrator);
        inspect_safety(lab, capsule, boosters);

        capsule.flight_software_version = version;
        capsule.status = CapsuleStatus::READY_FOR_LAUNCH;
    }

    //
    // FINAL CHECK
    //
    public fun check_capsule_ready(capsule: &LaunchCapsule) {
        assert!(&capsule.status == CapsuleStatus::READY_FOR_LAUNCH, CAPSULE_NOT_READY);
        assert!(capsule.flight_software_version == REQUIRED_OS_VERSION, INVALID_OS_VERSION);
    }

    //
    // HELPER FUNCTIONS
    //
    public fun generate_flight_os(_lab: &OtternautLab, version: u8): OtterFlightOS {
        OtterFlightOS { version }
    }

    public fun build_boosters(_lab: &OtternautLab, thrust_rating: u8): Boosters {
        Boosters { thrust_rating }
    }

    fun install_frame(frame: HullFrame) {
        let HullFrame { id } = frame;
        id.delete();
    }

    fun tighten_bolts(wrench: MicroWrench) {
        let MicroWrench { id } = wrench;
        id.delete();
    }

    fun calibrate_avionics(calibrator: AvionicsCalibrator) {
        let AvionicsCalibrator { id } = calibrator;
        id.delete();
    }

    fun inspect_safety(lab: &LaunchInspectionLab, capsule: &mut LaunchCapsule, boosters: Boosters) {
        let Boosters { thrust_rating } = boosters;
        assert!(thrust_rating >= lab.required_safety, INSUFFICIENT_SAFETY);
        capsule.safety_rating = thrust_rating;
    }
}

