module solution::solution {
    use challenge::otternaut_launch::{
        LaunchCapsule, OtternautLab, LaunchInspectionLab, MicroWrench, AvionicsCalibrator, HullFrame
    };

    public fun solve(
        capsule: &mut LaunchCapsule,
        otternaut_lab: &OtternautLab,
        inspection_lab: &LaunchInspectionLab,
        wrench: MicroWrench,
        calibrator: AvionicsCalibrator,
        frame: HullFrame,
    ) {
        // Create flight OS with the required version 42
        let os = challenge::otternaut_launch::generate_flight_os(otternaut_lab, 42);

        // Build boosters with the required thrust rating of 9
        let boosters = challenge::otternaut_launch::build_boosters(otternaut_lab, 9);

        // Assemble the capsule
        challenge::otternaut_launch::assemble_launch_capsule(
            capsule,
            otternaut_lab,
            inspection_lab,
            wrench,
            calibrator,
            frame,
            boosters,
            os,
        );
    }
}