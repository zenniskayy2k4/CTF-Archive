namespace UnityEngine.Rendering
{
	public enum AdvancedUpscalers : byte
	{
		[InspectorName("Deep Learning Super Sampling (DLSS)")]
		DLSS = 0,
		[InspectorName("FidelityFX Super Resolution 2.0 (FSR2)")]
		FSR2 = 1,
		[InspectorName("Spatial-Temporal Post-Processing (STP)")]
		STP = 2
	}
}
