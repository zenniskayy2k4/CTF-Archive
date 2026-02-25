namespace UnityEngine.Rendering
{
	public enum LightProbeOutsideHullStrategy
	{
		[InspectorName("Find closest Light Probe")]
		kLightProbeSearchTetrahedralHull = 0,
		[InspectorName("Use Ambient Probe")]
		kLightProbeUseAmbientProbe = 1
	}
}
