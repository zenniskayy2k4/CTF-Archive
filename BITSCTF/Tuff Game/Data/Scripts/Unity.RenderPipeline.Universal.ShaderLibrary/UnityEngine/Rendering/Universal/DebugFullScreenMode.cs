namespace UnityEngine.Rendering.Universal
{
	[GenerateHLSL(PackingRules.Exact, true, false, false, 1, false, false, false, -1, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\ShaderLibrary\\Debug\\DebugViewEnums.cs")]
	public enum DebugFullScreenMode
	{
		None = 0,
		Depth = 1,
		[InspectorName("Motion Vector (100x, normalized)")]
		MotionVector = 2,
		AdditionalLightsShadowMap = 3,
		MainLightShadowMap = 4,
		AdditionalLightsCookieAtlas = 5,
		ReflectionProbeAtlas = 6,
		STP = 7
	}
}
