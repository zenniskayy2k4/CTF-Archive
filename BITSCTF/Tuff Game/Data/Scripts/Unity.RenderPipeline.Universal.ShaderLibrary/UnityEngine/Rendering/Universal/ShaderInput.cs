using System;

namespace UnityEngine.Rendering.Universal
{
	public static class ShaderInput
	{
		[Obsolete("ShaderInput.ShadowData was deprecated. Shadow slice matrices and per-light shadow parameters are now passed to the GPU using entries in buffers m_AdditionalLightsWorldToShadow_SSBO and m_AdditionalShadowParams_SSBO. #from(2021.1) #breakingFrom(2023.1)", true)]
		public struct ShadowData
		{
			public Matrix4x4 worldToShadowMatrix;

			public Vector4 shadowParams;
		}

		[GenerateHLSL(PackingRules.Exact, false, false, false, 1, false, false, false, -1, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\ShaderLibrary\\ShaderTypes.cs")]
		public struct LightData
		{
			public Vector4 position;

			public Vector4 color;

			public Vector4 attenuation;

			public Vector4 spotDirection;

			public Vector4 occlusionProbeChannels;

			public uint layerMask;
		}
	}
}
