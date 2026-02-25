namespace UnityEngine.Rendering.Universal
{
	internal enum URPProfileId
	{
		UniversalRenderTotal = 0,
		UpdateVolumeFramework = 1,
		RenderCameraStack = 2,
		AdditionalLightsShadow = 3,
		ColorGradingLUT = 4,
		CopyColor = 5,
		CopyDepth = 6,
		DrawDepthNormalPrepass = 7,
		DepthPrepass = 8,
		UpdateReflectionProbeAtlas = 9,
		DrawOpaqueObjects = 10,
		DrawTransparentObjects = 11,
		DrawScreenSpaceUI = 12,
		RecordRenderGraph = 13,
		LightCookies = 14,
		MainLightShadow = 15,
		ResolveShadows = 16,
		SSAO = 17,
		StopNaNs = 18,
		SMAA = 19,
		GaussianDepthOfField = 20,
		BokehDepthOfField = 21,
		TemporalAA = 22,
		MotionBlur = 23,
		PaniniProjection = 24,
		UberPostProcess = 25,
		Bloom = 26,
		LensFlareDataDrivenComputeOcclusion = 27,
		LensFlareDataDriven = 28,
		LensFlareScreenSpace = 29,
		DrawMotionVectors = 30,
		DrawFullscreen = 31,
		[HideInDebugUI]
		RG_SetupPostFX = 32,
		[HideInDebugUI]
		RG_StopNaNs = 33,
		[HideInDebugUI]
		RG_SMAAMaterialSetup = 34,
		[HideInDebugUI]
		RG_SMAAEdgeDetection = 35,
		[HideInDebugUI]
		RG_SMAABlendWeight = 36,
		[HideInDebugUI]
		RG_SMAANeighborhoodBlend = 37,
		[HideInDebugUI]
		RG_SetupDoF = 38,
		[HideInDebugUI]
		RG_DOFComputeCOC = 39,
		[HideInDebugUI]
		RG_DOFDownscalePrefilter = 40,
		[HideInDebugUI]
		RG_DOFBlurH = 41,
		[HideInDebugUI]
		RG_DOFBlurV = 42,
		[HideInDebugUI]
		RG_DOFBlurBokeh = 43,
		[HideInDebugUI]
		RG_DOFPostFilter = 44,
		[HideInDebugUI]
		RG_DOFComposite = 45,
		[HideInDebugUI]
		RG_TAA = 46,
		[HideInDebugUI]
		RG_TAACopyHistory = 47,
		[HideInDebugUI]
		RG_MotionBlur = 48,
		[HideInDebugUI]
		RG_BloomSetup = 49,
		[HideInDebugUI]
		RG_BloomPrefilter = 50,
		[HideInDebugUI]
		RG_BloomDownsample = 51,
		[HideInDebugUI]
		RG_BloomUpsample = 52,
		[HideInDebugUI]
		RG_UberPostSetupBloomPass = 53,
		[HideInDebugUI]
		RG_UberPost = 54,
		[HideInDebugUI]
		RG_FinalSetup = 55,
		[HideInDebugUI]
		RG_FinalFSRScale = 56,
		[HideInDebugUI]
		RG_FinalBlit = 57,
		BlitFinalToBackBuffer = 58,
		DrawSkybox = 59
	}
}
