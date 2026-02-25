using System;
using System.Collections.Generic;
using UnityEngine.AdaptivePerformance;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;
using UnityEngine.Rendering.RenderGraphModule.Util;
using UnityEngine.Rendering.Universal.Internal;
using UnityEngine.VFX;

namespace UnityEngine.Rendering.Universal
{
	public sealed class UniversalRenderer : ScriptableRenderer
	{
		private struct RenderPassInputSummary
		{
			internal bool requiresDepthTexture;

			internal bool requiresDepthPrepass;

			internal bool requiresNormalsTexture;

			internal bool requiresColorTexture;

			internal bool requiresMotionVectors;

			internal RenderPassEvent requiresDepthNormalAtEvent;

			internal RenderPassEvent requiresDepthTextureEarliestEvent;
		}

		private class CopyToDebugTexturePassData
		{
			internal TextureHandle src;

			internal TextureHandle dest;
		}

		private readonly struct ClearCameraParams
		{
			internal readonly bool mustClearColor;

			internal readonly bool mustClearDepth;

			internal readonly Color clearValue;

			internal ClearCameraParams(bool clearColor, bool clearDepth, Color clearVal)
			{
				mustClearColor = clearColor;
				mustClearDepth = clearDepth;
				clearValue = clearVal;
			}
		}

		private enum OccluderPass
		{
			None = 0,
			DepthPrepass = 1,
			ForwardOpaque = 2,
			GBuffer = 3
		}

		private enum DepthCopySchedule
		{
			DuringPrepass = 0,
			AfterPrepass = 1,
			AfterGBuffer = 2,
			AfterOpaques = 3,
			AfterSkybox = 4,
			AfterTransparents = 5,
			None = 6
		}

		private enum ColorCopySchedule
		{
			AfterSkybox = 0,
			None = 1
		}

		private struct TextureCopySchedules
		{
			internal DepthCopySchedule depth;

			internal ColorCopySchedule color;
		}

		private const int k_FinalBlitPassQueueOffset = 1;

		private const int k_AfterFinalBlitPassQueueOffset = 2;

		private DepthOnlyPass m_DepthPrepass;

		private DepthNormalOnlyPass m_DepthNormalPrepass;

		private MotionVectorRenderPass m_MotionVectorPass;

		private MainLightShadowCasterPass m_MainLightShadowCasterPass;

		private AdditionalLightsShadowCasterPass m_AdditionalLightsShadowCasterPass;

		private GBufferPass m_GBufferPass;

		private DeferredPass m_DeferredPass;

		private DrawObjectsPass m_RenderOpaqueForwardOnlyPass;

		private DrawObjectsPass m_RenderOpaqueForwardPass;

		private DrawObjectsWithRenderingLayersPass m_RenderOpaqueForwardWithRenderingLayersPass;

		private DrawSkyboxPass m_DrawSkyboxPass;

		private CopyDepthPass m_CopyDepthPass;

		private CopyColorPass m_CopyColorPass;

		private TransparentSettingsPass m_TransparentSettingsPass;

		private DrawObjectsPass m_RenderTransparentForwardPass;

		private InvokeOnRenderObjectCallbackPass m_OnRenderObjectCallbackPass;

		private FinalBlitPass m_FinalBlitPass;

		private FinalBlitPass m_OffscreenUICoverPrepass;

		private CapturePass m_CapturePass;

		private XROcclusionMeshPass m_XROcclusionMeshPass;

		private CopyDepthPass m_XRCopyDepthPass;

		private XRDepthMotionPass m_XRDepthMotionPass;

		private DrawScreenSpaceUIPass m_DrawOffscreenUIPass;

		private DrawScreenSpaceUIPass m_DrawOverlayUIPass;

		private CopyColorPass m_HistoryRawColorCopyPass;

		private CopyDepthPass m_HistoryRawDepthCopyPass;

		private StencilCrossFadeRenderPass m_StencilCrossFadeRenderPass;

		private RTHandle m_TargetColorHandle;

		private RTHandle m_TargetDepthHandle;

		private ForwardLights m_ForwardLights;

		private DeferredLights m_DeferredLights;

		private RenderingMode m_RenderingMode;

		private DepthPrimingMode m_DepthPrimingMode;

		private CopyDepthMode m_CopyDepthMode;

		private DepthFormat m_CameraDepthAttachmentFormat;

		private DepthFormat m_CameraDepthTextureFormat;

		private StencilState m_DefaultStencilState;

		private LightCookieManager m_LightCookieManager;

		private IntermediateTextureMode m_IntermediateTextureMode;

		private Material m_BlitMaterial;

		private Material m_BlitHDRMaterial;

		private Material m_SamplingMaterial;

		private Material m_BlitOffscreenUICoverMaterial;

		private Material m_StencilDeferredMaterial;

		private Material m_ClusterDeferredMaterial;

		private Material m_CameraMotionVecMaterial;

		private Material m_DebugBlitMaterial = Blitter.GetBlitMaterial(TextureXR.dimension);

		private static RTHandle[] m_RenderGraphCameraColorHandles = new RTHandle[2];

		private static RTHandle m_RenderGraphCameraDepthHandle;

		private static int m_CurrentColorHandle = 0;

		private static RTHandle m_RenderGraphDebugTextureHandle;

		private static RTHandle m_OffscreenUIColorHandle;

		private bool m_RequiresRenderingLayer;

		private RenderingLayerUtils.Event m_RenderingLayersEvent;

		private RenderingLayerUtils.MaskSize m_RenderingLayersMaskSize;

		private bool m_RenderingLayerProvidesRenderObjectPass;

		private bool m_RenderingLayerProvidesByDepthNormalPass;

		private string m_RenderingLayersTextureName;

		private ColorGradingLutPass m_ColorGradingLutPassRenderGraph;

		private PostProcessPassRenderGraph m_PostProcessPassRenderGraph;

		private const string _CameraTargetAttachmentAName = "_CameraTargetAttachmentA";

		private const string _CameraTargetAttachmentBName = "_CameraTargetAttachmentB";

		private const string _SingleCameraTargetAttachmentName = "_CameraTargetAttachment";

		private const string _CameraDepthAttachmentName = "_CameraDepthAttachment";

		private const string _CameraColorUpscaled = "_CameraColorUpscaled";

		private const string _CameraColorAfterPostProcessingName = "_CameraColorAfterPostProcessing";

		private bool m_IssuedGPUOcclusionUnsupportedMsg;

		private static bool m_RequiresIntermediateAttachments;

		internal RenderingMode renderingModeRequested => m_RenderingMode;

		private bool deferredModeUnsupported
		{
			get
			{
				if (!GL.wireframe && (base.DebugHandler == null || !base.DebugHandler.IsActiveModeUnsupportedForDeferred) && m_DeferredLights != null)
				{
					return !m_DeferredLights.IsRuntimeSupportedThisFrame();
				}
				return true;
			}
		}

		internal RenderingMode renderingModeActual
		{
			get
			{
				switch (renderingModeRequested)
				{
				case RenderingMode.Deferred:
					if (!deferredModeUnsupported)
					{
						return RenderingMode.Deferred;
					}
					return RenderingMode.Forward;
				case RenderingMode.DeferredPlus:
					if (!deferredModeUnsupported)
					{
						return RenderingMode.DeferredPlus;
					}
					return RenderingMode.ForwardPlus;
				default:
					return renderingModeRequested;
				}
			}
		}

		internal bool usesDeferredLighting
		{
			get
			{
				if (renderingModeActual != RenderingMode.Deferred)
				{
					return renderingModeActual == RenderingMode.DeferredPlus;
				}
				return true;
			}
		}

		internal bool usesClusterLightLoop
		{
			get
			{
				if (renderingModeActual != RenderingMode.ForwardPlus)
				{
					return renderingModeActual == RenderingMode.DeferredPlus;
				}
				return true;
			}
		}

		internal bool accurateGbufferNormals
		{
			get
			{
				if (m_DeferredLights == null)
				{
					return false;
				}
				return m_DeferredLights.AccurateGbufferNormals;
			}
		}

		internal bool needTransparencyPass
		{
			get
			{
				UniversalRenderPipelineAsset asset = UniversalRenderPipeline.asset;
				if ((object)asset == null || asset.useAdaptivePerformance)
				{
					return !AdaptivePerformanceRenderSettings.SkipTransparentObjects;
				}
				return true;
			}
		}

		public DepthPrimingMode depthPrimingMode
		{
			get
			{
				return m_DepthPrimingMode;
			}
			set
			{
				m_DepthPrimingMode = value;
			}
		}

		internal bool isPostProcessPassRenderGraphActive => m_PostProcessPassRenderGraph != null;

		internal DeferredLights deferredLights => m_DeferredLights;

		internal LayerMask prepassLayerMask { get; set; }

		internal LayerMask opaqueLayerMask { get; set; }

		internal LayerMask transparentLayerMask { get; set; }

		internal bool shadowTransparentReceive { get; set; }

		internal GraphicsFormat cameraDepthTextureFormat
		{
			get
			{
				if (m_CameraDepthTextureFormat == DepthFormat.Default)
				{
					return CoreUtils.GetDefaultDepthStencilFormat();
				}
				return (GraphicsFormat)m_CameraDepthTextureFormat;
			}
		}

		internal GraphicsFormat cameraDepthAttachmentFormat
		{
			get
			{
				if (m_CameraDepthAttachmentFormat == DepthFormat.Default)
				{
					return CoreUtils.GetDefaultDepthStencilFormat();
				}
				return (GraphicsFormat)m_CameraDepthAttachmentFormat;
			}
		}

		internal override bool supportsNativeRenderPassRendergraphCompiler => true;

		private RTHandle currentRenderGraphCameraColorHandle
		{
			get
			{
				if (m_CurrentColorHandle < 0)
				{
					return null;
				}
				return m_RenderGraphCameraColorHandles[m_CurrentColorHandle];
			}
		}

		private RTHandle nextRenderGraphCameraColorHandle
		{
			get
			{
				if (m_CurrentColorHandle < 0)
				{
					return null;
				}
				m_CurrentColorHandle = (m_CurrentColorHandle + 1) % 2;
				return currentRenderGraphCameraColorHandle;
			}
		}

		public override bool supportsGPUOcclusion
		{
			get
			{
				bool num = SystemInfo.graphicsDeviceVendorID != 20803;
				if (!num && !m_IssuedGPUOcclusionUnsupportedMsg)
				{
					Debug.LogWarning("The GPU Occlusion Culling feature is currently unavailable on this device due to suspected driver issues.");
					m_IssuedGPUOcclusionUnsupportedMsg = true;
				}
				return num;
			}
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Setup(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void SetupLights(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public override int SupportedCameraStackingTypes()
		{
			switch (m_RenderingMode)
			{
			case RenderingMode.Forward:
			case RenderingMode.ForwardPlus:
				return 3;
			case RenderingMode.Deferred:
			case RenderingMode.DeferredPlus:
				return 1;
			default:
				return 0;
			}
		}

		protected internal override bool SupportsMotionVectors()
		{
			return true;
		}

		protected internal override bool SupportsCameraOpaque()
		{
			return true;
		}

		protected internal override bool SupportsCameraNormals()
		{
			return true;
		}

		public UniversalRenderer(UniversalRendererData data)
			: base(data)
		{
			PlatformAutoDetect.Initialize();
			if (GraphicsSettings.TryGetRenderPipelineSettings<UniversalRenderPipelineRuntimeXRResources>(out var settings))
			{
				XRSystem.Initialize(XRPassUniversal.Create, settings.xrOcclusionMeshPS, settings.xrMirrorViewPS);
				m_XRDepthMotionPass = new XRDepthMotionPass(RenderPassEvent.BeforeRenderingPrePasses, settings.xrMotionVector);
			}
			if (GraphicsSettings.TryGetRenderPipelineSettings<UniversalRenderPipelineRuntimeShaders>(out var settings2))
			{
				m_BlitMaterial = CoreUtils.CreateEngineMaterial(settings2.coreBlitPS);
				m_BlitHDRMaterial = CoreUtils.CreateEngineMaterial(settings2.blitHDROverlay);
				m_SamplingMaterial = CoreUtils.CreateEngineMaterial(settings2.samplingPS);
				m_BlitOffscreenUICoverMaterial = CoreUtils.CreateEngineMaterial(settings2.blitHDROverlay);
			}
			Shader copyDepthShader = null;
			if (GraphicsSettings.TryGetRenderPipelineSettings<UniversalRendererResources>(out var settings3))
			{
				copyDepthShader = settings3.copyDepthPS;
				m_StencilDeferredMaterial = CoreUtils.CreateEngineMaterial(settings3.stencilDeferredPS);
				m_ClusterDeferredMaterial = CoreUtils.CreateEngineMaterial(settings3.clusterDeferred);
				m_CameraMotionVecMaterial = CoreUtils.CreateEngineMaterial(settings3.cameraMotionVector);
				m_StencilCrossFadeRenderPass = new StencilCrossFadeRenderPass(settings3.stencilDitherMaskSeedPS);
			}
			StencilStateData defaultStencilState = data.defaultStencilState;
			m_DefaultStencilState = StencilState.defaultValue;
			m_DefaultStencilState.enabled = defaultStencilState.overrideStencilState;
			m_DefaultStencilState.SetCompareFunction(defaultStencilState.stencilCompareFunction);
			m_DefaultStencilState.SetPassOperation(defaultStencilState.passOperation);
			m_DefaultStencilState.SetFailOperation(defaultStencilState.failOperation);
			m_DefaultStencilState.SetZFailOperation(defaultStencilState.zFailOperation);
			m_IntermediateTextureMode = data.intermediateTextureMode;
			prepassLayerMask = data.prepassLayerMask;
			opaqueLayerMask = data.opaqueLayerMask;
			transparentLayerMask = data.transparentLayerMask;
			shadowTransparentReceive = data.shadowTransparentReceive;
			UniversalRenderPipelineAsset asset = UniversalRenderPipeline.asset;
			if (asset != null && asset.supportsLightCookies)
			{
				LightCookieManager.Settings settings4 = LightCookieManager.Settings.Create();
				if ((bool)asset)
				{
					settings4.atlas.format = asset.additionalLightsCookieFormat;
					settings4.atlas.resolution = asset.additionalLightsCookieResolution;
				}
				m_LightCookieManager = new LightCookieManager(ref settings4);
			}
			base.stripShadowsOffVariants = data.stripShadowsOffVariants;
			base.stripAdditionalLightOffVariants = data.stripAdditionalLightOffVariants;
			ForwardLights.InitParams initParams = default(ForwardLights.InitParams);
			initParams.lightCookieManager = m_LightCookieManager;
			initParams.forwardPlus = data.renderingMode == RenderingMode.DeferredPlus || data.renderingMode == RenderingMode.ForwardPlus;
			m_ForwardLights = new ForwardLights(initParams);
			m_RenderingMode = data.renderingMode;
			m_DepthPrimingMode = data.depthPrimingMode;
			m_CopyDepthMode = data.copyDepthMode;
			m_CameraDepthAttachmentFormat = data.depthAttachmentFormat;
			m_CameraDepthTextureFormat = data.depthTextureFormat;
			useRenderPassEnabled = data.useNativeRenderPass;
			m_MainLightShadowCasterPass = new MainLightShadowCasterPass(RenderPassEvent.BeforeRenderingShadows);
			m_AdditionalLightsShadowCasterPass = new AdditionalLightsShadowCasterPass(RenderPassEvent.BeforeRenderingShadows);
			m_XROcclusionMeshPass = new XROcclusionMeshPass(RenderPassEvent.BeforeRenderingOpaques);
			m_XRCopyDepthPass = new CopyDepthPass((RenderPassEvent)1002, copyDepthShader);
			m_DepthPrepass = new DepthOnlyPass(RenderPassEvent.BeforeRenderingPrePasses, RenderQueueRange.opaque, prepassLayerMask);
			m_DepthNormalPrepass = new DepthNormalOnlyPass(RenderPassEvent.BeforeRenderingPrePasses, RenderQueueRange.opaque, prepassLayerMask);
			if (renderingModeRequested == RenderingMode.Deferred || renderingModeRequested == RenderingMode.DeferredPlus)
			{
				m_DeferredLights = new DeferredLights(new DeferredLights.InitParams
				{
					stencilDeferredMaterial = m_StencilDeferredMaterial,
					clusterDeferredMaterial = m_ClusterDeferredMaterial,
					lightCookieManager = m_LightCookieManager,
					deferredPlus = (renderingModeRequested == RenderingMode.DeferredPlus)
				}, useRenderPassEnabled);
				m_DeferredLights.AccurateGbufferNormals = data.accurateGbufferNormals;
				m_GBufferPass = new GBufferPass(RenderPassEvent.BeforeRenderingGbuffer, RenderQueueRange.opaque, data.opaqueLayerMask, m_DefaultStencilState, defaultStencilState.stencilReference, m_DeferredLights);
				StencilState stencilState = DeferredLights.OverwriteStencil(m_DefaultStencilState, 96);
				ShaderTagId[] shaderTagIds = new ShaderTagId[3]
				{
					new ShaderTagId("UniversalForwardOnly"),
					new ShaderTagId("SRPDefaultUnlit"),
					new ShaderTagId("LightweightForward")
				};
				int stencilReference = defaultStencilState.stencilReference | 0;
				m_DeferredPass = new DeferredPass(RenderPassEvent.BeforeRenderingDeferredLights, m_DeferredLights);
				m_RenderOpaqueForwardOnlyPass = new DrawObjectsPass("Draw Opaques Forward Only", shaderTagIds, opaque: true, RenderPassEvent.BeforeRenderingOpaques, RenderQueueRange.opaque, data.opaqueLayerMask, stencilState, stencilReference);
			}
			m_RenderOpaqueForwardPass = new DrawObjectsPass(URPProfileId.DrawOpaqueObjects, opaque: true, RenderPassEvent.BeforeRenderingOpaques, RenderQueueRange.opaque, data.opaqueLayerMask, m_DefaultStencilState, defaultStencilState.stencilReference);
			m_RenderOpaqueForwardWithRenderingLayersPass = new DrawObjectsWithRenderingLayersPass(URPProfileId.DrawOpaqueObjects, opaque: true, RenderPassEvent.BeforeRenderingOpaques, RenderQueueRange.opaque, data.opaqueLayerMask, m_DefaultStencilState, defaultStencilState.stencilReference);
			bool flag = m_CopyDepthMode == CopyDepthMode.AfterTransparents;
			RenderPassEvent renderPassEvent = (flag ? RenderPassEvent.AfterRenderingTransparents : RenderPassEvent.AfterRenderingSkybox);
			m_CopyDepthPass = new CopyDepthPass(renderPassEvent, copyDepthShader, shouldClear: true, copyToDepth: false, RenderingUtils.MultisampleDepthResolveSupported() && flag);
			m_MotionVectorPass = new MotionVectorRenderPass(renderPassEvent + 1, m_CameraMotionVecMaterial, data.opaqueLayerMask);
			m_DrawSkyboxPass = new DrawSkyboxPass(RenderPassEvent.BeforeRenderingSkybox);
			m_CopyColorPass = new CopyColorPass(RenderPassEvent.AfterRenderingSkybox, m_SamplingMaterial, m_BlitMaterial);
			if (needTransparencyPass)
			{
				m_TransparentSettingsPass = new TransparentSettingsPass(RenderPassEvent.BeforeRenderingTransparents, data.shadowTransparentReceive);
				m_RenderTransparentForwardPass = new DrawObjectsPass(URPProfileId.DrawTransparentObjects, opaque: false, RenderPassEvent.BeforeRenderingTransparents, RenderQueueRange.transparent, data.transparentLayerMask, m_DefaultStencilState, defaultStencilState.stencilReference);
			}
			m_OnRenderObjectCallbackPass = new InvokeOnRenderObjectCallbackPass(RenderPassEvent.BeforeRenderingPostProcessing);
			m_HistoryRawColorCopyPass = new CopyColorPass(RenderPassEvent.BeforeRenderingPostProcessing, m_SamplingMaterial, m_BlitMaterial, "Copy Color Raw History");
			m_HistoryRawDepthCopyPass = new CopyDepthPass(RenderPassEvent.BeforeRenderingPostProcessing, copyDepthShader, shouldClear: false, RenderingUtils.MultisampleDepthResolveSupported(), copyResolvedDepth: false, "Copy Depth Raw History");
			m_DrawOffscreenUIPass = new DrawScreenSpaceUIPass(RenderPassEvent.BeforeRenderingPostProcessing, renderOffscreen: true);
			m_DrawOverlayUIPass = new DrawScreenSpaceUIPass((RenderPassEvent)1002, renderOffscreen: false);
			if (data.postProcessData != null)
			{
				GraphicsFormat requestPostProColorFormat = ((asset == null) ? GraphicsFormat.B10G11R11_UFloatPack32 : UniversalRenderPipeline.MakeRenderTextureGraphicsFormat(asset.supportsHDR, asset.hdrColorBufferPrecision, needsAlpha: false));
				m_PostProcessPassRenderGraph = new PostProcessPassRenderGraph(data.postProcessData, requestPostProColorFormat);
				m_ColorGradingLutPassRenderGraph = new ColorGradingLutPass(RenderPassEvent.BeforeRenderingPrePasses, data.postProcessData);
			}
			m_CapturePass = new CapturePass(RenderPassEvent.AfterRendering);
			m_FinalBlitPass = new FinalBlitPass((RenderPassEvent)1001, m_BlitMaterial, m_BlitHDRMaterial);
			m_OffscreenUICoverPrepass = new FinalBlitPass((RenderPassEvent)551, m_BlitMaterial, m_BlitOffscreenUICoverMaterial);
			base.supportedRenderingFeatures = new RenderingFeatures();
			if (renderingModeRequested == RenderingMode.Deferred || renderingModeRequested == RenderingMode.DeferredPlus)
			{
				base.supportedRenderingFeatures.msaa = false;
			}
			LensFlareCommonSRP.mergeNeeded = 0;
			LensFlareCommonSRP.maxLensFlareWithOcclusionTemporalSample = 1;
			LensFlareCommonSRP.Initialize();
		}

		protected override void Dispose(bool disposing)
		{
			m_ForwardLights.Cleanup();
			m_GBufferPass?.Dispose();
			m_FinalBlitPass?.Dispose();
			m_OffscreenUICoverPrepass?.Dispose();
			m_DrawOffscreenUIPass?.Dispose();
			m_DrawOverlayUIPass?.Dispose();
			m_CopyDepthPass?.Dispose();
			m_HistoryRawDepthCopyPass?.Dispose();
			m_XRCopyDepthPass?.Dispose();
			m_XRDepthMotionPass?.Dispose();
			m_StencilCrossFadeRenderPass?.Dispose();
			m_PostProcessPassRenderGraph?.Cleanup();
			m_ColorGradingLutPassRenderGraph?.Cleanup();
			m_TargetColorHandle?.Release();
			m_TargetDepthHandle?.Release();
			ReleaseRenderTargets();
			base.Dispose(disposing);
			CoreUtils.Destroy(m_BlitMaterial);
			CoreUtils.Destroy(m_BlitHDRMaterial);
			CoreUtils.Destroy(m_BlitOffscreenUICoverMaterial);
			CoreUtils.Destroy(m_SamplingMaterial);
			CoreUtils.Destroy(m_StencilDeferredMaterial);
			CoreUtils.Destroy(m_ClusterDeferredMaterial);
			CoreUtils.Destroy(m_CameraMotionVecMaterial);
			CleanupRenderGraphResources();
			LensFlareCommonSRP.Dispose();
			XRSystem.Dispose();
		}

		internal override void ReleaseRenderTargets()
		{
			if (m_DeferredLights != null && !m_DeferredLights.UseFramebufferFetch)
			{
				m_GBufferPass?.Dispose();
			}
			m_MainLightShadowCasterPass?.Dispose();
			m_AdditionalLightsShadowCasterPass?.Dispose();
			hasReleasedRTs = true;
		}

		public static bool IsOffscreenDepthTexture(ref CameraData cameraData)
		{
			return IsOffscreenDepthTexture(cameraData.universalCameraData);
		}

		public static bool IsOffscreenDepthTexture(UniversalCameraData cameraData)
		{
			if (cameraData.targetTexture != null)
			{
				return cameraData.targetTexture.format == RenderTextureFormat.Depth;
			}
			return false;
		}

		private static bool IsWebGL()
		{
			return false;
		}

		private static bool IsGLESDevice()
		{
			return SystemInfo.graphicsDeviceType == GraphicsDeviceType.OpenGLES3;
		}

		private static bool IsGLDevice()
		{
			if (!IsGLESDevice())
			{
				return SystemInfo.graphicsDeviceType == GraphicsDeviceType.OpenGLCore;
			}
			return true;
		}

		private static bool HasActiveRenderFeatures(List<ScriptableRendererFeature> rendererFeatures)
		{
			if (rendererFeatures.Count == 0)
			{
				return false;
			}
			foreach (ScriptableRendererFeature rendererFeature in rendererFeatures)
			{
				if (rendererFeature.isActive)
				{
					return true;
				}
			}
			return false;
		}

		private static bool HasPassesRequiringIntermediateTexture(List<ScriptableRenderPass> activeRenderPassQueue)
		{
			if (activeRenderPassQueue.Count == 0)
			{
				return false;
			}
			foreach (ScriptableRenderPass item in activeRenderPassQueue)
			{
				if (item.requiresIntermediateTexture)
				{
					return true;
				}
			}
			return false;
		}

		private static void SetupVFXCameraBuffer(UniversalCameraData cameraData)
		{
			if (cameraData != null && cameraData.historyManager != null)
			{
				VFXCameraBufferTypes vFXCameraBufferTypes = VFXManager.IsCameraBufferNeeded(cameraData.camera);
				if (vFXCameraBufferTypes.HasFlag(VFXCameraBufferTypes.Color))
				{
					cameraData.historyManager.RequestAccess<RawColorHistory>();
					RTHandle rTHandle = cameraData.historyManager.GetHistoryForRead<RawColorHistory>()?.GetCurrentTexture();
					VFXManager.SetCameraBuffer(cameraData.camera, VFXCameraBufferTypes.Color, rTHandle, 0, 0, (int)((float)cameraData.pixelWidth * cameraData.renderScale), (int)((float)cameraData.pixelHeight * cameraData.renderScale));
				}
				if (vFXCameraBufferTypes.HasFlag(VFXCameraBufferTypes.Depth))
				{
					cameraData.historyManager.RequestAccess<RawDepthHistory>();
					RTHandle rTHandle2 = cameraData.historyManager.GetHistoryForRead<RawDepthHistory>()?.GetCurrentTexture();
					VFXManager.SetCameraBuffer(cameraData.camera, VFXCameraBufferTypes.Depth, rTHandle2, 0, 0, (int)((float)cameraData.pixelWidth * cameraData.renderScale), (int)((float)cameraData.pixelHeight * cameraData.renderScale));
				}
			}
		}

		public override void SetupCullingParameters(ref ScriptableCullingParameters cullingParameters, ref CameraData cameraData)
		{
			bool flag = UniversalRenderPipeline.asset.ShouldUseReflectionProbeAtlasBlending(renderingModeActual);
			if (usesClusterLightLoop && flag)
			{
				cullingParameters.cullingOptions |= CullingOptions.DisablePerObjectCulling;
			}
			bool num = !UniversalRenderPipeline.asset.supportsMainLightShadows && !UniversalRenderPipeline.asset.supportsAdditionalLightShadows;
			bool flag2 = Mathf.Approximately(cameraData.maxShadowDistance, 0f);
			if (num || flag2)
			{
				cullingParameters.cullingOptions &= ~CullingOptions.ShadowCasters;
			}
			if (usesClusterLightLoop)
			{
				cullingParameters.maximumVisibleLights = UniversalRenderPipeline.maxVisibleAdditionalLights;
				cullingParameters.reflectionProbeSortingCriteria = ReflectionProbeSortingCriteria.None;
			}
			else if (renderingModeActual == RenderingMode.Deferred)
			{
				cullingParameters.maximumVisibleLights = 65535;
			}
			else
			{
				cullingParameters.maximumVisibleLights = UniversalRenderPipeline.maxVisibleAdditionalLights + 1;
			}
			cullingParameters.shadowDistance = cameraData.maxShadowDistance;
			cullingParameters.conservativeEnclosingSphere = UniversalRenderPipeline.asset.conservativeEnclosingSphere;
			cullingParameters.numIterationsEnclosingSphere = UniversalRenderPipeline.asset.numIterationsEnclosingSphere;
		}

		public override void FinishRendering(CommandBuffer cmd)
		{
		}

		private static RenderPassInputSummary GetRenderPassInputs(bool isTemporalAAEnabled, bool postProcessingEnabled, bool isSceneViewCamera, bool renderingLayerProvidesByDepthNormalPass, List<ScriptableRenderPass> activeRenderPassQueue, MotionVectorRenderPass motionVectorPass)
		{
			RenderPassInputSummary result = new RenderPassInputSummary
			{
				requiresDepthNormalAtEvent = RenderPassEvent.BeforeRenderingOpaques,
				requiresDepthTextureEarliestEvent = RenderPassEvent.BeforeRenderingPostProcessing
			};
			for (int i = 0; i < activeRenderPassQueue.Count; i++)
			{
				ScriptableRenderPass scriptableRenderPass = activeRenderPassQueue[i];
				bool flag = (scriptableRenderPass.input & ScriptableRenderPassInput.Depth) != 0;
				bool flag2 = (scriptableRenderPass.input & ScriptableRenderPassInput.Normal) != 0;
				bool flag3 = (scriptableRenderPass.input & ScriptableRenderPassInput.Color) != 0;
				bool flag4 = (scriptableRenderPass.input & ScriptableRenderPassInput.Motion) != 0;
				bool flag5 = scriptableRenderPass.renderPassEvent < RenderPassEvent.AfterRenderingOpaques;
				result.requiresDepthTexture |= flag;
				result.requiresDepthPrepass |= flag2 || (flag && flag5);
				result.requiresNormalsTexture |= flag2;
				result.requiresColorTexture |= flag3;
				result.requiresMotionVectors |= flag4;
				if (flag)
				{
					result.requiresDepthTextureEarliestEvent = (RenderPassEvent)Mathf.Min((int)scriptableRenderPass.renderPassEvent, (int)result.requiresDepthTextureEarliestEvent);
				}
				if (flag2 || flag)
				{
					result.requiresDepthNormalAtEvent = (RenderPassEvent)Mathf.Min((int)scriptableRenderPass.renderPassEvent, (int)result.requiresDepthNormalAtEvent);
				}
			}
			if (isTemporalAAEnabled)
			{
				result.requiresMotionVectors = true;
			}
			if (postProcessingEnabled)
			{
				MotionBlur component = VolumeManager.instance.stack.GetComponent<MotionBlur>();
				if (component != null && component.IsActive() && component.mode.value == MotionBlurMode.CameraAndObjects)
				{
					result.requiresMotionVectors = true;
				}
			}
			if (result.requiresMotionVectors)
			{
				result.requiresDepthTexture = true;
				result.requiresDepthTextureEarliestEvent = (RenderPassEvent)Mathf.Min((int)motionVectorPass.renderPassEvent, (int)result.requiresDepthTextureEarliestEvent);
			}
			if (renderingLayerProvidesByDepthNormalPass)
			{
				result.requiresNormalsTexture = true;
			}
			return result;
		}

		internal static bool PlatformRequiresExplicitMsaaResolve()
		{
			if (!SystemInfo.supportsMultisampleAutoResolve || !Application.isMobilePlatform)
			{
				return SystemInfo.graphicsDeviceType != GraphicsDeviceType.Metal;
			}
			return false;
		}

		private static bool RequiresIntermediateColorTexture(UniversalCameraData cameraData, in RenderPassInputSummary renderPassInputs, bool usesDeferredLighting, bool applyPostProcessing)
		{
			if (cameraData.renderType == CameraRenderType.Base && !cameraData.resolveFinalTarget)
			{
				return true;
			}
			if (usesDeferredLighting)
			{
				return true;
			}
			bool isSceneViewCamera = cameraData.isSceneViewCamera;
			RenderTextureDescriptor cameraTargetDescriptor = cameraData.cameraTargetDescriptor;
			int msaaSamples = cameraTargetDescriptor.msaaSamples;
			bool flag = cameraData.imageScalingMode != ImageScalingMode.None;
			bool flag2 = IsScalableBufferManagerUsed(cameraData);
			bool flag3 = cameraTargetDescriptor.dimension == TextureDimension.Tex2D;
			bool flag4 = msaaSamples > 1 && PlatformRequiresExplicitMsaaResolve();
			bool num = cameraData.targetTexture != null && !isSceneViewCamera;
			bool flag5 = cameraData.captureActions != null;
			if (cameraData.xr.enabled)
			{
				flag = false;
				flag2 = false;
				flag3 = cameraData.xr.renderTargetDesc.dimension == cameraTargetDescriptor.dimension;
			}
			bool flag6 = cameraData.requiresOpaqueTexture || renderPassInputs.requiresColorTexture;
			bool flag7 = applyPostProcessing || flag6 || flag4 || !cameraData.isDefaultViewport;
			if (num)
			{
				return flag7;
			}
			if (!(flag7 || flag || flag2 || cameraData.isHdrEnabled || !flag3 || flag5))
			{
				return cameraData.requireSrgbConversion;
			}
			return true;
		}

		private static bool IsScalableBufferManagerUsed(UniversalCameraData cameraData)
		{
			bool allowDynamicResolution = cameraData.camera.allowDynamicResolution;
			bool flag = Mathf.Abs(ScalableBufferManager.widthScaleFactor - 1f) > 0.0001f;
			bool flag2 = Mathf.Abs(ScalableBufferManager.heightScaleFactor - 1f) > 0.0001f;
			if (allowDynamicResolution)
			{
				return flag || flag2;
			}
			return false;
		}

		private static bool CanCopyDepth(UniversalCameraData cameraData)
		{
			bool num = cameraData.cameraTargetDescriptor.msaaSamples > 1;
			bool flag = SystemInfo.copyTextureSupport != CopyTextureSupport.None;
			bool flag2 = RenderingUtils.SupportsRenderTextureFormat(RenderTextureFormat.Depth);
			bool flag3 = !num && (flag2 || flag);
			bool flag4 = num && SystemInfo.supportsMultisampledTextures != 0;
			if (IsGLESDevice() && flag4)
			{
				return false;
			}
			return flag3 || flag4;
		}

		private bool DebugHandlerRequireDepthPass(UniversalCameraData cameraData)
		{
			if (base.DebugHandler != null && base.DebugHandler.IsActiveForCamera(cameraData.isPreviewCamera) && base.DebugHandler.TryGetFullscreenDebugMode(out var _))
			{
				return true;
			}
			return false;
		}

		private void CreateDebugTexture(RenderTextureDescriptor descriptor)
		{
			RenderTextureDescriptor descriptor2 = descriptor;
			descriptor2.useMipMap = false;
			descriptor2.autoGenerateMips = false;
			descriptor2.bindMS = false;
			descriptor2.depthStencilFormat = GraphicsFormat.None;
			RenderingUtils.ReAllocateHandleIfNeeded(ref m_RenderGraphDebugTextureHandle, in descriptor2, FilterMode.Point, TextureWrapMode.Clamp, 1, 0f, "_RenderingDebuggerTexture");
		}

		private Rect CalculateUVRect(UniversalCameraData cameraData, float width, float height)
		{
			float num = width / (float)cameraData.pixelWidth;
			float num2 = height / (float)cameraData.pixelHeight;
			return new Rect(1f - num, 1f - num2, num, num2);
		}

		private Rect CalculateUVRect(UniversalCameraData cameraData, int textureHeightPercent)
		{
			float num = Mathf.Clamp01((float)textureHeightPercent / 100f);
			float width = num * (float)cameraData.pixelWidth;
			float height = num * (float)cameraData.pixelHeight;
			return CalculateUVRect(cameraData, width, height);
		}

		private void CorrectForTextureAspectRatio(ref float width, ref float height, float sourceWidth, float sourceHeight)
		{
			if (sourceWidth != 0f && sourceHeight != 0f)
			{
				float num = height * sourceWidth / sourceHeight;
				if (num > width)
				{
					height = width * sourceHeight / sourceWidth;
				}
				else
				{
					width = num;
				}
			}
		}

		private void SetupRenderGraphFinalPassDebug(RenderGraph renderGraph, ContextContainer frameData)
		{
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			if (base.DebugHandler != null && base.DebugHandler.IsActiveForCamera(universalCameraData.isPreviewCamera))
			{
				if (base.DebugHandler.TryGetFullscreenDebugMode(out var debugFullScreenMode, out var textureHeightPercent) && (debugFullScreenMode != DebugFullScreenMode.ReflectionProbeAtlas || usesClusterLightLoop) && debugFullScreenMode != DebugFullScreenMode.STP)
				{
					float num = universalCameraData.pixelWidth;
					float num2 = universalCameraData.pixelHeight;
					float num3 = Mathf.Clamp01((float)textureHeightPercent / 100f);
					float height = num3 * num2;
					float width = num3 * num;
					bool supportsStereo = false;
					Vector4 zero = Vector4.zero;
					RenderTextureDescriptor cameraTargetDescriptor = universalCameraData.cameraTargetDescriptor;
					if (SystemInfo.IsFormatSupported(GraphicsFormat.R16G16B16A16_SFloat, GraphicsFormatUsage.Linear | GraphicsFormatUsage.Render))
					{
						cameraTargetDescriptor.graphicsFormat = GraphicsFormat.R16G16B16A16_SFloat;
					}
					CreateDebugTexture(cameraTargetDescriptor);
					TextureHandle destination = renderGraph.ImportTexture(importParams: new ImportResourceParams
					{
						clearOnFirstUse = false,
						discardOnLastUse = false
					}, rt: m_RenderGraphDebugTextureHandle);
					switch (debugFullScreenMode)
					{
					case DebugFullScreenMode.Depth:
						BlitToDebugTexture(renderGraph, universalResourceData.cameraDepthTexture, destination);
						supportsStereo = true;
						break;
					case DebugFullScreenMode.MotionVector:
						BlitToDebugTexture(renderGraph, universalResourceData.motionVectorColor, destination, isSourceTextureColor: true);
						supportsStereo = true;
						zero.x = -0.01f;
						zero.y = 0.01f;
						zero.z = 0f;
						zero.w = 1f;
						break;
					case DebugFullScreenMode.AdditionalLightsShadowMap:
						BlitToDebugTexture(renderGraph, universalResourceData.additionalShadowsTexture, destination);
						break;
					case DebugFullScreenMode.MainLightShadowMap:
						BlitToDebugTexture(renderGraph, universalResourceData.mainShadowsTexture, destination);
						break;
					case DebugFullScreenMode.AdditionalLightsCookieAtlas:
					{
						LightCookieManager lightCookieManager = m_LightCookieManager;
						TextureHandle source2 = ((lightCookieManager != null && lightCookieManager.AdditionalLightsCookieAtlasTexture != null) ? renderGraph.ImportTexture(m_LightCookieManager.AdditionalLightsCookieAtlasTexture) : TextureHandle.nullHandle);
						BlitToDebugTexture(renderGraph, source2, destination);
						break;
					}
					case DebugFullScreenMode.ReflectionProbeAtlas:
					{
						TextureHandle source = ((m_ForwardLights.reflectionProbeManager.atlasRT != null) ? renderGraph.ImportTexture(RTHandles.Alloc(m_ForwardLights.reflectionProbeManager.atlasRT, transferOwnership: true)) : TextureHandle.nullHandle);
						BlitToDebugTexture(renderGraph, source, destination);
						break;
					}
					}
					RenderTexture renderTexture = null;
					switch (debugFullScreenMode)
					{
					case DebugFullScreenMode.AdditionalLightsShadowMap:
						renderTexture = m_AdditionalLightsShadowCasterPass?.m_AdditionalLightsShadowmapHandle?.rt;
						break;
					case DebugFullScreenMode.MainLightShadowMap:
						renderTexture = m_MainLightShadowCasterPass?.m_MainLightShadowmapTexture?.rt;
						break;
					case DebugFullScreenMode.AdditionalLightsCookieAtlas:
						renderTexture = m_LightCookieManager?.AdditionalLightsCookieAtlasTexture?.rt;
						break;
					case DebugFullScreenMode.ReflectionProbeAtlas:
						renderTexture = m_ForwardLights?.reflectionProbeManager.atlasRT;
						break;
					}
					if (renderTexture != null)
					{
						CorrectForTextureAspectRatio(ref width, ref height, renderTexture.width, renderTexture.height);
					}
					Rect displayRect = CalculateUVRect(universalCameraData, width, height);
					base.DebugHandler.SetDebugRenderTarget(m_RenderGraphDebugTextureHandle, displayRect, supportsStereo, zero);
				}
				else
				{
					base.DebugHandler.ResetDebugRenderTarget();
				}
			}
			if (base.DebugHandler != null && !base.DebugHandler.TryGetFullscreenDebugMode(out var _, out var textureHeightPercent2))
			{
				DebugDisplayGPUResidentDrawer gpuResidentDrawerSettings = base.DebugHandler.DebugDisplaySettings.gpuResidentDrawerSettings;
				GPUResidentDrawer.RenderDebugOcclusionTestOverlay(renderGraph, gpuResidentDrawerSettings, universalCameraData.camera.GetInstanceID(), universalResourceData.activeColorTexture);
				float num4 = (int)((float)universalCameraData.pixelHeight * universalCameraData.renderScale);
				float num5 = (int)((float)universalCameraData.pixelHeight * universalCameraData.renderScale);
				float num6 = num5 * (float)textureHeightPercent2 / 100f;
				GPUResidentDrawer.RenderDebugOccluderOverlay(renderGraph, gpuResidentDrawerSettings, new Vector2(0.25f * num4, num5 - 1.5f * num6), num6, universalResourceData.activeColorTexture);
			}
		}

		private void SetupAfterPostRenderGraphFinalPassDebug(RenderGraph renderGraph, ContextContainer frameData)
		{
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			if (base.DebugHandler != null && base.DebugHandler.IsActiveForCamera(universalCameraData.isPreviewCamera) && base.DebugHandler.TryGetFullscreenDebugMode(out var debugFullScreenMode, out var textureHeightPercent) && debugFullScreenMode == DebugFullScreenMode.STP)
			{
				CreateDebugTexture(universalCameraData.cameraTargetDescriptor);
				TextureHandle destination = renderGraph.ImportTexture(importParams: new ImportResourceParams
				{
					clearOnFirstUse = false,
					discardOnLastUse = false
				}, rt: m_RenderGraphDebugTextureHandle);
				BlitToDebugTexture(renderGraph, universalResourceData.stpDebugView, destination);
				Rect displayRect = CalculateUVRect(universalCameraData, textureHeightPercent);
				Vector4 zero = Vector4.zero;
				base.DebugHandler.SetDebugRenderTarget(m_RenderGraphDebugTextureHandle, displayRect, supportsStereo: true, zero);
			}
		}

		private void BlitToDebugTexture(RenderGraph renderGraph, TextureHandle source, TextureHandle destination, bool isSourceTextureColor = false)
		{
			if (source.IsValid())
			{
				if (isSourceTextureColor)
				{
					renderGraph.AddCopyPass(source, destination, "Copy Pass Utility", returnBuilder: false, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\UniversalRendererDebug.cs", 251);
					return;
				}
				UnityEngine.Rendering.RenderGraphModule.Util.RenderGraphUtils.BlitMaterialParameters blitParameters = new UnityEngine.Rendering.RenderGraphModule.Util.RenderGraphUtils.BlitMaterialParameters(source, destination, m_DebugBlitMaterial, 0);
				renderGraph.AddBlitPass(blitParameters, "Blit Pass Utility w. Material", returnBuilder: false, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\UniversalRendererDebug.cs", 260);
			}
			else
			{
				BlitEmptyTexture(renderGraph, destination);
			}
		}

		private void BlitEmptyTexture(RenderGraph renderGraph, TextureHandle destination, string passName = "Copy To Debug Texture")
		{
			CopyToDebugTexturePassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<CopyToDebugTexturePassData>(passName, out passData, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\UniversalRendererDebug.cs", 271);
			passData.src = renderGraph.defaultResources.blackTexture;
			passData.dest = destination;
			rasterRenderGraphBuilder.SetRenderAttachment(destination, 0);
			rasterRenderGraphBuilder.AllowPassCulling(value: false);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(CopyToDebugTexturePassData data, RasterGraphContext context)
			{
				Blitter.BlitTexture(context.cmd, data.src, new Vector4(1f, 1f, 0f, 0f), 0f, bilinear: false);
			});
		}

		private void CleanupRenderGraphResources()
		{
			m_RenderGraphCameraColorHandles[0]?.Release();
			m_RenderGraphCameraColorHandles[1]?.Release();
			m_RenderGraphCameraDepthHandle?.Release();
			m_RenderGraphDebugTextureHandle?.Release();
			m_OffscreenUIColorHandle?.Release();
		}

		public static TextureHandle CreateRenderGraphTexture(RenderGraph renderGraph, RenderTextureDescriptor desc, string name, bool clear, FilterMode filterMode = FilterMode.Point, TextureWrapMode wrapMode = TextureWrapMode.Clamp)
		{
			GetTextureDesc(in desc, out var rgDesc);
			rgDesc.clearBuffer = clear;
			rgDesc.name = name;
			rgDesc.filterMode = filterMode;
			rgDesc.wrapMode = wrapMode;
			return renderGraph.CreateTexture(in rgDesc);
		}

		internal static TextureHandle CreateRenderGraphTexture(RenderGraph renderGraph, in RenderTextureDescriptor desc, string name, bool clear, Color color, FilterMode filterMode = FilterMode.Point, TextureWrapMode wrapMode = TextureWrapMode.Clamp, bool discardOnLastUse = false)
		{
			GetTextureDesc(in desc, out var rgDesc);
			rgDesc.clearBuffer = clear;
			rgDesc.clearColor = color;
			rgDesc.msaaSamples = (MSAASamples)desc.msaaSamples;
			rgDesc.name = name;
			rgDesc.filterMode = filterMode;
			rgDesc.wrapMode = wrapMode;
			rgDesc.discardBuffer = discardOnLastUse;
			return renderGraph.CreateTexture(in rgDesc);
		}

		internal static void GetTextureDesc(in RenderTextureDescriptor desc, out TextureDesc rgDesc)
		{
			rgDesc = new TextureDesc(desc.width, desc.height);
			rgDesc.dimension = desc.dimension;
			rgDesc.bindTextureMS = desc.bindMS;
			rgDesc.format = ((desc.depthStencilFormat != GraphicsFormat.None) ? desc.depthStencilFormat : desc.graphicsFormat);
			rgDesc.isShadowMap = desc.shadowSamplingMode != ShadowSamplingMode.None && desc.depthStencilFormat != GraphicsFormat.None;
			rgDesc.slices = desc.volumeDepth;
			rgDesc.msaaSamples = (MSAASamples)desc.msaaSamples;
			rgDesc.enableRandomWrite = desc.enableRandomWrite;
			rgDesc.enableShadingRate = desc.enableShadingRate;
			rgDesc.useDynamicScale = desc.useDynamicScale;
			rgDesc.useDynamicScaleExplicit = desc.useDynamicScaleExplicit;
			rgDesc.vrUsage = desc.vrUsage;
		}

		internal static TextureHandle CreateRenderGraphTexture(RenderGraph renderGraph, in TextureDesc desc, string name, bool clear, Color clearColor, FilterMode filterMode = FilterMode.Point, TextureWrapMode wrapMode = TextureWrapMode.Clamp, bool discardOnLastUse = false)
		{
			TextureDesc desc2 = desc;
			desc2.name = name;
			desc2.clearBuffer = clear;
			desc2.clearColor = clearColor;
			desc2.filterMode = filterMode;
			desc2.wrapMode = wrapMode;
			desc2.discardBuffer = discardOnLastUse;
			return renderGraph.CreateTexture(in desc2);
		}

		private bool RequiresIntermediateAttachments(UniversalCameraData cameraData, in RenderPassInputSummary renderPassInputs, bool requireCopyFromDepth, bool applyPostProcessing)
		{
			return ((HasActiveRenderFeatures(base.rendererFeatures) && m_IntermediateTextureMode == IntermediateTextureMode.Always) | HasPassesRequiringIntermediateTexture(base.activeRenderPassQueue) | RequiresIntermediateColorTexture(cameraData, in renderPassInputs, usesDeferredLighting, applyPostProcessing)) || requireCopyFromDepth;
		}

		private void UpdateCameraHistory(UniversalCameraData cameraData)
		{
			if (cameraData != null && cameraData.historyManager != null)
			{
				int num = 0;
				bool num2 = cameraData.xr.enabled && !cameraData.xr.singlePassEnabled;
				num = cameraData.xr.multipassId;
				if (!num2 || num == 0)
				{
					UniversalCameraHistory historyManager = cameraData.historyManager;
					historyManager.GatherHistoryRequests();
					historyManager.ReleaseUnusedHistory();
					historyManager.SwapAndSetReferenceSize(cameraData.cameraTargetDescriptor.width, cameraData.cameraTargetDescriptor.height);
				}
			}
		}

		private void CreateRenderGraphCameraRenderTargets(RenderGraph renderGraph, bool isCameraTargetOffscreenDepth, bool requireIntermediateAttachments, bool depthTextureIsDepthFormat)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			UniversalCameraData universalCameraData = base.frameData.Get<UniversalCameraData>();
			ClearCameraParams clearCameraParams = GetClearCameraParams(universalCameraData);
			SetupTargetHandles(universalCameraData);
			UpdateCameraHistory(universalCameraData);
			ImportBackBuffers(renderGraph, universalCameraData, clearCameraParams.clearValue, isCameraTargetOffscreenDepth);
			GetTextureDesc(in universalCameraData.cameraTargetDescriptor, out var rgDesc);
			rgDesc.useMipMap = false;
			rgDesc.autoGenerateMips = false;
			rgDesc.mipMapBias = 0f;
			rgDesc.anisoLevel = 1;
			if (requireIntermediateAttachments)
			{
				rgDesc.format = universalCameraData.cameraTargetDescriptor.graphicsFormat;
				if (!isCameraTargetOffscreenDepth)
				{
					CreateIntermediateCameraColorAttachment(renderGraph, universalCameraData, in rgDesc, clearCameraParams.mustClearColor, clearCameraParams.clearValue);
				}
				rgDesc.format = universalCameraData.cameraTargetDescriptor.depthStencilFormat;
				CreateIntermediateCameraDepthAttachment(renderGraph, universalCameraData, in rgDesc, clearCameraParams.mustClearDepth, clearCameraParams.clearValue, depthTextureIsDepthFormat);
			}
			else
			{
				universalResourceData.SwitchActiveTexturesToBackbuffer();
			}
			CreateCameraDepthCopyTexture(renderGraph, rgDesc, depthTextureIsDepthFormat, clearCameraParams.clearValue);
			CreateCameraNormalsTexture(renderGraph, rgDesc);
			CreateMotionVectorTextures(renderGraph, rgDesc);
			CreateRenderingLayersTexture(renderGraph, rgDesc);
			if (universalCameraData.isHDROutputActive && universalCameraData.rendersOverlayUI)
			{
				CreateOffscreenUITexture(renderGraph, rgDesc);
			}
		}

		private ClearCameraParams GetClearCameraParams(UniversalCameraData cameraData)
		{
			bool clearColor = cameraData.renderType == CameraRenderType.Base;
			bool clearDepth = cameraData.renderType == CameraRenderType.Base || cameraData.clearDepth;
			Color color = ((cameraData.camera.clearFlags == CameraClearFlags.Nothing && cameraData.targetTexture == null) ? Color.yellow : cameraData.backgroundColor);
			if (IsSceneFilteringEnabled(cameraData.camera))
			{
				color.a = 0f;
				clearDepth = false;
			}
			DebugHandler debugHandler = cameraData.renderer.DebugHandler;
			if (debugHandler != null && debugHandler.IsActiveForCamera(cameraData.isPreviewCamera) && debugHandler.IsScreenClearNeeded)
			{
				clearColor = true;
				clearDepth = true;
				if (base.DebugHandler != null && base.DebugHandler.IsActiveForCamera(cameraData.isPreviewCamera))
				{
					base.DebugHandler.TryGetScreenClearColor(ref color);
				}
			}
			return new ClearCameraParams(clearColor, clearDepth, color);
		}

		private void SetupTargetHandles(UniversalCameraData cameraData)
		{
			RenderTargetIdentifier renderTargetIdentifier = ((cameraData.targetTexture != null) ? new RenderTargetIdentifier(cameraData.targetTexture) : ((RenderTargetIdentifier)BuiltinRenderTextureType.CameraTarget));
			RenderTargetIdentifier renderTargetIdentifier2 = ((cameraData.targetTexture != null) ? new RenderTargetIdentifier(cameraData.targetTexture) : ((RenderTargetIdentifier)BuiltinRenderTextureType.Depth));
			if (cameraData.xr.enabled)
			{
				renderTargetIdentifier = cameraData.xr.renderTarget;
				renderTargetIdentifier2 = cameraData.xr.renderTarget;
			}
			if (m_TargetColorHandle == null)
			{
				m_TargetColorHandle = RTHandles.Alloc(renderTargetIdentifier, "Backbuffer color");
			}
			else if (m_TargetColorHandle.nameID != renderTargetIdentifier)
			{
				RTHandleStaticHelpers.SetRTHandleUserManagedWrapper(ref m_TargetColorHandle, renderTargetIdentifier);
			}
			if (m_TargetDepthHandle == null)
			{
				m_TargetDepthHandle = RTHandles.Alloc(renderTargetIdentifier2, "Backbuffer depth");
			}
			else if (m_TargetDepthHandle.nameID != renderTargetIdentifier2)
			{
				RTHandleStaticHelpers.SetRTHandleUserManagedWrapper(ref m_TargetDepthHandle, renderTargetIdentifier2);
			}
		}

		private void SetupRenderingLayers(int msaaSamples)
		{
			m_RequiresRenderingLayer = RenderingLayerUtils.RequireRenderingLayers(this, base.rendererFeatures, msaaSamples, out m_RenderingLayersEvent, out m_RenderingLayersMaskSize);
			m_RenderingLayerProvidesRenderObjectPass = m_RequiresRenderingLayer && m_RenderingLayersEvent == RenderingLayerUtils.Event.Opaque;
			m_RenderingLayerProvidesByDepthNormalPass = m_RequiresRenderingLayer && m_RenderingLayersEvent == RenderingLayerUtils.Event.DepthNormalPrePass;
			if (m_DeferredLights != null)
			{
				m_DeferredLights.RenderingLayerMaskSize = m_RenderingLayersMaskSize;
				m_DeferredLights.UseDecalLayers = m_RequiresRenderingLayer;
			}
		}

		internal void SetupRenderGraphLights(RenderGraph renderGraph, UniversalRenderingData renderingData, UniversalCameraData cameraData, UniversalLightData lightData)
		{
			m_ForwardLights.SetupRenderGraphLights(renderGraph, renderingData, cameraData, lightData);
			if (usesDeferredLighting)
			{
				m_DeferredLights.UseFramebufferFetch = renderGraph.nativeRenderPassesEnabled;
				m_DeferredLights.SetupRenderGraphLights(renderGraph, cameraData, lightData);
			}
		}

		private void RenderRawColorDepthHistory(RenderGraph renderGraph, UniversalCameraData cameraData, UniversalResourceData resourceData)
		{
			if (cameraData == null || cameraData.historyManager == null || resourceData == null)
			{
				return;
			}
			UniversalCameraHistory historyManager = cameraData.historyManager;
			bool flag = false;
			int num = 0;
			flag = cameraData.xr.enabled && !cameraData.xr.singlePassEnabled;
			num = cameraData.xr.multipassId;
			if (historyManager.IsAccessRequested<RawColorHistory>() && resourceData.cameraColor.IsValid())
			{
				RawColorHistory historyForWrite = historyManager.GetHistoryForWrite<RawColorHistory>();
				if (historyForWrite != null)
				{
					historyForWrite.Update(ref cameraData.cameraTargetDescriptor, flag);
					if (historyForWrite.GetCurrentTexture(num) != null)
					{
						TextureHandle destination = renderGraph.ImportTexture(historyForWrite.GetCurrentTexture(num));
						m_HistoryRawColorCopyPass.RenderToExistingTexture(renderGraph, base.frameData, in destination, resourceData.cameraColor);
					}
				}
			}
			if (!historyManager.IsAccessRequested<RawDepthHistory>() || !resourceData.cameraDepth.IsValid())
			{
				return;
			}
			RawDepthHistory historyForWrite2 = historyManager.GetHistoryForWrite<RawDepthHistory>();
			if (historyForWrite2 != null)
			{
				if (!m_HistoryRawDepthCopyPass.CopyToDepth)
				{
					RenderTextureDescriptor cameraDesc = cameraData.cameraTargetDescriptor;
					cameraDesc.graphicsFormat = GraphicsFormat.R32_SFloat;
					cameraDesc.depthStencilFormat = GraphicsFormat.None;
					historyForWrite2.Update(ref cameraDesc, flag);
				}
				else
				{
					RenderTextureDescriptor cameraDesc2 = cameraData.cameraTargetDescriptor;
					cameraDesc2.graphicsFormat = GraphicsFormat.None;
					historyForWrite2.Update(ref cameraDesc2, flag);
				}
				if (historyForWrite2.GetCurrentTexture(num) != null)
				{
					TextureHandle destination2 = renderGraph.ImportTexture(historyForWrite2.GetCurrentTexture(num));
					m_HistoryRawDepthCopyPass.Render(renderGraph, base.frameData, destination2, resourceData.cameraDepth);
				}
			}
		}

		public override void OnBeginRenderGraphFrame()
		{
			base.frameData.Get<UniversalResourceData>().InitFrame();
		}

		internal override void OnRecordRenderGraph(RenderGraph renderGraph, ScriptableRenderContext context)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			UniversalRenderingData renderingData = base.frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = base.frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = base.frameData.Get<UniversalLightData>();
			UniversalPostProcessingData universalPostProcessingData = base.frameData.Get<UniversalPostProcessingData>();
			useRenderPassEnabled = renderGraph.nativeRenderPassesEnabled;
			MotionVectorRenderPass.SetRenderGraphMotionVectorGlobalMatrices(renderGraph, universalCameraData);
			SetupRenderGraphLights(renderGraph, renderingData, universalCameraData, lightData);
			SetupRenderingLayers(universalCameraData.cameraTargetDescriptor.msaaSamples);
			bool flag = universalCameraData.camera.targetTexture != null && universalCameraData.camera.targetTexture.format == RenderTextureFormat.Depth;
			RenderPassInputSummary renderPassInputs = GetRenderPassInputs(universalCameraData.IsTemporalAAEnabled(), universalPostProcessingData.isEnabled, universalCameraData.isSceneViewCamera, m_RenderingLayerProvidesByDepthNormalPass, base.activeRenderPassQueue, m_MotionVectorPass);
			bool applyPostProcessing = universalCameraData.postProcessEnabled && m_PostProcessPassRenderGraph != null;
			bool flag2 = RequireDepthTexture(universalCameraData, in renderPassInputs, applyPostProcessing);
			bool flag3 = RequirePrepassForTextures(universalCameraData, in renderPassInputs, flag2);
			base.useDepthPriming = IsDepthPrimingEnabledRenderGraph(universalCameraData, in renderPassInputs, m_DepthPrimingMode, flag2, flag3, usesDeferredLighting);
			bool requiresPrepass = flag3 || base.useDepthPriming;
			bool flag4 = flag3 && !usesDeferredLighting;
			bool depthTextureIsDepthFormat = flag4;
			bool requireCopyFromDepth = flag2 && !flag4;
			if (universalCameraData.renderType == CameraRenderType.Base)
			{
				m_RequiresIntermediateAttachments = RequiresIntermediateAttachments(universalCameraData, in renderPassInputs, requireCopyFromDepth, applyPostProcessing);
			}
			CreateRenderGraphCameraRenderTargets(renderGraph, flag, m_RequiresIntermediateAttachments, depthTextureIsDepthFormat);
			_ = base.DebugHandler;
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRendering);
			SetupRenderGraphCameraProperties(renderGraph, universalResourceData.activeColorTexture.IsValid() ? universalResourceData.activeColorTexture : universalResourceData.activeDepthTexture);
			universalCameraData.renderer.useDepthPriming = base.useDepthPriming;
			if (flag)
			{
				OnOffscreenDepthTextureRendering(renderGraph, context, universalResourceData, universalCameraData);
				return;
			}
			OnBeforeRendering(renderGraph);
			BeginRenderGraphXRRendering(renderGraph);
			OnMainRendering(renderGraph, context, in renderPassInputs, requiresPrepass, flag2);
			OnAfterRendering(renderGraph, applyPostProcessing);
			EndRenderGraphXRRendering(renderGraph);
		}

		public override void OnEndRenderGraphFrame()
		{
			base.frameData.Get<UniversalResourceData>().EndFrame();
		}

		internal override void OnFinishRenderGraphRendering(CommandBuffer cmd)
		{
			if (usesDeferredLighting)
			{
				m_DeferredPass.OnCameraCleanup(cmd);
			}
			m_CopyDepthPass.OnCameraCleanup(cmd);
			m_DepthNormalPrepass.OnCameraCleanup(cmd);
		}

		private void OnOffscreenDepthTextureRendering(RenderGraph renderGraph, ScriptableRenderContext context, UniversalResourceData resourceData, UniversalCameraData cameraData)
		{
			if (!renderGraph.nativeRenderPassesEnabled)
			{
				ClearTargetsPass.Render(renderGraph, resourceData.activeColorTexture, resourceData.backBufferDepth, RTClearFlags.Depth, cameraData.backgroundColor);
			}
			UniversalRenderingData renderingData = base.frameData.Get<UniversalRenderingData>();
			UniversalLightData lightData = base.frameData.Get<UniversalLightData>();
			UniversalShadowData shadowData = base.frameData.Get<UniversalShadowData>();
			if (m_MainLightShadowCasterPass.Setup(renderingData, cameraData, lightData, shadowData))
			{
				resourceData.mainShadowsTexture = m_MainLightShadowCasterPass.Render(renderGraph, base.frameData);
			}
			if (m_AdditionalLightsShadowCasterPass.Setup(renderingData, cameraData, lightData, shadowData))
			{
				resourceData.additionalShadowsTexture = m_AdditionalLightsShadowCasterPass.Render(renderGraph, base.frameData);
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRenderingShadows, RenderPassEvent.BeforeRenderingOpaques);
			m_RenderOpaqueForwardPass.Render(renderGraph, base.frameData, TextureHandle.nullHandle, resourceData.backBufferDepth, TextureHandle.nullHandle, TextureHandle.nullHandle);
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingOpaques, RenderPassEvent.BeforeRenderingTransparents);
			if (needTransparencyPass)
			{
				m_RenderTransparentForwardPass.Render(renderGraph, base.frameData, TextureHandle.nullHandle, resourceData.backBufferDepth, TextureHandle.nullHandle, TextureHandle.nullHandle);
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingTransparents, RenderPassEvent.AfterRendering);
		}

		private void OnBeforeRendering(RenderGraph renderGraph)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			UniversalRenderingData renderingData = base.frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = base.frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = base.frameData.Get<UniversalLightData>();
			UniversalShadowData shadowData = base.frameData.Get<UniversalShadowData>();
			m_ForwardLights.PreSetup(renderingData, universalCameraData, lightData);
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRenderingShadows);
			bool flag = false;
			if (m_MainLightShadowCasterPass.Setup(renderingData, universalCameraData, lightData, shadowData))
			{
				flag = true;
				universalResourceData.mainShadowsTexture = m_MainLightShadowCasterPass.Render(renderGraph, base.frameData);
			}
			if (m_AdditionalLightsShadowCasterPass.Setup(renderingData, universalCameraData, lightData, shadowData))
			{
				flag = true;
				universalResourceData.additionalShadowsTexture = m_AdditionalLightsShadowCasterPass.Render(renderGraph, base.frameData);
			}
			if (flag)
			{
				SetupRenderGraphCameraProperties(renderGraph, universalResourceData.activeColorTexture.IsValid() ? universalResourceData.activeColorTexture : universalResourceData.activeDepthTexture);
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingShadows);
			if (universalCameraData.postProcessEnabled && m_PostProcessPassRenderGraph != null)
			{
				m_ColorGradingLutPassRenderGraph.Render(renderGraph, base.frameData, out var internalColorLut);
				universalResourceData.internalColorLut = internalColorLut;
			}
		}

		private void UpdateInstanceOccluders(RenderGraph renderGraph, UniversalCameraData cameraData, TextureHandle depthTexture)
		{
			int x = (int)((float)cameraData.pixelWidth * cameraData.renderScale);
			int y = (int)((float)cameraData.pixelHeight * cameraData.renderScale);
			bool flag = cameraData.xr.enabled && cameraData.xr.singlePassEnabled;
			OccluderParameters occluderParameters = new OccluderParameters(cameraData.camera.GetInstanceID());
			occluderParameters.subviewCount = ((!flag) ? 1 : 2);
			occluderParameters.depthTexture = depthTexture;
			occluderParameters.depthSize = new Vector2Int(x, y);
			occluderParameters.depthIsArray = flag;
			OccluderParameters occluderParameters2 = occluderParameters;
			Span<OccluderSubviewUpdate> span = stackalloc OccluderSubviewUpdate[occluderParameters2.subviewCount];
			for (int i = 0; i < occluderParameters2.subviewCount; i++)
			{
				Matrix4x4 viewMatrix = cameraData.GetViewMatrix(i);
				Matrix4x4 projectionMatrix = cameraData.GetProjectionMatrix(i);
				span[i] = new OccluderSubviewUpdate(i)
				{
					depthSliceIndex = i,
					viewMatrix = viewMatrix,
					invViewMatrix = viewMatrix.inverse,
					gpuProjMatrix = GL.GetGPUProjectionMatrix(projectionMatrix, renderIntoTexture: true),
					viewOffsetWorldSpace = Vector3.zero
				};
			}
			GPUResidentDrawer.UpdateInstanceOccluders(renderGraph, in occluderParameters2, span);
		}

		private void InstanceOcclusionTest(RenderGraph renderGraph, UniversalCameraData cameraData, OcclusionTest occlusionTest)
		{
			bool flag = cameraData.xr.enabled && cameraData.xr.singlePassEnabled;
			int num = ((!flag) ? 1 : 2);
			OcclusionCullingSettings occlusionCullingSettings = new OcclusionCullingSettings(cameraData.camera.GetInstanceID(), occlusionTest);
			occlusionCullingSettings.instanceMultiplier = ((!flag || SystemInfo.supportsMultiview) ? 1 : 2);
			OcclusionCullingSettings settings = occlusionCullingSettings;
			Span<SubviewOcclusionTest> span = stackalloc SubviewOcclusionTest[num];
			for (int i = 0; i < num; i++)
			{
				span[i] = new SubviewOcclusionTest
				{
					cullingSplitIndex = 0,
					occluderSubviewIndex = i
				};
			}
			GPUResidentDrawer.InstanceOcclusionTest(renderGraph, in settings, span);
		}

		private void RecordCustomPassesWithDepthCopyAndMotion(RenderGraph renderGraph, UniversalResourceData resourceData, RenderPassEvent earliestDepthReadEvent, RenderPassEvent currentEvent, bool renderMotionVectors)
		{
			CalculateSplitEventRange(currentEvent, earliestDepthReadEvent, out var startEvent, out var splitEvent, out var endEvent);
			RecordCustomRenderGraphPassesInEventRange(renderGraph, startEvent, splitEvent);
			ExecuteScheduledDepthCopyWithMotion(renderGraph, resourceData, renderMotionVectors);
			RecordCustomRenderGraphPassesInEventRange(renderGraph, splitEvent, endEvent);
		}

		private static bool AllowPartialDepthNormalsPrepass(bool isDeferred, RenderPassEvent requiresDepthNormalEvent, bool useDepthPriming)
		{
			if (isDeferred && RenderPassEvent.AfterRenderingGbuffer <= requiresDepthNormalEvent && requiresDepthNormalEvent <= RenderPassEvent.BeforeRenderingOpaques)
			{
				return !useDepthPriming;
			}
			return false;
		}

		private DepthCopySchedule CalculateDepthCopySchedule(RenderPassEvent earliestDepthReadEvent, bool hasFullPrepass)
		{
			if (earliestDepthReadEvent < RenderPassEvent.AfterRenderingOpaques || m_CopyDepthMode == CopyDepthMode.ForcePrepass)
			{
				if (hasFullPrepass)
				{
					return DepthCopySchedule.AfterPrepass;
				}
				return DepthCopySchedule.AfterGBuffer;
			}
			if (earliestDepthReadEvent < RenderPassEvent.AfterRenderingTransparents || m_CopyDepthMode == CopyDepthMode.AfterOpaques)
			{
				if (earliestDepthReadEvent < RenderPassEvent.AfterRenderingSkybox)
				{
					return DepthCopySchedule.AfterOpaques;
				}
				return DepthCopySchedule.AfterSkybox;
			}
			if (earliestDepthReadEvent < RenderPassEvent.BeforeRenderingPostProcessing || m_CopyDepthMode == CopyDepthMode.AfterTransparents)
			{
				return DepthCopySchedule.AfterTransparents;
			}
			return DepthCopySchedule.None;
		}

		private TextureCopySchedules CalculateTextureCopySchedules(UniversalCameraData cameraData, in RenderPassInputSummary renderPassInputs, bool isDeferred, bool requiresDepthPrepass, bool hasFullPrepass, bool requireDepthTexture)
		{
			DepthCopySchedule depth = DepthCopySchedule.None;
			if (requireDepthTexture)
			{
				depth = ((isDeferred || !requiresDepthPrepass || base.useDepthPriming) ? CalculateDepthCopySchedule(renderPassInputs.requiresDepthTextureEarliestEvent, hasFullPrepass) : DepthCopySchedule.DuringPrepass);
			}
			ColorCopySchedule color = ((!cameraData.requiresOpaqueTexture && !renderPassInputs.requiresColorTexture) ? ColorCopySchedule.None : ColorCopySchedule.AfterSkybox);
			TextureCopySchedules result = default(TextureCopySchedules);
			result.depth = depth;
			result.color = color;
			return result;
		}

		private void CopyDepthToDepthTexture(RenderGraph renderGraph, UniversalResourceData resourceData)
		{
			m_CopyDepthPass.Render(renderGraph, base.frameData, resourceData.cameraDepthTexture, resourceData.activeDepthTexture, bindAsCameraDepth: true);
		}

		private void RenderMotionVectors(RenderGraph renderGraph, UniversalResourceData resourceData)
		{
			m_MotionVectorPass.Render(renderGraph, base.frameData, resourceData.cameraDepthTexture, resourceData.motionVectorColor, resourceData.motionVectorDepth);
		}

		private void ExecuteScheduledDepthCopyWithMotion(RenderGraph renderGraph, UniversalResourceData resourceData, bool renderMotionVectors)
		{
			CopyDepthToDepthTexture(renderGraph, resourceData);
			if (renderMotionVectors)
			{
				RenderMotionVectors(renderGraph, resourceData);
			}
		}

		private void OnMainRendering(RenderGraph renderGraph, ScriptableRenderContext context, in RenderPassInputSummary renderPassInputs, bool requiresPrepass, bool requireDepthTexture)
		{
			UniversalRenderingData universalRenderingData = base.frameData.Get<UniversalRenderingData>();
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			UniversalCameraData cameraData = base.frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = base.frameData.Get<UniversalLightData>();
			base.frameData.Get<UniversalPostProcessingData>();
			if (!renderGraph.nativeRenderPassesEnabled)
			{
				RTClearFlags cameraClearFlag = (RTClearFlags)ScriptableRenderer.GetCameraClearFlag(cameraData);
				if (cameraClearFlag != RTClearFlags.None)
				{
					ClearTargetsPass.Render(renderGraph, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, cameraClearFlag, cameraData.backgroundColor);
				}
			}
			if (universalRenderingData.stencilLodCrossFadeEnabled)
			{
				m_StencilCrossFadeRenderPass.Render(renderGraph, context, universalResourceData.activeDepthTexture);
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRenderingPrePasses);
			bool num = requiresPrepass && !renderPassInputs.requiresNormalsTexture;
			bool flag = requiresPrepass && renderPassInputs.requiresNormalsTexture;
			bool flag2 = num || (flag && !AllowPartialDepthNormalsPrepass(usesDeferredLighting, renderPassInputs.requiresDepthNormalAtEvent, base.useDepthPriming));
			TextureCopySchedules textureCopySchedules = CalculateTextureCopySchedules(cameraData, in renderPassInputs, usesDeferredLighting, requiresPrepass, flag2, requireDepthTexture);
			bool flag3 = RenderPassEvent.AfterRenderingGbuffer <= renderPassInputs.requiresDepthNormalAtEvent && renderPassInputs.requiresDepthNormalAtEvent <= RenderPassEvent.BeforeRenderingOpaques;
			bool flag4 = requiresPrepass && (!usesDeferredLighting || !flag3);
			OccluderPass occluderPass = OccluderPass.None;
			if (cameraData.useGPUOcclusionCulling)
			{
				occluderPass = (flag4 ? OccluderPass.DepthPrepass : (usesDeferredLighting ? OccluderPass.GBuffer : OccluderPass.ForwardOpaque));
			}
			if (cameraData.xr.enabled && cameraData.xr.hasMotionVectorPass)
			{
				m_XRDepthMotionPass?.Update(ref cameraData);
				m_XRDepthMotionPass?.Render(renderGraph, base.frameData);
			}
			if (requiresPrepass)
			{
				bool flag5 = usesDeferredLighting || base.useDepthPriming;
				TextureHandle depthTexture = (flag5 ? universalResourceData.activeDepthTexture : universalResourceData.cameraDepthTexture);
				if (universalRenderingData.stencilLodCrossFadeEnabled && flag && !flag5)
				{
					m_StencilCrossFadeRenderPass.Render(renderGraph, context, universalResourceData.cameraDepthTexture);
				}
				bool flag6 = occluderPass == OccluderPass.DepthPrepass;
				int num2 = ((!flag6) ? 1 : 2);
				for (int i = 0; i < num2; i++)
				{
					uint batchLayerMask = uint.MaxValue;
					if (flag6)
					{
						OcclusionTest occlusionTest = ((i == 0) ? OcclusionTest.TestAll : OcclusionTest.TestCulled);
						InstanceOcclusionTest(renderGraph, cameraData, occlusionTest);
						batchLayerMask = occlusionTest.GetBatchLayerMask();
					}
					bool num3 = i == num2 - 1;
					bool setGlobalDepth = num3 && !flag5;
					bool setGlobalTextures = num3 && flag2;
					if (flag)
					{
						if (universalResourceData.isActiveTargetBackBuffer)
						{
							SetupRenderGraphCameraProperties(renderGraph, depthTexture);
						}
						DepthNormalPrepassRender(renderGraph, renderPassInputs, in depthTexture, batchLayerMask, setGlobalDepth, setGlobalTextures, !flag2);
						if (universalResourceData.isActiveTargetBackBuffer)
						{
							SetupRenderGraphCameraProperties(renderGraph, universalResourceData.activeColorTexture.IsValid() ? universalResourceData.activeColorTexture : universalResourceData.activeDepthTexture);
						}
					}
					else
					{
						m_DepthPrepass.Render(renderGraph, base.frameData, in depthTexture, batchLayerMask, setGlobalDepth);
					}
					if (flag6)
					{
						UpdateInstanceOccluders(renderGraph, cameraData, depthTexture);
						if (i != 0)
						{
							InstanceOcclusionTest(renderGraph, cameraData, OcclusionTest.TestAll);
						}
					}
				}
			}
			if (textureCopySchedules.depth == DepthCopySchedule.AfterPrepass)
			{
				ExecuteScheduledDepthCopyWithMotion(renderGraph, universalResourceData, renderPassInputs.requiresMotionVectors);
			}
			else if (textureCopySchedules.depth == DepthCopySchedule.DuringPrepass && renderPassInputs.requiresMotionVectors)
			{
				RenderMotionVectors(renderGraph, universalResourceData);
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingPrePasses);
			if (cameraData.xr.hasValidOcclusionMesh)
			{
				m_XROcclusionMeshPass.Render(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture);
			}
			if (usesDeferredLighting)
			{
				m_DeferredLights.Setup(m_AdditionalLightsShadowCasterPass);
				m_DeferredLights.UseFramebufferFetch = renderGraph.nativeRenderPassesEnabled;
				m_DeferredLights.HasNormalPrepass = flag;
				m_DeferredLights.HasDepthPrepass = requiresPrepass;
				m_DeferredLights.ResolveMixedLightingMode(lightData);
				m_DeferredLights.CreateGbufferResourcesRenderGraph(renderGraph, universalResourceData);
				universalResourceData.gBuffer = m_DeferredLights.GbufferTextureHandles;
				RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRenderingGbuffer);
				bool flag7 = occluderPass == OccluderPass.GBuffer;
				int num4 = ((!flag7) ? 1 : 2);
				for (int j = 0; j < num4; j++)
				{
					uint batchLayerMask2 = uint.MaxValue;
					if (flag7)
					{
						OcclusionTest occlusionTest2 = ((j == 0) ? OcclusionTest.TestAll : OcclusionTest.TestCulled);
						InstanceOcclusionTest(renderGraph, cameraData, occlusionTest2);
						batchLayerMask2 = occlusionTest2.GetBatchLayerMask();
					}
					bool setGlobalTextures2 = flag && !flag2;
					m_GBufferPass.Render(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, setGlobalTextures2, batchLayerMask2);
					if (flag7)
					{
						UpdateInstanceOccluders(renderGraph, cameraData, universalResourceData.activeDepthTexture);
						if (j != 0)
						{
							InstanceOcclusionTest(renderGraph, cameraData, OcclusionTest.TestAll);
						}
					}
				}
				if (textureCopySchedules.depth == DepthCopySchedule.AfterGBuffer)
				{
					ExecuteScheduledDepthCopyWithMotion(renderGraph, universalResourceData, renderPassInputs.requiresMotionVectors);
				}
				else if (!renderGraph.nativeRenderPassesEnabled)
				{
					CopyDepthToDepthTexture(renderGraph, universalResourceData);
				}
				RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingGbuffer, RenderPassEvent.BeforeRenderingDeferredLights);
				m_DeferredPass.Render(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, universalResourceData.gBuffer);
				RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingDeferredLights, RenderPassEvent.BeforeRenderingOpaques);
				TextureHandle mainShadowsTexture = universalResourceData.mainShadowsTexture;
				TextureHandle additionalShadowsTexture = universalResourceData.additionalShadowsTexture;
				m_RenderOpaqueForwardOnlyPass.Render(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, mainShadowsTexture, additionalShadowsTexture);
			}
			else
			{
				RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRenderingGbuffer, RenderPassEvent.BeforeRenderingOpaques);
				bool flag8 = occluderPass == OccluderPass.ForwardOpaque;
				int num5 = ((!flag8) ? 1 : 2);
				for (int k = 0; k < num5; k++)
				{
					uint batchLayerMask3 = uint.MaxValue;
					if (flag8)
					{
						OcclusionTest occlusionTest3 = ((k == 0) ? OcclusionTest.TestAll : OcclusionTest.TestCulled);
						InstanceOcclusionTest(renderGraph, cameraData, occlusionTest3);
						batchLayerMask3 = occlusionTest3.GetBatchLayerMask();
					}
					if (m_RenderingLayerProvidesRenderObjectPass)
					{
						m_RenderOpaqueForwardWithRenderingLayersPass.Render(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.renderingLayersTexture, universalResourceData.activeDepthTexture, universalResourceData.mainShadowsTexture, universalResourceData.additionalShadowsTexture, m_RenderingLayersMaskSize, batchLayerMask3);
						SetRenderingLayersGlobalTextures(renderGraph);
					}
					else
					{
						m_RenderOpaqueForwardPass.Render(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, universalResourceData.mainShadowsTexture, universalResourceData.additionalShadowsTexture, batchLayerMask3, isMainOpaquePass: true);
					}
					if (flag8)
					{
						UpdateInstanceOccluders(renderGraph, cameraData, universalResourceData.activeDepthTexture);
						if (k != 0)
						{
							InstanceOcclusionTest(renderGraph, cameraData, OcclusionTest.TestAll);
						}
					}
				}
			}
			if (textureCopySchedules.depth == DepthCopySchedule.AfterOpaques)
			{
				RecordCustomPassesWithDepthCopyAndMotion(renderGraph, universalResourceData, renderPassInputs.requiresDepthTextureEarliestEvent, RenderPassEvent.AfterRenderingOpaques, renderPassInputs.requiresMotionVectors);
			}
			else
			{
				RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingOpaques);
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRenderingSkybox);
			if (cameraData.camera.clearFlags == CameraClearFlags.Skybox && cameraData.renderType != CameraRenderType.Overlay)
			{
				cameraData.camera.TryGetComponent<Skybox>(out var component);
				Material material = ((component != null) ? component.material : RenderSettings.skybox);
				if (material != null)
				{
					m_DrawSkyboxPass.Render(renderGraph, base.frameData, context, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, material);
				}
			}
			if (textureCopySchedules.depth == DepthCopySchedule.AfterSkybox)
			{
				ExecuteScheduledDepthCopyWithMotion(renderGraph, universalResourceData, renderPassInputs.requiresMotionVectors);
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingSkybox);
			if (textureCopySchedules.color == ColorCopySchedule.AfterSkybox)
			{
				TextureHandle source = universalResourceData.cameraColor;
				Downsampling opaqueDownsampling = UniversalRenderPipeline.asset.opaqueDownsampling;
				m_CopyColorPass.Render(renderGraph, base.frameData, out var destination, in source, opaqueDownsampling);
				universalResourceData.cameraOpaqueTexture = destination;
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRenderingTransparents);
			if (needTransparencyPass)
			{
				m_RenderTransparentForwardPass.m_ShouldTransparentsReceiveShadows = !m_TransparentSettingsPass.Setup();
				m_RenderTransparentForwardPass.Render(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, universalResourceData.mainShadowsTexture, universalResourceData.additionalShadowsTexture);
			}
			if (textureCopySchedules.depth == DepthCopySchedule.AfterTransparents)
			{
				RecordCustomPassesWithDepthCopyAndMotion(renderGraph, universalResourceData, renderPassInputs.requiresDepthTextureEarliestEvent, RenderPassEvent.AfterRenderingTransparents, renderPassInputs.requiresMotionVectors);
			}
			else
			{
				RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingTransparents);
			}
			if (context.HasInvokeOnRenderObjectCallbacks())
			{
				m_OnRenderObjectCallbackPass.Render(renderGraph, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture);
			}
			RenderRawColorDepthHistory(renderGraph, cameraData, universalResourceData);
			bool rendersOverlayUI = cameraData.rendersOverlayUI;
			bool isHDROutputActive = cameraData.isHDROutputActive;
			if (!(rendersOverlayUI && isHDROutputActive))
			{
				return;
			}
			if (cameraData.rendersOffscreenUI)
			{
				m_DrawOffscreenUIPass.RenderOffscreen(renderGraph, base.frameData, cameraDepthAttachmentFormat, universalResourceData.overlayUITexture);
				if (cameraData.blitsOffscreenUICover)
				{
					RenderTextureDescriptor desc = new RenderTextureDescriptor(1, 1, GraphicsFormat.R8G8B8A8_SRGB, 0);
					TextureHandle src = CreateRenderGraphTexture(renderGraph, desc, "BlackTexture", clear: false);
					m_OffscreenUICoverPrepass.Render(renderGraph, base.frameData, cameraData, in src, universalResourceData.backBufferColor, universalResourceData.overlayUITexture, useFullScreenViewport: true);
				}
			}
			else
			{
				RenderGraphUtils.SetGlobalTexture(renderGraph, ShaderPropertyId.overlayUITexture, universalResourceData.overlayUITexture, "Set Global Texture", ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\UniversalRendererRenderGraph.cs", 1348);
			}
		}

		private void OnAfterRendering(RenderGraph renderGraph, bool applyPostProcessing)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			base.frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = base.frameData.Get<UniversalCameraData>();
			UniversalPostProcessingData universalPostProcessingData = base.frameData.Get<UniversalPostProcessingData>();
			if (universalCameraData.resolveFinalTarget)
			{
				SetupRenderGraphFinalPassDebug(renderGraph, base.frameData);
			}
			bool flag = DebugDisplaySettings<UniversalRenderPipelineDebugDisplaySettings>.Instance.renderingSettings.sceneOverrideMode == DebugSceneOverrideMode.None;
			if (flag)
			{
				DrawRenderGraphGizmos(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, GizmoSubset.PreImageEffects);
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.BeforeRenderingPostProcessing);
			bool flag2 = universalPostProcessingData.isEnabled && m_PostProcessPassRenderGraph != null && universalCameraData.resolveFinalTarget && (universalCameraData.antialiasing == AntialiasingMode.FastApproximateAntialiasing || (universalCameraData.imageScalingMode == ImageScalingMode.Upscaling && universalCameraData.upscalingFilter != ImageUpscalingFilter.Linear) || (universalCameraData.IsTemporalAAEnabled() && universalCameraData.taaSettings.contrastAdaptiveSharpening > 0f));
			bool flag3 = universalCameraData.captureActions != null && universalCameraData.resolveFinalTarget;
			bool flag4 = base.activeRenderPassQueue.Find((ScriptableRenderPass x) => x.renderPassEvent >= RenderPassEvent.AfterRenderingPostProcessing && x.renderPassEvent < RenderPassEvent.AfterRendering) != null;
			bool flag5 = !flag3 && !flag4 && !flag2;
			bool flag6 = base.DebugHandler == null || !base.DebugHandler.HDRDebugViewIsActive(universalCameraData.resolveFinalTarget);
			bool flag7 = universalResourceData.activeDepthID == UniversalResourceDataBase.ActiveID.BackBuffer;
			DebugHandler activeDebugHandler = ScriptableRenderPass.GetActiveDebugHandler(universalCameraData);
			bool flag8 = activeDebugHandler?.WriteToDebugScreenTexture(universalCameraData.resolveFinalTarget) ?? false;
			if (flag8)
			{
				RenderTextureDescriptor descriptor = universalCameraData.cameraTargetDescriptor;
				DebugHandler.ConfigureColorDescriptorForDebugScreen(ref descriptor, universalCameraData.pixelWidth, universalCameraData.pixelHeight);
				universalResourceData.debugScreenColor = CreateRenderGraphTexture(renderGraph, descriptor, "_DebugScreenColor", clear: false);
				RenderTextureDescriptor descriptor2 = universalCameraData.cameraTargetDescriptor;
				DebugHandler.ConfigureDepthDescriptorForDebugScreen(ref descriptor2, cameraDepthAttachmentFormat, universalCameraData.pixelWidth, universalCameraData.pixelHeight);
				universalResourceData.debugScreenDepth = CreateRenderGraphTexture(renderGraph, descriptor2, "_DebugScreenDepth", clear: false);
			}
			_ = universalResourceData.afterPostProcessColor;
			if (applyPostProcessing)
			{
				TextureHandle activeCameraColorTexture = universalResourceData.activeColorTexture;
				TextureHandle backBufferColor = universalResourceData.backBufferColor;
				TextureHandle lutTexture = universalResourceData.internalColorLut;
				TextureHandle overlayUITexture = universalResourceData.overlayUITexture;
				bool flag9 = universalCameraData.resolveFinalTarget && !flag2 && !flag4;
				TextureHandle postProcessingTarget;
				if (flag9)
				{
					postProcessingTarget = backBufferColor;
				}
				else
				{
					ImportResourceParams importParams = new ImportResourceParams
					{
						clearOnFirstUse = true,
						clearColor = Color.black,
						discardOnLastUse = universalCameraData.resolveFinalTarget
					};
					if (!universalCameraData.IsSTPEnabled())
					{
						if (universalCameraData.IsTemporalAAEnabled())
						{
						}
						bool flag10 = universalCameraData.resolveFinalTarget && universalCameraData.renderType == CameraRenderType.Base;
						universalResourceData.cameraColor = (flag10 ? renderGraph.CreateTexture(activeCameraColorTexture, "_CameraColorAfterPostProcessing") : renderGraph.ImportTexture(nextRenderGraphCameraColorHandle, importParams));
					}
					else
					{
						TextureDesc desc = universalResourceData.cameraColor.GetDescriptor(renderGraph);
						PostProcessPassRenderGraph.MakeCompatible(ref desc);
						desc.width = universalCameraData.pixelWidth;
						desc.height = universalCameraData.pixelHeight;
						desc.name = "_CameraColorUpscaled";
						universalResourceData.cameraColor = renderGraph.CreateTexture(in desc);
					}
					postProcessingTarget = universalResourceData.cameraColor;
				}
				if (flag8 && flag9)
				{
					postProcessingTarget = universalResourceData.debugScreenColor;
				}
				bool enableColorEndingIfNeeded = flag5 && flag6;
				m_PostProcessPassRenderGraph.RenderPostProcessingRenderGraph(renderGraph, base.frameData, in activeCameraColorTexture, in lutTexture, in overlayUITexture, in postProcessingTarget, flag2, flag8, enableColorEndingIfNeeded);
				if (universalCameraData.resolveFinalTarget)
				{
					SetupAfterPostRenderGraphFinalPassDebug(renderGraph, base.frameData);
				}
				if (flag9)
				{
					universalResourceData.SwitchActiveTexturesToBackbuffer();
				}
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRenderingPostProcessing);
			if (universalCameraData.captureActions != null)
			{
				m_CapturePass.RecordRenderGraph(renderGraph, base.frameData);
			}
			if (flag2)
			{
				TextureHandle backBufferColor2 = universalResourceData.backBufferColor;
				TextureHandle overlayUITexture2 = universalResourceData.overlayUITexture;
				TextureHandle postProcessingTarget2 = backBufferColor2;
				if (flag8)
				{
					postProcessingTarget2 = universalResourceData.debugScreenColor;
				}
				TextureHandle source = universalResourceData.cameraColor;
				m_PostProcessPassRenderGraph.RenderFinalPassRenderGraph(renderGraph, base.frameData, in source, in overlayUITexture2, in postProcessingTarget2, flag6);
				universalResourceData.SwitchActiveTexturesToBackbuffer();
			}
			bool flag11 = flag2 || (applyPostProcessing && !flag4 && !flag3);
			if (!universalResourceData.isActiveTargetBackBuffer && universalCameraData.resolveFinalTarget && !flag11)
			{
				TextureHandle backBufferColor3 = universalResourceData.backBufferColor;
				TextureHandle overlayUITexture3 = universalResourceData.overlayUITexture;
				TextureHandle dest = backBufferColor3;
				if (flag8)
				{
					dest = universalResourceData.debugScreenColor;
				}
				TextureHandle src = universalResourceData.cameraColor;
				m_FinalBlitPass.Render(renderGraph, base.frameData, universalCameraData, in src, in dest, overlayUITexture3);
				universalResourceData.SwitchActiveTexturesToBackbuffer();
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent.AfterRendering);
			bool num = universalCameraData.rendersOverlayUI && universalCameraData.isLastBaseCamera;
			bool isHDROutputActive = universalCameraData.isHDROutputActive;
			if (num && !isHDROutputActive)
			{
				TextureHandle depthBuffer = universalResourceData.backBufferDepth;
				TextureHandle colorBuffer = universalResourceData.backBufferColor;
				if (flag8)
				{
					colorBuffer = universalResourceData.debugScreenColor;
					depthBuffer = universalResourceData.debugScreenDepth;
				}
				m_DrawOverlayUIPass.RenderOverlay(renderGraph, base.frameData, in colorBuffer, in depthBuffer);
			}
			if (universalCameraData.xr.enabled && !flag7 && universalCameraData.xr.copyDepth)
			{
				m_XRCopyDepthPass.CopyToDepthXR = true;
				m_XRCopyDepthPass.MsaaSamples = 1;
				m_XRCopyDepthPass.Render(renderGraph, base.frameData, universalResourceData.backBufferDepth, universalResourceData.cameraDepth, bindAsCameraDepth: false, "XR Depth Copy");
			}
			if (activeDebugHandler != null)
			{
				_ = universalResourceData.overlayUITexture;
				_ = universalResourceData.debugScreenColor;
			}
			if (universalCameraData.resolveFinalTarget)
			{
				if (universalCameraData.isSceneViewCamera)
				{
					DrawRenderGraphWireOverlay(renderGraph, base.frameData, universalResourceData.backBufferColor);
				}
				if (flag)
				{
					DrawRenderGraphGizmos(renderGraph, base.frameData, universalResourceData.backBufferColor, universalResourceData.activeDepthTexture, GizmoSubset.PostImageEffects);
				}
			}
		}

		private bool RequirePrepassForTextures(UniversalCameraData cameraData, in RenderPassInputSummary renderPassInputs, bool requireDepthTexture)
		{
			return (requireDepthTexture && !CanCopyDepth(cameraData)) | (cameraData.requiresDepthTexture && m_CopyDepthMode == CopyDepthMode.ForcePrepass) | renderPassInputs.requiresDepthPrepass | DebugHandlerRequireDepthPass(cameraData) | renderPassInputs.requiresNormalsTexture;
		}

		private static bool RequireDepthTexture(UniversalCameraData cameraData, in RenderPassInputSummary renderPassInputs, bool applyPostProcessing)
		{
			bool num = cameraData.requiresDepthTexture || renderPassInputs.requiresDepthTexture;
			bool flag = applyPostProcessing && cameraData.postProcessingRequiresDepthTexture;
			return num || flag;
		}

		private static bool IsDepthPrimingEnabledRenderGraph(UniversalCameraData cameraData, in RenderPassInputSummary renderPassInputs, DepthPrimingMode depthPrimingMode, bool requireDepthTexture, bool requirePrepassForTextures, bool usesDeferredLighting)
		{
			bool flag = true;
			if (requireDepthTexture && !CanCopyDepth(cameraData))
			{
				return false;
			}
			bool flag2 = !IsWebGL();
			bool num = (flag && depthPrimingMode == DepthPrimingMode.Auto) || depthPrimingMode == DepthPrimingMode.Forced;
			bool flag3 = cameraData.cameraTargetDescriptor.msaaSamples == 1;
			bool flag4 = cameraData.renderType == CameraRenderType.Base || cameraData.clearDepth;
			bool flag5 = !IsOffscreenDepthTexture(cameraData);
			return num && !usesDeferredLighting && flag4 && flag5 && flag2 && flag3;
		}

		internal void SetRenderingLayersGlobalTextures(RenderGraph renderGraph)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			if (universalResourceData.renderingLayersTexture.IsValid() && !usesDeferredLighting)
			{
				RenderGraphUtils.SetGlobalTexture(renderGraph, Shader.PropertyToID(m_RenderingLayersTextureName), universalResourceData.renderingLayersTexture, "Set Global Rendering Layers Texture", ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\UniversalRendererRenderGraph.cs", 1683);
			}
		}

		private void ImportBackBuffers(RenderGraph renderGraph, UniversalCameraData cameraData, Color clearBackgroundColor, bool isCameraTargetOffscreenDepth)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			bool flag = cameraData.renderType == CameraRenderType.Base && !m_RequiresIntermediateAttachments;
			flag = flag || isCameraTargetOffscreenDepth;
			bool flag2 = !SupportedRenderingFeatures.active.rendersUIOverlay && cameraData.resolveToScreen;
			bool flag3 = Watermark.IsVisible() || flag2;
			bool discardOnLastUse = !m_RequiresIntermediateAttachments && !flag3 && cameraData.cameraTargetDescriptor.msaaSamples > 1;
			TextureUVOrigin textureUVOrigin = ((!cameraData.isSceneViewCamera && !cameraData.isPreviewCamera && cameraData.targetTexture == null) ? (SystemInfo.graphicsUVStartsAtTop ? TextureUVOrigin.TopLeft : TextureUVOrigin.BottomLeft) : TextureUVOrigin.BottomLeft);
			ImportResourceParams importParams = new ImportResourceParams
			{
				clearOnFirstUse = flag,
				clearColor = clearBackgroundColor,
				discardOnLastUse = discardOnLastUse,
				textureUVOrigin = textureUVOrigin
			};
			ImportResourceParams importParams2 = new ImportResourceParams
			{
				clearOnFirstUse = flag,
				clearColor = clearBackgroundColor,
				discardOnLastUse = !isCameraTargetOffscreenDepth,
				textureUVOrigin = textureUVOrigin
			};
			if (cameraData.xr.enabled && cameraData.xr.copyDepth)
			{
				importParams2.discardOnLastUse = false;
			}
			RenderTargetInfo renderTargetInfo = default(RenderTargetInfo);
			RenderTargetInfo renderTargetInfo2 = default(RenderTargetInfo);
			bool flag4 = cameraData.targetTexture == null;
			if (cameraData.xr.enabled)
			{
				flag4 = false;
			}
			if (flag4)
			{
				int msaaSamples = AdjustAndGetScreenMSAASamples(renderGraph, m_RequiresIntermediateAttachments);
				renderTargetInfo.width = Screen.width;
				renderTargetInfo.height = Screen.height;
				renderTargetInfo.volumeDepth = 1;
				renderTargetInfo.msaaSamples = msaaSamples;
				renderTargetInfo.format = cameraData.cameraTargetDescriptor.graphicsFormat;
				renderTargetInfo2 = renderTargetInfo;
				renderTargetInfo2.format = cameraData.cameraTargetDescriptor.depthStencilFormat;
			}
			else
			{
				if (cameraData.xr.enabled)
				{
					renderTargetInfo.width = cameraData.xr.renderTargetDesc.width;
					renderTargetInfo.height = cameraData.xr.renderTargetDesc.height;
					renderTargetInfo.volumeDepth = cameraData.xr.renderTargetDesc.volumeDepth;
					renderTargetInfo.msaaSamples = cameraData.xr.renderTargetDesc.msaaSamples;
					renderTargetInfo.format = cameraData.xr.renderTargetDesc.graphicsFormat;
					if (!PlatformRequiresExplicitMsaaResolve())
					{
						renderTargetInfo.bindMS = renderTargetInfo.msaaSamples > 1;
					}
					renderTargetInfo2 = renderTargetInfo;
					renderTargetInfo2.format = cameraData.xr.renderTargetDesc.depthStencilFormat;
				}
				else
				{
					renderTargetInfo.width = cameraData.targetTexture.width;
					renderTargetInfo.height = cameraData.targetTexture.height;
					renderTargetInfo.volumeDepth = cameraData.targetTexture.volumeDepth;
					renderTargetInfo.msaaSamples = cameraData.targetTexture.antiAliasing;
					renderTargetInfo.format = cameraData.targetTexture.graphicsFormat;
					renderTargetInfo2 = renderTargetInfo;
					renderTargetInfo2.format = cameraData.targetTexture.depthStencilFormat;
				}
				if (renderTargetInfo2.format == GraphicsFormat.None)
				{
					renderTargetInfo2.format = SystemInfo.GetGraphicsFormat(DefaultFormat.DepthStencil);
					Debug.LogWarning("In the render graph API, the output Render Texture must have a depth buffer. When you select a Render Texture in any camera's Output Texture property, the Depth Stencil Format property of the texture must be set to a value other than None.");
				}
			}
			if (!isCameraTargetOffscreenDepth)
			{
				universalResourceData.backBufferColor = renderGraph.ImportTexture(m_TargetColorHandle, renderTargetInfo, importParams);
			}
			universalResourceData.backBufferDepth = renderGraph.ImportTexture(m_TargetDepthHandle, renderTargetInfo2, importParams2);
		}

		private void CreateIntermediateCameraColorAttachment(RenderGraph renderGraph, UniversalCameraData cameraData, in TextureDesc cameraDescriptor, bool clearColor, Color clearBackgroundColor)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			TextureDesc desc = cameraDescriptor;
			desc.useMipMap = false;
			desc.autoGenerateMips = false;
			desc.filterMode = FilterMode.Bilinear;
			desc.wrapMode = TextureWrapMode.Clamp;
			if (cameraData.resolveFinalTarget && cameraData.renderType == CameraRenderType.Base)
			{
				universalResourceData.cameraColor = CreateRenderGraphTexture(renderGraph, in desc, "_CameraTargetAttachment", clearColor, clearBackgroundColor, desc.filterMode, TextureWrapMode.Clamp, cameraData.resolveFinalTarget);
				m_CurrentColorHandle = -1;
			}
			else
			{
				RenderingUtils.ReAllocateHandleIfNeeded(ref m_RenderGraphCameraColorHandles[0], desc, "_CameraTargetAttachmentA");
				RenderingUtils.ReAllocateHandleIfNeeded(ref m_RenderGraphCameraColorHandles[1], desc, "_CameraTargetAttachmentB");
				if (cameraData.renderType == CameraRenderType.Base)
				{
					m_CurrentColorHandle = 0;
				}
				universalResourceData.cameraColor = renderGraph.ImportTexture(importParams: new ImportResourceParams
				{
					clearOnFirstUse = clearColor,
					clearColor = clearBackgroundColor,
					discardOnLastUse = cameraData.resolveFinalTarget
				}, rt: currentRenderGraphCameraColorHandle);
			}
			universalResourceData.activeColorID = UniversalResourceDataBase.ActiveID.Camera;
		}

		private void CreateIntermediateCameraDepthAttachment(RenderGraph renderGraph, UniversalCameraData cameraData, in TextureDesc cameraDescriptor, bool clearDepth, Color clearBackgroundDepth, bool depthTextureIsDepthFormat)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			TextureDesc desc = cameraDescriptor;
			desc.useMipMap = false;
			desc.autoGenerateMips = false;
			bool flag = desc.msaaSamples != MSAASamples.None;
			bool flag2 = RenderingUtils.MultisampleDepthResolveSupported() && renderGraph.nativeRenderPassesEnabled;
			desc.bindTextureMS = !flag2 && flag;
			if (IsGLESDevice())
			{
				desc.bindTextureMS = false;
			}
			desc.format = cameraDepthAttachmentFormat;
			desc.filterMode = FilterMode.Point;
			desc.wrapMode = TextureWrapMode.Clamp;
			bool resolveFinalTarget = cameraData.resolveFinalTarget;
			if (cameraData.resolveFinalTarget && cameraData.renderType == CameraRenderType.Base)
			{
				universalResourceData.cameraDepth = CreateRenderGraphTexture(renderGraph, in desc, "_CameraDepthAttachment", clearDepth, clearBackgroundDepth, desc.filterMode, desc.wrapMode, resolveFinalTarget);
			}
			else
			{
				RenderingUtils.ReAllocateHandleIfNeeded(ref m_RenderGraphCameraDepthHandle, desc, "_CameraDepthAttachment");
				universalResourceData.cameraDepth = renderGraph.ImportTexture(importParams: new ImportResourceParams
				{
					clearOnFirstUse = clearDepth,
					clearColor = clearBackgroundDepth,
					discardOnLastUse = resolveFinalTarget
				}, rt: m_RenderGraphCameraDepthHandle);
			}
			universalResourceData.activeDepthID = UniversalResourceDataBase.ActiveID.Camera;
			m_CopyDepthPass.MsaaSamples = (int)desc.msaaSamples;
			m_CopyDepthPass.CopyToDepth = depthTextureIsDepthFormat;
			bool copyResolvedDepth = !desc.bindTextureMS;
			m_CopyDepthPass.m_CopyResolvedDepth = copyResolvedDepth;
			m_XRCopyDepthPass.m_CopyResolvedDepth = copyResolvedDepth;
		}

		private void CreateCameraDepthCopyTexture(RenderGraph renderGraph, TextureDesc descriptor, bool isDepthTexture, Color clearColor)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			TextureDesc desc = descriptor;
			desc.msaaSamples = MSAASamples.None;
			if (isDepthTexture)
			{
				desc.format = cameraDepthTextureFormat;
				desc.clearBuffer = true;
			}
			else
			{
				desc.format = GraphicsFormat.R32_SFloat;
				desc.clearBuffer = false;
			}
			universalResourceData.cameraDepthTexture = CreateRenderGraphTexture(renderGraph, in desc, "_CameraDepthTexture", desc.clearBuffer, clearColor);
		}

		private void CreateMotionVectorTextures(RenderGraph renderGraph, TextureDesc descriptor)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			descriptor.msaaSamples = MSAASamples.None;
			descriptor.format = GraphicsFormat.R16G16_SFloat;
			universalResourceData.motionVectorColor = CreateRenderGraphTexture(renderGraph, in descriptor, "_MotionVectorTexture", clear: true, Color.black);
			descriptor.format = cameraDepthAttachmentFormat;
			universalResourceData.motionVectorDepth = CreateRenderGraphTexture(renderGraph, in descriptor, "_MotionVectorDepthTexture", clear: true, Color.black);
		}

		private void CreateCameraNormalsTexture(RenderGraph renderGraph, TextureDesc descriptor)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			descriptor.msaaSamples = MSAASamples.None;
			string name = ((!usesDeferredLighting) ? DepthNormalOnlyPass.k_CameraNormalsTextureName : DeferredLights.k_GBufferNames[m_DeferredLights.GBufferNormalSmoothnessIndex]);
			descriptor.format = ((!usesDeferredLighting) ? DepthNormalOnlyPass.GetGraphicsFormat() : m_DeferredLights.GetGBufferFormat(m_DeferredLights.GBufferNormalSmoothnessIndex));
			universalResourceData.cameraNormalsTexture = CreateRenderGraphTexture(renderGraph, in descriptor, name, clear: true, Color.black);
		}

		private void CreateRenderingLayersTexture(RenderGraph renderGraph, TextureDesc descriptor)
		{
			if (m_RequiresRenderingLayer)
			{
				UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
				m_RenderingLayersTextureName = "_CameraRenderingLayersTexture";
				if (usesDeferredLighting && m_DeferredLights.UseRenderingLayers)
				{
					m_RenderingLayersTextureName = DeferredLights.k_GBufferNames[m_DeferredLights.GBufferRenderingLayers];
				}
				if (!m_RenderingLayerProvidesRenderObjectPass)
				{
					descriptor.msaaSamples = MSAASamples.None;
				}
				if (usesDeferredLighting && m_RequiresRenderingLayer)
				{
					descriptor.format = m_DeferredLights.GetGBufferFormat(m_DeferredLights.GBufferRenderingLayers);
				}
				else
				{
					descriptor.format = RenderingLayerUtils.GetFormat(m_RenderingLayersMaskSize);
				}
				universalResourceData.renderingLayersTexture = CreateRenderGraphTexture(renderGraph, in descriptor, m_RenderingLayersTextureName, clear: true, descriptor.clearColor);
			}
		}

		private void CreateAfterPostProcessTexture(RenderGraph renderGraph, RenderTextureDescriptor descriptor)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			RenderTextureDescriptor compatibleDescriptor = PostProcessPassRenderGraph.GetCompatibleDescriptor(descriptor, descriptor.width, descriptor.height, descriptor.graphicsFormat);
			universalResourceData.afterPostProcessColor = CreateRenderGraphTexture(renderGraph, compatibleDescriptor, "_AfterPostProcessTexture", clear: true);
		}

		private void CreateOffscreenUITexture(RenderGraph renderGraph, TextureDesc descriptor)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			DrawScreenSpaceUIPass.ConfigureOffscreenUITextureDesc(ref descriptor);
			RenderingUtils.ReAllocateHandleIfNeeded(ref m_OffscreenUIColorHandle, descriptor, "_OverlayUITexture");
			universalResourceData.overlayUITexture = renderGraph.ImportTexture(m_OffscreenUIColorHandle);
		}

		private void DepthNormalPrepassRender(RenderGraph renderGraph, RenderPassInputSummary renderPassInputs, in TextureHandle depthTarget, uint batchLayerMask, bool setGlobalDepth, bool setGlobalTextures, bool partialPass)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			if (m_RenderingLayerProvidesByDepthNormalPass)
			{
				m_DepthNormalPrepass.enableRenderingLayers = true;
				m_DepthNormalPrepass.renderingLayersMaskSize = m_RenderingLayersMaskSize;
			}
			else
			{
				m_DepthNormalPrepass.enableRenderingLayers = false;
			}
			m_DepthNormalPrepass.Render(renderGraph, base.frameData, universalResourceData.cameraNormalsTexture, in depthTarget, universalResourceData.renderingLayersTexture, batchLayerMask, setGlobalDepth, setGlobalTextures, partialPass);
			if (m_RequiresRenderingLayer)
			{
				SetRenderingLayersGlobalTextures(renderGraph);
			}
		}
	}
}
