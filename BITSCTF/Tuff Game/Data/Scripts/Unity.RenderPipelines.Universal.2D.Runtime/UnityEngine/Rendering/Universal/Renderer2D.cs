using System.Collections.Generic;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;
using UnityEngine.Rendering.Universal.Internal;

namespace UnityEngine.Rendering.Universal
{
	internal sealed class Renderer2D : ScriptableRenderer
	{
		private struct RenderPassInputSummary
		{
			internal bool requiresDepthTexture;

			internal bool requiresColorTexture;
		}

		private struct ImportResourceSummary
		{
			internal RenderTargetInfo importInfo;

			internal RenderTargetInfo importInfoDepth;

			internal ImportResourceParams cameraColorParams;

			internal ImportResourceParams cameraDepthParams;

			internal ImportResourceParams backBufferColorParams;

			internal ImportResourceParams backBufferDepthParams;
		}

		private const int k_FinalBlitPassQueueOffset = 1;

		private const int k_AfterFinalBlitPassQueueOffset = 2;

		private static int m_CurrentColorHandle;

		internal RTHandle[] m_RenderGraphCameraColorHandles = new RTHandle[2];

		internal RTHandle m_RenderGraphCameraDepthHandle;

		private RTHandle m_RenderGraphBackbufferColorHandle;

		private RTHandle m_RenderGraphBackbufferDepthHandle;

		private RTHandle m_CameraSortingLayerHandle;

		private static RTHandle m_OffscreenUIColorHandle;

		private Material m_BlitMaterial;

		private Material m_BlitHDRMaterial;

		private Material m_BlitOffscreenUICoverMaterial;

		private Material m_SamplingMaterial;

		private DrawNormal2DPass m_NormalPass = new DrawNormal2DPass();

		private DrawLight2DPass m_LightPass = new DrawLight2DPass();

		private DrawShadow2DPass m_ShadowPass = new DrawShadow2DPass();

		private DrawRenderer2DPass m_RendererPass = new DrawRenderer2DPass();

		private CopyDepthPass m_CopyDepthPass;

		private UpscalePass m_UpscalePass;

		private CopyCameraSortingLayerPass m_CopyCameraSortingLayerPass;

		private FinalBlitPass m_FinalBlitPass;

		private FinalBlitPass m_OffscreenUICoverPrepass;

		private DrawScreenSpaceUIPass m_DrawOffscreenUIPass;

		private DrawScreenSpaceUIPass m_DrawOverlayUIPass;

		private Renderer2DData m_Renderer2DData;

		private LayerBatch[] m_LayerBatches;

		private int m_BatchCount;

		internal bool m_CreateColorTexture;

		internal bool m_CreateDepthTexture;

		private bool ppcUpscaleRT;

		private PostProcessPassRenderGraph m_PostProcessPassRenderGraph;

		private ColorGradingLutPass m_ColorGradingLutPassRenderGraph;

		private RTHandle currentRenderGraphCameraColorHandle => m_RenderGraphCameraColorHandles[m_CurrentColorHandle];

		private RTHandle nextRenderGraphCameraColorHandle
		{
			get
			{
				m_CurrentColorHandle = (m_CurrentColorHandle + 1) % 2;
				return currentRenderGraphCameraColorHandle;
			}
		}

		internal static bool supportsMRT => !IsGLESDevice();

		internal override bool supportsNativeRenderPassRendergraphCompiler => true;

		public override int SupportedCameraStackingTypes()
		{
			return 3;
		}

		public Renderer2D(Renderer2DData data)
			: base(data)
		{
			if (GraphicsSettings.TryGetRenderPipelineSettings<UniversalRenderPipelineRuntimeShaders>(out var settings))
			{
				m_BlitMaterial = CoreUtils.CreateEngineMaterial(settings.coreBlitPS);
				m_BlitHDRMaterial = CoreUtils.CreateEngineMaterial(settings.blitHDROverlay);
				m_BlitOffscreenUICoverMaterial = CoreUtils.CreateEngineMaterial(settings.blitHDROverlay);
				m_SamplingMaterial = CoreUtils.CreateEngineMaterial(settings.samplingPS);
			}
			if (GraphicsSettings.TryGetRenderPipelineSettings<Renderer2DResources>(out var settings2))
			{
				m_CopyDepthPass = new CopyDepthPass(RenderPassEvent.AfterRenderingTransparents, settings2.copyDepthPS, shouldClear: true, copyToDepth: false, RenderingUtils.MultisampleDepthResolveSupported());
			}
			m_UpscalePass = new UpscalePass(RenderPassEvent.AfterRenderingPostProcessing, m_BlitMaterial);
			m_CopyCameraSortingLayerPass = new CopyCameraSortingLayerPass(m_BlitMaterial);
			m_FinalBlitPass = new FinalBlitPass((RenderPassEvent)1001, m_BlitMaterial, m_BlitHDRMaterial);
			m_OffscreenUICoverPrepass = new FinalBlitPass(RenderPassEvent.BeforeRenderingPostProcessing, m_BlitMaterial, m_BlitOffscreenUICoverMaterial);
			m_DrawOffscreenUIPass = new DrawScreenSpaceUIPass(RenderPassEvent.BeforeRenderingPostProcessing, renderOffscreen: true);
			m_DrawOverlayUIPass = new DrawScreenSpaceUIPass((RenderPassEvent)1002, renderOffscreen: false);
			m_Renderer2DData = data;
			m_Renderer2DData.lightCullResult = new Light2DCullResult();
			base.supportedRenderingFeatures = new RenderingFeatures();
			LensFlareCommonSRP.mergeNeeded = 0;
			LensFlareCommonSRP.maxLensFlareWithOcclusionTemporalSample = 1;
			LensFlareCommonSRP.Initialize();
			Light2DManager.Initialize();
			if (data.postProcessData != null)
			{
				m_PostProcessPassRenderGraph = new PostProcessPassRenderGraph(data.postProcessData, GraphicsFormat.B10G11R11_UFloatPack32);
				m_ColorGradingLutPassRenderGraph = new ColorGradingLutPass(RenderPassEvent.BeforeRenderingPrePasses, data.postProcessData);
			}
			PlatformAutoDetect.Initialize();
			if (GraphicsSettings.TryGetRenderPipelineSettings<UniversalRenderPipelineRuntimeXRResources>(out var settings3))
			{
				XRSystem.Initialize(XRPassUniversal.Create, settings3.xrOcclusionMeshPS, settings3.xrMirrorViewPS);
			}
		}

		internal static bool IsDepthUsageAllowed(ContextContainer frameData, Renderer2DData rendererData)
		{
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			bool flag = rendererData.useDepthStencilBuffer;
			if (universalCameraData.targetTexture != null)
			{
				flag &= universalCameraData.targetTexture.dimension != TextureDimension.Tex3D;
			}
			return flag;
		}

		private bool IsPixelPerfectCameraEnabled(UniversalCameraData cameraData, out PixelPerfectCamera ppc)
		{
			ppc = null;
			if (cameraData.renderType == CameraRenderType.Base && cameraData.resolveFinalTarget)
			{
				cameraData.camera.TryGetComponent<PixelPerfectCamera>(out ppc);
			}
			if (ppc != null)
			{
				return ppc.enabled;
			}
			return false;
		}

		private RenderPassInputSummary GetRenderPassInputs(UniversalCameraData cameraData)
		{
			RenderPassInputSummary result = default(RenderPassInputSummary);
			for (int i = 0; i < base.activeRenderPassQueue.Count; i++)
			{
				ScriptableRenderPass scriptableRenderPass = base.activeRenderPassQueue[i];
				bool flag = (scriptableRenderPass.input & ScriptableRenderPassInput.Depth) != 0;
				bool flag2 = (scriptableRenderPass.input & ScriptableRenderPassInput.Color) != 0;
				result.requiresDepthTexture |= flag;
				result.requiresColorTexture |= flag2;
			}
			result.requiresColorTexture |= cameraData.postProcessEnabled || cameraData.isHdrEnabled || cameraData.isSceneViewCamera || !cameraData.isDefaultViewport || cameraData.requireSrgbConversion || !cameraData.resolveFinalTarget || (cameraData.cameraTargetDescriptor.msaaSamples > 1 && UniversalRenderer.PlatformRequiresExplicitMsaaResolve()) || m_Renderer2DData.useCameraSortingLayerTexture || !Mathf.Approximately(cameraData.renderScale, 1f) || (base.DebugHandler != null && base.DebugHandler.WriteToDebugScreenTexture(cameraData.resolveFinalTarget));
			return result;
		}

		private ImportResourceSummary GetImportResourceSummary(RenderGraph renderGraph, UniversalCameraData cameraData)
		{
			ImportResourceSummary result = default(ImportResourceSummary);
			bool clearOnFirstUse = cameraData.renderType == CameraRenderType.Base;
			bool clearOnFirstUse2 = cameraData.renderType == CameraRenderType.Base || cameraData.clearDepth;
			PixelPerfectCamera ppc;
			bool flag = IsPixelPerfectCameraEnabled(cameraData, out ppc) && ppc.cropFrame != PixelPerfectCamera.CropFrame.None;
			bool clearOnFirstUse3 = cameraData.renderType == CameraRenderType.Base && (!m_CreateColorTexture || flag);
			bool clearOnFirstUse4 = cameraData.renderType == CameraRenderType.Base && !m_CreateColorTexture;
			Color color = ((cameraData.camera.clearFlags == CameraClearFlags.Nothing) ? Color.yellow : cameraData.backgroundColor);
			Color clearColor = (flag ? Color.black : color);
			if (IsSceneFilteringEnabled(cameraData.camera))
			{
				color.a = 0f;
				clearOnFirstUse2 = false;
			}
			DebugHandler debugHandler = cameraData.renderer.DebugHandler;
			if (debugHandler != null && debugHandler.IsActiveForCamera(cameraData.isPreviewCamera) && debugHandler.IsScreenClearNeeded)
			{
				clearOnFirstUse = true;
				clearOnFirstUse2 = true;
				debugHandler.TryGetScreenClearColor(ref color);
			}
			result.cameraColorParams.clearOnFirstUse = clearOnFirstUse;
			result.cameraColorParams.clearColor = color;
			result.cameraColorParams.discardOnLastUse = false;
			result.cameraDepthParams.clearOnFirstUse = clearOnFirstUse2;
			result.cameraDepthParams.clearColor = color;
			result.cameraDepthParams.discardOnLastUse = false;
			result.backBufferColorParams.clearOnFirstUse = clearOnFirstUse3;
			result.backBufferColorParams.clearColor = clearColor;
			result.backBufferColorParams.discardOnLastUse = false;
			result.backBufferDepthParams.clearOnFirstUse = clearOnFirstUse4;
			result.backBufferDepthParams.clearColor = clearColor;
			result.backBufferDepthParams.discardOnLastUse = true;
			bool flag2 = cameraData.targetTexture == null;
			TextureUVOrigin textureUVOrigin = ((!cameraData.isSceneViewCamera && !cameraData.isPreviewCamera && cameraData.targetTexture == null) ? (SystemInfo.graphicsUVStartsAtTop ? TextureUVOrigin.TopLeft : TextureUVOrigin.BottomLeft) : TextureUVOrigin.BottomLeft);
			result.backBufferColorParams.textureUVOrigin = textureUVOrigin;
			result.backBufferDepthParams.textureUVOrigin = textureUVOrigin;
			if (cameraData.xr.enabled)
			{
				flag2 = false;
			}
			if (!flag2)
			{
				if (cameraData.xr.enabled)
				{
					result.importInfo.width = cameraData.xr.renderTargetDesc.width;
					result.importInfo.height = cameraData.xr.renderTargetDesc.height;
					result.importInfo.volumeDepth = cameraData.xr.renderTargetDesc.volumeDepth;
					result.importInfo.msaaSamples = cameraData.xr.renderTargetDesc.msaaSamples;
					result.importInfo.format = cameraData.xr.renderTargetDesc.graphicsFormat;
					if (!UniversalRenderer.PlatformRequiresExplicitMsaaResolve())
					{
						result.importInfo.bindMS = result.importInfo.msaaSamples > 1;
					}
					result.importInfoDepth = result.importInfo;
					result.importInfoDepth.format = cameraData.xr.renderTargetDesc.depthStencilFormat;
				}
				else
				{
					result.importInfo.width = cameraData.targetTexture.width;
					result.importInfo.height = cameraData.targetTexture.height;
					result.importInfo.volumeDepth = cameraData.targetTexture.volumeDepth;
					result.importInfo.msaaSamples = cameraData.targetTexture.antiAliasing;
					result.importInfo.format = cameraData.targetTexture.graphicsFormat;
					result.importInfoDepth = result.importInfo;
					result.importInfoDepth.format = cameraData.targetTexture.depthStencilFormat;
					if (result.importInfoDepth.format == GraphicsFormat.None)
					{
						result.importInfoDepth.format = SystemInfo.GetGraphicsFormat(DefaultFormat.DepthStencil);
						Debug.LogWarning("In the render graph API, the output Render Texture must have a depth buffer. When you select a Render Texture in any camera's Output Texture property, the Depth Stencil Format property of the texture must be set to a value other than None.");
					}
				}
			}
			else
			{
				int msaaSamples = AdjustAndGetScreenMSAASamples(renderGraph, m_CreateColorTexture);
				result.importInfo.width = Screen.width;
				result.importInfo.height = Screen.height;
				result.importInfo.volumeDepth = 1;
				result.importInfo.msaaSamples = msaaSamples;
				result.importInfo.format = cameraData.cameraTargetDescriptor.graphicsFormat;
				result.importInfoDepth = result.importInfo;
				result.importInfoDepth.format = SystemInfo.GetGraphicsFormat(DefaultFormat.DepthStencil);
			}
			return result;
		}

		public override void SetupCullingParameters(ref ScriptableCullingParameters cullingParameters, ref CameraData cameraData)
		{
			cullingParameters.cullingOptions = CullingOptions.None;
			cullingParameters.isOrthographic = cameraData.camera.orthographic;
			cullingParameters.shadowDistance = 0f;
			(m_Renderer2DData.lightCullResult as Light2DCullResult).SetupCulling(ref cullingParameters, cameraData.camera);
		}

		private void InitializeLayerBatches()
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Get<Universal2DResourceData>();
			m_LayerBatches = LayerUtility.CalculateBatches(m_Renderer2DData, out m_BatchCount);
			if (universal2DResourceData.normalsTexture.Length != m_BatchCount)
			{
				universal2DResourceData.normalsTexture = new TextureHandle[m_BatchCount];
			}
			if (universal2DResourceData.shadowTextures.Length != m_BatchCount)
			{
				universal2DResourceData.shadowTextures = new TextureHandle[m_BatchCount][];
			}
			if (universal2DResourceData.lightTextures.Length != m_BatchCount)
			{
				universal2DResourceData.lightTextures = new TextureHandle[m_BatchCount][];
			}
			for (int i = 0; i < universal2DResourceData.lightTextures.Length; i++)
			{
				if (universal2DResourceData.lightTextures[i] == null || universal2DResourceData.lightTextures[i].Length != m_LayerBatches[i].activeBlendStylesIndices.Length)
				{
					universal2DResourceData.lightTextures[i] = new TextureHandle[m_LayerBatches[i].activeBlendStylesIndices.Length];
				}
			}
			for (int j = 0; j < universal2DResourceData.shadowTextures.Length; j++)
			{
				if (universal2DResourceData.shadowTextures[j] == null || universal2DResourceData.shadowTextures[j].Length != m_LayerBatches[j].shadowIndices.Count)
				{
					universal2DResourceData.shadowTextures[j] = new TextureHandle[m_LayerBatches[j].shadowIndices.Count];
				}
			}
		}

		private void CreateResources(RenderGraph renderGraph)
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Get<Universal2DResourceData>();
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			UniversalCameraData universalCameraData = base.frameData.Get<UniversalCameraData>();
			ref RenderTextureDescriptor cameraTargetDescriptor = ref universalCameraData.cameraTargetDescriptor;
			FilterMode filterMode = FilterMode.Bilinear;
			bool resolveFinalTarget = universalCameraData.resolveFinalTarget;
			bool flag = false;
			if (universalCameraData.renderType == CameraRenderType.Base && resolveFinalTarget)
			{
				universalCameraData.camera.TryGetComponent<PixelPerfectCamera>(out var component);
				if (component != null && component.enabled)
				{
					if (component.offscreenRTSize != Vector2Int.zero)
					{
						flag = true;
						cameraTargetDescriptor.width = component.offscreenRTSize.x;
						cameraTargetDescriptor.height = component.offscreenRTSize.y;
					}
					filterMode = FilterMode.Point;
					ppcUpscaleRT = component.gridSnapping == PixelPerfectCamera.GridSnapping.UpscaleRenderTexture || component.requiresUpscalePass;
					if (component.requiresUpscalePass)
					{
						RenderTextureDescriptor desc = cameraTargetDescriptor;
						desc.width = component.refResolutionX * component.pixelRatio;
						desc.height = component.refResolutionY * component.pixelRatio;
						desc.depthStencilFormat = GraphicsFormat.None;
						universal2DResourceData.upscaleTexture = UniversalRenderer.CreateRenderGraphTexture(renderGraph, desc, "_UpscaleTexture", clear: true, component.finalBlitFilterMode);
					}
				}
			}
			float lightRenderTextureScale = m_Renderer2DData.lightRenderTextureScale;
			int width = (int)Mathf.Max(1f, (float)universalCameraData.cameraTargetDescriptor.width * lightRenderTextureScale);
			int height = (int)Mathf.Max(1f, (float)universalCameraData.cameraTargetDescriptor.height * lightRenderTextureScale);
			CreateCameraNormalsTextures(renderGraph, cameraTargetDescriptor, width, height);
			CreateLightTextures(renderGraph, width, height);
			CreateShadowTextures(renderGraph, width, height);
			if (m_Renderer2DData.useCameraSortingLayerTexture)
			{
				CreateCameraSortingLayerTexture(renderGraph, cameraTargetDescriptor);
			}
			if (universalCameraData.renderType == CameraRenderType.Base)
			{
				RenderPassInputSummary renderPassInputs = GetRenderPassInputs(universalCameraData);
				m_CreateColorTexture = renderPassInputs.requiresColorTexture;
				m_CreateDepthTexture = renderPassInputs.requiresDepthTexture;
				m_CreateColorTexture |= flag;
				m_CreateDepthTexture |= m_CreateColorTexture;
				if (m_CreateColorTexture)
				{
					cameraTargetDescriptor.useMipMap = false;
					cameraTargetDescriptor.autoGenerateMips = false;
					cameraTargetDescriptor.depthStencilFormat = GraphicsFormat.None;
					RenderingUtils.ReAllocateHandleIfNeeded(ref m_RenderGraphCameraColorHandles[0], in cameraTargetDescriptor, filterMode, TextureWrapMode.Clamp, 1, 0f, "_CameraTargetAttachmentA");
					RenderingUtils.ReAllocateHandleIfNeeded(ref m_RenderGraphCameraColorHandles[1], in cameraTargetDescriptor, filterMode, TextureWrapMode.Clamp, 1, 0f, "_CameraTargetAttachmentB");
					universalResourceData.activeColorID = UniversalResourceDataBase.ActiveID.Camera;
				}
				else
				{
					universalResourceData.activeColorID = UniversalResourceDataBase.ActiveID.BackBuffer;
				}
				if (m_CreateDepthTexture)
				{
					RenderTextureDescriptor descriptor = universalCameraData.cameraTargetDescriptor;
					descriptor.useMipMap = false;
					descriptor.autoGenerateMips = false;
					bool flag2 = descriptor.msaaSamples > 1 && SystemInfo.supportsMultisampledTextures != 0;
					bool flag3 = RenderingUtils.MultisampleDepthResolveSupported() && renderGraph.nativeRenderPassesEnabled;
					descriptor.bindMS = !flag3 && flag2;
					if (IsGLESDevice())
					{
						descriptor.bindMS = false;
					}
					if (m_CopyDepthPass != null)
					{
						m_CopyDepthPass.MsaaSamples = descriptor.msaaSamples;
						m_CopyDepthPass.m_CopyResolvedDepth = !descriptor.bindMS;
					}
					descriptor.graphicsFormat = GraphicsFormat.None;
					descriptor.depthStencilFormat = CoreUtils.GetDefaultDepthStencilFormat();
					RenderingUtils.ReAllocateHandleIfNeeded(ref m_RenderGraphCameraDepthHandle, in descriptor, FilterMode.Point, TextureWrapMode.Clamp, 1, 0f, "_CameraDepthAttachment");
					universalResourceData.activeDepthID = UniversalResourceDataBase.ActiveID.Camera;
				}
				else
				{
					universalResourceData.activeDepthID = UniversalResourceDataBase.ActiveID.BackBuffer;
				}
			}
			else
			{
				universalCameraData.baseCamera.TryGetComponent<UniversalAdditionalCameraData>(out var component2);
				Renderer2D renderer2D = (Renderer2D)component2.scriptableRenderer;
				m_RenderGraphCameraColorHandles = renderer2D.m_RenderGraphCameraColorHandles;
				m_RenderGraphCameraDepthHandle = renderer2D.m_RenderGraphCameraDepthHandle;
				m_RenderGraphBackbufferColorHandle = renderer2D.m_RenderGraphBackbufferColorHandle;
				m_RenderGraphBackbufferDepthHandle = renderer2D.m_RenderGraphBackbufferDepthHandle;
				m_CreateColorTexture = renderer2D.m_CreateColorTexture;
				m_CreateDepthTexture = renderer2D.m_CreateDepthTexture;
				universalResourceData.activeColorID = ((!m_CreateColorTexture) ? UniversalResourceDataBase.ActiveID.BackBuffer : UniversalResourceDataBase.ActiveID.Camera);
				universalResourceData.activeDepthID = ((!m_CreateDepthTexture) ? UniversalResourceDataBase.ActiveID.BackBuffer : UniversalResourceDataBase.ActiveID.Camera);
			}
			ImportResourceSummary importResourceSummary = GetImportResourceSummary(renderGraph, universalCameraData);
			if (m_CreateColorTexture)
			{
				importResourceSummary.cameraColorParams.discardOnLastUse = resolveFinalTarget;
				importResourceSummary.cameraDepthParams.discardOnLastUse = resolveFinalTarget;
				universalResourceData.cameraColor = renderGraph.ImportTexture(currentRenderGraphCameraColorHandle, importResourceSummary.cameraColorParams);
				universalResourceData.cameraDepth = renderGraph.ImportTexture(m_RenderGraphCameraDepthHandle, importResourceSummary.cameraDepthParams);
			}
			RenderTargetIdentifier renderTargetIdentifier = ((universalCameraData.targetTexture != null) ? new RenderTargetIdentifier(universalCameraData.targetTexture) : ((RenderTargetIdentifier)BuiltinRenderTextureType.CameraTarget));
			RenderTargetIdentifier renderTargetIdentifier2 = ((universalCameraData.targetTexture != null) ? new RenderTargetIdentifier(universalCameraData.targetTexture) : ((RenderTargetIdentifier)BuiltinRenderTextureType.Depth));
			if (universalCameraData.xr.enabled)
			{
				renderTargetIdentifier = universalCameraData.xr.renderTarget;
				renderTargetIdentifier2 = universalCameraData.xr.renderTarget;
			}
			if (m_RenderGraphBackbufferColorHandle == null)
			{
				m_RenderGraphBackbufferColorHandle = RTHandles.Alloc(renderTargetIdentifier, "Backbuffer color");
			}
			else if (m_RenderGraphBackbufferColorHandle.nameID != renderTargetIdentifier)
			{
				RTHandleStaticHelpers.SetRTHandleUserManagedWrapper(ref m_RenderGraphBackbufferColorHandle, renderTargetIdentifier);
			}
			if (m_RenderGraphBackbufferDepthHandle == null)
			{
				m_RenderGraphBackbufferDepthHandle = RTHandles.Alloc(renderTargetIdentifier2, "Backbuffer depth");
			}
			else if (m_RenderGraphBackbufferDepthHandle.nameID != renderTargetIdentifier2)
			{
				RTHandleStaticHelpers.SetRTHandleUserManagedWrapper(ref m_RenderGraphBackbufferDepthHandle, renderTargetIdentifier2);
			}
			universalResourceData.backBufferColor = renderGraph.ImportTexture(m_RenderGraphBackbufferColorHandle, importResourceSummary.importInfo, importResourceSummary.backBufferColorParams);
			universalResourceData.backBufferDepth = renderGraph.ImportTexture(m_RenderGraphBackbufferDepthHandle, importResourceSummary.importInfoDepth, importResourceSummary.backBufferDepthParams);
			RenderTextureDescriptor compatibleDescriptor = PostProcessPassRenderGraph.GetCompatibleDescriptor(cameraTargetDescriptor, cameraTargetDescriptor.width, cameraTargetDescriptor.height, cameraTargetDescriptor.graphicsFormat);
			universalResourceData.afterPostProcessColor = UniversalRenderer.CreateRenderGraphTexture(renderGraph, compatibleDescriptor, "_AfterPostProcessTexture", clear: true);
			if (RequiresDepthCopyPass(universalCameraData))
			{
				CreateCameraDepthCopyTexture(renderGraph, cameraTargetDescriptor);
			}
			if (universalCameraData.isHDROutputActive && universalCameraData.rendersOverlayUI)
			{
				CreateOffscreenUITexture(renderGraph, in cameraTargetDescriptor);
			}
		}

		private void CreateCameraNormalsTextures(RenderGraph renderGraph, RenderTextureDescriptor descriptor, int width, int height)
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Get<Universal2DResourceData>();
			RenderTextureDescriptor desc = new RenderTextureDescriptor(width, height);
			desc.graphicsFormat = RendererLighting.GetRenderTextureFormat();
			desc.autoGenerateMips = false;
			desc.msaaSamples = descriptor.msaaSamples;
			for (int i = 0; i < universal2DResourceData.normalsTexture.Length; i++)
			{
				universal2DResourceData.normalsTexture[i] = UniversalRenderer.CreateRenderGraphTexture(renderGraph, in desc, "_NormalMap", clear: true, RendererLighting.k_NormalClearColor);
			}
			if (IsDepthUsageAllowed(base.frameData, m_Renderer2DData))
			{
				RenderTextureDescriptor desc2 = new RenderTextureDescriptor(width, height);
				desc2.graphicsFormat = GraphicsFormat.None;
				desc2.autoGenerateMips = false;
				desc2.msaaSamples = descriptor.msaaSamples;
				desc2.depthStencilFormat = CoreUtils.GetDefaultDepthStencilFormat();
				universal2DResourceData.normalsDepth = UniversalRenderer.CreateRenderGraphTexture(renderGraph, desc2, "_NormalDepth", clear: false, FilterMode.Bilinear);
			}
		}

		private void CreateLightTextures(RenderGraph renderGraph, int width, int height)
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Get<Universal2DResourceData>();
			RenderTextureDescriptor desc = new RenderTextureDescriptor(width, height);
			desc.graphicsFormat = RendererLighting.GetRenderTextureFormat();
			desc.autoGenerateMips = false;
			for (int i = 0; i < universal2DResourceData.lightTextures.Length; i++)
			{
				for (int j = 0; j < m_LayerBatches[i].activeBlendStylesIndices.Length; j++)
				{
					int num = m_LayerBatches[i].activeBlendStylesIndices[j];
					if (!Light2DManager.GetGlobalColor(m_LayerBatches[i].startLayerID, num, out var color))
					{
						color = Color.black;
					}
					universal2DResourceData.lightTextures[i][j] = UniversalRenderer.CreateRenderGraphTexture(renderGraph, in desc, RendererLighting.k_ShapeLightTextureIDs[num], clear: true, color, FilterMode.Bilinear);
				}
			}
		}

		private void CreateShadowTextures(RenderGraph renderGraph, int width, int height)
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Get<Universal2DResourceData>();
			RenderTextureDescriptor desc = new RenderTextureDescriptor(width, height);
			desc.graphicsFormat = GraphicsFormat.B10G11R11_UFloatPack32;
			desc.autoGenerateMips = false;
			for (int i = 0; i < universal2DResourceData.shadowTextures.Length; i++)
			{
				for (int j = 0; j < m_LayerBatches[i].shadowIndices.Count; j++)
				{
					universal2DResourceData.shadowTextures[i][j] = UniversalRenderer.CreateRenderGraphTexture(renderGraph, desc, "_ShadowTex", clear: false, FilterMode.Bilinear);
				}
			}
			RenderTextureDescriptor desc2 = new RenderTextureDescriptor(width, height);
			desc2.graphicsFormat = GraphicsFormat.None;
			desc2.autoGenerateMips = false;
			desc2.depthStencilFormat = CoreUtils.GetDefaultDepthStencilFormat();
			universal2DResourceData.shadowDepth = UniversalRenderer.CreateRenderGraphTexture(renderGraph, desc2, "_ShadowDepth", clear: false, FilterMode.Bilinear);
		}

		private void CreateCameraSortingLayerTexture(RenderGraph renderGraph, RenderTextureDescriptor descriptor)
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Get<Universal2DResourceData>();
			descriptor.msaaSamples = 1;
			CopyCameraSortingLayerPass.ConfigureDescriptor(m_Renderer2DData.cameraSortingLayerDownsamplingMethod, ref descriptor, out var filterMode);
			RenderingUtils.ReAllocateHandleIfNeeded(ref m_CameraSortingLayerHandle, in descriptor, filterMode, TextureWrapMode.Clamp, 1, 0f, CopyCameraSortingLayerPass.k_CameraSortingLayerTexture);
			universal2DResourceData.cameraSortingLayerTexture = renderGraph.ImportTexture(m_CameraSortingLayerHandle);
		}

		private bool RequiresDepthCopyPass(UniversalCameraData cameraData)
		{
			RenderPassInputSummary renderPassInputs = GetRenderPassInputs(cameraData);
			bool flag = cameraData.requiresDepthTexture || renderPassInputs.requiresDepthTexture;
			if ((cameraData.postProcessEnabled && m_PostProcessPassRenderGraph != null && cameraData.postProcessingRequiresDepthTexture) || flag)
			{
				return m_CreateDepthTexture;
			}
			return false;
		}

		private void CreateCameraDepthCopyTexture(RenderGraph renderGraph, RenderTextureDescriptor descriptor)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			RenderTextureDescriptor desc = descriptor;
			desc.msaaSamples = 1;
			desc.graphicsFormat = GraphicsFormat.R32_SFloat;
			desc.depthStencilFormat = GraphicsFormat.None;
			universalResourceData.cameraDepthTexture = UniversalRenderer.CreateRenderGraphTexture(renderGraph, desc, "_CameraDepthTexture", clear: true);
		}

		private void CreateOffscreenUITexture(RenderGraph renderGraph, in RenderTextureDescriptor descriptor)
		{
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			TextureDesc textureDesc = new TextureDesc(descriptor);
			DrawScreenSpaceUIPass.ConfigureOffscreenUITextureDesc(ref textureDesc);
			RenderingUtils.ReAllocateHandleIfNeeded(ref m_OffscreenUIColorHandle, textureDesc, "_OverlayUITexture");
			universalResourceData.overlayUITexture = renderGraph.ImportTexture(m_OffscreenUIColorHandle);
		}

		public override void OnBeginRenderGraphFrame()
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Create<Universal2DResourceData>();
			UniversalResourceData orCreate = base.frameData.GetOrCreate<UniversalResourceData>();
			universal2DResourceData.InitFrame();
			orCreate.InitFrame();
		}

		internal void RecordCustomRenderGraphPasses(RenderGraph renderGraph, RenderPassEvent2D activeRPEvent)
		{
			foreach (ScriptableRenderPass item in base.activeRenderPassQueue)
			{
				item.GetInjectionPoint2D(out var rpEvent, out var _);
				if (rpEvent == activeRPEvent)
				{
					item.RecordRenderGraph(renderGraph, base.frameData);
				}
			}
		}

		internal override void OnRecordRenderGraph(RenderGraph renderGraph, ScriptableRenderContext context)
		{
			UniversalResourceData orCreate = base.frameData.GetOrCreate<UniversalResourceData>();
			base.frameData.Get<UniversalCameraData>();
			InitializeLayerBatches();
			CreateResources(renderGraph);
			SetupRenderGraphCameraProperties(renderGraph, orCreate.activeColorTexture);
			OnBeforeRendering(renderGraph);
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent2D.BeforeRendering);
			BeginRenderGraphXRRendering(renderGraph);
			OnMainRendering(renderGraph);
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent2D.BeforeRenderingPostProcessing);
			OnAfterRendering(renderGraph);
			EndRenderGraphXRRendering(renderGraph);
		}

		public override void OnEndRenderGraphFrame()
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Get<Universal2DResourceData>();
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			universal2DResourceData.EndFrame();
			universalResourceData.EndFrame();
		}

		internal override void OnFinishRenderGraphRendering(CommandBuffer cmd)
		{
			m_CopyDepthPass?.OnCameraCleanup(cmd);
		}

		private void OnBeforeRendering(RenderGraph renderGraph)
		{
			UniversalCameraData universalCameraData = base.frameData.Get<UniversalCameraData>();
			m_LightPass.Setup(renderGraph, ref m_Renderer2DData);
			List<Light2D> visibleLights = m_Renderer2DData.lightCullResult.visibleLights;
			for (int i = 0; i < visibleLights.Count; i++)
			{
				visibleLights[i].CacheValues();
			}
			ShadowCasterGroup2DManager.CacheValues();
			ShadowRendering.CallOnBeforeRender(universalCameraData.camera, m_Renderer2DData.lightCullResult);
			RendererLighting.lightBatch.Reset();
		}

		private void OnMainRendering(RenderGraph renderGraph)
		{
			base.frameData.Get<Universal2DResourceData>();
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			UniversalCameraData universalCameraData = base.frameData.Get<UniversalCameraData>();
			if (universalCameraData.postProcessEnabled && m_PostProcessPassRenderGraph != null)
			{
				m_ColorGradingLutPassRenderGraph.Render(renderGraph, base.frameData, out var internalColorLut);
				universalResourceData.internalColorLut = internalColorLut;
			}
			short cameraSortingLayerBoundsIndex = m_Renderer2DData.GetCameraSortingLayerBoundsIndex();
			bool flag = false;
			for (int i = 0; i < m_BatchCount; i++)
			{
				flag |= m_LayerBatches[i].lightStats.useLights;
			}
			GlobalPropertiesPass.Setup(renderGraph, base.frameData, m_Renderer2DData, universalCameraData, flag);
			for (int j = 0; j < m_BatchCount; j++)
			{
				m_NormalPass.Render(renderGraph, base.frameData, m_Renderer2DData, ref m_LayerBatches[j], j);
			}
			for (int k = 0; k < m_BatchCount; k++)
			{
				m_ShadowPass.Render(renderGraph, base.frameData, m_Renderer2DData, ref m_LayerBatches[k], k);
			}
			for (int l = 0; l < m_BatchCount; l++)
			{
				m_LightPass.Render(renderGraph, base.frameData, m_Renderer2DData, ref m_LayerBatches[l], l);
			}
			for (int m = 0; m < m_BatchCount; m++)
			{
				if (!renderGraph.nativeRenderPassesEnabled && m == 0)
				{
					RTClearFlags cameraClearFlag = (RTClearFlags)ScriptableRenderer.GetCameraClearFlag(universalCameraData);
					if (cameraClearFlag != RTClearFlags.None)
					{
						ClearTargetsPass.Render(renderGraph, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, cameraClearFlag, universalCameraData.backgroundColor);
					}
				}
				ref LayerBatch reference = ref m_LayerBatches[m];
				LayerUtility.GetFilterSettings(m_Renderer2DData, ref m_LayerBatches[m], out var filterSettings);
				m_RendererPass.Render(renderGraph, base.frameData, m_Renderer2DData, ref m_LayerBatches, m, ref filterSettings);
				m_ShadowPass.Render(renderGraph, base.frameData, m_Renderer2DData, ref m_LayerBatches[m], m, isVolumetric: true);
				m_LightPass.Render(renderGraph, base.frameData, m_Renderer2DData, ref m_LayerBatches[m], m, isVolumetric: true);
				if (m_Renderer2DData.useCameraSortingLayerTexture && cameraSortingLayerBoundsIndex >= reference.layerRange.lowerBound && cameraSortingLayerBoundsIndex <= reference.layerRange.upperBound)
				{
					m_CopyCameraSortingLayerPass.Render(renderGraph, base.frameData);
				}
			}
			if (RequiresDepthCopyPass(universalCameraData))
			{
				m_CopyDepthPass?.Render(renderGraph, base.frameData, universalResourceData.cameraDepthTexture, universalResourceData.activeDepthTexture, bindAsCameraDepth: true);
			}
			bool rendersOverlayUI = universalCameraData.rendersOverlayUI;
			bool isHDROutputActive = universalCameraData.isHDROutputActive;
			if (!(rendersOverlayUI && isHDROutputActive))
			{
				return;
			}
			if (universalCameraData.rendersOffscreenUI)
			{
				m_DrawOffscreenUIPass.RenderOffscreen(renderGraph, base.frameData, CoreUtils.GetDefaultDepthStencilFormat(), universalResourceData.overlayUITexture);
				if (universalCameraData.blitsOffscreenUICover)
				{
					RenderTextureDescriptor desc = new RenderTextureDescriptor(1, 1, GraphicsFormat.R8G8B8A8_SRGB, 0);
					TextureHandle src = UniversalRenderer.CreateRenderGraphTexture(renderGraph, desc, "BlackTexture", clear: false);
					m_OffscreenUICoverPrepass.Render(renderGraph, base.frameData, universalCameraData, in src, universalResourceData.backBufferColor, universalResourceData.overlayUITexture, useFullScreenViewport: true);
				}
			}
			else
			{
				RenderGraphUtils.SetGlobalTexture(renderGraph, ShaderPropertyId.overlayUITexture, universalResourceData.overlayUITexture, "Set Global Texture", ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\2D\\Rendergraph\\Renderer2DRendergraph.cs", 851);
			}
		}

		private void OnAfterRendering(RenderGraph renderGraph)
		{
			Universal2DResourceData universal2DResourceData = base.frameData.Get<Universal2DResourceData>();
			UniversalResourceData universalResourceData = base.frameData.Get<UniversalResourceData>();
			base.frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = base.frameData.Get<UniversalCameraData>();
			UniversalPostProcessingData universalPostProcessingData = base.frameData.Get<UniversalPostProcessingData>();
			bool flag = DebugDisplaySettings<UniversalRenderPipelineDebugDisplaySettings>.Instance.renderingSettings.sceneOverrideMode == DebugSceneOverrideMode.None;
			if (flag)
			{
				DrawRenderGraphGizmos(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, GizmoSubset.PreImageEffects);
			}
			bool flag2 = ScriptableRenderPass.GetActiveDebugHandler(universalCameraData)?.WriteToDebugScreenTexture(universalCameraData.resolveFinalTarget) ?? false;
			if (flag2)
			{
				RenderTextureDescriptor descriptor = universalCameraData.cameraTargetDescriptor;
				DebugHandler.ConfigureColorDescriptorForDebugScreen(ref descriptor, universalCameraData.pixelWidth, universalCameraData.pixelHeight);
				universalResourceData.debugScreenColor = UniversalRenderer.CreateRenderGraphTexture(renderGraph, descriptor, "_DebugScreenColor", clear: false);
				RenderTextureDescriptor descriptor2 = universalCameraData.cameraTargetDescriptor;
				DebugHandler.ConfigureDepthDescriptorForDebugScreen(ref descriptor2, CoreUtils.GetDefaultDepthStencilFormat(), universalCameraData.pixelWidth, universalCameraData.pixelHeight);
				universalResourceData.debugScreenDepth = UniversalRenderer.CreateRenderGraphTexture(renderGraph, descriptor2, "_DebugScreenDepth", clear: false);
			}
			bool flag3 = universalCameraData.postProcessEnabled && m_PostProcessPassRenderGraph != null;
			bool flag4 = universalPostProcessingData.isEnabled && m_PostProcessPassRenderGraph != null;
			PixelPerfectCamera ppc;
			bool num = IsPixelPerfectCameraEnabled(universalCameraData, out ppc) && ppc.requiresUpscalePass;
			bool flag5 = universalCameraData.resolveFinalTarget && !ppcUpscaleRT && flag4 && universalCameraData.antialiasing == AntialiasingMode.FastApproximateAntialiasing;
			bool flag6 = base.activeRenderPassQueue.Find((ScriptableRenderPass x) => x.renderPassEvent == RenderPassEvent.AfterRenderingPostProcessing) != null;
			bool flag7 = base.DebugHandler == null || !base.DebugHandler.HDRDebugViewIsActive(universalCameraData.resolveFinalTarget);
			bool flag8 = ppc != null && ppc.enabled;
			bool flag9 = universalCameraData.captureActions != null && universalCameraData.resolveFinalTarget;
			bool flag10 = universalCameraData.resolveFinalTarget && !flag9 && !flag6 && !flag5 && !flag8;
			bool enableColorEndingIfNeeded = flag10 && flag7;
			if (flag3)
			{
				TextureHandle activeCameraColorTexture = universalResourceData.activeColorTexture;
				bool flag11 = flag10;
				if (!flag11)
				{
					universalResourceData.cameraColor = renderGraph.ImportTexture(importParams: new ImportResourceParams
					{
						clearOnFirstUse = true,
						clearColor = Color.black,
						discardOnLastUse = universalCameraData.resolveFinalTarget
					}, rt: nextRenderGraphCameraColorHandle);
				}
				TextureHandle postProcessingTarget = (flag11 ? universalResourceData.backBufferColor : universalResourceData.cameraColor);
				if (flag2 && flag11)
				{
					postProcessingTarget = universalResourceData.debugScreenColor;
				}
				m_PostProcessPassRenderGraph.RenderPostProcessingRenderGraph(renderGraph, base.frameData, in activeCameraColorTexture, universalResourceData.internalColorLut, universalResourceData.overlayUITexture, in postProcessingTarget, flag5, flag2, enableColorEndingIfNeeded);
				if (flag11)
				{
					universalResourceData.activeColorID = UniversalResourceDataBase.ActiveID.BackBuffer;
					universalResourceData.activeDepthID = UniversalResourceDataBase.ActiveID.BackBuffer;
				}
			}
			RecordCustomRenderGraphPasses(renderGraph, RenderPassEvent2D.AfterRenderingPostProcessing);
			TextureHandle cameraColorAttachment = universalResourceData.activeColorTexture;
			if (num)
			{
				m_UpscalePass.Render(renderGraph, universalCameraData.camera, in cameraColorAttachment, universal2DResourceData.upscaleTexture);
				cameraColorAttachment = universal2DResourceData.upscaleTexture;
			}
			TextureHandle postProcessingTarget2 = (flag2 ? universalResourceData.debugScreenColor : universalResourceData.backBufferColor);
			TextureHandle depthBuffer = (flag2 ? universalResourceData.debugScreenDepth : universalResourceData.backBufferDepth);
			if (flag5)
			{
				m_PostProcessPassRenderGraph.RenderFinalPassRenderGraph(renderGraph, base.frameData, in cameraColorAttachment, universalResourceData.overlayUITexture, in postProcessingTarget2, flag7);
				cameraColorAttachment = postProcessingTarget2;
				universalResourceData.activeColorID = UniversalResourceDataBase.ActiveID.BackBuffer;
				universalResourceData.activeDepthID = UniversalResourceDataBase.ActiveID.BackBuffer;
			}
			bool flag12 = flag5 || (flag3 && !flag6 && !flag9 && !flag8);
			if (!universalResourceData.isActiveTargetBackBuffer && universalCameraData.resolveFinalTarget && !flag12)
			{
				m_FinalBlitPass.Render(renderGraph, base.frameData, universalCameraData, in cameraColorAttachment, in postProcessingTarget2, universalResourceData.overlayUITexture);
				cameraColorAttachment = postProcessingTarget2;
				universalResourceData.activeColorID = UniversalResourceDataBase.ActiveID.BackBuffer;
				universalResourceData.activeDepthID = UniversalResourceDataBase.ActiveID.BackBuffer;
			}
			bool num2 = universalCameraData.rendersOverlayUI && universalCameraData.isLastBaseCamera;
			bool isHDROutputActive = universalCameraData.isHDROutputActive;
			if (num2 && !isHDROutputActive)
			{
				m_DrawOverlayUIPass.RenderOverlay(renderGraph, base.frameData, in cameraColorAttachment, in depthBuffer);
			}
			if (universalCameraData.resolveFinalTarget)
			{
				if (universalCameraData.isSceneViewCamera)
				{
					DrawRenderGraphWireOverlay(renderGraph, base.frameData, universalResourceData.backBufferColor);
				}
				if (flag)
				{
					DrawRenderGraphGizmos(renderGraph, base.frameData, universalResourceData.activeColorTexture, universalResourceData.activeDepthTexture, GizmoSubset.PostImageEffects);
				}
			}
		}

		public Renderer2DData GetRenderer2DData()
		{
			return m_Renderer2DData;
		}

		protected override void Dispose(bool disposing)
		{
			CleanupRenderGraphResources();
			base.Dispose(disposing);
		}

		private void CleanupRenderGraphResources()
		{
			m_Renderer2DData.Dispose();
			m_UpscalePass.Dispose();
			m_CopyDepthPass?.Dispose();
			m_FinalBlitPass?.Dispose();
			m_OffscreenUICoverPrepass?.Dispose();
			m_DrawOffscreenUIPass?.Dispose();
			m_DrawOverlayUIPass?.Dispose();
			m_PostProcessPassRenderGraph?.Cleanup();
			m_ColorGradingLutPassRenderGraph?.Cleanup();
			m_RenderGraphCameraColorHandles[0]?.Release();
			m_RenderGraphCameraColorHandles[1]?.Release();
			m_RenderGraphCameraDepthHandle?.Release();
			m_RenderGraphBackbufferColorHandle?.Release();
			m_RenderGraphBackbufferDepthHandle?.Release();
			m_CameraSortingLayerHandle?.Release();
			Light2DManager.Dispose();
			Light2DLookupTexture.Release();
			CoreUtils.Destroy(m_BlitMaterial);
			CoreUtils.Destroy(m_BlitHDRMaterial);
			CoreUtils.Destroy(m_BlitOffscreenUICoverMaterial);
			CoreUtils.Destroy(m_SamplingMaterial);
			XRSystem.Dispose();
		}

		internal static bool IsGLESDevice()
		{
			return SystemInfo.graphicsDeviceType == GraphicsDeviceType.OpenGLES3;
		}
	}
}
