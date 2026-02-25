using System;
using System.Collections.Generic;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal.Internal
{
	public class DepthNormalOnlyPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal bool enableRenderingLayers;

			internal RenderingLayerUtils.MaskSize maskSize;

			internal RendererListHandle rendererList;
		}

		private FilteringSettings m_FilteringSettings;

		private static readonly List<ShaderTagId> k_DepthNormals = new List<ShaderTagId>
		{
			new ShaderTagId("DepthNormals"),
			new ShaderTagId("DepthNormalsOnly")
		};

		private static readonly List<ShaderTagId> k_DepthNormalsOnly = new List<ShaderTagId>
		{
			new ShaderTagId("DepthNormalsOnly")
		};

		internal static readonly string k_CameraNormalsTextureName = "_CameraNormalsTexture";

		private static readonly int s_CameraDepthTextureID = Shader.PropertyToID("_CameraDepthTexture");

		private static readonly int s_CameraNormalsTextureID = Shader.PropertyToID(k_CameraNormalsTextureName);

		private static readonly int s_CameraRenderingLayersTextureID = Shader.PropertyToID("_CameraRenderingLayersTexture");

		internal List<ShaderTagId> shaderTagIds { get; set; }

		internal bool enableRenderingLayers { get; set; }

		internal RenderingLayerUtils.MaskSize renderingLayersMaskSize { get; set; }

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void OnCameraSetup(CommandBuffer cmd, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public DepthNormalOnlyPass(RenderPassEvent evt, RenderQueueRange renderQueueRange, LayerMask layerMask)
		{
			base.profilingSampler = ProfilingSampler.Get(URPProfileId.DrawDepthNormalPrepass);
			m_FilteringSettings = new FilteringSettings(renderQueueRange, layerMask);
			base.renderPassEvent = evt;
			shaderTagIds = k_DepthNormals;
		}

		public static GraphicsFormat GetGraphicsFormat()
		{
			if (SystemInfo.IsFormatSupported(GraphicsFormat.R8G8B8A8_SNorm, GraphicsFormatUsage.Render))
			{
				return GraphicsFormat.R8G8B8A8_SNorm;
			}
			if (SystemInfo.IsFormatSupported(GraphicsFormat.R16G16B16A16_SFloat, GraphicsFormatUsage.Render))
			{
				return GraphicsFormat.R16G16B16A16_SFloat;
			}
			return GraphicsFormat.R32G32B32A32_SFloat;
		}

		public void Setup(RTHandle depthHandle, RTHandle normalHandle)
		{
			enableRenderingLayers = false;
		}

		public void Setup(RTHandle depthHandle, RTHandle normalHandle, RTHandle decalLayerHandle)
		{
			Setup(depthHandle, normalHandle);
			enableRenderingLayers = true;
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData passData, RendererList rendererList)
		{
			if (passData.enableRenderingLayers)
			{
				cmd.SetKeyword(in ShaderGlobalKeywords.WriteRenderingLayers, value: true);
			}
			cmd.DrawRendererList(rendererList);
			if (passData.enableRenderingLayers)
			{
				cmd.SetKeyword(in ShaderGlobalKeywords.WriteRenderingLayers, value: false);
			}
		}

		public override void OnCameraCleanup(CommandBuffer cmd)
		{
			if (cmd == null)
			{
				throw new ArgumentNullException("cmd");
			}
			shaderTagIds = k_DepthNormals;
		}

		private RendererListParams InitRendererListParams(UniversalRenderingData renderingData, UniversalCameraData cameraData, UniversalLightData lightData)
		{
			SortingCriteria defaultOpaqueSortFlags = cameraData.defaultOpaqueSortFlags;
			DrawingSettings drawSettings = RenderingUtils.CreateDrawingSettings(shaderTagIds, renderingData, cameraData, lightData, defaultOpaqueSortFlags);
			drawSettings.perObjectData = PerObjectData.None;
			return new RendererListParams(renderingData.cullResults, drawSettings, m_FilteringSettings);
		}

		internal void Render(RenderGraph renderGraph, ContextContainer frameData, in TextureHandle cameraNormalsTexture, in TextureHandle depthTexture, in TextureHandle renderingLayersTexture, uint batchLayerMask, bool setGlobalDepth, bool setGlobalNormalAndRenderingLayers, bool allowPartialPass)
		{
			if (allowPartialPass)
			{
				shaderTagIds = k_DepthNormalsOnly;
			}
			else
			{
				shaderTagIds = k_DepthNormals;
			}
			UniversalRenderingData renderingData = frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = frameData.Get<UniversalLightData>();
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\DepthNormalOnlyPass.cs", 222);
			rasterRenderGraphBuilder.SetRenderAttachment(cameraNormalsTexture, 0);
			rasterRenderGraphBuilder.SetRenderAttachmentDepth(depthTexture, AccessFlags.ReadWrite);
			passData.enableRenderingLayers = enableRenderingLayers;
			if (passData.enableRenderingLayers)
			{
				rasterRenderGraphBuilder.SetRenderAttachment(renderingLayersTexture, 1);
				passData.maskSize = renderingLayersMaskSize;
			}
			RendererListParams desc = InitRendererListParams(renderingData, universalCameraData, lightData);
			desc.filteringSettings.batchLayerMask = batchLayerMask;
			passData.rendererList = renderGraph.CreateRendererList(in desc);
			rasterRenderGraphBuilder.UseRendererList(in passData.rendererList);
			if (universalCameraData.xr.enabled)
			{
				rasterRenderGraphBuilder.EnableFoveatedRasterization(universalCameraData.xr.supportsFoveatedRendering && universalCameraData.xrUniversal.canFoveateIntermediatePasses);
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			}
			if (setGlobalNormalAndRenderingLayers)
			{
				rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in cameraNormalsTexture, s_CameraNormalsTextureID);
				if (passData.enableRenderingLayers)
				{
					rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in renderingLayersTexture, s_CameraRenderingLayersTextureID);
				}
			}
			if (setGlobalDepth)
			{
				rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in depthTexture, s_CameraDepthTextureID);
			}
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				RenderingLayerUtils.SetupProperties(context.cmd, data.maskSize);
				ExecutePass(context.cmd, data, data.rendererList);
			});
		}
	}
}
