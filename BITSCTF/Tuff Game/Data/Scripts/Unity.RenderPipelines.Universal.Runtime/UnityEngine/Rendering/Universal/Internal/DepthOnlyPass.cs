using System;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal.Internal
{
	public class DepthOnlyPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal RendererListHandle rendererList;
		}

		private FilteringSettings m_FilteringSettings;

		private static readonly ShaderTagId k_ShaderTagId = new ShaderTagId("DepthOnly");

		private static readonly int s_CameraDepthTextureID = Shader.PropertyToID("_CameraDepthTexture");

		internal ShaderTagId shaderTagId { get; set; } = k_ShaderTagId;

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void OnCameraSetup(CommandBuffer cmd, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public DepthOnlyPass(RenderPassEvent evt, RenderQueueRange renderQueueRange, LayerMask layerMask)
		{
			base.profilingSampler = new ProfilingSampler("Draw Depth Only");
			m_FilteringSettings = new FilteringSettings(renderQueueRange, layerMask);
			base.renderPassEvent = evt;
			shaderTagId = k_ShaderTagId;
		}

		public void Setup(RenderTextureDescriptor baseDescriptor, RTHandle depthAttachmentHandle)
		{
		}

		private static void ExecutePass(RasterCommandBuffer cmd, RendererList rendererList)
		{
			using (new ProfilingScope(cmd, ProfilingSampler.Get(URPProfileId.DepthPrepass)))
			{
				cmd.DrawRendererList(rendererList);
			}
		}

		private RendererListParams InitRendererListParams(UniversalRenderingData renderingData, UniversalCameraData cameraData, UniversalLightData lightData)
		{
			SortingCriteria defaultOpaqueSortFlags = cameraData.defaultOpaqueSortFlags;
			DrawingSettings drawSettings = RenderingUtils.CreateDrawingSettings(shaderTagId, renderingData, cameraData, lightData, defaultOpaqueSortFlags);
			drawSettings.perObjectData = PerObjectData.None;
			drawSettings.lodCrossFadeStencilMask = 0;
			return new RendererListParams(renderingData.cullResults, drawSettings, m_FilteringSettings);
		}

		internal void Render(RenderGraph renderGraph, ContextContainer frameData, in TextureHandle depthTexture, uint batchLayerMask, bool setGlobalDepth)
		{
			UniversalRenderingData renderingData = frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = frameData.Get<UniversalLightData>();
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\DepthOnlyPass.cs", 143);
			RendererListParams desc = InitRendererListParams(renderingData, universalCameraData, lightData);
			desc.filteringSettings.batchLayerMask = batchLayerMask;
			passData.rendererList = renderGraph.CreateRendererList(in desc);
			rasterRenderGraphBuilder.UseRendererList(in passData.rendererList);
			rasterRenderGraphBuilder.SetRenderAttachmentDepth(depthTexture, AccessFlags.ReadWrite);
			if (setGlobalDepth)
			{
				rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in depthTexture, s_CameraDepthTextureID);
			}
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			if (universalCameraData.xr.enabled)
			{
				rasterRenderGraphBuilder.EnableFoveatedRasterization(universalCameraData.xr.supportsFoveatedRendering && universalCameraData.xrUniversal.canFoveateIntermediatePasses);
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			}
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				ExecutePass(context.cmd, data.rendererList);
			});
		}
	}
}
