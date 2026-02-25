using System.Collections.Generic;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal class DecalPreviewPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal RendererListHandle rendererList;
		}

		private FilteringSettings m_FilteringSettings;

		private List<ShaderTagId> m_ShaderTagIdList;

		private ProfilingSampler m_ProfilingSampler;

		public DecalPreviewPass()
		{
			base.renderPassEvent = RenderPassEvent.AfterRenderingOpaques;
			ConfigureInput(ScriptableRenderPassInput.Depth);
			m_ProfilingSampler = new ProfilingSampler("Decal Preview Render");
			m_FilteringSettings = new FilteringSettings(RenderQueueRange.opaque);
			m_ShaderTagIdList = new List<ShaderTagId>();
			m_ShaderTagIdList.Add(new ShaderTagId("DecalScreenSpaceMesh"));
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData passData, RendererList rendererList)
		{
			cmd.DrawRendererList(rendererList);
		}

		public override void RecordRenderGraph(RenderGraph renderGraph, ContextContainer frameData)
		{
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>("Decal Preview Pass", out passData, m_ProfilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Decal\\DecalPreviewPass.cs", 68);
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			UniversalRenderingData universalRenderingData = frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = frameData.Get<UniversalLightData>();
			_ = (UniversalRenderer)universalCameraData.renderer;
			rasterRenderGraphBuilder.SetRenderAttachment(universalResourceData.activeColorTexture, 0);
			rasterRenderGraphBuilder.SetRenderAttachmentDepth(universalResourceData.activeDepthTexture, AccessFlags.Read);
			SortingCriteria defaultOpaqueSortFlags = universalCameraData.defaultOpaqueSortFlags;
			DrawingSettings drawSettings = RenderingUtils.CreateDrawingSettings(m_ShaderTagIdList, universalRenderingData, universalCameraData, lightData, defaultOpaqueSortFlags);
			RendererListParams desc = new RendererListParams(universalRenderingData.cullResults, drawSettings, m_FilteringSettings);
			passData.rendererList = renderGraph.CreateRendererList(in desc);
			rasterRenderGraphBuilder.UseRendererList(in passData.rendererList);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext rgContext)
			{
				ExecutePass(rgContext.cmd, data, data.rendererList);
			});
		}
	}
}
