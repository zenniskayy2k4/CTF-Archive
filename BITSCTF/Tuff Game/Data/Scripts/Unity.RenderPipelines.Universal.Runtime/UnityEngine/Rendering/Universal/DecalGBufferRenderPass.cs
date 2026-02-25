using System;
using System.Collections.Generic;
using UnityEngine.Rendering.RenderGraphModule;
using UnityEngine.Rendering.Universal.Internal;

namespace UnityEngine.Rendering.Universal
{
	internal class DecalGBufferRenderPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal DecalDrawGBufferSystem drawSystem;

			internal DecalScreenSpaceSettings settings;

			internal bool decalLayers;

			internal UniversalCameraData cameraData;

			internal RendererListHandle rendererList;
		}

		private FilteringSettings m_FilteringSettings;

		private List<ShaderTagId> m_ShaderTagIdList;

		private DecalDrawGBufferSystem m_DrawSystem;

		private DecalScreenSpaceSettings m_Settings;

		private DeferredLights m_DeferredLights;

		private bool m_DecalLayers;

		public DecalGBufferRenderPass(DecalScreenSpaceSettings settings, DecalDrawGBufferSystem drawSystem, bool decalLayers)
		{
			base.renderPassEvent = RenderPassEvent.AfterRenderingGbuffer;
			m_DrawSystem = drawSystem;
			m_Settings = settings;
			base.profilingSampler = new ProfilingSampler("Draw Decal To GBuffer");
			m_FilteringSettings = new FilteringSettings(RenderQueueRange.opaque);
			m_DecalLayers = decalLayers;
			m_ShaderTagIdList = new List<ShaderTagId>();
			if (drawSystem == null)
			{
				m_ShaderTagIdList.Add(new ShaderTagId("DecalGBufferProjector"));
			}
			else
			{
				m_ShaderTagIdList.Add(new ShaderTagId("DecalGBufferMesh"));
			}
		}

		internal void Setup(DeferredLights deferredLights)
		{
			m_DeferredLights = deferredLights;
		}

		private void InitPassData(UniversalCameraData cameraData, ref PassData passData)
		{
			passData.drawSystem = m_DrawSystem;
			passData.settings = m_Settings;
			passData.decalLayers = m_DecalLayers;
			passData.cameraData = cameraData;
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData passData, RendererList rendererList)
		{
			NormalReconstruction.SetupProperties(cmd, in passData.cameraData);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalNormalBlendLow, passData.settings.normalBlend == DecalNormalBlend.Low);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalNormalBlendMedium, passData.settings.normalBlend == DecalNormalBlend.Medium);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalNormalBlendHigh, passData.settings.normalBlend == DecalNormalBlend.High);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalLayers, passData.decalLayers);
			passData.drawSystem?.Execute(cmd);
			cmd.DrawRendererList(rendererList);
		}

		public override void RecordRenderGraph(RenderGraph renderGraph, ContextContainer frameData)
		{
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			TextureHandle cameraDepthTexture = universalResourceData.cameraDepthTexture;
			TextureHandle renderingLayersTexture = universalResourceData.renderingLayersTexture;
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Decal\\ScreenSpace\\DecalGBufferRenderPass.cs", 173);
			UniversalRenderingData universalRenderingData = frameData.Get<UniversalRenderingData>();
			UniversalCameraData cameraData = frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = frameData.Get<UniversalLightData>();
			InitPassData(cameraData, ref passData);
			for (int i = 0; i <= m_DeferredLights.GBufferLightingIndex; i++)
			{
				if (universalResourceData.gBuffer[i].IsValid())
				{
					rasterRenderGraphBuilder.SetRenderAttachment(universalResourceData.gBuffer[i], i);
				}
			}
			rasterRenderGraphBuilder.SetRenderAttachmentDepth(universalResourceData.activeDepthTexture, AccessFlags.Read);
			if (renderGraph.nativeRenderPassesEnabled)
			{
				if (universalResourceData.gBuffer[4].IsValid())
				{
					rasterRenderGraphBuilder.SetInputAttachment(universalResourceData.gBuffer[4], 0);
				}
				if (m_DecalLayers && universalResourceData.gBuffer[5].IsValid())
				{
					rasterRenderGraphBuilder.SetInputAttachment(universalResourceData.gBuffer[5], 1);
				}
			}
			else
			{
				if (cameraDepthTexture.IsValid())
				{
					rasterRenderGraphBuilder.UseTexture(in cameraDepthTexture);
				}
				if (m_DecalLayers && renderingLayersTexture.IsValid())
				{
					rasterRenderGraphBuilder.UseTexture(in renderingLayersTexture);
				}
			}
			SortingCriteria defaultOpaqueSortFlags = passData.cameraData.defaultOpaqueSortFlags;
			DrawingSettings drawSettings = RenderingUtils.CreateDrawingSettings(m_ShaderTagIdList, universalRenderingData, passData.cameraData, lightData, defaultOpaqueSortFlags);
			RendererListParams desc = new RendererListParams(universalRenderingData.cullResults, drawSettings, m_FilteringSettings);
			passData.rendererList = renderGraph.CreateRendererList(in desc);
			rasterRenderGraphBuilder.UseRendererList(in passData.rendererList);
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext rgContext)
			{
				ExecutePass(rgContext.cmd, data, data.rendererList);
			});
		}

		public override void OnCameraCleanup(CommandBuffer cmd)
		{
			if (cmd == null)
			{
				throw new ArgumentNullException("cmd");
			}
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalNormalBlendLow, value: false);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalNormalBlendMedium, value: false);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalNormalBlendHigh, value: false);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalLayers, value: false);
		}
	}
}
