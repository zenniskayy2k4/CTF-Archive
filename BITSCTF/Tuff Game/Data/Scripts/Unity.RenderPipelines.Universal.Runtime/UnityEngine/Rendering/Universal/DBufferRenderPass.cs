using System;
using System.Collections.Generic;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal class DBufferRenderPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal DecalDrawDBufferSystem drawSystem;

			internal DBufferSettings settings;

			internal bool decalLayers;

			internal RTHandle dBufferDepth;

			internal RTHandle[] dBufferColorHandles;

			internal RendererListHandle rendererList;
		}

		internal static string[] s_DBufferNames = new string[4] { "_DBufferTexture0", "_DBufferTexture1", "_DBufferTexture2", "_DBufferTexture3" };

		internal static string s_DBufferDepthName = "DBufferDepth";

		private static readonly int s_SSAOTextureID = Shader.PropertyToID("_ScreenSpaceOcclusionTexture");

		private DecalDrawDBufferSystem m_DrawSystem;

		private DBufferSettings m_Settings;

		private FilteringSettings m_FilteringSettings;

		private List<ShaderTagId> m_ShaderTagIdList;

		private bool m_DecalLayers;

		private TextureHandle[] dbufferHandles;

		public DBufferRenderPass(Material dBufferClear, DBufferSettings settings, DecalDrawDBufferSystem drawSystem, bool decalLayers)
		{
			base.renderPassEvent = (RenderPassEvent)201;
			ScriptableRenderPassInput passInput = ScriptableRenderPassInput.Depth | ScriptableRenderPassInput.Normal;
			ConfigureInput(passInput);
			base.requiresIntermediateTexture = true;
			m_DrawSystem = drawSystem;
			m_Settings = settings;
			base.profilingSampler = new ProfilingSampler("Draw DBuffer");
			m_FilteringSettings = new FilteringSettings(RenderQueueRange.opaque);
			m_DecalLayers = decalLayers;
			m_ShaderTagIdList = new List<ShaderTagId>();
			m_ShaderTagIdList.Add(new ShaderTagId("DBufferMesh"));
			m_ShaderTagIdList.Add(new ShaderTagId("DBufferProjectorVFX"));
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData passData, RendererList rendererList, bool renderGraph)
		{
			passData.drawSystem.Execute(cmd);
			cmd.DrawRendererList(rendererList);
		}

		private static void SetKeywords(RasterCommandBuffer cmd, PassData passData)
		{
			cmd.SetKeyword(in ShaderGlobalKeywords.DBufferMRT1, passData.settings.surfaceData == DecalSurfaceData.Albedo);
			cmd.SetKeyword(in ShaderGlobalKeywords.DBufferMRT2, passData.settings.surfaceData == DecalSurfaceData.AlbedoNormal);
			cmd.SetKeyword(in ShaderGlobalKeywords.DBufferMRT3, passData.settings.surfaceData == DecalSurfaceData.AlbedoNormalMAOS);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalLayers, passData.decalLayers);
		}

		private void InitPassData(ref PassData passData)
		{
			passData.drawSystem = m_DrawSystem;
			passData.settings = m_Settings;
			passData.decalLayers = m_DecalLayers;
		}

		private RendererListParams InitRendererListParams(UniversalRenderingData renderingData, UniversalCameraData cameraData, UniversalLightData lightData)
		{
			SortingCriteria defaultOpaqueSortFlags = cameraData.defaultOpaqueSortFlags;
			DrawingSettings drawSettings = RenderingUtils.CreateDrawingSettings(m_ShaderTagIdList, renderingData, cameraData, lightData, defaultOpaqueSortFlags);
			return new RendererListParams(renderingData.cullResults, drawSettings, m_FilteringSettings);
		}

		public override void RecordRenderGraph(RenderGraph renderGraph, ContextContainer frameData)
		{
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			UniversalRenderingData renderingData = frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = frameData.Get<UniversalLightData>();
			TextureHandle cameraDepthTexture = universalResourceData.cameraDepthTexture;
			TextureHandle cameraNormalsTexture = universalResourceData.cameraNormalsTexture;
			TextureHandle tex = (universalResourceData.dBufferDepth.IsValid() ? universalResourceData.dBufferDepth : universalResourceData.activeDepthTexture);
			TextureHandle renderingLayersTexture = universalResourceData.renderingLayersTexture;
			PassData passData;
			using (IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Decal\\DBuffer\\DBufferRenderPass.cs", 240))
			{
				InitPassData(ref passData);
				if (dbufferHandles == null)
				{
					dbufferHandles = new TextureHandle[3];
				}
				RenderTextureDescriptor desc = universalCameraData.cameraTargetDescriptor;
				desc.graphicsFormat = ((QualitySettings.activeColorSpace == ColorSpace.Linear) ? GraphicsFormat.R8G8B8A8_SRGB : GraphicsFormat.R8G8B8A8_UNorm);
				desc.depthStencilFormat = GraphicsFormat.None;
				desc.msaaSamples = 1;
				dbufferHandles[0] = UniversalRenderer.CreateRenderGraphTexture(renderGraph, in desc, s_DBufferNames[0], clear: true, new Color(0f, 0f, 0f, 1f));
				rasterRenderGraphBuilder.SetRenderAttachment(dbufferHandles[0], 0);
				if (m_Settings.surfaceData == DecalSurfaceData.AlbedoNormal || m_Settings.surfaceData == DecalSurfaceData.AlbedoNormalMAOS)
				{
					RenderTextureDescriptor desc2 = universalCameraData.cameraTargetDescriptor;
					desc2.graphicsFormat = GraphicsFormat.R8G8B8A8_UNorm;
					desc2.depthStencilFormat = GraphicsFormat.None;
					desc2.msaaSamples = 1;
					dbufferHandles[1] = UniversalRenderer.CreateRenderGraphTexture(renderGraph, in desc2, s_DBufferNames[1], clear: true, new Color(0.5f, 0.5f, 0.5f, 1f));
					rasterRenderGraphBuilder.SetRenderAttachment(dbufferHandles[1], 1);
				}
				if (m_Settings.surfaceData == DecalSurfaceData.AlbedoNormalMAOS)
				{
					RenderTextureDescriptor desc3 = universalCameraData.cameraTargetDescriptor;
					desc3.graphicsFormat = GraphicsFormat.R8G8B8A8_UNorm;
					desc3.depthStencilFormat = GraphicsFormat.None;
					desc3.msaaSamples = 1;
					dbufferHandles[2] = UniversalRenderer.CreateRenderGraphTexture(renderGraph, in desc3, s_DBufferNames[2], clear: true, new Color(0f, 0f, 0f, 1f));
					rasterRenderGraphBuilder.SetRenderAttachment(dbufferHandles[2], 2);
				}
				rasterRenderGraphBuilder.SetRenderAttachmentDepth(tex, AccessFlags.Read);
				if (cameraDepthTexture.IsValid())
				{
					rasterRenderGraphBuilder.UseTexture(in cameraDepthTexture);
				}
				if (cameraNormalsTexture.IsValid())
				{
					rasterRenderGraphBuilder.UseTexture(in cameraNormalsTexture);
				}
				if (passData.decalLayers && renderingLayersTexture.IsValid())
				{
					rasterRenderGraphBuilder.UseTexture(in renderingLayersTexture);
				}
				if (universalResourceData.ssaoTexture.IsValid())
				{
					rasterRenderGraphBuilder.UseGlobalTexture(s_SSAOTextureID);
				}
				RendererListParams desc4 = InitRendererListParams(renderingData, universalCameraData, lightData);
				passData.rendererList = renderGraph.CreateRendererList(in desc4);
				rasterRenderGraphBuilder.UseRendererList(in passData.rendererList);
				for (int i = 0; i < 3; i++)
				{
					if (dbufferHandles[i].IsValid())
					{
						rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in dbufferHandles[i], Shader.PropertyToID(s_DBufferNames[i]));
					}
				}
				rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
				rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext rgContext)
				{
					SetKeywords(rgContext.cmd, data);
					ExecutePass(rgContext.cmd, data, data.rendererList, renderGraph: true);
				});
			}
			universalResourceData.dBuffer = dbufferHandles;
		}

		public override void OnCameraCleanup(CommandBuffer cmd)
		{
			if (cmd == null)
			{
				throw new ArgumentNullException("cmd");
			}
			cmd.SetKeyword(in ShaderGlobalKeywords.DBufferMRT1, value: false);
			cmd.SetKeyword(in ShaderGlobalKeywords.DBufferMRT2, value: false);
			cmd.SetKeyword(in ShaderGlobalKeywords.DBufferMRT3, value: false);
			cmd.SetKeyword(in ShaderGlobalKeywords.DecalLayers, value: false);
		}
	}
}
