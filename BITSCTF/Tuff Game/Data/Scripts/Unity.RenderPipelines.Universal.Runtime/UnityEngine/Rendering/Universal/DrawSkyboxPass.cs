using System;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	public class DrawSkyboxPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal XRPass xr;

			internal RendererListHandle skyRendererListHandle;

			internal Material material;
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public DrawSkyboxPass(RenderPassEvent evt)
		{
			base.profilingSampler = ProfilingSampler.Get(URPProfileId.DrawSkybox);
			base.renderPassEvent = evt;
		}

		private RendererListHandle CreateSkyBoxRendererList(RenderGraph renderGraph, UniversalCameraData cameraData)
		{
			RendererListHandle rendererListHandle = default(RendererListHandle);
			if (cameraData.xr.enabled)
			{
				if (cameraData.xr.singlePassEnabled)
				{
					return renderGraph.CreateSkyboxRendererList(in cameraData.camera, cameraData.GetProjectionMatrix(), cameraData.GetViewMatrix(), cameraData.GetProjectionMatrix(1), cameraData.GetViewMatrix(1));
				}
				return renderGraph.CreateSkyboxRendererList(in cameraData.camera, cameraData.GetProjectionMatrix(), cameraData.GetViewMatrix());
			}
			return renderGraph.CreateSkyboxRendererList(in cameraData.camera);
		}

		private static void ExecutePass(RasterCommandBuffer cmd, XRPass xr, RendererList rendererList)
		{
			if (xr.enabled && xr.singlePassEnabled)
			{
				cmd.SetSinglePassStereo(SystemInfo.supportsMultiview ? SinglePassStereoMode.Multiview : SinglePassStereoMode.Instancing);
			}
			cmd.DrawRendererList(rendererList);
			if (xr.enabled && xr.singlePassEnabled)
			{
				cmd.SetSinglePassStereo(SinglePassStereoMode.None);
			}
		}

		private void InitPassData(ref PassData passData, in XRPass xr, in RendererListHandle handle)
		{
			passData.xr = xr;
			passData.skyRendererListHandle = handle;
		}

		internal void Render(RenderGraph renderGraph, ContextContainer frameData, ScriptableRenderContext context, TextureHandle colorTarget, TextureHandle depthTarget, Material skyboxMaterial)
		{
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			DebugHandler activeDebugHandler = ScriptableRenderPass.GetActiveDebugHandler(universalCameraData);
			if (activeDebugHandler != null && activeDebugHandler.IsScreenClearNeeded)
			{
				return;
			}
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\DrawSkyboxPass.cs", 147);
			RendererListHandle handle = CreateSkyBoxRendererList(renderGraph, universalCameraData);
			InitPassData(ref passData, universalCameraData.xr, in handle);
			passData.material = skyboxMaterial;
			rasterRenderGraphBuilder.UseRendererList(in handle);
			rasterRenderGraphBuilder.SetRenderAttachment(colorTarget, 0);
			rasterRenderGraphBuilder.SetRenderAttachmentDepth(depthTarget);
			rasterRenderGraphBuilder.AllowPassCulling(value: false);
			if (universalCameraData.xr.enabled)
			{
				bool flag = universalCameraData.xrUniversal.canFoveateIntermediatePasses || universalResourceData.isActiveTargetBackBuffer;
				rasterRenderGraphBuilder.EnableFoveatedRasterization(universalCameraData.xr.supportsFoveatedRendering && flag);
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			}
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext rasterGraphContext)
			{
				ExecutePass(rasterGraphContext.cmd, data.xr, data.skyRendererListHandle);
			});
		}
	}
}
