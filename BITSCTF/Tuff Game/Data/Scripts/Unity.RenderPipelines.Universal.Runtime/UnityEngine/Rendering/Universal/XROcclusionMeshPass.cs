using System;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	public class XROcclusionMeshPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal XRPass xr;

			internal bool isActiveTargetBackBuffer;

			internal bool shouldYFlip;

			internal TextureHandle cameraColorAttachment;
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public bool m_IsActiveTargetBackBuffer;

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public XROcclusionMeshPass(RenderPassEvent evt)
		{
			base.profilingSampler = new ProfilingSampler("Draw XR Occlusion Mesh");
			base.renderPassEvent = evt;
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData data)
		{
			if (data.xr.hasValidOcclusionMesh)
			{
				if (data.isActiveTargetBackBuffer)
				{
					cmd.SetViewport(data.xr.GetViewport());
				}
				data.xr.RenderOcclusionMesh(cmd, data.shouldYFlip);
			}
		}

		internal void Render(RenderGraph renderGraph, ContextContainer frameData, in TextureHandle cameraColorAttachment, in TextureHandle cameraDepthAttachment)
		{
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\XROcclusionMeshPass.cs", 72);
			passData.xr = universalCameraData.xr;
			passData.cameraColorAttachment = cameraColorAttachment;
			rasterRenderGraphBuilder.SetRenderAttachment(cameraColorAttachment, 0);
			rasterRenderGraphBuilder.SetRenderAttachmentDepth(cameraDepthAttachment);
			passData.isActiveTargetBackBuffer = universalResourceData.isActiveTargetBackBuffer;
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			if (universalCameraData.xr.enabled)
			{
				bool flag = universalCameraData.xrUniversal.canFoveateIntermediatePasses || universalResourceData.isActiveTargetBackBuffer;
				rasterRenderGraphBuilder.EnableFoveatedRasterization(universalCameraData.xr.supportsFoveatedRendering && flag);
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			}
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				passData.shouldYFlip = RenderingUtils.IsHandleYFlipped(in context, in data.cameraColorAttachment);
				ExecutePass(context.cmd, data);
			});
		}
	}
}
