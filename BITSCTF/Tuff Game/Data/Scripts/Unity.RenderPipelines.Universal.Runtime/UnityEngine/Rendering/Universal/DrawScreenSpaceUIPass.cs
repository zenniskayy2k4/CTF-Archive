using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal class DrawScreenSpaceUIPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal RendererListHandle rendererList;
		}

		private class UnsafePassData
		{
			internal RendererListHandle rendererList;

			internal TextureHandle colorTarget;
		}

		private RTHandle m_ColorTarget;

		private RTHandle m_DepthTarget;

		private bool m_RenderOffscreen;

		public DrawScreenSpaceUIPass(RenderPassEvent evt, bool renderOffscreen)
		{
			base.profilingSampler = ProfilingSampler.Get(URPProfileId.DrawScreenSpaceUI);
			base.renderPassEvent = evt;
			m_RenderOffscreen = renderOffscreen;
		}

		private static void ConfigureColorDescriptor(ref RenderTextureDescriptor descriptor, int cameraWidth, int cameraHeight)
		{
			descriptor.graphicsFormat = GraphicsFormat.R8G8B8A8_SRGB;
			descriptor.depthStencilFormat = GraphicsFormat.None;
			descriptor.width = cameraWidth;
			descriptor.height = cameraHeight;
		}

		internal static void ConfigureOffscreenUITextureDesc(ref TextureDesc textureDesc)
		{
			textureDesc.format = GraphicsFormat.R8G8B8A8_SRGB;
			textureDesc.depthBufferBits = DepthBits.None;
			textureDesc.width = Screen.width;
			textureDesc.height = Screen.height;
		}

		private static void ConfigureDepthDescriptor(ref RenderTextureDescriptor descriptor, GraphicsFormat depthStencilFormat, int targetWidth, int targetHeight)
		{
			descriptor.graphicsFormat = GraphicsFormat.None;
			descriptor.depthStencilFormat = depthStencilFormat;
			descriptor.width = targetWidth;
			descriptor.height = targetHeight;
		}

		private static void ExecutePass(RasterCommandBuffer commandBuffer, PassData passData, RendererList rendererList)
		{
			commandBuffer.DrawRendererList(rendererList);
		}

		private static void ExecutePass(UnsafeCommandBuffer commandBuffer, UnsafePassData passData, RendererList rendererList)
		{
			commandBuffer.DrawRendererList(rendererList);
		}

		public void Dispose()
		{
			m_ColorTarget?.Release();
			m_DepthTarget?.Release();
		}

		public void Setup(UniversalCameraData cameraData, GraphicsFormat depthStencilFormat)
		{
			if (m_RenderOffscreen)
			{
				RenderTextureDescriptor descriptor = cameraData.cameraTargetDescriptor;
				ConfigureColorDescriptor(ref descriptor, cameraData.pixelWidth, cameraData.pixelHeight);
				RenderingUtils.ReAllocateHandleIfNeeded(ref m_ColorTarget, in descriptor, FilterMode.Point, TextureWrapMode.Repeat, 1, 0f, "_OverlayUITexture");
				RenderTextureDescriptor descriptor2 = cameraData.cameraTargetDescriptor;
				ConfigureDepthDescriptor(ref descriptor2, depthStencilFormat, cameraData.pixelWidth, cameraData.pixelHeight);
				RenderingUtils.ReAllocateHandleIfNeeded(ref m_DepthTarget, in descriptor2, FilterMode.Point, TextureWrapMode.Repeat, 1, 0f, "_OverlayUITexture_Depth");
			}
		}

		internal void RenderOffscreen(RenderGraph renderGraph, ContextContainer frameData, GraphicsFormat depthStencilFormat, TextureHandle overlayUITexture)
		{
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			RenderTextureDescriptor descriptor = universalCameraData.cameraTargetDescriptor;
			ConfigureDepthDescriptor(ref descriptor, depthStencilFormat, Screen.width, Screen.height);
			TextureHandle tex = UniversalRenderer.CreateRenderGraphTexture(renderGraph, descriptor, "_OverlayUITexture_Depth", clear: false);
			PassData passData;
			using (IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>("Draw Screen Space UIToolkit/uGUI - Offscreen", out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\DrawScreenSpaceUIPass.cs", 193))
			{
				rasterRenderGraphBuilder.UseAllGlobalTextures(enable: true);
				rasterRenderGraphBuilder.SetRenderAttachment(overlayUITexture, 0);
				passData.rendererList = renderGraph.CreateUIOverlayRendererList(in universalCameraData.camera, UISubset.UIToolkit_UGUI);
				rasterRenderGraphBuilder.UseRendererList(in passData.rendererList);
				rasterRenderGraphBuilder.SetRenderAttachmentDepth(tex, AccessFlags.ReadWrite);
				if (overlayUITexture.IsValid())
				{
					rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in overlayUITexture, ShaderPropertyId.overlayUITexture);
				}
				rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
				{
					context.cmd.ClearRenderTarget(clearDepth: true, clearColor: true, Color.clear);
					ExecutePass(context.cmd, data, data.rendererList);
				});
			}
			UnsafePassData passData2;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<UnsafePassData>("Draw Screen Space IMGUI/SoftwareCursor - Offscreen", out passData2, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\DrawScreenSpaceUIPass.cs", 218);
			passData2.colorTarget = overlayUITexture;
			unsafeRenderGraphBuilder.UseTexture(in overlayUITexture, AccessFlags.Write);
			passData2.rendererList = renderGraph.CreateUIOverlayRendererList(in universalCameraData.camera, UISubset.LowLevel);
			unsafeRenderGraphBuilder.UseRendererList(in passData2.rendererList);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(UnsafePassData data, UnsafeGraphContext context)
			{
				context.cmd.SetRenderTarget(data.colorTarget);
				ExecutePass(context.cmd, data, data.rendererList);
			});
		}

		internal void RenderOverlay(RenderGraph renderGraph, ContextContainer frameData, in TextureHandle colorBuffer, in TextureHandle depthBuffer)
		{
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			frameData.Get<UniversalResourceData>();
			_ = universalCameraData.renderer;
			PassData passData;
			using (IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>("Draw UIToolkit/uGUI Overlay", out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\DrawScreenSpaceUIPass.cs", 241))
			{
				rasterRenderGraphBuilder.UseAllGlobalTextures(enable: true);
				rasterRenderGraphBuilder.SetRenderAttachment(colorBuffer, 0);
				rasterRenderGraphBuilder.SetRenderAttachmentDepth(depthBuffer, AccessFlags.ReadWrite);
				passData.rendererList = renderGraph.CreateUIOverlayRendererList(in universalCameraData.camera, UISubset.UIToolkit_UGUI);
				rasterRenderGraphBuilder.UseRendererList(in passData.rendererList);
				rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
				{
					ExecutePass(context.cmd, data, data.rendererList);
				});
			}
			UnsafePassData passData2;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<UnsafePassData>("Draw IMGUI/SoftwareCursor Overlay", out passData2, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\DrawScreenSpaceUIPass.cs", 261);
			passData2.colorTarget = colorBuffer;
			unsafeRenderGraphBuilder.UseTexture(in colorBuffer, AccessFlags.Write);
			passData2.rendererList = renderGraph.CreateUIOverlayRendererList(in universalCameraData.camera, UISubset.LowLevel);
			unsafeRenderGraphBuilder.UseRendererList(in passData2.rendererList);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(UnsafePassData data, UnsafeGraphContext context)
			{
				context.cmd.SetRenderTarget(data.colorTarget);
				ExecutePass(context.cmd, data, data.rendererList);
			});
		}
	}
}
