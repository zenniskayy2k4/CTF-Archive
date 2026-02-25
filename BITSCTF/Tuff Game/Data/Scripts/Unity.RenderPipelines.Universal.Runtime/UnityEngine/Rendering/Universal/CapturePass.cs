using System;
using System.Collections.Generic;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal class CapturePass : ScriptableRenderPass
	{
		private class UnsafePassData
		{
			internal TextureHandle source;

			public IEnumerator<Action<RenderTargetIdentifier, CommandBuffer>> captureActions;
		}

		public CapturePass(RenderPassEvent evt)
		{
			base.profilingSampler = new ProfilingSampler("Capture Camera output");
			base.renderPassEvent = evt;
		}

		public override void RecordRenderGraph(RenderGraph renderGraph, ContextContainer frameData)
		{
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			UnsafePassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<UnsafePassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\CapturePass.cs", 59);
			passData.source = universalResourceData.cameraColor;
			passData.captureActions = universalCameraData.captureActions;
			unsafeRenderGraphBuilder.AllowPassCulling(value: false);
			unsafeRenderGraphBuilder.UseTexture(universalResourceData.cameraColor);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(UnsafePassData data, UnsafeGraphContext unsafeContext)
			{
				CommandBuffer nativeCommandBuffer = CommandBufferHelpers.GetNativeCommandBuffer(unsafeContext.cmd);
				IEnumerator<Action<RenderTargetIdentifier, CommandBuffer>> captureActions = data.captureActions;
				data.captureActions.Reset();
				while (data.captureActions.MoveNext())
				{
					captureActions.Current(data.source, nativeCommandBuffer);
				}
			});
		}
	}
}
