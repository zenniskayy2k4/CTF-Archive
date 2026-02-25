using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal class InvokeOnRenderObjectCallbackPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal TextureHandle colorTarget;

			internal TextureHandle depthTarget;
		}

		public InvokeOnRenderObjectCallbackPass(RenderPassEvent evt)
		{
			base.profilingSampler = new ProfilingSampler("Invoke OnRenderObject Callback");
			base.renderPassEvent = evt;
		}

		internal void Render(RenderGraph renderGraph, TextureHandle colorTarget, TextureHandle depthTarget)
		{
			PassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\InvokeOnRenderObjectCallbackPass.cs", 42);
			passData.colorTarget = colorTarget;
			unsafeRenderGraphBuilder.UseTexture(in colorTarget, AccessFlags.Write);
			passData.depthTarget = depthTarget;
			unsafeRenderGraphBuilder.UseTexture(in depthTarget, AccessFlags.Write);
			unsafeRenderGraphBuilder.AllowPassCulling(value: false);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(PassData data, UnsafeGraphContext context)
			{
				context.cmd.SetRenderTarget(data.colorTarget, data.depthTarget);
				context.cmd.InvokeOnRenderObjectCallbacks();
			});
		}
	}
}
