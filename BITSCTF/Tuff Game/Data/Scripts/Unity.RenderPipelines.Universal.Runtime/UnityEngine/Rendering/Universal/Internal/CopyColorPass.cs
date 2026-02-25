using System;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;
using UnityEngine.Rendering.RenderGraphModule.Util;

namespace UnityEngine.Rendering.Universal.Internal
{
	public class CopyColorPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal TextureHandle source;

			internal TextureHandle destination;

			internal bool useProceduralBlit;

			internal Material samplingMaterial;

			internal Material copyColorMaterial;

			internal Downsampling downsamplingMethod;

			internal int sampleOffsetShaderHandle;
		}

		private int m_SampleOffsetShaderHandle;

		private Material m_SamplingMaterial;

		private Downsampling m_DownsamplingMethod;

		private Material m_CopyColorMaterial;

		private static readonly string k_CopyColorPassName = "Copy Color";

		private static readonly string k_DownsampleAndCopyPassName = "Downsample Color";

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void OnCameraSetup(CommandBuffer cmd, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public CopyColorPass(RenderPassEvent evt, Material samplingMaterial, Material copyColorMaterial = null, string customPassName = null)
		{
			base.profilingSampler = ((customPassName != null) ? new ProfilingSampler(customPassName) : ProfilingSampler.Get(URPProfileId.CopyColor));
			m_SamplingMaterial = samplingMaterial;
			m_CopyColorMaterial = copyColorMaterial;
			m_SampleOffsetShaderHandle = Shader.PropertyToID("_SampleOffset");
			base.renderPassEvent = evt;
			m_DownsamplingMethod = Downsampling.None;
		}

		public static void ConfigureDescriptor(Downsampling downsamplingMethod, ref RenderTextureDescriptor descriptor, out FilterMode filterMode)
		{
			descriptor.msaaSamples = 1;
			descriptor.depthStencilFormat = GraphicsFormat.None;
			switch (downsamplingMethod)
			{
			case Downsampling._2xBilinear:
				descriptor.width = Mathf.Max(1, descriptor.width / 2);
				descriptor.height = Mathf.Max(1, descriptor.height / 2);
				break;
			case Downsampling._4xBox:
			case Downsampling._4xBilinear:
				descriptor.width = Mathf.Max(1, descriptor.width / 4);
				descriptor.height = Mathf.Max(1, descriptor.height / 4);
				break;
			}
			filterMode = ((downsamplingMethod != Downsampling.None) ? FilterMode.Bilinear : FilterMode.Point);
		}

		[Obsolete("Use RTHandles for source and destination #from(2022.1) #breakingFrom(2023.1).", true)]
		public void Setup(RenderTargetIdentifier source, RenderTargetHandle destination, Downsampling downsampling)
		{
			throw new NotSupportedException("Setup with RenderTargetIdentifier has been deprecated. Use it with RTHandles instead.");
		}

		public void Setup(RTHandle source, RTHandle destination, Downsampling downsampling)
		{
			m_DownsamplingMethod = downsampling;
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData passData, RTHandle source, bool useDrawProceduralBlit)
		{
			Material samplingMaterial = passData.samplingMaterial;
			Material copyColorMaterial = passData.copyColorMaterial;
			Downsampling downsamplingMethod = passData.downsamplingMethod;
			int sampleOffsetShaderHandle = passData.sampleOffsetShaderHandle;
			if (samplingMaterial == null)
			{
				Debug.LogErrorFormat("Missing {0}. Copy Color render pass will not execute. Check for missing reference in the renderer resources.", samplingMaterial);
				return;
			}
			using (new ProfilingScope(cmd, ProfilingSampler.Get(URPProfileId.CopyColor)))
			{
				Vector2 vector = (source.useScaling ? new Vector2(source.rtHandleProperties.rtHandleScale.x, source.rtHandleProperties.rtHandleScale.y) : Vector2.one);
				switch (downsamplingMethod)
				{
				case Downsampling.None:
					Blitter.BlitTexture(cmd, source, vector, copyColorMaterial, 0);
					break;
				case Downsampling._2xBilinear:
					Blitter.BlitTexture(cmd, source, vector, copyColorMaterial, 1);
					break;
				case Downsampling._4xBox:
					samplingMaterial.SetFloat(sampleOffsetShaderHandle, 2f);
					Blitter.BlitTexture(cmd, source, vector, samplingMaterial, 0);
					break;
				case Downsampling._4xBilinear:
					Blitter.BlitTexture(cmd, source, vector, copyColorMaterial, 1);
					break;
				}
			}
		}

		internal TextureHandle Render(RenderGraph renderGraph, ContextContainer frameData, out TextureHandle destination, in TextureHandle source, Downsampling downsampling)
		{
			m_DownsamplingMethod = downsampling;
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			RenderTextureDescriptor descriptor = universalCameraData.cameraTargetDescriptor;
			ConfigureDescriptor(downsampling, ref descriptor, out var filterMode);
			destination = UniversalRenderer.CreateRenderGraphTexture(renderGraph, descriptor, "_CameraOpaqueTexture", clear: true, filterMode);
			RenderInternal(renderGraph, in destination, in source, universalCameraData.xr.enabled);
			return destination;
		}

		internal void RenderToExistingTexture(RenderGraph renderGraph, ContextContainer frameData, in TextureHandle destination, in TextureHandle source, Downsampling downsampling = Downsampling.None)
		{
			m_DownsamplingMethod = downsampling;
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			RenderInternal(renderGraph, in destination, in source, universalCameraData.xr.enabled);
		}

		private void RenderInternal(RenderGraph renderGraph, in TextureHandle destination, in TextureHandle source, bool useProceduralBlit)
		{
			bool flag = SystemInfo.graphicsDeviceType == GraphicsDeviceType.OpenGLES3;
			if (m_DownsamplingMethod != Downsampling.None || flag)
			{
				AddDownsampleAndCopyColorRenderPass(renderGraph, in destination, in source, useProceduralBlit, k_DownsampleAndCopyPassName);
				return;
			}
			using IBaseRenderGraphBuilder baseRenderGraphBuilder = renderGraph.AddBlitPass(source, destination, Vector2.one, Vector2.zero, 0, 0, -1, 0, 0, 1, UnityEngine.Rendering.RenderGraphModule.Util.RenderGraphUtils.BlitFilterMode.ClampBilinear, k_CopyColorPassName, returnBuilder: true, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\CopyColorPass.cs", 232);
			baseRenderGraphBuilder.SetGlobalTextureAfterPass(in destination, Shader.PropertyToID("_CameraOpaqueTexture"));
		}

		private void AddDownsampleAndCopyColorRenderPass(RenderGraph renderGraph, in TextureHandle destination, in TextureHandle source, bool useProceduralBlit, string passName)
		{
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\CopyColorPass.cs", 241);
			rasterRenderGraphBuilder.SetRenderAttachment(destination, 0, AccessFlags.WriteAll);
			passData.source = source;
			rasterRenderGraphBuilder.UseTexture(in source);
			passData.useProceduralBlit = useProceduralBlit;
			passData.samplingMaterial = m_SamplingMaterial;
			passData.copyColorMaterial = m_CopyColorMaterial;
			passData.downsamplingMethod = m_DownsamplingMethod;
			passData.sampleOffsetShaderHandle = m_SampleOffsetShaderHandle;
			rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in destination, Shader.PropertyToID("_CameraOpaqueTexture"));
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				ExecutePass(context.cmd, data, data.source, data.useProceduralBlit);
			});
		}
	}
}
