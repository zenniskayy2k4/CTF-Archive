using System;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal.Internal
{
	public class CopyDepthPass : ScriptableRenderPass
	{
		private static class ShaderConstants
		{
			public static readonly int _CameraDepthAttachment = Shader.PropertyToID("_CameraDepthAttachment");

			public static readonly int _CameraDepthTexture = Shader.PropertyToID("_CameraDepthTexture");

			public static readonly int _ZWriteShaderHandle = Shader.PropertyToID("_ZWrite");
		}

		private class PassData
		{
			internal TextureHandle source;

			internal TextureHandle destination;

			internal UniversalCameraData cameraData;

			internal Material copyDepthMaterial;

			internal int msaaSamples;

			internal bool copyResolvedDepth;

			internal bool copyToDepth;

			internal bool isDstBackbuffer;
		}

		private Material m_CopyDepthMaterial;

		internal bool m_CopyResolvedDepth;

		internal int MsaaSamples { get; set; }

		internal bool CopyToDepth { get; set; }

		internal bool CopyToDepthXR { get; set; }

		internal bool CopyToBackbuffer { get; set; }

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void OnCameraSetup(CommandBuffer cmd, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public CopyDepthPass(RenderPassEvent evt, Shader copyDepthShader, bool shouldClear = false, bool copyToDepth = false, bool copyResolvedDepth = false, string customPassName = null)
		{
			base.profilingSampler = ((customPassName != null) ? new ProfilingSampler(customPassName) : ProfilingSampler.Get(URPProfileId.CopyDepth));
			CopyToDepth = copyToDepth;
			m_CopyDepthMaterial = ((copyDepthShader != null) ? CoreUtils.CreateEngineMaterial(copyDepthShader) : null);
			base.renderPassEvent = evt;
			m_CopyResolvedDepth = copyResolvedDepth;
			CopyToDepthXR = false;
			CopyToBackbuffer = false;
		}

		public void Setup(RTHandle source, RTHandle destination)
		{
			MsaaSamples = -1;
		}

		public void Dispose()
		{
			CoreUtils.Destroy(m_CopyDepthMaterial);
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData passData, RTHandle source, bool yflip)
		{
			Material copyDepthMaterial = passData.copyDepthMaterial;
			int msaaSamples = passData.msaaSamples;
			bool copyResolvedDepth = passData.copyResolvedDepth;
			bool copyToDepth = passData.copyToDepth;
			if (copyDepthMaterial == null)
			{
				Debug.LogErrorFormat("Missing {0}. Copy Depth render pass will not execute. Check for missing reference in the renderer resources.", copyDepthMaterial);
				return;
			}
			using (new ProfilingScope(cmd, ProfilingSampler.Get(URPProfileId.CopyDepth)))
			{
				int num = 0;
				switch ((copyResolvedDepth || SystemInfo.supportsMultisampledTextures == 0) ? 1 : ((msaaSamples != -1) ? msaaSamples : source.rt.antiAliasing))
				{
				case 8:
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa2, value: false);
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa4, value: false);
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa8, value: true);
					break;
				case 4:
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa2, value: false);
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa4, value: true);
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa8, value: false);
					break;
				case 2:
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa2, value: true);
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa4, value: false);
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa8, value: false);
					break;
				default:
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa2, value: false);
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa4, value: false);
					cmd.SetKeyword(in ShaderGlobalKeywords.DepthMsaa8, value: false);
					break;
				}
				cmd.SetKeyword(in ShaderGlobalKeywords._OUTPUT_DEPTH, copyToDepth);
				Vector2 vector = (source.useScaling ? new Vector2(source.rtHandleProperties.rtHandleScale.x, source.rtHandleProperties.rtHandleScale.y) : Vector2.one);
				Vector4 scaleBias = (yflip ? new Vector4(vector.x, 0f - vector.y, 0f, vector.y) : new Vector4(vector.x, vector.y, 0f, 0f));
				if (passData.isDstBackbuffer)
				{
					cmd.SetViewport(passData.cameraData.pixelRect);
				}
				copyDepthMaterial.SetTexture(ShaderConstants._CameraDepthAttachment, source);
				copyDepthMaterial.SetFloat(ShaderConstants._ZWriteShaderHandle, copyToDepth ? 1f : 0f);
				Blitter.BlitTexture(cmd, source, scaleBias, copyDepthMaterial, 0);
			}
		}

		public override void OnCameraCleanup(CommandBuffer cmd)
		{
		}

		public void Render(RenderGraph renderGraph, ContextContainer frameData, TextureHandle destination, TextureHandle source, bool bindAsCameraDepth = false, string passName = "Copy Depth")
		{
			UniversalResourceData resourceData = frameData.Get<UniversalResourceData>();
			UniversalCameraData cameraData = frameData.Get<UniversalCameraData>();
			Render(renderGraph, destination, source, resourceData, cameraData, bindAsCameraDepth, passName);
		}

		public void Render(RenderGraph renderGraph, TextureHandle destination, TextureHandle source, UniversalResourceData resourceData, UniversalCameraData cameraData, bool bindAsCameraDepth = false, string passName = "Copy Depth")
		{
			MsaaSamples = -1;
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\CopyDepthPass.cs", 281);
			passData.copyDepthMaterial = m_CopyDepthMaterial;
			passData.msaaSamples = MsaaSamples;
			passData.cameraData = cameraData;
			passData.copyResolvedDepth = m_CopyResolvedDepth;
			passData.copyToDepth = CopyToDepth || CopyToDepthXR;
			passData.isDstBackbuffer = CopyToBackbuffer || CopyToDepthXR;
			if (cameraData.xr.enabled)
			{
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			}
			if (CopyToDepth)
			{
				rasterRenderGraphBuilder.SetRenderAttachmentDepth(destination, AccessFlags.WriteAll);
			}
			else if (CopyToDepthXR)
			{
				rasterRenderGraphBuilder.SetRenderAttachmentDepth(destination, AccessFlags.WriteAll);
				if (cameraData.xr.enabled && cameraData.xr.copyDepth)
				{
					RenderTargetInfo renderTargetInfo = renderGraph.GetRenderTargetInfo(resourceData.backBufferColor);
					if (renderTargetInfo.msaaSamples > 1)
					{
						TextureDesc desc = new TextureDesc(renderTargetInfo.width, renderTargetInfo.height, dynamicResolution: false, xrReady: true)
						{
							name = "XR Copy Depth Dummy Render Target",
							slices = renderTargetInfo.volumeDepth,
							format = renderTargetInfo.format,
							msaaSamples = (MSAASamples)renderTargetInfo.msaaSamples,
							clearBuffer = false,
							bindTextureMS = renderTargetInfo.bindMS
						};
						TextureHandle tex = renderGraph.CreateTexture(in desc);
						rasterRenderGraphBuilder.SetRenderAttachment(tex, 0);
					}
					else
					{
						rasterRenderGraphBuilder.SetRenderAttachment(resourceData.backBufferColor, 0);
					}
				}
			}
			else
			{
				rasterRenderGraphBuilder.SetRenderAttachment(destination, 0, AccessFlags.WriteAll);
			}
			passData.source = source;
			passData.destination = destination;
			rasterRenderGraphBuilder.UseTexture(in source);
			if (bindAsCameraDepth && destination.IsValid())
			{
				rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in destination, ShaderConstants._CameraDepthTexture);
			}
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				bool yflip = context.GetTextureUVOrigin(in data.source) != context.GetTextureUVOrigin(in data.destination);
				ExecutePass(context.cmd, data, data.source, yflip);
			});
		}
	}
}
