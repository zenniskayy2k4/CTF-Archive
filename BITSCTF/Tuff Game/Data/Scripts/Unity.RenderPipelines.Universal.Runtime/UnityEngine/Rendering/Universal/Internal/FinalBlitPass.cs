using System;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal.Internal
{
	public class FinalBlitPass : ScriptableRenderPass
	{
		private static class BlitPassNames
		{
			public const string NearestSampler = "NearestDebugDraw";

			public const string BilinearSampler = "BilinearDebugDraw";
		}

		private enum BlitType
		{
			Core = 0,
			HDR = 1,
			Count = 2
		}

		private struct BlitMaterialData
		{
			public Material material;

			public int nearestSamplerPass;

			public int bilinearSamplerPass;
		}

		private class PassData
		{
			internal TextureHandle source;

			internal TextureHandle destination;

			internal int sourceID;

			internal Vector4 hdrOutputLuminanceParams;

			internal bool requireSrgbConversion;

			internal bool enableAlphaOutput;

			internal BlitMaterialData blitMaterialData;

			internal UniversalCameraData cameraData;

			internal bool useFullScreenViewport;
		}

		private static readonly int s_CameraDepthTextureID = Shader.PropertyToID("_CameraDepthTexture");

		private BlitMaterialData[] m_BlitMaterialData;

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void OnCameraSetup(CommandBuffer cmd, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public FinalBlitPass(RenderPassEvent evt, Material blitMaterial, Material blitHDRMaterial)
		{
			base.profilingSampler = ProfilingSampler.Get(URPProfileId.BlitFinalToBackBuffer);
			base.renderPassEvent = evt;
			m_BlitMaterialData = new BlitMaterialData[2];
			for (int i = 0; i < 2; i++)
			{
				m_BlitMaterialData[i].material = ((i == 0) ? blitMaterial : blitHDRMaterial);
				m_BlitMaterialData[i].nearestSamplerPass = m_BlitMaterialData[i].material?.FindPass("NearestDebugDraw") ?? (-1);
				m_BlitMaterialData[i].bilinearSamplerPass = m_BlitMaterialData[i].material?.FindPass("BilinearDebugDraw") ?? (-1);
			}
		}

		public void Dispose()
		{
		}

		[Obsolete("Use RTHandles for colorHandle. #from(2022.1) #breakingFrom(2023.1)", true)]
		public void Setup(RenderTextureDescriptor baseDescriptor, RenderTargetHandle colorHandle)
		{
			throw new NotSupportedException("Setup with RenderTargetHandle has been deprecated. Use it with RTHandles instead.");
		}

		public void Setup(RenderTextureDescriptor baseDescriptor, RTHandle colorHandle)
		{
		}

		private static void SetupHDROutput(ColorGamut hdrDisplayColorGamut, Material material, HDROutputUtils.Operation hdrOperation, Vector4 hdrOutputParameters, bool rendersOverlayUI)
		{
			material.SetVector(ShaderPropertyId.hdrOutputLuminanceParams, hdrOutputParameters);
			HDROutputUtils.ConfigureHDROutput(material, hdrDisplayColorGamut, hdrOperation);
			CoreUtils.SetKeyword(material, "_HDR_OVERLAY", rendersOverlayUI);
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData data, RTHandle source, RTHandle destination, UniversalCameraData cameraData, Vector4 scaleBias)
		{
			bool flag = !cameraData.isSceneViewCamera;
			if (cameraData.xr.enabled)
			{
				flag = new RenderTargetIdentifier(destination.nameID, 0, CubemapFace.Unknown, -1) == new RenderTargetIdentifier(cameraData.xr.renderTarget, 0, CubemapFace.Unknown, -1);
			}
			Rect pixelRect = (data.useFullScreenViewport ? new Rect(0f, 0f, Screen.width, Screen.height) : cameraData.pixelRect);
			RenderingUtils.SetupOffscreenUIViewportParams(data.blitMaterialData.material, ref pixelRect, flag);
			if (flag)
			{
				cmd.SetViewport(pixelRect);
			}
			cmd.SetWireframe(enable: false);
			CoreUtils.SetKeyword(data.blitMaterialData.material, "_ENABLE_ALPHA_OUTPUT", data.enableAlphaOutput);
			RenderTexture rt = source.rt;
			int pass = (((object)rt != null && rt.filterMode == FilterMode.Bilinear) ? data.blitMaterialData.bilinearSamplerPass : data.blitMaterialData.nearestSamplerPass);
			Blitter.BlitTexture(cmd, source, scaleBias, data.blitMaterialData.material, pass);
		}

		private void InitPassData(UniversalCameraData cameraData, ref PassData passData, BlitType blitType, bool enableAlphaOutput, bool useFullScreenViewport)
		{
			passData.cameraData = cameraData;
			passData.requireSrgbConversion = cameraData.requireSrgbConversion;
			passData.enableAlphaOutput = enableAlphaOutput;
			passData.useFullScreenViewport = useFullScreenViewport;
			passData.blitMaterialData = m_BlitMaterialData[(int)blitType];
		}

		internal void Render(RenderGraph renderGraph, ContextContainer frameData, UniversalCameraData cameraData, in TextureHandle src, in TextureHandle dest, TextureHandle overlayUITexture, bool useFullScreenViewport = false)
		{
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\FinalBlitPass.cs", 285);
			frameData.Get<UniversalResourceData>();
			bool flag = cameraData.renderer is UniversalRenderer;
			if (cameraData.requiresDepthTexture && flag)
			{
				rasterRenderGraphBuilder.UseGlobalTexture(s_CameraDepthTextureID);
			}
			bool isHDROutputActive = cameraData.isHDROutputActive;
			bool isAlphaOutputEnabled = cameraData.isAlphaOutputEnabled;
			InitPassData(cameraData, ref passData, isHDROutputActive ? BlitType.HDR : BlitType.Core, isAlphaOutputEnabled, useFullScreenViewport);
			passData.sourceID = ShaderPropertyId.sourceTex;
			passData.source = src;
			rasterRenderGraphBuilder.UseTexture(in src);
			passData.destination = dest;
			AccessFlags flags = AccessFlags.Write;
			bool flag2 = !XRSystem.foveatedRenderingCaps.HasFlag(FoveatedRenderingCaps.NonUniformRaster);
			rasterRenderGraphBuilder.EnableFoveatedRasterization(cameraData.xr.supportsFoveatedRendering && flag2);
			rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			if (cameraData.xr.enabled && cameraData.isDefaultViewport && !isAlphaOutputEnabled)
			{
				flags = AccessFlags.WriteAll;
			}
			rasterRenderGraphBuilder.SetRenderAttachment(dest, 0, flags);
			if (isHDROutputActive && overlayUITexture.IsValid())
			{
				Tonemapping component = VolumeManager.instance.stack.GetComponent<Tonemapping>();
				UniversalRenderPipeline.GetHDROutputLuminanceParameters(passData.cameraData.hdrDisplayInformation, passData.cameraData.hdrDisplayColorGamut, component, out passData.hdrOutputLuminanceParams);
				rasterRenderGraphBuilder.UseTexture(in overlayUITexture);
			}
			else
			{
				passData.hdrOutputLuminanceParams = new Vector4(-1f, -1f, -1f, -1f);
			}
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				data.blitMaterialData.material.enabledKeywords = null;
				context.cmd.SetKeyword(in ShaderGlobalKeywords.LinearToSRGBConversion, data.requireSrgbConversion);
				data.blitMaterialData.material.SetTexture(data.sourceID, data.source);
				DebugHandler activeDebugHandler = ScriptableRenderPass.GetActiveDebugHandler(data.cameraData);
				bool num = activeDebugHandler?.WriteToDebugScreenTexture(data.cameraData.resolveFinalTarget) ?? false;
				if (data.hdrOutputLuminanceParams.w >= 0f)
				{
					HDROutputUtils.Operation operation = HDROutputUtils.Operation.None;
					if (activeDebugHandler == null || !activeDebugHandler.HDRDebugViewIsActive(data.cameraData.resolveFinalTarget))
					{
						operation |= HDROutputUtils.Operation.ColorEncoding;
					}
					if (!data.cameraData.postProcessEnabled)
					{
						operation |= HDROutputUtils.Operation.ColorConversion;
					}
					SetupHDROutput(data.cameraData.hdrDisplayColorGamut, data.blitMaterialData.material, operation, data.hdrOutputLuminanceParams, data.cameraData.rendersOverlayUI);
				}
				if (num)
				{
					RTHandle rTHandle = data.source;
					Vector2 vector = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
					RenderTexture rt = rTHandle.rt;
					int pass = (((object)rt != null && rt.filterMode == FilterMode.Bilinear) ? data.blitMaterialData.bilinearSamplerPass : data.blitMaterialData.nearestSamplerPass);
					Blitter.BlitTexture(context.cmd, rTHandle, vector, data.blitMaterialData.material, pass);
				}
				else
				{
					Vector4 finalBlitScaleBias = RenderingUtils.GetFinalBlitScaleBias(in context, in data.source, in data.destination);
					ExecutePass(context.cmd, data, data.source, data.destination, data.cameraData, finalBlitScaleBias);
				}
			});
		}
	}
}
