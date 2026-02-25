using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal class HDRDebugViewPass : ScriptableRenderPass
	{
		private enum HDRDebugPassId
		{
			CIExyPrepass = 0,
			DebugViewPass = 1
		}

		private class PassDataCIExy
		{
			internal Material material;

			internal Vector4 luminanceParameters;

			internal TextureHandle srcColor;

			internal TextureHandle xyBuffer;

			internal TextureHandle passThrough;
		}

		private class PassDataDebugView
		{
			internal Material material;

			internal HDRDebugMode hdrDebugMode;

			internal UniversalCameraData cameraData;

			internal Vector4 luminanceParameters;

			internal TextureHandle xyBuffer;

			internal TextureHandle srcColor;

			internal TextureHandle dstColor;
		}

		internal class ShaderConstants
		{
			public static readonly int _DebugHDRModeId = Shader.PropertyToID("_DebugHDRMode");

			public static readonly int _HDRDebugParamsId = Shader.PropertyToID("_HDRDebugParams");

			public static readonly int _xyTextureId = Shader.PropertyToID("_xyBuffer");

			public static readonly int _SizeOfHDRXYMapping = 512;

			public static readonly int _CIExyUAVIndex = 1;
		}

		private RTHandle m_PassthroughRT;

		private Material m_material;

		public HDRDebugViewPass(Material mat)
		{
			base.profilingSampler = new ProfilingSampler("Blit HDR Debug Data");
			base.renderPassEvent = (RenderPassEvent)1003;
			m_material = mat;
		}

		public static void ConfigureDescriptorForCIEPrepass(ref RenderTextureDescriptor descriptor)
		{
			descriptor.graphicsFormat = GraphicsFormat.R32_SFloat;
			int width = (descriptor.height = ShaderConstants._SizeOfHDRXYMapping);
			descriptor.width = width;
			descriptor.useMipMap = false;
			descriptor.autoGenerateMips = false;
			descriptor.useDynamicScale = true;
			descriptor.depthStencilFormat = GraphicsFormat.None;
			descriptor.enableRandomWrite = true;
			descriptor.msaaSamples = 1;
			descriptor.dimension = TextureDimension.Tex2D;
			descriptor.vrUsage = VRTextureUsage.None;
		}

		internal static Vector4 GetLuminanceParameters(UniversalCameraData cameraData)
		{
			Vector4 hdrOutputParameters = Vector4.zero;
			if (cameraData.isHDROutputActive)
			{
				Tonemapping component = VolumeManager.instance.stack.GetComponent<Tonemapping>();
				UniversalRenderPipeline.GetHDROutputLuminanceParameters(cameraData.hdrDisplayInformation, cameraData.hdrDisplayColorGamut, component, out hdrOutputParameters);
			}
			else
			{
				hdrOutputParameters.z = 1f;
			}
			return hdrOutputParameters;
		}

		private static void ExecuteCIExyPrepass(CommandBuffer cmd, PassDataCIExy data, RTHandle sourceTexture, RTHandle xyTarget, RTHandle destTexture)
		{
			CoreUtils.SetRenderTarget(cmd, destTexture, RenderBufferLoadAction.DontCare, RenderBufferStoreAction.DontCare, ClearFlag.None, Color.clear);
			Vector4 value = new Vector4(ShaderConstants._SizeOfHDRXYMapping, ShaderConstants._SizeOfHDRXYMapping, 0f, 0f);
			cmd.SetRandomWriteTarget(ShaderConstants._CIExyUAVIndex, xyTarget);
			data.material.SetVector(ShaderConstants._HDRDebugParamsId, value);
			data.material.SetVector(ShaderPropertyId.hdrOutputLuminanceParams, data.luminanceParameters);
			Vector2 vector = (sourceTexture.useScaling ? new Vector2(sourceTexture.rtHandleProperties.rtHandleScale.x, sourceTexture.rtHandleProperties.rtHandleScale.y) : Vector2.one);
			Blitter.BlitTexture(cmd, sourceTexture, vector, data.material, 0);
			cmd.ClearRandomWriteTargets();
		}

		private static void ExecuteHDRDebugViewFinalPass(RasterCommandBuffer cmd, in PassDataDebugView data, RTHandle source, Vector4 scaleBias, RTHandle destination, RTHandle xyTarget)
		{
			if (data.cameraData.isHDROutputActive)
			{
				HDROutputUtils.ConfigureHDROutput(data.material, data.cameraData.hdrDisplayColorGamut, HDROutputUtils.Operation.ColorEncoding);
				CoreUtils.SetKeyword(data.material, "_HDR_OVERLAY", data.cameraData.rendersOverlayUI);
			}
			data.material.SetTexture(ShaderConstants._xyTextureId, xyTarget);
			Vector4 value = new Vector4(ShaderConstants._SizeOfHDRXYMapping, ShaderConstants._SizeOfHDRXYMapping, 0f, 0f);
			data.material.SetVector(ShaderConstants._HDRDebugParamsId, value);
			data.material.SetVector(ShaderPropertyId.hdrOutputLuminanceParams, data.luminanceParameters);
			data.material.SetInteger(ShaderConstants._DebugHDRModeId, (int)data.hdrDebugMode);
			RenderTargetIdentifier renderTargetIdentifier = BuiltinRenderTextureType.CameraTarget;
			if (data.cameraData.xr.enabled)
			{
				renderTargetIdentifier = data.cameraData.xr.renderTarget;
			}
			if (destination.nameID == renderTargetIdentifier || data.cameraData.targetTexture != null)
			{
				cmd.SetViewport(data.cameraData.pixelRect);
			}
			Blitter.BlitTexture(cmd, source, scaleBias, data.material, 1);
		}

		public void Dispose()
		{
			m_PassthroughRT?.Release();
		}

		public void Setup(UniversalCameraData cameraData, HDRDebugMode hdrdebugMode)
		{
			RenderTextureDescriptor descriptor = cameraData.cameraTargetDescriptor;
			DebugHandler.ConfigureColorDescriptorForDebugScreen(ref descriptor, cameraData.pixelWidth, cameraData.pixelHeight);
			RenderingUtils.ReAllocateHandleIfNeeded(ref m_PassthroughRT, in descriptor, FilterMode.Point, TextureWrapMode.Repeat, 1, 0f, "_HDRDebugDummyRT");
		}

		internal void RenderHDRDebug(RenderGraph renderGraph, UniversalCameraData cameraData, TextureHandle srcColor, TextureHandle overlayUITexture, TextureHandle dstColor, HDRDebugMode hdrDebugMode)
		{
			bool flag = hdrDebugMode != HDRDebugMode.ValuesAbovePaperWhite;
			Vector4 luminanceParameters = GetLuminanceParameters(cameraData);
			TextureHandle textureHandle = srcColor;
			TextureHandle xyBuffer = TextureHandle.nullHandle;
			if (flag)
			{
				RenderTextureDescriptor descriptor = cameraData.cameraTargetDescriptor;
				DebugHandler.ConfigureColorDescriptorForDebugScreen(ref descriptor, cameraData.pixelWidth, cameraData.pixelHeight);
				textureHandle = UniversalRenderer.CreateRenderGraphTexture(renderGraph, descriptor, "_HDRDebugDummyRT", clear: false);
				ConfigureDescriptorForCIEPrepass(ref descriptor);
				xyBuffer = UniversalRenderer.CreateRenderGraphTexture(renderGraph, descriptor, "_xyBuffer", clear: true);
				PassDataCIExy passData;
				using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<PassDataCIExy>("Blit HDR DebugView CIExy", out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\HDRDebugViewPass.cs", 245);
				passData.material = m_material;
				passData.luminanceParameters = luminanceParameters;
				passData.srcColor = srcColor;
				unsafeRenderGraphBuilder.UseTexture(in srcColor);
				passData.xyBuffer = xyBuffer;
				unsafeRenderGraphBuilder.UseTexture(in xyBuffer, AccessFlags.Write);
				passData.passThrough = textureHandle;
				unsafeRenderGraphBuilder.UseTexture(in textureHandle, AccessFlags.Write);
				unsafeRenderGraphBuilder.SetRenderFunc(delegate(PassDataCIExy data, UnsafeGraphContext context)
				{
					ExecuteCIExyPrepass(CommandBufferHelpers.GetNativeCommandBuffer(context.cmd), data, data.srcColor, data.xyBuffer, data.passThrough);
				});
			}
			PassDataDebugView passData2;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassDataDebugView>("Blit HDR DebugView", out passData2, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\HDRDebugViewPass.cs", 263);
			passData2.material = m_material;
			passData2.hdrDebugMode = hdrDebugMode;
			passData2.luminanceParameters = luminanceParameters;
			passData2.cameraData = cameraData;
			if (flag)
			{
				passData2.xyBuffer = xyBuffer;
				rasterRenderGraphBuilder.UseTexture(in xyBuffer);
			}
			passData2.srcColor = srcColor;
			rasterRenderGraphBuilder.UseTexture(in srcColor);
			passData2.dstColor = dstColor;
			rasterRenderGraphBuilder.SetRenderAttachment(dstColor, 0, AccessFlags.WriteAll);
			if (overlayUITexture.IsValid())
			{
				rasterRenderGraphBuilder.UseTexture(in overlayUITexture);
			}
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassDataDebugView data, RasterGraphContext context)
			{
				data.material.enabledKeywords = null;
				Vector4 finalBlitScaleBias = RenderingUtils.GetFinalBlitScaleBias(in context, in data.srcColor, in data.dstColor);
				ExecuteHDRDebugViewFinalPass(context.cmd, in data, data.srcColor, finalBlitScaleBias, data.dstColor, data.xyBuffer);
			});
		}
	}
}
