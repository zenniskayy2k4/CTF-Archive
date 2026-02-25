using System;
using System.Runtime.CompilerServices;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal class PostProcessPassRenderGraph
	{
		internal static class ShaderConstants
		{
			public static readonly int _CameraDepthTextureID = Shader.PropertyToID("_CameraDepthTexture");

			public static readonly int _StencilRef = Shader.PropertyToID("_StencilRef");

			public static readonly int _StencilMask = Shader.PropertyToID("_StencilMask");

			public static readonly int _ColorTexture = Shader.PropertyToID("_ColorTexture");

			public static readonly int _Params = Shader.PropertyToID("_Params");

			public static readonly int _Params2 = Shader.PropertyToID("_Params2");

			public static readonly int _ViewProjM = Shader.PropertyToID("_ViewProjM");

			public static readonly int _PrevViewProjM = Shader.PropertyToID("_PrevViewProjM");

			public static readonly int _ViewProjMStereo = Shader.PropertyToID("_ViewProjMStereo");

			public static readonly int _PrevViewProjMStereo = Shader.PropertyToID("_PrevViewProjMStereo");

			public static readonly int _FullscreenProjMat = Shader.PropertyToID("_FullscreenProjMat");

			public static readonly int _FullCoCTexture = Shader.PropertyToID("_FullCoCTexture");

			public static readonly int _HalfCoCTexture = Shader.PropertyToID("_HalfCoCTexture");

			public static readonly int _DofTexture = Shader.PropertyToID("_DofTexture");

			public static readonly int _CoCParams = Shader.PropertyToID("_CoCParams");

			public static readonly int _BokehKernel = Shader.PropertyToID("_BokehKernel");

			public static readonly int _BokehConstants = Shader.PropertyToID("_BokehConstants");

			public static readonly int _DownSampleScaleFactor = Shader.PropertyToID("_DownSampleScaleFactor");

			public static readonly int _Metrics = Shader.PropertyToID("_Metrics");

			public static readonly int _AreaTexture = Shader.PropertyToID("_AreaTexture");

			public static readonly int _SearchTexture = Shader.PropertyToID("_SearchTexture");

			public static readonly int _BlendTexture = Shader.PropertyToID("_BlendTexture");

			public static readonly int _SourceTexLowMip = Shader.PropertyToID("_SourceTexLowMip");

			public static readonly int _Bloom_Params = Shader.PropertyToID("_Bloom_Params");

			public static readonly int _Bloom_Texture = Shader.PropertyToID("_Bloom_Texture");

			public static readonly int _LensDirt_Texture = Shader.PropertyToID("_LensDirt_Texture");

			public static readonly int _LensDirt_Params = Shader.PropertyToID("_LensDirt_Params");

			public static readonly int _LensDirt_Intensity = Shader.PropertyToID("_LensDirt_Intensity");

			public static readonly int _Distortion_Params1 = Shader.PropertyToID("_Distortion_Params1");

			public static readonly int _Distortion_Params2 = Shader.PropertyToID("_Distortion_Params2");

			public static readonly int _Chroma_Params = Shader.PropertyToID("_Chroma_Params");

			public static readonly int _Vignette_Params1 = Shader.PropertyToID("_Vignette_Params1");

			public static readonly int _Vignette_Params2 = Shader.PropertyToID("_Vignette_Params2");

			public static readonly int _Vignette_ParamsXR = Shader.PropertyToID("_Vignette_ParamsXR");

			public static readonly int _InternalLut = Shader.PropertyToID("_InternalLut");

			public static readonly int _Lut_Params = Shader.PropertyToID("_Lut_Params");

			public static readonly int _UserLut = Shader.PropertyToID("_UserLut");

			public static readonly int _UserLut_Params = Shader.PropertyToID("_UserLut_Params");
		}

		internal static class Constants
		{
			public const int k_MaxPyramidSize = 16;

			public const int k_GaussianDoFPassComputeCoc = 0;

			public const int k_GaussianDoFPassDownscalePrefilter = 1;

			public const int k_GaussianDoFPassBlurH = 2;

			public const int k_GaussianDoFPassBlurV = 3;

			public const int k_GaussianDoFPassComposite = 4;

			public const int k_BokehDoFPassComputeCoc = 0;

			public const int k_BokehDoFPassDownscalePrefilter = 1;

			public const int k_BokehDoFPassBlur = 2;

			public const int k_BokehDoFPassPostFilter = 3;

			public const int k_BokehDoFPassComposite = 4;
		}

		private class UpdateCameraResolutionPassData
		{
			internal Vector2Int newCameraTargetSize;
		}

		private class StopNaNsPassData
		{
			internal TextureHandle sourceTexture;

			internal Material stopNaN;
		}

		private class SMAASetupPassData
		{
			internal Vector4 metrics;

			internal Texture2D areaTexture;

			internal Texture2D searchTexture;

			internal float stencilRef;

			internal float stencilMask;

			internal AntialiasingQuality antialiasingQuality;

			internal Material material;
		}

		private class SMAAPassData
		{
			internal TextureHandle sourceTexture;

			internal TextureHandle blendTexture;

			internal Material material;
		}

		private class UberSetupBloomPassData
		{
			internal Vector4 bloomParams;

			internal Vector4 dirtScaleOffset;

			internal float dirtIntensity;

			internal Texture dirtTexture;

			internal bool highQualityFilteringValue;

			internal TextureHandle bloomTexture;

			internal Material uberMaterial;
		}

		private class BloomPassData
		{
			internal int mipCount;

			internal Material material;

			internal Material[] upsampleMaterials;

			internal TextureHandle sourceTexture;

			internal TextureHandle[] bloomMipUp;

			internal TextureHandle[] bloomMipDown;
		}

		internal struct BloomMaterialParams
		{
			internal Vector4 parameters;

			internal Vector4 parameters2;

			internal BloomFilterMode bloomFilter;

			internal bool highQualityFiltering;

			internal bool enableAlphaOutput;

			internal bool Equals(ref BloomMaterialParams other)
			{
				if (parameters == other.parameters && parameters2 == other.parameters2 && highQualityFiltering == other.highQualityFiltering && enableAlphaOutput == other.enableAlphaOutput)
				{
					return bloomFilter == other.bloomFilter;
				}
				return false;
			}
		}

		private class DoFGaussianPassData
		{
			internal int downsample;

			internal RenderingData renderingData;

			internal Vector3 cocParams;

			internal bool highQualitySamplingValue;

			internal TextureHandle sourceTexture;

			internal TextureHandle depthTexture;

			internal Material material;

			internal Material materialCoC;

			internal TextureHandle halfCoCTexture;

			internal TextureHandle fullCoCTexture;

			internal TextureHandle pingTexture;

			internal TextureHandle pongTexture;

			internal RenderTargetIdentifier[] multipleRenderTargets = new RenderTargetIdentifier[2];

			internal TextureHandle destination;
		}

		private class DoFBokehPassData
		{
			internal Vector4[] bokehKernel;

			internal int downSample;

			internal float uvMargin;

			internal Vector4 cocParams;

			internal bool useFastSRGBLinearConversion;

			internal TextureHandle sourceTexture;

			internal TextureHandle depthTexture;

			internal Material material;

			internal Material materialCoC;

			internal TextureHandle halfCoCTexture;

			internal TextureHandle fullCoCTexture;

			internal TextureHandle pingTexture;

			internal TextureHandle pongTexture;

			internal TextureHandle destination;
		}

		private class PaniniProjectionPassData
		{
			internal TextureHandle destinationTexture;

			internal TextureHandle sourceTexture;

			internal Material material;

			internal Vector4 paniniParams;

			internal bool isPaniniGeneric;
		}

		private class MotionBlurPassData
		{
			internal TextureHandle sourceTexture;

			internal TextureHandle motionVectors;

			internal Material material;

			internal int passIndex;

			internal Camera camera;

			internal XRPass xr;

			internal float intensity;

			internal float clamp;

			internal bool enableAlphaOutput;
		}

		private class LensFlarePassData
		{
			internal TextureHandle destinationTexture;

			internal UniversalCameraData cameraData;

			internal Material material;

			internal Rect viewport;

			internal float paniniDistance;

			internal float paniniCropToFit;

			internal float width;

			internal float height;

			internal bool usePanini;
		}

		private class LensFlareScreenSpacePassData
		{
			internal TextureHandle streakTmpTexture;

			internal TextureHandle streakTmpTexture2;

			internal TextureHandle originalBloomTexture;

			internal TextureHandle screenSpaceLensFlareBloomMipTexture;

			internal TextureHandle result;

			internal int actualWidth;

			internal int actualHeight;

			internal Camera camera;

			internal Material material;

			internal ScreenSpaceLensFlare lensFlareScreenSpace;

			internal int downsample;
		}

		private class PostProcessingFinalSetupPassData
		{
			internal TextureHandle destinationTexture;

			internal TextureHandle sourceTexture;

			internal Material material;

			internal UniversalCameraData cameraData;
		}

		private class PostProcessingFinalFSRScalePassData
		{
			internal TextureHandle sourceTexture;

			internal Material material;

			internal bool enableAlphaOutput;

			internal Vector2 fsrInputSize;

			internal Vector2 fsrOutputSize;
		}

		private class PostProcessingFinalBlitPassData
		{
			internal TextureHandle destinationTexture;

			internal TextureHandle sourceTexture;

			internal Material material;

			internal UniversalCameraData cameraData;

			internal FinalBlitSettings settings;
		}

		public struct FinalBlitSettings
		{
			public bool isFxaaEnabled;

			public bool isFsrEnabled;

			public bool isTaaSharpeningEnabled;

			public bool requireHDROutput;

			public bool isAlphaOutputEnabled;

			public HDROutputUtils.Operation hdrOperations;

			public static FinalBlitSettings Create()
			{
				return new FinalBlitSettings
				{
					isFxaaEnabled = false,
					isFsrEnabled = false,
					isTaaSharpeningEnabled = false,
					requireHDROutput = false,
					isAlphaOutputEnabled = false,
					hdrOperations = HDROutputUtils.Operation.None
				};
			}
		}

		private class UberPostPassData
		{
			internal TextureHandle destinationTexture;

			internal TextureHandle sourceTexture;

			internal TextureHandle lutTexture;

			internal TextureHandle bloomTexture;

			internal Vector4 lutParams;

			internal TextureHandle userLutTexture;

			internal Vector4 userLutParams;

			internal Material material;

			internal UniversalCameraData cameraData;

			internal TonemappingMode toneMappingMode;

			internal bool isHdrGrading;

			internal bool isBackbuffer;

			internal bool enableAlphaOutput;

			internal bool hasFinalPass;
		}

		private class PostFXSetupPassData
		{
		}

		private PostProcessMaterialLibrary m_Materials;

		private DepthOfField m_DepthOfField;

		private MotionBlur m_MotionBlur;

		private PaniniProjection m_PaniniProjection;

		private Bloom m_Bloom;

		private ScreenSpaceLensFlare m_LensFlareScreenSpace;

		private LensDistortion m_LensDistortion;

		private ChromaticAberration m_ChromaticAberration;

		private Vignette m_Vignette;

		private ColorLookup m_ColorLookup;

		private ColorAdjustments m_ColorAdjustments;

		private Tonemapping m_Tonemapping;

		private FilmGrain m_FilmGrain;

		private string[] m_BloomMipDownName;

		private string[] m_BloomMipUpName;

		private TextureHandle[] _BloomMipUp;

		private TextureHandle[] _BloomMipDown;

		private RTHandle m_UserLut;

		private RTHandle m_InternalLut;

		private readonly GraphicsFormat m_SMAAEdgeFormat;

		private readonly GraphicsFormat m_BloomColorFormat;

		private BloomMaterialParams m_BloomParamsPrev;

		private readonly GraphicsFormat m_GaussianCoCFormat;

		private readonly GraphicsFormat m_GaussianDoFColorFormat;

		private Vector4[] m_BokehKernel;

		private int m_BokehHash;

		private float m_BokehMaxRadius;

		private float m_BokehRCPAspect;

		private readonly GraphicsFormat m_LensFlareScreenSpaceColorFormat;

		private int m_DitheringTextureIndex;

		private bool m_HasFinalPass;

		private bool m_EnableColorEncodingIfNeeded;

		private bool m_UseFastSRGBLinearConversion;

		private bool m_SupportScreenSpaceLensFlare;

		private bool m_SupportDataDrivenLensFlare;

		private const string _TemporalAATargetName = "_TemporalAATarget";

		private const string _UpscaledColorTargetName = "_CameraColorUpscaledSTP";

		public PostProcessPassRenderGraph(PostProcessData data, GraphicsFormat requestPostProColorFormat)
		{
			m_Materials = new PostProcessMaterialLibrary(data);
			m_BloomMipDownName = new string[16];
			m_BloomMipUpName = new string[16];
			for (int i = 0; i < 16; i++)
			{
				m_BloomMipUpName[i] = "_BloomMipUp" + i;
				m_BloomMipDownName[i] = "_BloomMipDown" + i;
			}
			_BloomMipUp = new TextureHandle[16];
			_BloomMipDown = new TextureHandle[16];
			bool num = IsHDRFormat(requestPostProColorFormat);
			GraphicsFormat graphicsFormat = GraphicsFormat.None;
			graphicsFormat = (m_BloomColorFormat = ((!num) ? ((QualitySettings.activeColorSpace == ColorSpace.Linear) ? GraphicsFormat.R8G8B8A8_SRGB : GraphicsFormat.R8G8B8A8_UNorm) : (SystemInfo.IsFormatSupported(requestPostProColorFormat, GraphicsFormatUsage.Blend) ? requestPostProColorFormat : ((!SystemInfo.IsFormatSupported(GraphicsFormat.B10G11R11_UFloatPack32, GraphicsFormatUsage.Blend)) ? ((QualitySettings.activeColorSpace == ColorSpace.Linear) ? GraphicsFormat.R8G8B8A8_SRGB : GraphicsFormat.R8G8B8A8_UNorm) : GraphicsFormat.B10G11R11_UFloatPack32))));
			if (SystemInfo.IsFormatSupported(GraphicsFormat.R8G8_UNorm, GraphicsFormatUsage.Render) && SystemInfo.graphicsDeviceVendor.ToLowerInvariant().Contains("arm"))
			{
				m_SMAAEdgeFormat = GraphicsFormat.R8G8_UNorm;
			}
			else
			{
				m_SMAAEdgeFormat = GraphicsFormat.R8G8B8A8_UNorm;
			}
			if (SystemInfo.IsFormatSupported(GraphicsFormat.R16_UNorm, GraphicsFormatUsage.Blend))
			{
				m_GaussianCoCFormat = GraphicsFormat.R16_UNorm;
			}
			else if (SystemInfo.IsFormatSupported(GraphicsFormat.R16_SFloat, GraphicsFormatUsage.Blend))
			{
				m_GaussianCoCFormat = GraphicsFormat.R16_SFloat;
			}
			else
			{
				m_GaussianCoCFormat = GraphicsFormat.R8_UNorm;
			}
			m_GaussianDoFColorFormat = graphicsFormat;
			m_LensFlareScreenSpaceColorFormat = graphicsFormat;
		}

		public void Cleanup()
		{
			m_Materials.Cleanup();
			Dispose();
		}

		public void Dispose()
		{
			m_UserLut?.Release();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static bool IsHDRFormat(GraphicsFormat format)
		{
			if (format != GraphicsFormat.B10G11R11_UFloatPack32 && !GraphicsFormatUtility.IsHalfFormat(format))
			{
				return GraphicsFormatUtility.IsFloatFormat(format);
			}
			return true;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static bool IsAlphaFormat(GraphicsFormat format)
		{
			return GraphicsFormatUtility.HasAlphaChannel(format);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private bool RequireSRGBConversionBlitToBackBuffer(bool requireSrgbConversion)
		{
			if (requireSrgbConversion)
			{
				return m_EnableColorEncodingIfNeeded;
			}
			return false;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static bool RequireHDROutput(UniversalCameraData cameraData)
		{
			if (cameraData.isHDROutputActive)
			{
				return cameraData.captureActions == null;
			}
			return false;
		}

		private void UpdateCameraResolution(RenderGraph renderGraph, UniversalCameraData cameraData, Vector2Int newCameraTargetSize)
		{
			cameraData.cameraTargetDescriptor.width = newCameraTargetSize.x;
			cameraData.cameraTargetDescriptor.height = newCameraTargetSize.y;
			UpdateCameraResolutionPassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<UpdateCameraResolutionPassData>("Update Camera Resolution", out passData, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 320);
			passData.newCameraTargetSize = newCameraTargetSize;
			unsafeRenderGraphBuilder.AllowGlobalStateModification(value: true);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(UpdateCameraResolutionPassData data, UnsafeGraphContext ctx)
			{
				ctx.cmd.SetGlobalVector(ShaderPropertyId.screenSize, new Vector4(data.newCameraTargetSize.x, data.newCameraTargetSize.y, 1f / (float)data.newCameraTargetSize.x, 1f / (float)data.newCameraTargetSize.y));
			});
		}

		internal static TextureHandle CreateCompatibleTexture(RenderGraph renderGraph, in TextureHandle source, string name, bool clear, FilterMode filterMode)
		{
			TextureDesc desc = source.GetDescriptor(renderGraph);
			MakeCompatible(ref desc);
			desc.name = name;
			desc.clearBuffer = clear;
			desc.filterMode = filterMode;
			return renderGraph.CreateTexture(in desc);
		}

		internal static TextureHandle CreateCompatibleTexture(RenderGraph renderGraph, in TextureDesc desc, string name, bool clear, FilterMode filterMode)
		{
			TextureDesc desc2 = GetCompatibleDescriptor(desc);
			desc2.name = name;
			desc2.clearBuffer = clear;
			desc2.filterMode = filterMode;
			return renderGraph.CreateTexture(in desc2);
		}

		internal static TextureDesc GetCompatibleDescriptor(TextureDesc desc, int width, int height, GraphicsFormat format)
		{
			desc.width = width;
			desc.height = height;
			desc.format = format;
			MakeCompatible(ref desc);
			return desc;
		}

		internal static TextureDesc GetCompatibleDescriptor(TextureDesc desc)
		{
			MakeCompatible(ref desc);
			return desc;
		}

		internal static void MakeCompatible(ref TextureDesc desc)
		{
			desc.msaaSamples = MSAASamples.None;
			desc.useMipMap = false;
			desc.autoGenerateMips = false;
			desc.anisoLevel = 0;
			desc.discardBuffer = false;
		}

		internal static RenderTextureDescriptor GetCompatibleDescriptor(RenderTextureDescriptor desc, int width, int height, GraphicsFormat format, GraphicsFormat depthStencilFormat = GraphicsFormat.None)
		{
			desc.depthStencilFormat = depthStencilFormat;
			desc.msaaSamples = 1;
			desc.width = width;
			desc.height = height;
			desc.graphicsFormat = format;
			return desc;
		}

		public void RenderStopNaN(RenderGraph renderGraph, in TextureHandle activeCameraColor, out TextureHandle stopNaNTarget)
		{
			stopNaNTarget = CreateCompatibleTexture(renderGraph, in activeCameraColor, "_StopNaNsTarget", clear: true, FilterMode.Bilinear);
			StopNaNsPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<StopNaNsPassData>("Stop NaNs", out passData, ProfilingSampler.Get(URPProfileId.RG_StopNaNs), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 409);
			rasterRenderGraphBuilder.SetRenderAttachment(stopNaNTarget, 0, AccessFlags.ReadWrite);
			passData.sourceTexture = activeCameraColor;
			rasterRenderGraphBuilder.UseTexture(in activeCameraColor);
			passData.stopNaN = m_Materials.stopNaN;
			rasterRenderGraphBuilder.SetRenderFunc(delegate(StopNaNsPassData data, RasterGraphContext context)
			{
				RasterCommandBuffer cmd = context.cmd;
				RTHandle rTHandle = data.sourceTexture;
				Vector2 vector = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
				Blitter.BlitTexture(cmd, rTHandle, vector, data.stopNaN, 0);
			});
		}

		public void RenderSMAA(RenderGraph renderGraph, UniversalResourceData resourceData, AntialiasingQuality antialiasingQuality, in TextureHandle source, out TextureHandle SMAATarget)
		{
			TextureDesc desc = renderGraph.GetTextureDesc(in source);
			SMAATarget = CreateCompatibleTexture(renderGraph, in desc, "_SMAATarget", clear: true, FilterMode.Bilinear);
			desc.clearColor = Color.black;
			desc.clearColor.a = 0f;
			TextureDesc desc2 = desc;
			desc2.format = m_SMAAEdgeFormat;
			TextureHandle input = CreateCompatibleTexture(renderGraph, in desc2, "_EdgeStencilTexture", clear: true, FilterMode.Bilinear);
			TextureDesc desc3 = desc;
			desc3.format = GraphicsFormatUtility.GetDepthStencilFormat(24);
			TextureHandle tex = CreateCompatibleTexture(renderGraph, in desc3, "_EdgeTexture", clear: true, FilterMode.Bilinear);
			TextureDesc desc4 = desc;
			desc4.format = GraphicsFormat.R8G8B8A8_UNorm;
			TextureHandle input2 = CreateCompatibleTexture(renderGraph, in desc4, "_BlendTexture", clear: true, FilterMode.Point);
			Material subpixelMorphologicalAntialiasing = m_Materials.subpixelMorphologicalAntialiasing;
			SMAASetupPassData passData;
			using (IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<SMAASetupPassData>("SMAA Material Setup", out passData, ProfilingSampler.Get(URPProfileId.RG_SMAAMaterialSetup), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 470))
			{
				passData.metrics = new Vector4(1f / (float)desc.width, 1f / (float)desc.height, desc.width, desc.height);
				passData.areaTexture = m_Materials.resources.textures.smaaAreaTex;
				passData.searchTexture = m_Materials.resources.textures.smaaSearchTex;
				passData.stencilRef = 64f;
				passData.stencilMask = 64f;
				passData.antialiasingQuality = antialiasingQuality;
				passData.material = subpixelMorphologicalAntialiasing;
				rasterRenderGraphBuilder.AllowPassCulling(value: false);
				rasterRenderGraphBuilder.SetRenderFunc(delegate(SMAASetupPassData data, RasterGraphContext context)
				{
					data.material.SetVector(ShaderConstants._Metrics, data.metrics);
					data.material.SetTexture(ShaderConstants._AreaTexture, data.areaTexture);
					data.material.SetTexture(ShaderConstants._SearchTexture, data.searchTexture);
					data.material.SetFloat(ShaderConstants._StencilRef, data.stencilRef);
					data.material.SetFloat(ShaderConstants._StencilMask, data.stencilMask);
					data.material.shaderKeywords = null;
					switch (data.antialiasingQuality)
					{
					case AntialiasingQuality.Low:
						data.material.EnableKeyword("_SMAA_PRESET_LOW");
						break;
					case AntialiasingQuality.Medium:
						data.material.EnableKeyword("_SMAA_PRESET_MEDIUM");
						break;
					case AntialiasingQuality.High:
						data.material.EnableKeyword("_SMAA_PRESET_HIGH");
						break;
					}
				});
			}
			SMAAPassData passData2;
			using (IRasterRenderGraphBuilder rasterRenderGraphBuilder2 = renderGraph.AddRasterRenderPass<SMAAPassData>("SMAA Edge Detection", out passData2, ProfilingSampler.Get(URPProfileId.RG_SMAAEdgeDetection), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 511))
			{
				rasterRenderGraphBuilder2.SetRenderAttachment(input, 0);
				rasterRenderGraphBuilder2.SetRenderAttachmentDepth(tex);
				passData2.sourceTexture = source;
				rasterRenderGraphBuilder2.UseTexture(in source);
				rasterRenderGraphBuilder2.UseTexture(resourceData.cameraDepth);
				passData2.material = subpixelMorphologicalAntialiasing;
				rasterRenderGraphBuilder2.SetRenderFunc(delegate(SMAAPassData data, RasterGraphContext context)
				{
					Material material = data.material;
					RasterCommandBuffer cmd = context.cmd;
					RTHandle rTHandle = data.sourceTexture;
					Vector2 vector = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
					Blitter.BlitTexture(cmd, rTHandle, vector, material, 0);
				});
			}
			SMAAPassData passData3;
			using (IRasterRenderGraphBuilder rasterRenderGraphBuilder3 = renderGraph.AddRasterRenderPass<SMAAPassData>("SMAA Blend weights", out passData3, ProfilingSampler.Get(URPProfileId.RG_SMAABlendWeight), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 532))
			{
				rasterRenderGraphBuilder3.SetRenderAttachment(input2, 0);
				rasterRenderGraphBuilder3.SetRenderAttachmentDepth(tex, AccessFlags.Read);
				passData3.sourceTexture = input;
				rasterRenderGraphBuilder3.UseTexture(in input);
				passData3.material = subpixelMorphologicalAntialiasing;
				rasterRenderGraphBuilder3.SetRenderFunc(delegate(SMAAPassData data, RasterGraphContext context)
				{
					Material material = data.material;
					RasterCommandBuffer cmd = context.cmd;
					RTHandle rTHandle = data.sourceTexture;
					Vector2 vector = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
					Blitter.BlitTexture(cmd, rTHandle, vector, material, 1);
				});
			}
			SMAAPassData passData4;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder4 = renderGraph.AddRasterRenderPass<SMAAPassData>("SMAA Neighborhood blending", out passData4, ProfilingSampler.Get(URPProfileId.RG_SMAANeighborhoodBlend), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 552);
			rasterRenderGraphBuilder4.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder4.SetRenderAttachment(SMAATarget, 0);
			passData4.sourceTexture = source;
			rasterRenderGraphBuilder4.UseTexture(in source);
			passData4.blendTexture = input2;
			rasterRenderGraphBuilder4.UseTexture(in input2);
			passData4.material = subpixelMorphologicalAntialiasing;
			rasterRenderGraphBuilder4.SetRenderFunc(delegate(SMAAPassData data, RasterGraphContext context)
			{
				Material material = data.material;
				RasterCommandBuffer cmd = context.cmd;
				RTHandle rTHandle = data.sourceTexture;
				material.SetTexture(ShaderConstants._BlendTexture, data.blendTexture);
				Vector2 vector = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
				Blitter.BlitTexture(cmd, rTHandle, vector, material, 2);
			});
		}

		public void UberPostSetupBloomPass(RenderGraph rendergraph, Material uberMaterial, in TextureDesc srcDesc)
		{
			using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_UberPostSetupBloomPass)))
			{
				Color color = m_Bloom.tint.value.linear;
				float num = ColorUtils.Luminance(in color);
				color = ((num > 0f) ? (color * (1f / num)) : Color.white);
				Vector4 value = new Vector4(m_Bloom.intensity.value, color.r, color.g, color.b);
				Texture texture = ((m_Bloom.dirtTexture.value == null) ? Texture2D.blackTexture : m_Bloom.dirtTexture.value);
				float num2 = (float)texture.width / (float)texture.height;
				float num3 = (float)srcDesc.width / (float)srcDesc.height;
				Vector4 value2 = new Vector4(1f, 1f, 0f, 0f);
				float value3 = m_Bloom.dirtIntensity.value;
				if (num2 > num3)
				{
					value2.x = num3 / num2;
					value2.z = (1f - value2.x) * 0.5f;
				}
				else if (num3 > num2)
				{
					value2.y = num2 / num3;
					value2.w = (1f - value2.y) * 0.5f;
				}
				bool value4 = m_Bloom.highQualityFiltering.value;
				uberMaterial.SetVector(ShaderConstants._Bloom_Params, value);
				uberMaterial.SetVector(ShaderConstants._LensDirt_Params, value2);
				uberMaterial.SetFloat(ShaderConstants._LensDirt_Intensity, value3);
				uberMaterial.SetTexture(ShaderConstants._LensDirt_Texture, texture);
				if (value4)
				{
					uberMaterial.EnableKeyword((value3 > 0f) ? "_BLOOM_HQ_DIRT" : "_BLOOM_HQ");
				}
				else
				{
					uberMaterial.EnableKeyword((value3 > 0f) ? "_BLOOM_LQ_DIRT" : "_BLOOM_LQ");
				}
			}
		}

		public Vector2Int CalcBloomResolution(Bloom bloom, in TextureDesc bloomSourceDesc)
		{
			int num = 1;
			num = m_Bloom.downscale.value switch
			{
				BloomDownscaleMode.Half => 1, 
				BloomDownscaleMode.Quarter => 2, 
				_ => throw new ArgumentOutOfRangeException(), 
			};
			int x = Mathf.Max(1, bloomSourceDesc.width >> num);
			int y = Mathf.Max(1, bloomSourceDesc.height >> num);
			return new Vector2Int(x, y);
		}

		public int CalcBloomMipCount(Bloom bloom, Vector2Int bloomResolution)
		{
			return Mathf.Clamp(Mathf.FloorToInt(Mathf.Log(Mathf.Max(bloomResolution.x, bloomResolution.y), 2f) - 1f), 1, m_Bloom.maxIterations.value);
		}

		public void RenderBloomTexture(RenderGraph renderGraph, in TextureHandle source, out TextureHandle destination, bool enableAlphaOutput)
		{
			TextureDesc bloomSourceDesc = source.GetDescriptor(renderGraph);
			Vector2Int bloomResolution = CalcBloomResolution(m_Bloom, in bloomSourceDesc);
			int num = CalcBloomMipCount(m_Bloom, bloomResolution);
			int num2 = bloomResolution.x;
			int num3 = bloomResolution.y;
			using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_BloomSetup)))
			{
				float value = m_Bloom.clamp.value;
				float num4 = Mathf.GammaToLinearSpace(m_Bloom.threshold.value);
				float w = num4 * 0.5f;
				float x = Mathf.Lerp(0.05f, 0.95f, m_Bloom.scatter.value);
				float y = Mathf.Clamp01(m_Bloom.scatter.value);
				float num5 = Mathf.Lerp(0.3f, 1.3f, m_Bloom.scatter.value);
				BloomMaterialParams other = new BloomMaterialParams
				{
					parameters = new Vector4(x, value, num4, w),
					parameters2 = new Vector4(0.5f, y, num5, 0.5f * num5),
					bloomFilter = m_Bloom.filter.value,
					highQualityFiltering = m_Bloom.highQualityFiltering.value,
					enableAlphaOutput = enableAlphaOutput
				};
				Material bloom = m_Materials.bloom;
				bool num6 = !m_BloomParamsPrev.Equals(ref other);
				bool flag = bloom.HasProperty(ShaderConstants._Params);
				if (num6 || !flag)
				{
					bloom.SetVector(ShaderConstants._Params, other.parameters);
					bloom.SetVector(ShaderConstants._Params2, other.parameters2);
					CoreUtils.SetKeyword(bloom, "_BLOOM_HQ", other.highQualityFiltering);
					CoreUtils.SetKeyword(bloom, "_ENABLE_ALPHA_OUTPUT", other.enableAlphaOutput);
					for (uint num7 = 0u; num7 < 16; num7++)
					{
						Material obj = m_Materials.bloomUpsample[num7];
						obj.SetVector(ShaderConstants._Params, other.parameters);
						CoreUtils.SetKeyword(obj, "_BLOOM_HQ", other.highQualityFiltering);
						CoreUtils.SetKeyword(obj, "_ENABLE_ALPHA_OUTPUT", other.enableAlphaOutput);
						float x2 = 0.5f + (float)((num7 > num / 2) ? (num7 - 1) : num7);
						Vector4 parameters = other.parameters2;
						parameters.x = x2;
						obj.SetVector(ShaderConstants._Params2, parameters);
					}
					m_BloomParamsPrev = other;
				}
				TextureDesc desc = GetCompatibleDescriptor(bloomSourceDesc, num2, num3, m_BloomColorFormat);
				_BloomMipDown[0] = CreateCompatibleTexture(renderGraph, in desc, m_BloomMipDownName[0], clear: false, FilterMode.Bilinear);
				_BloomMipUp[0] = CreateCompatibleTexture(renderGraph, in desc, m_BloomMipUpName[0], clear: false, FilterMode.Bilinear);
				if (other.bloomFilter != BloomFilterMode.Kawase)
				{
					for (int i = 1; i < num; i++)
					{
						num2 = Mathf.Max(1, num2 >> 1);
						num3 = Mathf.Max(1, num3 >> 1);
						ref TextureHandle reference = ref _BloomMipDown[i];
						ref TextureHandle reference2 = ref _BloomMipUp[i];
						desc.width = num2;
						desc.height = num3;
						reference = CreateCompatibleTexture(renderGraph, in desc, m_BloomMipDownName[i], clear: false, FilterMode.Bilinear);
						reference2 = CreateCompatibleTexture(renderGraph, in desc, m_BloomMipUpName[i], clear: false, FilterMode.Bilinear);
					}
				}
			}
			switch (m_Bloom.filter.value)
			{
			case BloomFilterMode.Dual:
				destination = BloomDual(renderGraph, source, num);
				break;
			case BloomFilterMode.Kawase:
				destination = BloomKawase(renderGraph, source, num);
				break;
			default:
				destination = BloomGaussian(renderGraph, source, num);
				break;
			}
		}

		private TextureHandle BloomGaussian(RenderGraph renderGraph, TextureHandle source, int mipCount)
		{
			BloomPassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<BloomPassData>("Blit Bloom Mipmaps", out passData, ProfilingSampler.Get(URPProfileId.Bloom), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 803);
			passData.mipCount = mipCount;
			passData.material = m_Materials.bloom;
			passData.upsampleMaterials = m_Materials.bloomUpsample;
			passData.sourceTexture = source;
			passData.bloomMipDown = _BloomMipDown;
			passData.bloomMipUp = _BloomMipUp;
			unsafeRenderGraphBuilder.AllowPassCulling(value: false);
			unsafeRenderGraphBuilder.UseTexture(in source);
			for (int i = 0; i < mipCount; i++)
			{
				unsafeRenderGraphBuilder.UseTexture(in _BloomMipDown[i], AccessFlags.ReadWrite);
				unsafeRenderGraphBuilder.UseTexture(in _BloomMipUp[i], AccessFlags.ReadWrite);
			}
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(BloomPassData data, UnsafeGraphContext context)
			{
				CommandBuffer nativeCommandBuffer = CommandBufferHelpers.GetNativeCommandBuffer(context.cmd);
				Material material = data.material;
				int mipCount2 = data.mipCount;
				RenderBufferLoadAction loadAction = RenderBufferLoadAction.DontCare;
				RenderBufferStoreAction storeAction = RenderBufferStoreAction.Store;
				using (new ProfilingScope(nativeCommandBuffer, ProfilingSampler.Get(URPProfileId.RG_BloomPrefilter)))
				{
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.sourceTexture, data.bloomMipDown[0], loadAction, storeAction, material, 0);
				}
				using (new ProfilingScope(nativeCommandBuffer, ProfilingSampler.Get(URPProfileId.RG_BloomDownsample)))
				{
					TextureHandle textureHandle = data.bloomMipDown[0];
					for (int j = 1; j < mipCount2; j++)
					{
						TextureHandle textureHandle2 = data.bloomMipDown[j];
						TextureHandle textureHandle3 = data.bloomMipUp[j];
						Blitter.BlitCameraTexture(nativeCommandBuffer, textureHandle, textureHandle3, loadAction, storeAction, material, 1);
						Blitter.BlitCameraTexture(nativeCommandBuffer, textureHandle3, textureHandle2, loadAction, storeAction, material, 2);
						textureHandle = textureHandle2;
					}
				}
				using (new ProfilingScope(nativeCommandBuffer, ProfilingSampler.Get(URPProfileId.RG_BloomUpsample)))
				{
					for (int num = mipCount2 - 2; num >= 0; num--)
					{
						TextureHandle textureHandle4 = ((num == mipCount2 - 2) ? data.bloomMipDown[num + 1] : data.bloomMipUp[num + 1]);
						TextureHandle textureHandle5 = data.bloomMipDown[num];
						TextureHandle textureHandle6 = data.bloomMipUp[num];
						Material material2 = data.upsampleMaterials[num];
						material2.SetTexture(ShaderConstants._SourceTexLowMip, textureHandle4);
						Blitter.BlitCameraTexture(nativeCommandBuffer, textureHandle5, textureHandle6, loadAction, storeAction, material2, 3);
					}
				}
			});
			return (mipCount == 1) ? passData.bloomMipDown[0] : passData.bloomMipUp[0];
		}

		private TextureHandle BloomKawase(RenderGraph renderGraph, TextureHandle source, int mipCount)
		{
			BloomPassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<BloomPassData>("Blit Bloom Mipmaps (Kawase)", out passData, ProfilingSampler.Get(URPProfileId.Bloom), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 886);
			passData.mipCount = mipCount;
			passData.material = m_Materials.bloom;
			passData.upsampleMaterials = m_Materials.bloomUpsample;
			passData.sourceTexture = source;
			passData.bloomMipDown = _BloomMipDown;
			passData.bloomMipUp = _BloomMipUp;
			unsafeRenderGraphBuilder.AllowPassCulling(value: false);
			unsafeRenderGraphBuilder.UseTexture(in source);
			unsafeRenderGraphBuilder.UseTexture(in _BloomMipDown[0], AccessFlags.ReadWrite);
			unsafeRenderGraphBuilder.UseTexture(in _BloomMipUp[0], AccessFlags.ReadWrite);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(BloomPassData data, UnsafeGraphContext context)
			{
				CommandBuffer nativeCommandBuffer = CommandBufferHelpers.GetNativeCommandBuffer(context.cmd);
				Material material = data.material;
				int mipCount2 = data.mipCount;
				RenderBufferLoadAction loadAction = RenderBufferLoadAction.DontCare;
				RenderBufferStoreAction storeAction = RenderBufferStoreAction.Store;
				using (new ProfilingScope(nativeCommandBuffer, ProfilingSampler.Get(URPProfileId.RG_BloomPrefilter)))
				{
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.sourceTexture, data.bloomMipDown[0], loadAction, storeAction, material, 0);
				}
				using (new ProfilingScope(nativeCommandBuffer, ProfilingSampler.Get(URPProfileId.RG_BloomDownsample)))
				{
					for (int i = 0; i < mipCount2; i++)
					{
						TextureHandle textureHandle = (((i & 1) == 0) ? data.bloomMipDown[0] : data.bloomMipUp[0]);
						TextureHandle textureHandle2 = (((i & 1) == 0) ? data.bloomMipUp[0] : data.bloomMipDown[0]);
						Material material2 = data.upsampleMaterials[i];
						Blitter.BlitCameraTexture(nativeCommandBuffer, textureHandle, textureHandle2, loadAction, storeAction, material2, 4);
					}
				}
			});
			return (((mipCount - 1) & 1) == 0) ? _BloomMipUp[0] : _BloomMipDown[0];
		}

		private TextureHandle BloomDual(RenderGraph renderGraph, TextureHandle source, int mipCount)
		{
			BloomPassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<BloomPassData>("Blit Bloom Mipmaps (Dual)", out passData, ProfilingSampler.Get(URPProfileId.Bloom), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 939);
			passData.mipCount = mipCount;
			passData.material = m_Materials.bloom;
			passData.upsampleMaterials = m_Materials.bloomUpsample;
			passData.sourceTexture = source;
			passData.bloomMipDown = _BloomMipDown;
			passData.bloomMipUp = _BloomMipUp;
			unsafeRenderGraphBuilder.AllowPassCulling(value: false);
			unsafeRenderGraphBuilder.UseTexture(in source);
			for (int i = 0; i < mipCount; i++)
			{
				unsafeRenderGraphBuilder.UseTexture(in _BloomMipDown[i], AccessFlags.ReadWrite);
				unsafeRenderGraphBuilder.UseTexture(in _BloomMipUp[i], AccessFlags.ReadWrite);
			}
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(BloomPassData data, UnsafeGraphContext context)
			{
				CommandBuffer nativeCommandBuffer = CommandBufferHelpers.GetNativeCommandBuffer(context.cmd);
				Material material = data.material;
				int mipCount2 = data.mipCount;
				RenderBufferLoadAction loadAction = RenderBufferLoadAction.DontCare;
				RenderBufferStoreAction storeAction = RenderBufferStoreAction.Store;
				using (new ProfilingScope(nativeCommandBuffer, ProfilingSampler.Get(URPProfileId.RG_BloomPrefilter)))
				{
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.sourceTexture, data.bloomMipDown[0], loadAction, storeAction, material, 0);
				}
				using (new ProfilingScope(nativeCommandBuffer, ProfilingSampler.Get(URPProfileId.RG_BloomDownsample)))
				{
					_ = ref data.bloomMipDown[0];
					for (int j = 1; j < mipCount2; j++)
					{
						TextureHandle textureHandle = data.bloomMipDown[j - 1];
						TextureHandle textureHandle2 = data.bloomMipDown[j];
						Blitter.BlitCameraTexture(nativeCommandBuffer, textureHandle, textureHandle2, loadAction, storeAction, material, 5);
					}
				}
				using (new ProfilingScope(nativeCommandBuffer, ProfilingSampler.Get(URPProfileId.RG_BloomUpsample)))
				{
					for (int num = mipCount2 - 2; num >= 0; num--)
					{
						TextureHandle textureHandle3 = ((num == mipCount2 - 2) ? data.bloomMipDown[num + 1] : data.bloomMipUp[num + 1]);
						TextureHandle textureHandle4 = data.bloomMipUp[num];
						Blitter.BlitCameraTexture(nativeCommandBuffer, textureHandle3, textureHandle4, loadAction, storeAction, material, 6);
					}
				}
			});
			return (mipCount == 1) ? passData.bloomMipDown[0] : passData.bloomMipUp[0];
		}

		public void RenderDoF(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, in TextureHandle source, out TextureHandle destination)
		{
			Material dofMaterial = ((m_DepthOfField.mode.value == DepthOfFieldMode.Gaussian) ? m_Materials.gaussianDepthOfField : m_Materials.bokehDepthOfField);
			destination = CreateCompatibleTexture(renderGraph, in source, "_DoFTarget", clear: true, FilterMode.Bilinear);
			CoreUtils.SetKeyword(dofMaterial, "_ENABLE_ALPHA_OUTPUT", cameraData.isAlphaOutputEnabled);
			if (m_DepthOfField.mode.value == DepthOfFieldMode.Gaussian)
			{
				RenderDoFGaussian(renderGraph, resourceData, cameraData, in source, destination, ref dofMaterial);
			}
			else if (m_DepthOfField.mode.value == DepthOfFieldMode.Bokeh)
			{
				RenderDoFBokeh(renderGraph, resourceData, cameraData, in source, in destination, ref dofMaterial);
			}
		}

		public void RenderDoFGaussian(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, in TextureHandle source, TextureHandle destination, ref Material dofMaterial)
		{
			TextureDesc descriptor = source.GetDescriptor(renderGraph);
			Material material = dofMaterial;
			int num = 2;
			int num2 = descriptor.width / num;
			int height = descriptor.height / num;
			TextureHandle input = CreateCompatibleTexture(renderGraph, GetCompatibleDescriptor(descriptor, descriptor.width, descriptor.height, m_GaussianCoCFormat), "_FullCoCTexture", clear: true, FilterMode.Bilinear);
			TextureHandle input2 = CreateCompatibleTexture(renderGraph, GetCompatibleDescriptor(descriptor, num2, height, m_GaussianCoCFormat), "_HalfCoCTexture", clear: true, FilterMode.Bilinear);
			TextureHandle input3 = CreateCompatibleTexture(renderGraph, GetCompatibleDescriptor(descriptor, num2, height, m_GaussianDoFColorFormat), "_PingTexture", clear: true, FilterMode.Bilinear);
			TextureHandle input4 = CreateCompatibleTexture(renderGraph, GetCompatibleDescriptor(descriptor, num2, height, m_GaussianDoFColorFormat), "_PongTexture", clear: true, FilterMode.Bilinear);
			DoFGaussianPassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<DoFGaussianPassData>("Depth of Field - Gaussian", out passData, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 1066);
			float value = m_DepthOfField.gaussianStart.value;
			float y = Mathf.Max(value, m_DepthOfField.gaussianEnd.value);
			float a = m_DepthOfField.gaussianMaxRadius.value * ((float)num2 / 1080f);
			a = Mathf.Min(a, 2f);
			passData.downsample = num;
			passData.cocParams = new Vector3(value, y, a);
			passData.highQualitySamplingValue = m_DepthOfField.highQualitySampling.value;
			passData.material = material;
			passData.materialCoC = m_Materials.gaussianDepthOfFieldCoC;
			passData.sourceTexture = source;
			unsafeRenderGraphBuilder.UseTexture(in source);
			passData.depthTexture = resourceData.cameraDepthTexture;
			unsafeRenderGraphBuilder.UseTexture(resourceData.cameraDepthTexture);
			passData.fullCoCTexture = input;
			unsafeRenderGraphBuilder.UseTexture(in input, AccessFlags.ReadWrite);
			passData.halfCoCTexture = input2;
			unsafeRenderGraphBuilder.UseTexture(in input2, AccessFlags.ReadWrite);
			passData.pingTexture = input3;
			unsafeRenderGraphBuilder.UseTexture(in input3, AccessFlags.ReadWrite);
			passData.pongTexture = input4;
			unsafeRenderGraphBuilder.UseTexture(in input4, AccessFlags.ReadWrite);
			passData.destination = destination;
			unsafeRenderGraphBuilder.UseTexture(in destination, AccessFlags.Write);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(DoFGaussianPassData data, UnsafeGraphContext context)
			{
				Material material2 = data.material;
				Material materialCoC = data.materialCoC;
				CommandBuffer nativeCommandBuffer = CommandBufferHelpers.GetNativeCommandBuffer(context.cmd);
				RTHandle rTHandle = data.sourceTexture;
				RTHandle destination2 = data.destination;
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_SetupDoF)))
				{
					material2.SetVector(ShaderConstants._CoCParams, data.cocParams);
					CoreUtils.SetKeyword(material2, "_HIGH_QUALITY_SAMPLING", data.highQualitySamplingValue);
					materialCoC.SetVector(ShaderConstants._CoCParams, data.cocParams);
					CoreUtils.SetKeyword(materialCoC, "_HIGH_QUALITY_SAMPLING", data.highQualitySamplingValue);
					PostProcessUtils.SetSourceSize(nativeCommandBuffer, data.sourceTexture);
					material2.SetVector(ShaderConstants._DownSampleScaleFactor, new Vector4(1f / (float)data.downsample, 1f / (float)data.downsample, data.downsample, data.downsample));
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFComputeCOC)))
				{
					material2.SetTexture(ShaderConstants._CameraDepthTextureID, data.depthTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.sourceTexture, data.fullCoCTexture, data.materialCoC, 0);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFDownscalePrefilter)))
				{
					material2.SetTexture(ShaderConstants._FullCoCTexture, data.fullCoCTexture);
					data.multipleRenderTargets[0] = data.halfCoCTexture;
					data.multipleRenderTargets[1] = data.pingTexture;
					CoreUtils.SetRenderTarget(nativeCommandBuffer, data.multipleRenderTargets, data.halfCoCTexture);
					Vector2 vector = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
					Blitter.BlitTexture(nativeCommandBuffer, data.sourceTexture, vector, material2, 1);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFBlurH)))
				{
					material2.SetTexture(ShaderConstants._HalfCoCTexture, data.halfCoCTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.pingTexture, data.pongTexture, material2, 2);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFBlurV)))
				{
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.pongTexture, data.pingTexture, material2, 3);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFComposite)))
				{
					material2.SetTexture(ShaderConstants._ColorTexture, data.pingTexture);
					material2.SetTexture(ShaderConstants._FullCoCTexture, data.fullCoCTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, rTHandle, destination2, material2, 4);
				}
			});
		}

		private void PrepareBokehKernel(float maxRadius, float rcpAspect)
		{
			if (m_BokehKernel == null)
			{
				m_BokehKernel = new Vector4[42];
			}
			int num = 0;
			float num2 = m_DepthOfField.bladeCount.value;
			float p = 1f - m_DepthOfField.bladeCurvature.value;
			float num3 = m_DepthOfField.bladeRotation.value * (MathF.PI / 180f);
			for (int i = 1; i < 4; i++)
			{
				float num4 = 1f / 7f;
				float num5 = ((float)i + num4) / (3f + num4);
				int num6 = i * 7;
				for (int j = 0; j < num6; j++)
				{
					float num7 = MathF.PI * 2f * (float)j / (float)num6;
					float num8 = Mathf.Cos(MathF.PI / num2);
					float num9 = Mathf.Cos(num7 - MathF.PI * 2f / num2 * Mathf.Floor((num2 * num7 + MathF.PI) / (MathF.PI * 2f)));
					float num10 = num5 * Mathf.Pow(num8 / num9, p);
					float num11 = num10 * Mathf.Cos(num7 - num3);
					float num12 = num10 * Mathf.Sin(num7 - num3);
					float num13 = num11 * maxRadius;
					float num14 = num12 * maxRadius;
					float num15 = num13 * num13;
					float num16 = num14 * num14;
					float z = Mathf.Sqrt(num15 + num16);
					float w = num13 * rcpAspect;
					m_BokehKernel[num] = new Vector4(num13, num14, z, w);
					num++;
				}
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static float GetMaxBokehRadiusInPixels(float viewportHeight)
		{
			return Mathf.Min(0.05f, 14f / viewportHeight);
		}

		public void RenderDoFBokeh(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, in TextureHandle source, in TextureHandle destination, ref Material dofMaterial)
		{
			TextureDesc descriptor = source.GetDescriptor(renderGraph);
			int num = 2;
			Material material = dofMaterial;
			int num2 = descriptor.width / num;
			int num3 = descriptor.height / num;
			TextureHandle input = CreateCompatibleTexture(renderGraph, GetCompatibleDescriptor(descriptor, descriptor.width, descriptor.height, GraphicsFormat.R8_UNorm), "_FullCoCTexture", clear: true, FilterMode.Bilinear);
			TextureHandle input2 = CreateCompatibleTexture(renderGraph, GetCompatibleDescriptor(descriptor, num2, num3, GraphicsFormat.R16G16B16A16_SFloat), "_PingTexture", clear: true, FilterMode.Bilinear);
			TextureHandle input3 = CreateCompatibleTexture(renderGraph, GetCompatibleDescriptor(descriptor, num2, num3, GraphicsFormat.R16G16B16A16_SFloat), "_PongTexture", clear: true, FilterMode.Bilinear);
			DoFBokehPassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<DoFBokehPassData>("Depth of Field - Bokeh", out passData, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 1278);
			float num4 = m_DepthOfField.focalLength.value / 1000f;
			float num5 = m_DepthOfField.focalLength.value / m_DepthOfField.aperture.value;
			float value = m_DepthOfField.focusDistance.value;
			float y = num5 * num4 / (value - num4);
			float maxBokehRadiusInPixels = GetMaxBokehRadiusInPixels(descriptor.height);
			float num6 = 1f / ((float)num2 / (float)num3);
			int hashCode = m_DepthOfField.GetHashCode();
			if (hashCode != m_BokehHash || maxBokehRadiusInPixels != m_BokehMaxRadius || num6 != m_BokehRCPAspect)
			{
				m_BokehHash = hashCode;
				m_BokehMaxRadius = maxBokehRadiusInPixels;
				m_BokehRCPAspect = num6;
				PrepareBokehKernel(maxBokehRadiusInPixels, num6);
			}
			float uvMargin = 1f / (float)descriptor.height * (float)num;
			passData.bokehKernel = m_BokehKernel;
			passData.downSample = num;
			passData.uvMargin = uvMargin;
			passData.cocParams = new Vector4(value, y, maxBokehRadiusInPixels, num6);
			passData.useFastSRGBLinearConversion = m_UseFastSRGBLinearConversion;
			passData.sourceTexture = source;
			unsafeRenderGraphBuilder.UseTexture(in source);
			passData.depthTexture = resourceData.cameraDepthTexture;
			unsafeRenderGraphBuilder.UseTexture(resourceData.cameraDepthTexture);
			passData.material = material;
			passData.materialCoC = m_Materials.bokehDepthOfFieldCoC;
			passData.fullCoCTexture = input;
			unsafeRenderGraphBuilder.UseTexture(in input, AccessFlags.ReadWrite);
			passData.pingTexture = input2;
			unsafeRenderGraphBuilder.UseTexture(in input2, AccessFlags.ReadWrite);
			passData.pongTexture = input3;
			unsafeRenderGraphBuilder.UseTexture(in input3, AccessFlags.ReadWrite);
			passData.destination = destination;
			unsafeRenderGraphBuilder.UseTexture(in destination, AccessFlags.Write);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(DoFBokehPassData data, UnsafeGraphContext context)
			{
				Material material2 = data.material;
				Material materialCoC = data.materialCoC;
				CommandBuffer nativeCommandBuffer = CommandBufferHelpers.GetNativeCommandBuffer(context.cmd);
				RTHandle source2 = data.sourceTexture;
				RTHandle destination2 = data.destination;
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_SetupDoF)))
				{
					CoreUtils.SetKeyword(material2, "_USE_FAST_SRGB_LINEAR_CONVERSION", data.useFastSRGBLinearConversion);
					CoreUtils.SetKeyword(materialCoC, "_USE_FAST_SRGB_LINEAR_CONVERSION", data.useFastSRGBLinearConversion);
					material2.SetVector(ShaderConstants._CoCParams, data.cocParams);
					material2.SetVectorArray(ShaderConstants._BokehKernel, data.bokehKernel);
					material2.SetVector(ShaderConstants._DownSampleScaleFactor, new Vector4(1f / (float)data.downSample, 1f / (float)data.downSample, data.downSample, data.downSample));
					material2.SetVector(ShaderConstants._BokehConstants, new Vector4(data.uvMargin, data.uvMargin * 2f));
					PostProcessUtils.SetSourceSize(nativeCommandBuffer, data.sourceTexture);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFComputeCOC)))
				{
					material2.SetTexture(ShaderConstants._CameraDepthTextureID, data.depthTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, source2, data.fullCoCTexture, material2, 0);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFDownscalePrefilter)))
				{
					material2.SetTexture(ShaderConstants._FullCoCTexture, data.fullCoCTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, source2, data.pingTexture, material2, 1);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFBlurBokeh)))
				{
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.pingTexture, data.pongTexture, material2, 2);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFPostFilter)))
				{
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.pongTexture, data.pingTexture, material2, 3);
				}
				using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RG_DOFComposite)))
				{
					material2.SetTexture(ShaderConstants._DofTexture, data.pingTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, source2, destination2, material2, 4);
				}
			});
		}

		public void RenderPaniniProjection(RenderGraph renderGraph, Camera camera, in TextureHandle source, out TextureHandle destination)
		{
			destination = CreateCompatibleTexture(renderGraph, in source, "_PaniniProjectionTarget", clear: true, FilterMode.Bilinear);
			TextureDesc descriptor = source.GetDescriptor(renderGraph);
			float value = m_PaniniProjection.distance.value;
			Vector2 vector = CalcViewExtents(camera, descriptor.width, descriptor.height);
			Vector2 vector2 = CalcCropExtents(camera, value, descriptor.width, descriptor.height);
			float a = vector2.x / vector.x;
			float b = vector2.y / vector.y;
			float value2 = Mathf.Min(a, b);
			float num = value;
			float w = Mathf.Lerp(1f, Mathf.Clamp01(value2), m_PaniniProjection.cropToFit.value);
			PaniniProjectionPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PaniniProjectionPassData>("Panini Projection", out passData, ProfilingSampler.Get(URPProfileId.PaniniProjection), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 1419);
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			passData.destinationTexture = destination;
			rasterRenderGraphBuilder.SetRenderAttachment(destination, 0);
			passData.sourceTexture = source;
			rasterRenderGraphBuilder.UseTexture(in source);
			passData.material = m_Materials.paniniProjection;
			passData.paniniParams = new Vector4(vector.x, vector.y, num, w);
			passData.isPaniniGeneric = 1f - Mathf.Abs(num) > float.Epsilon;
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PaniniProjectionPassData data, RasterGraphContext context)
			{
				RasterCommandBuffer cmd = context.cmd;
				RTHandle rTHandle = data.sourceTexture;
				cmd.SetGlobalVector(ShaderConstants._Params, data.paniniParams);
				data.material.EnableKeyword(data.isPaniniGeneric ? "_GENERIC" : "_UNIT_DISTANCE");
				Vector2 vector3 = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
				Blitter.BlitTexture(cmd, rTHandle, vector3, data.material, 0);
			});
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector2 CalcViewExtents(Camera camera, int width, int height)
		{
			float num = camera.fieldOfView * (MathF.PI / 180f);
			float num2 = (float)width / (float)height;
			float num3 = Mathf.Tan(0.5f * num);
			return new Vector2(num2 * num3, num3);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector2 CalcCropExtents(Camera camera, float d, int width, int height)
		{
			float num = 1f + d;
			Vector2 vector = CalcViewExtents(camera, width, height);
			float num2 = Mathf.Sqrt(vector.x * vector.x + 1f);
			float num3 = 1f / num2;
			float num4 = num3 + d;
			return vector * num3 * (num / num4);
		}

		private void RenderTemporalAA(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, ref TextureHandle source, out TextureHandle destination)
		{
			destination = CreateCompatibleTexture(renderGraph, in source, "_TemporalAATarget", clear: false, FilterMode.Bilinear);
			TextureHandle srcDepth = resourceData.cameraDepth;
			TextureHandle srcMotionVectors = resourceData.motionVectorColor;
			TemporalAA.Render(renderGraph, m_Materials.temporalAntialiasing, cameraData, ref source, ref srcDepth, ref srcMotionVectors, ref destination);
		}

		private void RenderSTP(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, ref TextureHandle source, out TextureHandle destination)
		{
			TextureHandle cameraDepthTexture = resourceData.cameraDepthTexture;
			TextureHandle motionVectorColor = resourceData.motionVectorColor;
			TextureDesc descriptor = source.GetDescriptor(renderGraph);
			TextureDesc desc = GetCompatibleDescriptor(descriptor, cameraData.pixelWidth, cameraData.pixelHeight, GraphicsFormatUtility.GetLinearFormat(descriptor.format));
			desc.enableRandomWrite = true;
			destination = CreateCompatibleTexture(renderGraph, in desc, "_CameraColorUpscaledSTP", clear: false, FilterMode.Bilinear);
			int frameCount = Time.frameCount;
			Texture2D noiseTexture = m_Materials.resources.textures.blueNoise16LTex[frameCount & (m_Materials.resources.textures.blueNoise16LTex.Length - 1)];
			StpUtils.Execute(renderGraph, resourceData, cameraData, source, cameraDepthTexture, motionVectorColor, destination, noiseTexture);
			UpdateCameraResolution(renderGraph, cameraData, new Vector2Int(desc.width, desc.height));
		}

		public void RenderMotionBlur(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, in TextureHandle source, out TextureHandle destination)
		{
			Material motionBlur = m_Materials.motionBlur;
			destination = CreateCompatibleTexture(renderGraph, in source, "_MotionBlurTarget", clear: true, FilterMode.Bilinear);
			TextureHandle input = resourceData.motionVectorColor;
			TextureHandle input2 = resourceData.cameraDepthTexture;
			MotionBlurMode value = m_MotionBlur.mode.value;
			int value2 = (int)m_MotionBlur.quality.value;
			value2 += ((value == MotionBlurMode.CameraAndObjects) ? 3 : 0);
			MotionBlurPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<MotionBlurPassData>("Motion Blur", out passData, ProfilingSampler.Get(URPProfileId.RG_MotionBlur), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 1575);
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderAttachment(destination, 0);
			passData.sourceTexture = source;
			rasterRenderGraphBuilder.UseTexture(in source);
			if (value == MotionBlurMode.CameraAndObjects)
			{
				passData.motionVectors = input;
				rasterRenderGraphBuilder.UseTexture(in input);
			}
			else
			{
				passData.motionVectors = TextureHandle.nullHandle;
			}
			rasterRenderGraphBuilder.UseTexture(in input2);
			passData.material = motionBlur;
			passData.passIndex = value2;
			passData.camera = cameraData.camera;
			passData.xr = cameraData.xr;
			passData.enableAlphaOutput = cameraData.isAlphaOutputEnabled;
			passData.intensity = m_MotionBlur.intensity.value;
			passData.clamp = m_MotionBlur.clamp.value;
			rasterRenderGraphBuilder.SetRenderFunc(delegate(MotionBlurPassData data, RasterGraphContext context)
			{
				RasterCommandBuffer cmd = context.cmd;
				RTHandle rTHandle = data.sourceTexture;
				UpdateMotionBlurMatrices(ref data.material, data.camera, data.xr);
				data.material.SetFloat("_Intensity", data.intensity);
				data.material.SetFloat("_Clamp", data.clamp);
				CoreUtils.SetKeyword(data.material, "_ENABLE_ALPHA_OUTPUT", data.enableAlphaOutput);
				PostProcessUtils.SetSourceSize(cmd, data.sourceTexture);
				Vector2 vector = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
				Blitter.BlitTexture(cmd, rTHandle, vector, data.material, data.passIndex);
			});
		}

		internal static void UpdateMotionBlurMatrices(ref Material material, Camera camera, XRPass xr)
		{
			MotionVectorsPersistentData motionVectorsPersistentData = null;
			if (camera.TryGetComponent<UniversalAdditionalCameraData>(out var component))
			{
				motionVectorsPersistentData = component.motionVectorsPersistentData;
			}
			if (motionVectorsPersistentData == null)
			{
				return;
			}
			if (xr.enabled && xr.singlePassEnabled)
			{
				int sourceIndex = xr.viewCount * xr.multipassId;
				Array.Copy(motionVectorsPersistentData.previousViewProjectionStereo, sourceIndex, motionVectorsPersistentData.stagingMatrixStereo, 0, xr.viewCount);
				material.SetMatrixArray(ShaderConstants._PrevViewProjMStereo, motionVectorsPersistentData.stagingMatrixStereo);
				Array.Copy(motionVectorsPersistentData.viewProjectionStereo, sourceIndex, motionVectorsPersistentData.stagingMatrixStereo, 0, xr.viewCount);
				material.SetMatrixArray(ShaderConstants._ViewProjMStereo, motionVectorsPersistentData.stagingMatrixStereo);
				return;
			}
			int num = 0;
			if (xr.enabled)
			{
				num = xr.multipassId * xr.viewCount;
			}
			material.SetMatrix(ShaderConstants._PrevViewProjM, motionVectorsPersistentData.previousViewProjectionStereo[num]);
			material.SetMatrix(ShaderConstants._ViewProjM, motionVectorsPersistentData.viewProjectionStereo[num]);
		}

		private void LensFlareDataDrivenComputeOcclusion(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, in TextureDesc srcDesc)
		{
			if (!LensFlareCommonSRP.IsOcclusionRTCompatible())
			{
				return;
			}
			LensFlarePassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<LensFlarePassData>("Lens Flare Compute Occlusion", out passData, ProfilingSampler.Get(URPProfileId.LensFlareDataDrivenComputeOcclusion), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 1681);
			_ = LensFlareCommonSRP.occlusionRT;
			TextureHandle input = (passData.destinationTexture = renderGraph.ImportTexture(LensFlareCommonSRP.occlusionRT));
			unsafeRenderGraphBuilder.UseTexture(in input, AccessFlags.Write);
			passData.cameraData = cameraData;
			passData.viewport = cameraData.pixelRect;
			passData.material = m_Materials.lensFlareDataDriven;
			passData.width = srcDesc.width;
			passData.height = srcDesc.height;
			if (m_PaniniProjection.IsActive())
			{
				passData.usePanini = true;
				passData.paniniDistance = m_PaniniProjection.distance.value;
				passData.paniniCropToFit = m_PaniniProjection.cropToFit.value;
			}
			else
			{
				passData.usePanini = false;
				passData.paniniDistance = 1f;
				passData.paniniCropToFit = 1f;
			}
			unsafeRenderGraphBuilder.UseTexture(resourceData.cameraDepthTexture);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(LensFlarePassData data, UnsafeGraphContext ctx)
			{
				Camera camera = data.cameraData.camera;
				XRPass xr = data.cameraData.xr;
				Matrix4x4 viewProjMatrix;
				if (xr.enabled)
				{
					if (xr.singlePassEnabled)
					{
						viewProjMatrix = GL.GetGPUProjectionMatrix(data.cameraData.GetProjectionMatrixNoJitter(), renderIntoTexture: true) * data.cameraData.GetViewMatrix();
					}
					else
					{
						viewProjMatrix = GL.GetGPUProjectionMatrix(camera.projectionMatrix, renderIntoTexture: true) * camera.worldToCameraMatrix;
						_ = data.cameraData.xr.multipassId;
					}
				}
				else
				{
					viewProjMatrix = GL.GetGPUProjectionMatrix(data.cameraData.GetProjectionMatrixNoJitter(), renderIntoTexture: true) * data.cameraData.GetViewMatrix();
				}
				LensFlareCommonSRP.ComputeOcclusion(data.material, camera, xr, xr.multipassId, data.width, data.height, data.usePanini, data.paniniDistance, data.paniniCropToFit, isCameraRelative: true, camera.transform.position, viewProjMatrix, ctx.cmd, taaEnabled: false, hasCloudLayer: false, null, null);
				if (xr.enabled && xr.singlePassEnabled)
				{
					for (int i = 1; i < xr.viewCount; i++)
					{
						Matrix4x4 viewProjMatrix2 = GL.GetGPUProjectionMatrix(data.cameraData.GetProjectionMatrixNoJitter(i), renderIntoTexture: true) * data.cameraData.GetViewMatrix(i);
						LensFlareCommonSRP.ComputeOcclusion(data.material, camera, xr, i, data.width, data.height, data.usePanini, data.paniniDistance, data.paniniCropToFit, isCameraRelative: true, camera.transform.position, viewProjMatrix2, ctx.cmd, taaEnabled: false, hasCloudLayer: false, null, null);
					}
				}
			});
		}

		public void RenderLensFlareDataDriven(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, in TextureHandle destination, in TextureDesc srcDesc)
		{
			LensFlarePassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<LensFlarePassData>("Lens Flare Data Driven Pass", out passData, ProfilingSampler.Get(URPProfileId.LensFlareDataDriven), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 1779);
			passData.destinationTexture = destination;
			unsafeRenderGraphBuilder.UseTexture(in destination, AccessFlags.Write);
			passData.cameraData = cameraData;
			passData.material = m_Materials.lensFlareDataDriven;
			passData.width = srcDesc.width;
			passData.height = srcDesc.height;
			passData.viewport.x = 0f;
			passData.viewport.y = 0f;
			passData.viewport.width = srcDesc.width;
			passData.viewport.height = srcDesc.height;
			if (m_PaniniProjection.IsActive())
			{
				passData.usePanini = true;
				passData.paniniDistance = m_PaniniProjection.distance.value;
				passData.paniniCropToFit = m_PaniniProjection.cropToFit.value;
			}
			else
			{
				passData.usePanini = false;
				passData.paniniDistance = 1f;
				passData.paniniCropToFit = 1f;
			}
			if (LensFlareCommonSRP.IsOcclusionRTCompatible())
			{
				unsafeRenderGraphBuilder.UseTexture(renderGraph.ImportTexture(LensFlareCommonSRP.occlusionRT));
			}
			else
			{
				unsafeRenderGraphBuilder.UseTexture(resourceData.cameraDepthTexture);
			}
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(LensFlarePassData data, UnsafeGraphContext ctx)
			{
				Camera camera = data.cameraData.camera;
				XRPass xr = data.cameraData.xr;
				if (!xr.enabled || (xr.enabled && !xr.singlePassEnabled))
				{
					Matrix4x4 viewProjMatrix = GL.GetGPUProjectionMatrix(camera.projectionMatrix, renderIntoTexture: true) * camera.worldToCameraMatrix;
					LensFlareCommonSRP.DoLensFlareDataDrivenCommon(data.material, data.cameraData.camera, data.viewport, xr, data.cameraData.xr.multipassId, data.width, data.height, data.usePanini, data.paniniDistance, data.paniniCropToFit, isCameraRelative: true, camera.transform.position, viewProjMatrix, ctx.cmd, taaEnabled: false, hasCloudLayer: false, null, null, data.destinationTexture, (Light light, Camera cam, Vector3 wo) => GetLensFlareLightAttenuation(light, cam, wo), debugView: false);
				}
				else
				{
					for (int num = 0; num < xr.viewCount; num++)
					{
						Matrix4x4 viewProjMatrix2 = GL.GetGPUProjectionMatrix(data.cameraData.GetProjectionMatrixNoJitter(num), renderIntoTexture: true) * data.cameraData.GetViewMatrix(num);
						LensFlareCommonSRP.DoLensFlareDataDrivenCommon(data.material, data.cameraData.camera, data.viewport, xr, data.cameraData.xr.multipassId, data.width, data.height, data.usePanini, data.paniniDistance, data.paniniCropToFit, isCameraRelative: true, camera.transform.position, viewProjMatrix2, ctx.cmd, taaEnabled: false, hasCloudLayer: false, null, null, data.destinationTexture, (Light light, Camera cam, Vector3 wo) => GetLensFlareLightAttenuation(light, cam, wo), debugView: false);
					}
				}
			});
		}

		private static float GetLensFlareLightAttenuation(Light light, Camera cam, Vector3 wo)
		{
			if (light != null)
			{
				return light.type switch
				{
					LightType.Directional => LensFlareCommonSRP.ShapeAttenuationDirLight(light.transform.forward, cam.transform.forward), 
					LightType.Point => LensFlareCommonSRP.ShapeAttenuationPointLight(), 
					LightType.Spot => LensFlareCommonSRP.ShapeAttenuationSpotConeLight(light.transform.forward, wo, light.spotAngle, light.innerSpotAngle / 180f), 
					_ => 1f, 
				};
			}
			return 1f;
		}

		public TextureHandle RenderLensFlareScreenSpace(RenderGraph renderGraph, Camera camera, in TextureDesc srcDesc, TextureHandle originalBloomTexture, TextureHandle screenSpaceLensFlareBloomMipTexture, bool sameBloomInputOutputTex)
		{
			int value = (int)m_LensFlareScreenSpace.resolution.value;
			int width = Math.Max(srcDesc.width / value, 1);
			int height = Math.Max(srcDesc.height / value, 1);
			TextureDesc desc = GetCompatibleDescriptor(srcDesc, width, height, m_LensFlareScreenSpaceColorFormat);
			TextureHandle input = CreateCompatibleTexture(renderGraph, in desc, "_StreakTmpTexture", clear: true, FilterMode.Bilinear);
			TextureHandle input2 = CreateCompatibleTexture(renderGraph, in desc, "_StreakTmpTexture2", clear: true, FilterMode.Bilinear);
			TextureHandle input3 = CreateCompatibleTexture(renderGraph, in desc, "_LensFlareScreenSpace", clear: true, FilterMode.Bilinear);
			LensFlareScreenSpacePassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<LensFlareScreenSpacePassData>("Blit Lens Flare Screen Space", out passData, ProfilingSampler.Get(URPProfileId.LensFlareScreenSpace), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 1922);
			passData.streakTmpTexture = input;
			unsafeRenderGraphBuilder.UseTexture(in input, AccessFlags.ReadWrite);
			passData.streakTmpTexture2 = input2;
			unsafeRenderGraphBuilder.UseTexture(in input2, AccessFlags.ReadWrite);
			passData.screenSpaceLensFlareBloomMipTexture = screenSpaceLensFlareBloomMipTexture;
			unsafeRenderGraphBuilder.UseTexture(in screenSpaceLensFlareBloomMipTexture, AccessFlags.ReadWrite);
			passData.originalBloomTexture = originalBloomTexture;
			if (!sameBloomInputOutputTex)
			{
				unsafeRenderGraphBuilder.UseTexture(in originalBloomTexture, AccessFlags.ReadWrite);
			}
			passData.actualWidth = srcDesc.width;
			passData.actualHeight = srcDesc.height;
			passData.camera = camera;
			passData.material = m_Materials.lensFlareScreenSpace;
			passData.lensFlareScreenSpace = m_LensFlareScreenSpace;
			passData.downsample = value;
			passData.result = input3;
			unsafeRenderGraphBuilder.UseTexture(in input3, AccessFlags.ReadWrite);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(LensFlareScreenSpacePassData data, UnsafeGraphContext context)
			{
				UnsafeCommandBuffer cmd = context.cmd;
				Camera camera2 = data.camera;
				ScreenSpaceLensFlare lensFlareScreenSpace = data.lensFlareScreenSpace;
				LensFlareCommonSRP.DoLensFlareScreenSpaceCommon(data.material, camera2, data.actualWidth, data.actualHeight, data.lensFlareScreenSpace.tintColor.value, data.originalBloomTexture, data.screenSpaceLensFlareBloomMipTexture, null, data.streakTmpTexture, data.streakTmpTexture2, new Vector4(lensFlareScreenSpace.intensity.value, lensFlareScreenSpace.firstFlareIntensity.value, lensFlareScreenSpace.secondaryFlareIntensity.value, lensFlareScreenSpace.warpedFlareIntensity.value), new Vector4(lensFlareScreenSpace.vignetteEffect.value, lensFlareScreenSpace.startingPosition.value, lensFlareScreenSpace.scale.value, 0f), new Vector4(lensFlareScreenSpace.samples.value, lensFlareScreenSpace.sampleDimmer.value, lensFlareScreenSpace.chromaticAbberationIntensity.value, 0f), new Vector4(lensFlareScreenSpace.streaksIntensity.value, lensFlareScreenSpace.streaksLength.value, lensFlareScreenSpace.streaksOrientation.value, lensFlareScreenSpace.streaksThreshold.value), new Vector4(data.downsample, lensFlareScreenSpace.warpedFlareScale.value.x, lensFlareScreenSpace.warpedFlareScale.value.y, 0f), cmd, data.result, debugView: false);
			});
			return originalBloomTexture;
		}

		private static void ScaleViewport(RasterCommandBuffer cmd, RTHandle sourceTextureHdl, RTHandle dest, UniversalCameraData cameraData, bool hasFinalPass)
		{
			RenderTargetIdentifier renderTargetIdentifier = BuiltinRenderTextureType.CameraTarget;
			if (cameraData.xr.enabled)
			{
				renderTargetIdentifier = cameraData.xr.renderTarget;
			}
			if (dest.nameID == renderTargetIdentifier || cameraData.targetTexture != null)
			{
				if (hasFinalPass || !cameraData.resolveFinalTarget)
				{
					int width = cameraData.cameraTargetDescriptor.width;
					int height = cameraData.cameraTargetDescriptor.height;
					Rect viewport = new Rect(0f, 0f, width, height);
					cmd.SetViewport(viewport);
				}
				else
				{
					cmd.SetViewport(cameraData.pixelRect);
				}
			}
		}

		private static void ScaleViewportAndBlit(in RasterGraphContext context, in TextureHandle source, in TextureHandle destination, UniversalCameraData cameraData, Material material, bool hasFinalPass)
		{
			Vector4 finalBlitScaleBias = RenderingUtils.GetFinalBlitScaleBias(in context, in source, in destination);
			ScaleViewport(context.cmd, source, destination, cameraData, hasFinalPass);
			Blitter.BlitTexture(context.cmd, source, finalBlitScaleBias, material, 0);
		}

		private static void ScaleViewportAndDrawVisibilityMesh(in RasterGraphContext context, in TextureHandle source, in TextureHandle destination, UniversalCameraData cameraData, Material material, bool hasFinalPass)
		{
			Vector4 finalBlitScaleBias = RenderingUtils.GetFinalBlitScaleBias(in context, in source, in destination);
			ScaleViewport(context.cmd, source, destination, cameraData, hasFinalPass);
			MaterialPropertyBlock materialPropertyBlock = XRSystemUniversal.GetMaterialPropertyBlock();
			materialPropertyBlock.SetVector(Shader.PropertyToID("_BlitScaleBias"), finalBlitScaleBias);
			materialPropertyBlock.SetTexture(Shader.PropertyToID("_BlitTexture"), source);
			cameraData.xr.RenderVisibleMeshCustomMaterial(context.cmd, cameraData.xr.occlusionMeshScale, material, materialPropertyBlock, 1, context.GetTextureUVOrigin(in destination) == TextureUVOrigin.BottomLeft);
		}

		public void RenderFinalSetup(RenderGraph renderGraph, UniversalCameraData cameraData, in TextureHandle source, in TextureHandle destination, ref FinalBlitSettings settings)
		{
			PostProcessingFinalSetupPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PostProcessingFinalSetupPassData>("Postprocessing Final Setup Pass", out passData, ProfilingSampler.Get(URPProfileId.RG_FinalSetup), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 2064);
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.AllowPassCulling(value: false);
			Material scalingSetup = m_Materials.scalingSetup;
			scalingSetup.shaderKeywords = null;
			scalingSetup.shaderKeywords = null;
			if (settings.isFxaaEnabled)
			{
				CoreUtils.SetKeyword(scalingSetup, "_FXAA", settings.isFxaaEnabled);
			}
			if (settings.isFsrEnabled)
			{
				CoreUtils.SetKeyword(scalingSetup, settings.hdrOperations.HasFlag(HDROutputUtils.Operation.ColorEncoding) ? "_GAMMA_20_AND_HDR_INPUT" : "_GAMMA_20", state: true);
			}
			if (settings.hdrOperations.HasFlag(HDROutputUtils.Operation.ColorEncoding))
			{
				SetupHDROutput(cameraData.hdrDisplayInformation, cameraData.hdrDisplayColorGamut, scalingSetup, settings.hdrOperations, cameraData.rendersOverlayUI);
			}
			if (settings.isAlphaOutputEnabled)
			{
				CoreUtils.SetKeyword(scalingSetup, "_ENABLE_ALPHA_OUTPUT", settings.isAlphaOutputEnabled);
			}
			passData.destinationTexture = destination;
			rasterRenderGraphBuilder.SetRenderAttachment(destination, 0);
			passData.sourceTexture = source;
			rasterRenderGraphBuilder.UseTexture(in source);
			passData.cameraData = cameraData;
			passData.material = scalingSetup;
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PostProcessingFinalSetupPassData data, RasterGraphContext context)
			{
				RTHandle source2 = data.sourceTexture;
				PostProcessUtils.SetSourceSize(context.cmd, source2);
				bool hasFinalPass = true;
				ScaleViewportAndBlit(in context, in data.sourceTexture, in data.destinationTexture, data.cameraData, data.material, hasFinalPass);
			});
		}

		public void RenderFinalFSRScale(RenderGraph renderGraph, in TextureHandle source, in TextureDesc srcDesc, in TextureHandle destination, in TextureDesc dstDesc, bool enableAlphaOutput)
		{
			m_Materials.easu.shaderKeywords = null;
			PostProcessingFinalFSRScalePassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PostProcessingFinalFSRScalePassData>("Postprocessing Final FSR Scale Pass", out passData, ProfilingSampler.Get(URPProfileId.RG_FinalFSRScale), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 2121);
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderAttachment(destination, 0);
			passData.sourceTexture = source;
			rasterRenderGraphBuilder.UseTexture(in source);
			passData.material = m_Materials.easu;
			passData.enableAlphaOutput = enableAlphaOutput;
			passData.fsrInputSize = new Vector2(srcDesc.width, srcDesc.height);
			passData.fsrOutputSize = new Vector2(dstDesc.width, dstDesc.height);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PostProcessingFinalFSRScalePassData data, RasterGraphContext context)
			{
				RasterCommandBuffer cmd = context.cmd;
				TextureHandle sourceTexture = data.sourceTexture;
				Material material = data.material;
				bool enableAlphaOutput2 = data.enableAlphaOutput;
				RTHandle rTHandle = sourceTexture;
				FSRUtils.SetEasuConstants(cmd, data.fsrInputSize, data.fsrInputSize, data.fsrOutputSize);
				CoreUtils.SetKeyword(material, "_ENABLE_ALPHA_OUTPUT", enableAlphaOutput2);
				Vector2 vector = (rTHandle.useScaling ? new Vector2(rTHandle.rtHandleProperties.rtHandleScale.x, rTHandle.rtHandleProperties.rtHandleScale.y) : Vector2.one);
				Blitter.BlitTexture(cmd, rTHandle, vector, material, 0);
			});
		}

		public void RenderFinalBlit(RenderGraph renderGraph, UniversalCameraData cameraData, in TextureHandle source, in TextureHandle overlayUITexture, in TextureHandle postProcessingTarget, ref FinalBlitSettings settings)
		{
			PostProcessingFinalBlitPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PostProcessingFinalBlitPassData>("Postprocessing Final Blit Pass", out passData, ProfilingSampler.Get(URPProfileId.RG_FinalBlit), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 2200);
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.AllowPassCulling(value: false);
			passData.destinationTexture = postProcessingTarget;
			rasterRenderGraphBuilder.SetRenderAttachment(postProcessingTarget, 0);
			passData.sourceTexture = source;
			rasterRenderGraphBuilder.UseTexture(in source);
			passData.cameraData = cameraData;
			passData.material = m_Materials.finalPass;
			passData.settings = settings;
			if (settings.requireHDROutput && m_EnableColorEncodingIfNeeded && cameraData.rendersOverlayUI)
			{
				rasterRenderGraphBuilder.UseTexture(in overlayUITexture);
			}
			if (cameraData.xr.enabled)
			{
				bool flag = !XRSystem.foveatedRenderingCaps.HasFlag(FoveatedRenderingCaps.NonUniformRaster);
				rasterRenderGraphBuilder.EnableFoveatedRasterization(cameraData.xr.supportsFoveatedRendering && flag);
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			}
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PostProcessingFinalBlitPassData data, RasterGraphContext context)
			{
				RasterCommandBuffer cmd = context.cmd;
				Material material = data.material;
				bool isFxaaEnabled = data.settings.isFxaaEnabled;
				bool isFsrEnabled = data.settings.isFsrEnabled;
				bool isTaaSharpeningEnabled = data.settings.isTaaSharpeningEnabled;
				bool requireHDROutput = data.settings.requireHDROutput;
				bool isAlphaOutputEnabled = data.settings.isAlphaOutputEnabled;
				RTHandle rTHandle = data.sourceTexture;
				_ = (RTHandle)data.destinationTexture;
				PostProcessUtils.SetSourceSize(cmd, data.sourceTexture);
				CoreUtils.SetKeyword(material, "_FXAA", isFxaaEnabled);
				if (isFsrEnabled)
				{
					float sharpnessLinear = (data.cameraData.fsrOverrideSharpness ? data.cameraData.fsrSharpness : 0.92f);
					if (data.cameraData.fsrSharpness > 0f)
					{
						CoreUtils.SetKeyword(material, requireHDROutput ? "_EASU_RCAS_AND_HDR_INPUT" : "_RCAS", state: true);
						FSRUtils.SetRcasConstantsLinear(cmd, sharpnessLinear);
					}
				}
				else if (isTaaSharpeningEnabled)
				{
					CoreUtils.SetKeyword(material, "_RCAS", state: true);
					FSRUtils.SetRcasConstantsLinear(cmd, data.cameraData.taaSettings.contrastAdaptiveSharpening);
				}
				if (isAlphaOutputEnabled)
				{
					CoreUtils.SetKeyword(material, "_ENABLE_ALPHA_OUTPUT", isAlphaOutputEnabled);
				}
				Vector4 finalBlitScaleBias = RenderingUtils.GetFinalBlitScaleBias(in context, in data.sourceTexture, in data.destinationTexture);
				cmd.SetViewport(data.cameraData.pixelRect);
				if (data.cameraData.xr.enabled && data.cameraData.xr.hasValidVisibleMesh)
				{
					MaterialPropertyBlock materialPropertyBlock = XRSystemUniversal.GetMaterialPropertyBlock();
					materialPropertyBlock.SetVector(Shader.PropertyToID("_BlitScaleBias"), finalBlitScaleBias);
					materialPropertyBlock.SetTexture(Shader.PropertyToID("_BlitTexture"), rTHandle);
					data.cameraData.xr.RenderVisibleMeshCustomMaterial(cmd, data.cameraData.xr.occlusionMeshScale, material, materialPropertyBlock, 1, context.GetTextureUVOrigin(in data.sourceTexture) == context.GetTextureUVOrigin(in data.destinationTexture));
				}
				else
				{
					Blitter.BlitTexture(cmd, rTHandle, finalBlitScaleBias, material, 0);
				}
			});
		}

		public void RenderFinalPassRenderGraph(RenderGraph renderGraph, ContextContainer frameData, in TextureHandle source, in TextureHandle overlayUITexture, in TextureHandle postProcessingTarget, bool enableColorEncodingIfNeeded)
		{
			VolumeStack stack = VolumeManager.instance.stack;
			m_Tonemapping = stack.GetComponent<Tonemapping>();
			m_FilmGrain = stack.GetComponent<FilmGrain>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			Material finalPass = m_Materials.finalPass;
			finalPass.shaderKeywords = null;
			FinalBlitSettings settings = FinalBlitSettings.Create();
			TextureDesc srcDesc = renderGraph.GetTextureDesc(in source);
			TextureDesc desc = srcDesc;
			desc.width = universalCameraData.pixelWidth;
			desc.height = universalCameraData.pixelHeight;
			m_HasFinalPass = false;
			m_EnableColorEncodingIfNeeded = enableColorEncodingIfNeeded;
			if (m_FilmGrain.IsActive())
			{
				finalPass.EnableKeyword("_FILM_GRAIN");
				PostProcessUtils.ConfigureFilmGrain(m_Materials.resources, m_FilmGrain, desc.width, desc.height, finalPass);
			}
			if (universalCameraData.isDitheringEnabled)
			{
				finalPass.EnableKeyword("_DITHERING");
				m_DitheringTextureIndex = PostProcessUtils.ConfigureDithering(m_Materials.resources, m_DitheringTextureIndex, desc.width, desc.height, finalPass);
			}
			if (RequireSRGBConversionBlitToBackBuffer(universalCameraData.requireSrgbConversion))
			{
				CoreUtils.SetKeyword(finalPass, "_LINEAR_TO_SRGB_CONVERSION", state: true);
			}
			settings.hdrOperations = HDROutputUtils.Operation.None;
			settings.requireHDROutput = RequireHDROutput(universalCameraData);
			if (settings.requireHDROutput)
			{
				settings.hdrOperations = (m_EnableColorEncodingIfNeeded ? HDROutputUtils.Operation.ColorEncoding : HDROutputUtils.Operation.None);
				if (!universalCameraData.postProcessEnabled)
				{
					settings.hdrOperations |= HDROutputUtils.Operation.ColorConversion;
				}
				SetupHDROutput(universalCameraData.hdrDisplayInformation, universalCameraData.hdrDisplayColorGamut, finalPass, settings.hdrOperations, universalCameraData.rendersOverlayUI);
				RenderingUtils.SetupOffscreenUIViewportParams(finalPass, ref universalCameraData.pixelRect, universalCameraData.resolveFinalTarget);
			}
			_ = ScriptableRenderPass.GetActiveDebugHandler(universalCameraData)?.WriteToDebugScreenTexture(universalCameraData.resolveFinalTarget) ?? false;
			settings.isAlphaOutputEnabled = universalCameraData.isAlphaOutputEnabled;
			settings.isFxaaEnabled = universalCameraData.antialiasing == AntialiasingMode.FastApproximateAntialiasing;
			settings.isFsrEnabled = universalCameraData.imageScalingMode == ImageScalingMode.Upscaling && universalCameraData.upscalingFilter == ImageUpscalingFilter.FSR;
			settings.isTaaSharpeningEnabled = universalCameraData.IsTemporalAAEnabled() && universalCameraData.taaSettings.contrastAdaptiveSharpening > 0f && !settings.isFsrEnabled && !universalCameraData.IsSTPEnabled();
			TextureDesc desc2 = srcDesc;
			if (!settings.requireHDROutput)
			{
				desc2.format = UniversalRenderPipeline.MakeUnormRenderTextureGraphicsFormat();
			}
			TextureHandle destination = CreateCompatibleTexture(renderGraph, in desc2, "scalingSetupTarget", clear: true, FilterMode.Point);
			TextureHandle destination2 = CreateCompatibleTexture(renderGraph, in desc, "_UpscaledTexture", clear: true, FilterMode.Point);
			TextureHandle source2 = source;
			if (universalCameraData.imageScalingMode != ImageScalingMode.None)
			{
				if (settings.isFxaaEnabled || settings.isFsrEnabled)
				{
					RenderFinalSetup(renderGraph, universalCameraData, in source2, in destination, ref settings);
					source2 = destination;
					settings.isFxaaEnabled = false;
				}
				switch (universalCameraData.imageScalingMode)
				{
				case ImageScalingMode.Upscaling:
					switch (universalCameraData.upscalingFilter)
					{
					case ImageUpscalingFilter.Point:
						if (!settings.isTaaSharpeningEnabled)
						{
							finalPass.EnableKeyword("_POINT_SAMPLING");
						}
						break;
					case ImageUpscalingFilter.FSR:
						RenderFinalFSRScale(renderGraph, in source2, in srcDesc, in destination2, in desc, settings.isAlphaOutputEnabled);
						source2 = destination2;
						break;
					}
					break;
				case ImageScalingMode.Downscaling:
					settings.isTaaSharpeningEnabled = false;
					break;
				}
			}
			else if (settings.isFxaaEnabled)
			{
				finalPass.EnableKeyword("_FXAA");
			}
			RenderFinalBlit(renderGraph, universalCameraData, in source2, in overlayUITexture, in postProcessingTarget, ref settings);
		}

		private TextureHandle TryGetCachedUserLutTextureHandle(RenderGraph renderGraph)
		{
			if (m_ColorLookup.texture.value == null)
			{
				if (m_UserLut != null)
				{
					m_UserLut.Release();
					m_UserLut = null;
				}
			}
			else if (m_UserLut == null || m_UserLut.externalTexture != m_ColorLookup.texture.value)
			{
				m_UserLut?.Release();
				m_UserLut = RTHandles.Alloc(m_ColorLookup.texture.value);
			}
			if (m_UserLut == null)
			{
				return TextureHandle.nullHandle;
			}
			return renderGraph.ImportTexture(m_UserLut);
		}

		public void RenderUberPost(RenderGraph renderGraph, ContextContainer frameData, UniversalCameraData cameraData, UniversalPostProcessingData postProcessingData, in TextureHandle sourceTexture, in TextureHandle destTexture, in TextureHandle lutTexture, in TextureHandle bloomTexture, in TextureHandle overlayUITexture, bool requireHDROutput, bool enableAlphaOutput, bool hasFinalPass)
		{
			Material uber = m_Materials.uber;
			bool isHdrGrading = postProcessingData.gradingMode == ColorGradingMode.HighDynamicRange;
			int lutSize = postProcessingData.lutSize;
			int num = lutSize * lutSize;
			float w = Mathf.Pow(2f, m_ColorAdjustments.postExposure.value);
			Vector4 lutParams = new Vector4(1f / (float)num, 1f / (float)lutSize, (float)lutSize - 1f, w);
			TextureHandle input = TryGetCachedUserLutTextureHandle(renderGraph);
			Vector4 userLutParams = ((!m_ColorLookup.IsActive()) ? Vector4.zero : new Vector4(1f / (float)m_ColorLookup.texture.value.width, 1f / (float)m_ColorLookup.texture.value.height, (float)m_ColorLookup.texture.value.height - 1f, m_ColorLookup.contribution.value));
			UberPostPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<UberPostPassData>("Blit Post Processing", out passData, ProfilingSampler.Get(URPProfileId.RG_UberPost), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 2512);
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			if (cameraData.xr.enabled)
			{
				bool flag = cameraData.xrUniversal.canFoveateIntermediatePasses || universalResourceData.isActiveTargetBackBuffer;
				flag &= !XRSystem.foveatedRenderingCaps.HasFlag(FoveatedRenderingCaps.NonUniformRaster);
				rasterRenderGraphBuilder.EnableFoveatedRasterization(cameraData.xr.supportsFoveatedRendering && flag);
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			}
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			passData.destinationTexture = destTexture;
			rasterRenderGraphBuilder.SetRenderAttachment(destTexture, 0);
			passData.sourceTexture = sourceTexture;
			rasterRenderGraphBuilder.UseTexture(in sourceTexture);
			passData.lutTexture = lutTexture;
			rasterRenderGraphBuilder.UseTexture(in lutTexture);
			passData.lutParams = lutParams;
			passData.userLutTexture = input;
			if (input.IsValid())
			{
				rasterRenderGraphBuilder.UseTexture(in input);
			}
			if (m_Bloom.IsActive())
			{
				rasterRenderGraphBuilder.UseTexture(in bloomTexture);
				passData.bloomTexture = bloomTexture;
			}
			if (requireHDROutput && m_EnableColorEncodingIfNeeded && overlayUITexture.IsValid())
			{
				rasterRenderGraphBuilder.UseTexture(in overlayUITexture);
			}
			passData.userLutParams = userLutParams;
			passData.cameraData = cameraData;
			passData.material = uber;
			passData.toneMappingMode = m_Tonemapping.mode.value;
			passData.isHdrGrading = isHdrGrading;
			passData.enableAlphaOutput = enableAlphaOutput;
			passData.hasFinalPass = hasFinalPass;
			rasterRenderGraphBuilder.SetRenderFunc(delegate(UberPostPassData data, RasterGraphContext context)
			{
				_ = data.cameraData.camera;
				Material material = data.material;
				material.SetTexture(ShaderConstants._InternalLut, data.lutTexture);
				material.SetVector(ShaderConstants._Lut_Params, data.lutParams);
				material.SetTexture(ShaderConstants._UserLut, data.userLutTexture);
				material.SetVector(ShaderConstants._UserLut_Params, data.userLutParams);
				if (data.bloomTexture.IsValid())
				{
					material.SetTexture(ShaderConstants._Bloom_Texture, data.bloomTexture);
				}
				if (data.isHdrGrading)
				{
					CoreUtils.SetKeyword(material, "_HDR_GRADING", state: true);
				}
				else
				{
					switch (data.toneMappingMode)
					{
					case TonemappingMode.Neutral:
						CoreUtils.SetKeyword(material, "_TONEMAP_NEUTRAL", state: true);
						break;
					case TonemappingMode.ACES:
						CoreUtils.SetKeyword(material, "_TONEMAP_ACES", state: true);
						break;
					}
				}
				CoreUtils.SetKeyword(material, "_ENABLE_ALPHA_OUTPUT", data.enableAlphaOutput);
				if (data.cameraData.xr.enabled && data.cameraData.xr.hasValidVisibleMesh)
				{
					ScaleViewportAndDrawVisibilityMesh(in context, in data.sourceTexture, in data.destinationTexture, data.cameraData, material, data.hasFinalPass);
				}
				else
				{
					ScaleViewportAndBlit(in context, in data.sourceTexture, in data.destinationTexture, data.cameraData, material, data.hasFinalPass);
				}
			});
		}

		public void RenderPostProcessingRenderGraph(RenderGraph renderGraph, ContextContainer frameData, in TextureHandle activeCameraColorTexture, in TextureHandle lutTexture, in TextureHandle overlayUITexture, in TextureHandle postProcessingTarget, bool hasFinalPass, bool resolveToDebugScreen, bool enableColorEndingIfNeeded)
		{
			UniversalResourceData resourceData = frameData.Get<UniversalResourceData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			UniversalPostProcessingData universalPostProcessingData = frameData.Get<UniversalPostProcessingData>();
			VolumeStack stack = VolumeManager.instance.stack;
			m_DepthOfField = stack.GetComponent<DepthOfField>();
			m_MotionBlur = stack.GetComponent<MotionBlur>();
			m_PaniniProjection = stack.GetComponent<PaniniProjection>();
			m_Bloom = stack.GetComponent<Bloom>();
			m_LensFlareScreenSpace = stack.GetComponent<ScreenSpaceLensFlare>();
			m_LensDistortion = stack.GetComponent<LensDistortion>();
			m_ChromaticAberration = stack.GetComponent<ChromaticAberration>();
			m_Vignette = stack.GetComponent<Vignette>();
			m_ColorLookup = stack.GetComponent<ColorLookup>();
			m_ColorAdjustments = stack.GetComponent<ColorAdjustments>();
			m_Tonemapping = stack.GetComponent<Tonemapping>();
			m_FilmGrain = stack.GetComponent<FilmGrain>();
			m_UseFastSRGBLinearConversion = universalPostProcessingData.useFastSRGBLinearConversion;
			m_SupportDataDrivenLensFlare = universalPostProcessingData.supportDataDrivenLensFlare;
			m_SupportScreenSpaceLensFlare = universalPostProcessingData.supportScreenSpaceLensFlare;
			m_HasFinalPass = hasFinalPass;
			m_EnableColorEncodingIfNeeded = enableColorEndingIfNeeded;
			ref ScriptableRenderer renderer = ref universalCameraData.renderer;
			bool isSceneViewCamera = universalCameraData.isSceneViewCamera;
			bool flag = universalCameraData.isStopNaNEnabled && m_Materials.stopNaN != null;
			bool flag2 = universalCameraData.antialiasing == AntialiasingMode.SubpixelMorphologicalAntiAliasing;
			Material material = ((m_DepthOfField.mode.value == DepthOfFieldMode.Gaussian) ? m_Materials.gaussianDepthOfField : m_Materials.bokehDepthOfField);
			bool flag3 = m_DepthOfField.IsActive() && !isSceneViewCamera && material != null;
			bool flag4 = !LensFlareCommonSRP.Instance.IsEmpty() && m_SupportDataDrivenLensFlare;
			bool flag5 = m_LensFlareScreenSpace.IsActive() && m_SupportScreenSpaceLensFlare;
			bool flag6 = m_MotionBlur.IsActive() && !isSceneViewCamera;
			bool flag7 = m_PaniniProjection.IsActive() && !isSceneViewCamera;
			flag6 = flag6 && Application.isPlaying;
			if (flag6 && m_MotionBlur.mode.value == MotionBlurMode.CameraAndObjects)
			{
				flag6 &= renderer.SupportsMotionVectors();
				if (!flag6)
				{
					string message = "Disabling Motion Blur for Camera And Objects because the renderer does not implement motion vectors.";
					if (Time.frameCount % 60 == 0)
					{
						Debug.LogWarning(message);
					}
				}
			}
			bool flag8 = universalCameraData.IsTemporalAAEnabled();
			bool flag9 = universalCameraData.IsSTPRequested();
			bool flag10 = flag8 && flag9;
			if (!flag8 && universalCameraData.IsTemporalAARequested())
			{
				TemporalAA.ValidateAndWarn(universalCameraData, flag9);
			}
			PostFXSetupPassData passData;
			using (IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PostFXSetupPassData>("Setup PostFX passes", out passData, ProfilingSampler.Get(URPProfileId.RG_SetupPostFX), ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\PostProcessPassRenderGraph.cs", 2674))
			{
				rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
				rasterRenderGraphBuilder.SetRenderFunc(delegate(PostFXSetupPassData data, RasterGraphContext context)
				{
					context.cmd.SetGlobalMatrix(ShaderConstants._FullscreenProjMat, GL.GetGPUProjectionMatrix(Matrix4x4.identity, renderIntoTexture: true));
				});
			}
			TextureHandle activeCameraColor = activeCameraColorTexture;
			if (flag)
			{
				RenderStopNaN(renderGraph, in activeCameraColor, out var stopNaNTarget);
				activeCameraColor = stopNaNTarget;
			}
			if (flag2)
			{
				RenderSMAA(renderGraph, resourceData, universalCameraData.antialiasingQuality, in activeCameraColor, out var SMAATarget);
				activeCameraColor = SMAATarget;
			}
			if (flag3)
			{
				RenderDoF(renderGraph, resourceData, universalCameraData, in activeCameraColor, out var destination);
				activeCameraColor = destination;
			}
			if (flag8)
			{
				if (flag10)
				{
					RenderSTP(renderGraph, resourceData, universalCameraData, ref activeCameraColor, out var destination2);
					activeCameraColor = destination2;
				}
				else
				{
					RenderTemporalAA(renderGraph, resourceData, universalCameraData, ref activeCameraColor, out var destination3);
					activeCameraColor = destination3;
				}
			}
			if (flag6)
			{
				RenderMotionBlur(renderGraph, resourceData, universalCameraData, in activeCameraColor, out var destination4);
				activeCameraColor = destination4;
			}
			if (flag7)
			{
				RenderPaniniProjection(renderGraph, universalCameraData.camera, in activeCameraColor, out var destination5);
				activeCameraColor = destination5;
			}
			m_Materials.uber.shaderKeywords = null;
			TextureDesc bloomSourceDesc = activeCameraColor.GetDescriptor(renderGraph);
			TextureHandle destination6 = TextureHandle.nullHandle;
			if (m_Bloom.IsActive() || flag5)
			{
				RenderBloomTexture(renderGraph, in activeCameraColor, out destination6, universalCameraData.isAlphaOutputEnabled);
				if (flag5)
				{
					int num = CalcBloomMipCount(m_Bloom, CalcBloomResolution(m_Bloom, in bloomSourceDesc));
					int max = Mathf.Clamp(num - 1, 0, m_Bloom.maxIterations.value / 2);
					int num2 = Mathf.Clamp(m_LensFlareScreenSpace.bloomMip.value, 0, max);
					TextureHandle screenSpaceLensFlareBloomMipTexture = _BloomMipUp[num2];
					bool sameBloomInputOutputTex = false;
					if (num2 == 0)
					{
						if (num == 1 && m_Bloom.filter != BloomFilterMode.Kawase)
						{
							screenSpaceLensFlareBloomMipTexture = _BloomMipDown[0];
						}
						sameBloomInputOutputTex = true;
					}
					if (m_Bloom.filter.value == BloomFilterMode.Kawase)
					{
						screenSpaceLensFlareBloomMipTexture = destination6;
						sameBloomInputOutputTex = true;
					}
					destination6 = RenderLensFlareScreenSpace(renderGraph, universalCameraData.camera, in bloomSourceDesc, destination6, screenSpaceLensFlareBloomMipTexture, sameBloomInputOutputTex);
				}
				UberPostSetupBloomPass(renderGraph, m_Materials.uber, in bloomSourceDesc);
			}
			if (flag4)
			{
				LensFlareDataDrivenComputeOcclusion(renderGraph, resourceData, universalCameraData, in bloomSourceDesc);
				RenderLensFlareDataDriven(renderGraph, resourceData, universalCameraData, in activeCameraColor, in bloomSourceDesc);
			}
			SetupLensDistortion(m_Materials.uber, isSceneViewCamera);
			SetupChromaticAberration(m_Materials.uber);
			SetupVignette(m_Materials.uber, universalCameraData.xr, bloomSourceDesc.width, bloomSourceDesc.height);
			SetupGrain(universalCameraData, m_Materials.uber);
			SetupDithering(universalCameraData, m_Materials.uber);
			if (RequireSRGBConversionBlitToBackBuffer(universalCameraData.requireSrgbConversion))
			{
				CoreUtils.SetKeyword(m_Materials.uber, "_LINEAR_TO_SRGB_CONVERSION", state: true);
			}
			if (m_UseFastSRGBLinearConversion)
			{
				CoreUtils.SetKeyword(m_Materials.uber, "_USE_FAST_SRGB_LINEAR_CONVERSION", state: true);
			}
			bool flag11 = RequireHDROutput(universalCameraData);
			if (flag11)
			{
				HDROutputUtils.Operation hdrOperations = ((!m_HasFinalPass && m_EnableColorEncodingIfNeeded) ? HDROutputUtils.Operation.ColorEncoding : HDROutputUtils.Operation.None);
				SetupHDROutput(universalCameraData.hdrDisplayInformation, universalCameraData.hdrDisplayColorGamut, m_Materials.uber, hdrOperations, universalCameraData.rendersOverlayUI);
				RenderingUtils.SetupOffscreenUIViewportParams(m_Materials.uber, ref universalCameraData.pixelRect, !m_HasFinalPass && universalCameraData.resolveFinalTarget);
			}
			bool isAlphaOutputEnabled = universalCameraData.isAlphaOutputEnabled;
			ScriptableRenderPass.GetActiveDebugHandler(universalCameraData);
			RenderUberPost(renderGraph, frameData, universalCameraData, universalPostProcessingData, in activeCameraColor, in postProcessingTarget, in lutTexture, in destination6, in overlayUITexture, flag11, isAlphaOutputEnabled, hasFinalPass);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void SetupLensDistortion(Material material, bool isSceneView)
		{
			float b = 1.6f * Mathf.Max(Mathf.Abs(m_LensDistortion.intensity.value * 100f), 1f);
			float num = MathF.PI / 180f * Mathf.Min(160f, b);
			float y = 2f * Mathf.Tan(num * 0.5f);
			Vector2 vector = m_LensDistortion.center.value * 2f - Vector2.one;
			Vector4 value = new Vector4(vector.x, vector.y, Mathf.Max(m_LensDistortion.xMultiplier.value, 0.0001f), Mathf.Max(m_LensDistortion.yMultiplier.value, 0.0001f));
			Vector4 value2 = new Vector4((m_LensDistortion.intensity.value >= 0f) ? num : (1f / num), y, 1f / m_LensDistortion.scale.value, m_LensDistortion.intensity.value * 100f);
			material.SetVector(ShaderConstants._Distortion_Params1, value);
			material.SetVector(ShaderConstants._Distortion_Params2, value2);
			if (m_LensDistortion.IsActive() && !isSceneView)
			{
				material.EnableKeyword("_DISTORTION");
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void SetupChromaticAberration(Material material)
		{
			material.SetFloat(ShaderConstants._Chroma_Params, m_ChromaticAberration.intensity.value * 0.05f);
			if (m_ChromaticAberration.IsActive())
			{
				material.EnableKeyword("_CHROMATIC_ABERRATION");
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void SetupVignette(Material material, XRPass xrPass, int width, int height)
		{
			Color value = m_Vignette.color.value;
			Vector2 center = m_Vignette.center.value;
			float num = (float)width / (float)height;
			if (xrPass != null && xrPass.enabled)
			{
				if (xrPass.singlePassEnabled)
				{
					material.SetVector(ShaderConstants._Vignette_ParamsXR, xrPass.ApplyXRViewCenterOffset(center));
				}
				else
				{
					center = xrPass.ApplyXRViewCenterOffset(center);
				}
			}
			Vector4 value2 = new Vector4(value.r, value.g, value.b, m_Vignette.rounded.value ? num : 1f);
			Vector4 value3 = new Vector4(center.x, center.y, m_Vignette.intensity.value * 3f, m_Vignette.smoothness.value * 5f);
			material.SetVector(ShaderConstants._Vignette_Params1, value2);
			material.SetVector(ShaderConstants._Vignette_Params2, value3);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void SetupGrain(UniversalCameraData cameraData, Material material)
		{
			if (!m_HasFinalPass && m_FilmGrain.IsActive())
			{
				material.EnableKeyword("_FILM_GRAIN");
				PostProcessUtils.ConfigureFilmGrain(m_Materials.resources, m_FilmGrain, cameraData.pixelWidth, cameraData.pixelHeight, material);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void SetupDithering(UniversalCameraData cameraData, Material material)
		{
			if (!m_HasFinalPass && cameraData.isDitheringEnabled)
			{
				material.EnableKeyword("_DITHERING");
				m_DitheringTextureIndex = PostProcessUtils.ConfigureDithering(m_Materials.resources, m_DitheringTextureIndex, cameraData.pixelWidth, cameraData.pixelHeight, material);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void SetupHDROutput(HDROutputUtils.HDRDisplayInformation hdrDisplayInformation, ColorGamut hdrDisplayColorGamut, Material material, HDROutputUtils.Operation hdrOperations, bool rendersOverlayUI)
		{
			UniversalRenderPipeline.GetHDROutputLuminanceParameters(hdrDisplayInformation, hdrDisplayColorGamut, m_Tonemapping, out var hdrOutputParameters);
			material.SetVector(ShaderPropertyId.hdrOutputLuminanceParams, hdrOutputParameters);
			HDROutputUtils.ConfigureHDROutput(material, hdrDisplayColorGamut, hdrOperations);
			CoreUtils.SetKeyword(material, "_HDR_OVERLAY", rendersOverlayUI);
		}
	}
}
