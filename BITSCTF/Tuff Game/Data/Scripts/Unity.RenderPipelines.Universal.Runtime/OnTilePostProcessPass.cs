using UnityEngine;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering;
using UnityEngine.Rendering.RenderGraphModule;
using UnityEngine.Rendering.Universal;

public class OnTilePostProcessPass : ScriptableRenderPass
{
	private enum UberShaderPasses
	{
		Normal = 0,
		MSAASoftwareResolve = 1,
		TextureRead = 2,
		NormalVisMesh = 3,
		MSAASoftwareResolveVisMesh = 4,
		TextureReadVisMesh = 5
	}

	private class PassData
	{
		internal TextureHandle source;

		internal TextureHandle destination;

		internal TextureHandle lutTexture;

		internal TextureHandle userLutTexture;

		internal Material material;

		internal UberShaderPasses shaderPass;

		internal Vector4 scaleBias;

		internal bool useXRVisibilityMesh;

		internal XRPass xr;

		internal int msaaSamples;
	}

	private static class ShaderConstants
	{
		public static readonly int _Vignette_Params1 = Shader.PropertyToID("_Vignette_Params1");

		public static readonly int _Vignette_Params2 = Shader.PropertyToID("_Vignette_Params2");

		public static readonly int _Vignette_ParamsXR = Shader.PropertyToID("_Vignette_ParamsXR");

		public static readonly int _Lut_Params = Shader.PropertyToID("_Lut_Params");

		public static readonly int _UserLut_Params = Shader.PropertyToID("_UserLut_Params");

		public static readonly int _InternalLut = Shader.PropertyToID("_InternalLut");

		public static readonly int _UserLut = Shader.PropertyToID("_UserLut");
	}

	internal bool m_UseMultisampleShaderResolve;

	internal bool m_UseTextureReadFallback;

	private RTHandle m_UserLut;

	private Material m_OnTileUberMaterial;

	private static readonly int s_BlitScaleBias = Shader.PropertyToID("_BlitScaleBias");

	private static readonly int s_BlitTexture = Shader.PropertyToID("_BlitTexture");

	private int m_DitheringTextureIndex;

	private PostProcessData m_PostProcessData;

	private const string m_PassName = "On Tile Post Processing";

	private const string m_FallbackPassName = "On Tile Post Processing (sampling fallback) ";

	internal OnTilePostProcessPass(PostProcessData postProcessData)
	{
		m_PostProcessData = postProcessData;
		m_UseMultisampleShaderResolve = SystemInfo.supportsMultisampledShaderResolve;
	}

	internal void Setup(ref Material onTileUberMaterial)
	{
		m_OnTileUberMaterial = onTileUberMaterial;
	}

	public void Dispose()
	{
		m_UserLut?.Release();
		CoreUtils.Destroy(m_OnTileUberMaterial);
	}

	public override void RecordRenderGraph(RenderGraph renderGraph, ContextContainer frameData)
	{
		if (m_OnTileUberMaterial == null)
		{
			return;
		}
		UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
		frameData.Get<UniversalRenderingData>();
		UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
		UniversalPostProcessingData universalPostProcessingData = frameData.Get<UniversalPostProcessingData>();
		if (SystemInfo.graphicsShaderLevel < 30)
		{
			Debug.LogError("DrawProcedural is required for the On-Tile post processing feature but it is not supported by the platform. Pass will not execute.");
			return;
		}
		int lutSize = universalPostProcessingData.lutSize;
		VolumeStack stack = VolumeManager.instance.stack;
		Vignette component = stack.GetComponent<Vignette>();
		ColorLookup component2 = stack.GetComponent<ColorLookup>();
		ColorAdjustments component3 = stack.GetComponent<ColorAdjustments>();
		Tonemapping component4 = stack.GetComponent<Tonemapping>();
		FilmGrain component5 = stack.GetComponent<FilmGrain>();
		bool flag = universalCameraData.xr.enabled && universalCameraData.xr.hasValidVisibleMesh;
		TextureHandle texture = universalResourceData.activeColorTexture;
		TextureDesc textureDesc = renderGraph.GetTextureDesc(in texture);
		TextureHandle backBufferColor = universalResourceData.backBufferColor;
		SetupVignette(m_OnTileUberMaterial, universalCameraData.xr, textureDesc.width, textureDesc.height, component);
		SetupLut(m_OnTileUberMaterial, component2, component3, lutSize);
		SetupTonemapping(m_OnTileUberMaterial, component4, universalPostProcessingData.gradingMode == ColorGradingMode.HighDynamicRange);
		SetupGrain(m_OnTileUberMaterial, universalCameraData, component5, m_PostProcessData);
		SetupDithering(m_OnTileUberMaterial, universalCameraData, m_PostProcessData);
		CoreUtils.SetKeyword(m_OnTileUberMaterial, "_ENABLE_ALPHA_OUTPUT", universalCameraData.isAlphaOutputEnabled);
		UberShaderPasses uberShaderPasses = (flag ? UberShaderPasses.NormalVisMesh : UberShaderPasses.Normal);
		bool flag2 = false;
		if (textureDesc.msaaSamples != MSAASamples.None)
		{
			if (textureDesc.msaaSamples == MSAASamples.MSAA8x)
			{
				Debug.LogError("MSAA8x is enabled in Universal Render Pipeline Asset but it is not supported by the on-tile post-processing feature yet. Please use MSAA4x or MSAA2x instead.");
				return;
			}
			RenderTargetInfo renderTargetInfo = renderGraph.GetRenderTargetInfo(backBufferColor);
			if (!m_UseMultisampleShaderResolve)
			{
				uberShaderPasses = ((renderTargetInfo.msaaSamples != (int)textureDesc.msaaSamples) ? (flag ? UberShaderPasses.TextureReadVisMesh : UberShaderPasses.TextureRead) : ((!flag) ? UberShaderPasses.MSAASoftwareResolve : UberShaderPasses.MSAASoftwareResolveVisMesh));
			}
			else
			{
				uberShaderPasses = ((!flag) ? UberShaderPasses.MSAASoftwareResolve : UberShaderPasses.MSAASoftwareResolveVisMesh);
				if (SystemInfo.supportsMultisampleAutoResolve)
				{
					flag2 = true;
				}
			}
		}
		if (m_UseTextureReadFallback)
		{
			uberShaderPasses = (flag ? UberShaderPasses.TextureReadVisMesh : UberShaderPasses.TextureRead);
			flag2 = false;
		}
		RenderTargetInfo renderTargetInfo2 = renderGraph.GetRenderTargetInfo(backBufferColor);
		TextureDesc textureDesc2 = new TextureDesc(renderTargetInfo2.width, renderTargetInfo2.height);
		textureDesc2.format = renderTargetInfo2.format;
		textureDesc2.msaaSamples = (MSAASamples)renderTargetInfo2.msaaSamples;
		textureDesc2.bindTextureMS = renderTargetInfo2.bindMS;
		textureDesc2.slices = renderTargetInfo2.volumeDepth;
		textureDesc2.dimension = ((renderTargetInfo2.volumeDepth > 1) ? TextureDimension.Tex2DArray : TextureDimension.Tex2D);
		if (textureDesc.width != textureDesc2.width || textureDesc.height != textureDesc2.height || textureDesc.slices != textureDesc2.slices)
		{
			uberShaderPasses = (flag ? UberShaderPasses.TextureReadVisMesh : UberShaderPasses.TextureRead);
			flag2 = false;
		}
		TextureHandle internalColorLut = universalResourceData.internalColorLut;
		string text = (m_UseTextureReadFallback ? "On Tile Post Processing (sampling fallback) " : "On Tile Post Processing");
		PassData passData;
		using (IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(text, out passData, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\RendererFeatures\\OnTilePostProcessPass.cs", 173))
		{
			passData.source = texture;
			passData.destination = backBufferColor;
			passData.material = m_OnTileUberMaterial;
			passData.shaderPass = uberShaderPasses;
			if (uberShaderPasses == UberShaderPasses.TextureRead || uberShaderPasses == UberShaderPasses.TextureReadVisMesh)
			{
				rasterRenderGraphBuilder.UseTexture(in texture);
			}
			else
			{
				rasterRenderGraphBuilder.SetInputAttachment(texture, 0);
				rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			}
			rasterRenderGraphBuilder.UseTexture(in internalColorLut);
			passData.lutTexture = internalColorLut;
			TextureHandle textureHandle = (passData.userLutTexture = TryGetCachedUserLutTextureHandle(component2, renderGraph));
			if (textureHandle.IsValid())
			{
				rasterRenderGraphBuilder.UseTexture(in textureHandle);
			}
			rasterRenderGraphBuilder.SetRenderAttachment(backBufferColor, 0, AccessFlags.WriteAll);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				ExecuteFBFetchPass(data, context);
			});
			passData.useXRVisibilityMesh = false;
			passData.msaaSamples = (int)textureDesc.msaaSamples;
			if (universalCameraData.xr.enabled)
			{
				ExtendedFeatureFlags extendedFeatureFlags = ExtendedFeatureFlags.MultiviewRenderRegionsCompatible;
				if (flag2)
				{
					extendedFeatureFlags |= ExtendedFeatureFlags.MultisampledShaderResolve;
				}
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(extendedFeatureFlags);
				bool flag3 = universalCameraData.xrUniversal.canFoveateIntermediatePasses || universalResourceData.isActiveTargetBackBuffer;
				rasterRenderGraphBuilder.EnableFoveatedRasterization(universalCameraData.xr.supportsFoveatedRendering && flag3);
				passData.useXRVisibilityMesh = flag;
				passData.xr = universalCameraData.xr;
			}
		}
		universalResourceData.activeColorID = UniversalResourceDataBase.ActiveID.BackBuffer;
		universalResourceData.activeDepthID = UniversalResourceDataBase.ActiveID.BackBuffer;
	}

	private static void ExecuteFBFetchPass(PassData data, RasterGraphContext context)
	{
		RasterCommandBuffer cmd = context.cmd;
		data.material.SetTexture(ShaderConstants._InternalLut, data.lutTexture);
		if (data.userLutTexture.IsValid())
		{
			data.material.SetTexture(ShaderConstants._UserLut, data.userLutTexture);
		}
		bool flag = RenderingUtils.IsHandleYFlipped(in context, in data.destination);
		data.material.SetVector(s_BlitScaleBias, (!flag) ? new Vector4(1f, -1f, 0f, 1f) : new Vector4(1f, 1f, 0f, 0f));
		if (data.shaderPass == UberShaderPasses.TextureRead || data.shaderPass == UberShaderPasses.TextureReadVisMesh)
		{
			data.material.SetTexture(s_BlitTexture, data.source);
		}
		else if (data.shaderPass == UberShaderPasses.MSAASoftwareResolve || data.shaderPass == UberShaderPasses.MSAASoftwareResolveVisMesh)
		{
			switch (data.msaaSamples)
			{
			case 4:
				CoreUtils.SetKeyword(data.material, "_MSAA_2", state: false);
				CoreUtils.SetKeyword(data.material, "_MSAA_4", state: true);
				break;
			case 2:
				CoreUtils.SetKeyword(data.material, "_MSAA_2", state: true);
				CoreUtils.SetKeyword(data.material, "_MSAA_4", state: false);
				break;
			default:
				CoreUtils.SetKeyword(data.material, "_MSAA_2", state: false);
				CoreUtils.SetKeyword(data.material, "_MSAA_4", state: false);
				break;
			}
		}
		if (data.useXRVisibilityMesh)
		{
			MaterialPropertyBlock materialPropertyBlock = XRSystemUniversal.GetMaterialPropertyBlock();
			data.xr.RenderVisibleMeshCustomMaterial(cmd, data.xr.occlusionMeshScale, data.material, materialPropertyBlock, (int)data.shaderPass);
		}
		else
		{
			cmd.DrawProcedural(Matrix4x4.identity, data.material, (int)data.shaderPass, MeshTopology.Triangles, 3, 1);
		}
	}

	private TextureHandle TryGetCachedUserLutTextureHandle(ColorLookup colorLookup, RenderGraph renderGraph)
	{
		if (colorLookup.texture.value == null)
		{
			if (m_UserLut != null)
			{
				m_UserLut.Release();
				m_UserLut = null;
			}
		}
		else if (m_UserLut == null || m_UserLut.externalTexture != colorLookup.texture.value)
		{
			m_UserLut?.Release();
			m_UserLut = RTHandles.Alloc(colorLookup.texture.value);
		}
		if (m_UserLut == null)
		{
			return TextureHandle.nullHandle;
		}
		return renderGraph.ImportTexture(m_UserLut);
	}

	private void SetupLut(Material material, ColorLookup colorLookup, ColorAdjustments colorAdjustments, int lutSize)
	{
		int num = lutSize * lutSize;
		float w = Mathf.Pow(2f, colorAdjustments.postExposure.value);
		Vector4 value = new Vector4(1f / (float)num, 1f / (float)lutSize, (float)lutSize - 1f, w);
		Vector4 value2 = ((!colorLookup.IsActive()) ? Vector4.zero : new Vector4(1f / (float)colorLookup.texture.value.width, 1f / (float)colorLookup.texture.value.height, (float)colorLookup.texture.value.height - 1f, colorLookup.contribution.value));
		material.SetVector(ShaderConstants._Lut_Params, value);
		material.SetVector(ShaderConstants._UserLut_Params, value2);
	}

	private void SetupVignette(Material material, XRPass xrPass, int width, int height, Vignette vignette)
	{
		Color value = vignette.color.value;
		Vector2 center = vignette.center.value;
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
		Vector4 value2 = new Vector4(value.r, value.g, value.b, vignette.rounded.value ? num : 1f);
		Vector4 value3 = new Vector4(center.x, center.y, vignette.intensity.value * 3f, vignette.smoothness.value * 5f);
		material.SetVector(ShaderConstants._Vignette_Params1, value2);
		material.SetVector(ShaderConstants._Vignette_Params2, value3);
	}

	private void SetupTonemapping(Material onTileUberMaterial, Tonemapping tonemapping, bool isHdrGrading)
	{
		if (isHdrGrading)
		{
			CoreUtils.SetKeyword(m_OnTileUberMaterial, "_HDR_GRADING", isHdrGrading);
			return;
		}
		CoreUtils.SetKeyword(m_OnTileUberMaterial, "_TONEMAP_NEUTRAL", tonemapping.mode.value == TonemappingMode.Neutral);
		CoreUtils.SetKeyword(m_OnTileUberMaterial, "_TONEMAP_ACES", tonemapping.mode.value == TonemappingMode.ACES);
	}

	private void SetupGrain(Material onTileUberMaterial, UniversalCameraData cameraData, FilmGrain filmgrain, PostProcessData data)
	{
		if (filmgrain.IsActive())
		{
			onTileUberMaterial.EnableKeyword("_FILM_GRAIN");
			PostProcessUtils.ConfigureFilmGrain(data, filmgrain, cameraData.pixelWidth, cameraData.pixelHeight, onTileUberMaterial);
		}
	}

	private void SetupDithering(Material onTileUberMaterial, UniversalCameraData cameraData, PostProcessData data)
	{
		if (cameraData.isDitheringEnabled)
		{
			onTileUberMaterial.EnableKeyword("_DITHERING");
			m_DitheringTextureIndex = PostProcessUtils.ConfigureDithering(data, m_DitheringTextureIndex, cameraData.pixelWidth, cameraData.pixelHeight, onTileUberMaterial);
		}
	}
}
