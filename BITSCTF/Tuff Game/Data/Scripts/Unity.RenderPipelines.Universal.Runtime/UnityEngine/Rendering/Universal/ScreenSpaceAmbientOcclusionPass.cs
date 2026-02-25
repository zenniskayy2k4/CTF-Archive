using System;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal class ScreenSpaceAmbientOcclusionPass : ScriptableRenderPass
	{
		private enum BlurTypes
		{
			Bilateral = 0,
			Gaussian = 1,
			Kawase = 2
		}

		private enum ShaderPasses
		{
			AmbientOcclusion = 0,
			BilateralBlurHorizontal = 1,
			BilateralBlurVertical = 2,
			BilateralBlurFinal = 3,
			BilateralAfterOpaque = 4,
			GaussianBlurHorizontal = 5,
			GaussianBlurVertical = 6,
			GaussianAfterOpaque = 7,
			KawaseBlur = 8,
			KawaseAfterOpaque = 9
		}

		private struct SSAOMaterialParams
		{
			internal bool orthographicCamera;

			internal bool aoBlueNoise;

			internal bool aoInterleavedGradient;

			internal bool sampleCountHigh;

			internal bool sampleCountMedium;

			internal bool sampleCountLow;

			internal bool sourceDepthNormals;

			internal bool sourceDepthHigh;

			internal bool sourceDepthMedium;

			internal bool sourceDepthLow;

			internal Vector4 ssaoParams;

			internal SSAOMaterialParams(ref ScreenSpaceAmbientOcclusionSettings settings, bool isOrthographic)
			{
				bool flag = settings.Source == ScreenSpaceAmbientOcclusionSettings.DepthSource.DepthNormals;
				float num = ((settings.AOMethod == ScreenSpaceAmbientOcclusionSettings.AOMethodOptions.BlueNoise) ? 1.5f : 1f);
				orthographicCamera = isOrthographic;
				aoBlueNoise = settings.AOMethod == ScreenSpaceAmbientOcclusionSettings.AOMethodOptions.BlueNoise;
				aoInterleavedGradient = settings.AOMethod == ScreenSpaceAmbientOcclusionSettings.AOMethodOptions.InterleavedGradient;
				sampleCountHigh = settings.Samples == ScreenSpaceAmbientOcclusionSettings.AOSampleOption.High;
				sampleCountMedium = settings.Samples == ScreenSpaceAmbientOcclusionSettings.AOSampleOption.Medium;
				sampleCountLow = settings.Samples == ScreenSpaceAmbientOcclusionSettings.AOSampleOption.Low;
				sourceDepthNormals = settings.Source == ScreenSpaceAmbientOcclusionSettings.DepthSource.DepthNormals;
				sourceDepthHigh = !flag && settings.NormalSamples == ScreenSpaceAmbientOcclusionSettings.NormalQuality.High;
				sourceDepthMedium = !flag && settings.NormalSamples == ScreenSpaceAmbientOcclusionSettings.NormalQuality.Medium;
				sourceDepthLow = !flag && settings.NormalSamples == ScreenSpaceAmbientOcclusionSettings.NormalQuality.Low;
				ssaoParams = new Vector4(settings.Intensity, settings.Radius * num, 1f / (float)((!settings.Downsample) ? 1 : 2), settings.Falloff);
			}

			internal bool Equals(ref SSAOMaterialParams other)
			{
				if (orthographicCamera == other.orthographicCamera && aoBlueNoise == other.aoBlueNoise && aoInterleavedGradient == other.aoInterleavedGradient && sampleCountHigh == other.sampleCountHigh && sampleCountMedium == other.sampleCountMedium && sampleCountLow == other.sampleCountLow && sourceDepthNormals == other.sourceDepthNormals && sourceDepthHigh == other.sourceDepthHigh && sourceDepthMedium == other.sourceDepthMedium && sourceDepthLow == other.sourceDepthLow)
				{
					return ssaoParams == other.ssaoParams;
				}
				return false;
			}
		}

		private class SSAOPassData
		{
			internal bool afterOpaque;

			internal ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions BlurQuality;

			internal Material material;

			internal float directLightingStrength;

			internal TextureHandle cameraColor;

			internal TextureHandle AOTexture;

			internal TextureHandle finalTexture;

			internal TextureHandle blurTexture;

			internal TextureHandle cameraNormalsTexture;

			internal UniversalCameraData cameraData;
		}

		private readonly bool m_SupportsR8RenderTextureFormat = SystemInfo.SupportsRenderTextureFormat(RenderTextureFormat.R8);

		private int m_BlueNoiseTextureIndex;

		private Material m_Material;

		private Texture2D[] m_BlueNoiseTextures;

		private Vector4[] m_CameraTopLeftCorner = new Vector4[2];

		private Vector4[] m_CameraXExtent = new Vector4[2];

		private Vector4[] m_CameraYExtent = new Vector4[2];

		private Vector4[] m_CameraZExtent = new Vector4[2];

		private BlurTypes m_BlurType;

		private Matrix4x4[] m_CameraViewProjections = new Matrix4x4[2];

		private ProfilingSampler m_ProfilingSampler = ProfilingSampler.Get(URPProfileId.SSAO);

		private RenderTextureDescriptor m_AOPassDescriptor;

		private ScreenSpaceAmbientOcclusionSettings m_CurrentSettings;

		private const string k_SSAOTextureName = "_ScreenSpaceOcclusionTexture";

		private const string k_AmbientOcclusionParamName = "_AmbientOcclusionParam";

		internal static readonly int s_AmbientOcclusionParamID = Shader.PropertyToID("_AmbientOcclusionParam");

		private static readonly int s_SSAOParamsID = Shader.PropertyToID("_SSAOParams");

		private static readonly int s_SSAOBlueNoiseParamsID = Shader.PropertyToID("_SSAOBlueNoiseParams");

		private static readonly int s_BlueNoiseTextureID = Shader.PropertyToID("_BlueNoiseTexture");

		private static readonly int s_SSAOFinalTextureID = Shader.PropertyToID("_ScreenSpaceOcclusionTexture");

		private static readonly int s_CameraViewXExtentID = Shader.PropertyToID("_CameraViewXExtent");

		private static readonly int s_CameraViewYExtentID = Shader.PropertyToID("_CameraViewYExtent");

		private static readonly int s_CameraViewZExtentID = Shader.PropertyToID("_CameraViewZExtent");

		private static readonly int s_ProjectionParams2ID = Shader.PropertyToID("_ProjectionParams2");

		private static readonly int s_CameraViewProjectionsID = Shader.PropertyToID("_CameraViewProjections");

		private static readonly int s_CameraViewTopLeftCornerID = Shader.PropertyToID("_CameraViewTopLeftCorner");

		private static readonly int s_CameraNormalsTextureID = Shader.PropertyToID("_CameraNormalsTexture");

		private SSAOMaterialParams m_SSAOParamsPrev;

		internal ScreenSpaceAmbientOcclusionPass()
		{
			m_CurrentSettings = new ScreenSpaceAmbientOcclusionSettings();
		}

		internal bool Setup(ref ScreenSpaceAmbientOcclusionSettings featureSettings, ref ScriptableRenderer renderer, ref Material material, ref Texture2D[] blueNoiseTextures)
		{
			m_BlueNoiseTextures = blueNoiseTextures;
			m_Material = material;
			m_CurrentSettings = featureSettings;
			if (renderer is UniversalRenderer { usesDeferredLighting: not false })
			{
				base.renderPassEvent = (m_CurrentSettings.AfterOpaque ? RenderPassEvent.AfterRenderingOpaques : RenderPassEvent.AfterRenderingGbuffer);
				m_CurrentSettings.Source = ScreenSpaceAmbientOcclusionSettings.DepthSource.DepthNormals;
			}
			else
			{
				base.renderPassEvent = (m_CurrentSettings.AfterOpaque ? RenderPassEvent.BeforeRenderingTransparents : ((RenderPassEvent)201));
			}
			switch (m_CurrentSettings.Source)
			{
			case ScreenSpaceAmbientOcclusionSettings.DepthSource.Depth:
				ConfigureInput(ScriptableRenderPassInput.Depth);
				break;
			case ScreenSpaceAmbientOcclusionSettings.DepthSource.DepthNormals:
				ConfigureInput(ScriptableRenderPassInput.Depth | ScriptableRenderPassInput.Normal);
				break;
			default:
				throw new ArgumentOutOfRangeException();
			}
			switch (m_CurrentSettings.BlurQuality)
			{
			case ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions.High:
				m_BlurType = BlurTypes.Bilateral;
				break;
			case ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions.Medium:
				m_BlurType = BlurTypes.Gaussian;
				break;
			case ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions.Low:
				m_BlurType = BlurTypes.Kawase;
				break;
			default:
				throw new ArgumentOutOfRangeException();
			}
			if (m_Material != null && m_CurrentSettings.Intensity > 0f && m_CurrentSettings.Radius > 0f)
			{
				return m_CurrentSettings.Falloff > 0f;
			}
			return false;
		}

		private void SetupKeywordsAndParameters(ref ScreenSpaceAmbientOcclusionSettings settings, ref UniversalCameraData cameraData)
		{
			int num = ((!cameraData.xr.enabled || !cameraData.xr.singlePassEnabled) ? 1 : 2);
			for (int i = 0; i < num; i++)
			{
				Matrix4x4 viewMatrix = cameraData.GetViewMatrix(i);
				Matrix4x4 projectionMatrix = cameraData.GetProjectionMatrix(i);
				m_CameraViewProjections[i] = projectionMatrix * viewMatrix;
				Matrix4x4 matrix4x = viewMatrix;
				matrix4x.SetColumn(3, new Vector4(0f, 0f, 0f, 1f));
				Matrix4x4 inverse = (projectionMatrix * matrix4x).inverse;
				Vector4 vector = inverse.MultiplyPoint(new Vector4(-1f, 1f, -1f, 1f));
				Vector4 vector2 = inverse.MultiplyPoint(new Vector4(1f, 1f, -1f, 1f));
				Vector4 vector3 = inverse.MultiplyPoint(new Vector4(-1f, -1f, -1f, 1f));
				Vector4 vector4 = inverse.MultiplyPoint(new Vector4(0f, 0f, 1f, 1f));
				m_CameraTopLeftCorner[i] = vector;
				m_CameraXExtent[i] = vector2 - vector;
				m_CameraYExtent[i] = vector3 - vector;
				m_CameraZExtent[i] = vector4;
			}
			m_Material.SetVector(s_ProjectionParams2ID, new Vector4(1f / cameraData.camera.nearClipPlane, 0f, 0f, 0f));
			m_Material.SetMatrixArray(s_CameraViewProjectionsID, m_CameraViewProjections);
			m_Material.SetVectorArray(s_CameraViewTopLeftCornerID, m_CameraTopLeftCorner);
			m_Material.SetVectorArray(s_CameraViewXExtentID, m_CameraXExtent);
			m_Material.SetVectorArray(s_CameraViewYExtentID, m_CameraYExtent);
			m_Material.SetVectorArray(s_CameraViewZExtentID, m_CameraZExtent);
			if (settings.AOMethod == ScreenSpaceAmbientOcclusionSettings.AOMethodOptions.BlueNoise)
			{
				m_BlueNoiseTextureIndex = (m_BlueNoiseTextureIndex + 1) % m_BlueNoiseTextures.Length;
				Texture2D value = m_BlueNoiseTextures[m_BlueNoiseTextureIndex];
				Vector4 value2 = new Vector4((float)cameraData.pixelWidth / (float)m_BlueNoiseTextures[m_BlueNoiseTextureIndex].width, (float)cameraData.pixelHeight / (float)m_BlueNoiseTextures[m_BlueNoiseTextureIndex].height, Random.value, Random.value);
				m_Material.SetTexture(s_BlueNoiseTextureID, value);
				m_Material.SetVector(s_SSAOBlueNoiseParamsID, value2);
			}
			SSAOMaterialParams other = new SSAOMaterialParams(ref settings, cameraData.camera.orthographic);
			bool num2 = !m_SSAOParamsPrev.Equals(ref other);
			bool flag = m_Material.HasProperty(s_SSAOParamsID);
			if (!(!num2 && flag))
			{
				m_SSAOParamsPrev = other;
				CoreUtils.SetKeyword(m_Material, "_ORTHOGRAPHIC", other.orthographicCamera);
				CoreUtils.SetKeyword(m_Material, "_BLUE_NOISE", other.aoBlueNoise);
				CoreUtils.SetKeyword(m_Material, "_INTERLEAVED_GRADIENT", other.aoInterleavedGradient);
				CoreUtils.SetKeyword(m_Material, "_SAMPLE_COUNT_HIGH", other.sampleCountHigh);
				CoreUtils.SetKeyword(m_Material, "_SAMPLE_COUNT_MEDIUM", other.sampleCountMedium);
				CoreUtils.SetKeyword(m_Material, "_SAMPLE_COUNT_LOW", other.sampleCountLow);
				CoreUtils.SetKeyword(m_Material, "_SOURCE_DEPTH_NORMALS", other.sourceDepthNormals);
				CoreUtils.SetKeyword(m_Material, "_SOURCE_DEPTH_HIGH", other.sourceDepthHigh);
				CoreUtils.SetKeyword(m_Material, "_SOURCE_DEPTH_MEDIUM", other.sourceDepthMedium);
				CoreUtils.SetKeyword(m_Material, "_SOURCE_DEPTH_LOW", other.sourceDepthLow);
				m_Material.SetVector(s_SSAOParamsID, other.ssaoParams);
			}
		}

		private void InitSSAOPassData(ref SSAOPassData data)
		{
			data.material = m_Material;
			data.BlurQuality = m_CurrentSettings.BlurQuality;
			data.afterOpaque = m_CurrentSettings.AfterOpaque;
			data.directLightingStrength = m_CurrentSettings.DirectLightingStrength;
		}

		private static Vector4 ComputeScaleBias(in UnsafeGraphContext context, in TextureHandle source, in TextureHandle destination)
		{
			RTHandle rTHandle = source;
			Vector2 one = default(Vector2);
			if (rTHandle != null && rTHandle.useScaling)
			{
				one.x = rTHandle.rtHandleProperties.rtHandleScale.x;
				one.y = rTHandle.rtHandleProperties.rtHandleScale.y;
			}
			else
			{
				one = Vector2.one;
			}
			if (context.GetTextureUVOrigin(in source) != context.GetTextureUVOrigin(in destination))
			{
				return new Vector4(one.x, 0f - one.y, 0f, one.y);
			}
			return new Vector4(one.x, one.y, 0f, 0f);
		}

		public override void RecordRenderGraph(RenderGraph renderGraph, ContextContainer frameData)
		{
			UniversalCameraData cameraData = frameData.Get<UniversalCameraData>();
			UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
			CreateRenderTextureHandles(renderGraph, universalResourceData, cameraData, out var aoTexture, out var blurTexture, out var finalTexture);
			TextureHandle cameraDepthTexture = universalResourceData.cameraDepthTexture;
			TextureHandle cameraNormalsTexture = universalResourceData.cameraNormalsTexture;
			SetupKeywordsAndParameters(ref m_CurrentSettings, ref cameraData);
			SSAOPassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<SSAOPassData>("Blit SSAO", out passData, m_ProfilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\ScreenSpaceAmbientOcclusionPass.cs", 369);
			unsafeRenderGraphBuilder.AllowGlobalStateModification(value: true);
			InitSSAOPassData(ref passData);
			passData.cameraColor = universalResourceData.cameraColor;
			passData.AOTexture = aoTexture;
			passData.finalTexture = finalTexture;
			passData.blurTexture = blurTexture;
			passData.cameraData = cameraData;
			unsafeRenderGraphBuilder.UseTexture(in passData.AOTexture, AccessFlags.ReadWrite);
			if (universalResourceData.cameraColor.IsValid())
			{
				unsafeRenderGraphBuilder.UseTexture(universalResourceData.cameraColor);
			}
			if (passData.BlurQuality != ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions.Low)
			{
				unsafeRenderGraphBuilder.UseTexture(in passData.blurTexture, AccessFlags.ReadWrite);
			}
			if (cameraDepthTexture.IsValid())
			{
				unsafeRenderGraphBuilder.UseTexture(in cameraDepthTexture);
			}
			if (m_CurrentSettings.Source == ScreenSpaceAmbientOcclusionSettings.DepthSource.DepthNormals && cameraNormalsTexture.IsValid())
			{
				unsafeRenderGraphBuilder.UseTexture(in cameraNormalsTexture);
				passData.cameraNormalsTexture = cameraNormalsTexture;
			}
			if (!passData.afterOpaque && finalTexture.IsValid())
			{
				unsafeRenderGraphBuilder.UseTexture(in passData.finalTexture, AccessFlags.Write);
				unsafeRenderGraphBuilder.SetGlobalTextureAfterPass(in finalTexture, s_SSAOFinalTextureID);
			}
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(SSAOPassData data, UnsafeGraphContext rgContext)
			{
				CommandBuffer nativeCommandBuffer = CommandBufferHelpers.GetNativeCommandBuffer(rgContext.cmd);
				RenderBufferLoadAction loadAction = ((!data.afterOpaque) ? RenderBufferLoadAction.DontCare : RenderBufferLoadAction.Load);
				PostProcessUtils.SetSourceSize(nativeCommandBuffer, data.cameraData.cameraTargetDescriptor.width, data.cameraData.cameraTargetDescriptor.height, data.cameraColor);
				if (data.cameraNormalsTexture.IsValid())
				{
					data.material.SetTexture(s_CameraNormalsTextureID, data.cameraNormalsTexture);
				}
				Blitter.BlitCameraTexture(nativeCommandBuffer, data.AOTexture, data.AOTexture, RenderBufferLoadAction.DontCare, RenderBufferStoreAction.Store, data.material, 0);
				switch (data.BlurQuality)
				{
				case ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions.High:
				{
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.AOTexture, data.blurTexture, RenderBufferLoadAction.DontCare, RenderBufferStoreAction.Store, data.material, 1);
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.blurTexture, data.AOTexture, RenderBufferLoadAction.DontCare, RenderBufferStoreAction.Store, data.material, 2);
					Vector4 scaleBias = ComputeScaleBias(in rgContext, in data.AOTexture, in data.finalTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.AOTexture, data.finalTexture, scaleBias, loadAction, RenderBufferStoreAction.Store, data.material, data.afterOpaque ? 4 : 3);
					break;
				}
				case ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions.Medium:
				{
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.AOTexture, data.blurTexture, RenderBufferLoadAction.Load, RenderBufferStoreAction.Store, data.material, 5);
					Vector4 scaleBias = ComputeScaleBias(in rgContext, in data.blurTexture, in data.finalTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.blurTexture, data.finalTexture, scaleBias, loadAction, RenderBufferStoreAction.Store, data.material, data.afterOpaque ? 7 : 6);
					break;
				}
				case ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions.Low:
				{
					Vector4 scaleBias = ComputeScaleBias(in rgContext, in data.AOTexture, in data.finalTexture);
					Blitter.BlitCameraTexture(nativeCommandBuffer, data.AOTexture, data.finalTexture, scaleBias, loadAction, RenderBufferStoreAction.Store, data.material, data.afterOpaque ? 9 : 8);
					break;
				}
				default:
					throw new ArgumentOutOfRangeException();
				}
				if (!data.afterOpaque)
				{
					rgContext.cmd.SetKeyword(in ShaderGlobalKeywords.ScreenSpaceOcclusion, value: true);
					rgContext.cmd.SetGlobalVector(s_AmbientOcclusionParamID, new Vector4(1f, 0f, 0f, data.directLightingStrength));
				}
			});
		}

		private void CreateRenderTextureHandles(RenderGraph renderGraph, UniversalResourceData resourceData, UniversalCameraData cameraData, out TextureHandle aoTexture, out TextureHandle blurTexture, out TextureHandle finalTexture)
		{
			RenderTextureDescriptor cameraTargetDescriptor = cameraData.cameraTargetDescriptor;
			cameraTargetDescriptor.colorFormat = (m_SupportsR8RenderTextureFormat ? RenderTextureFormat.R8 : RenderTextureFormat.ARGB32);
			cameraTargetDescriptor.depthStencilFormat = GraphicsFormat.None;
			cameraTargetDescriptor.msaaSamples = 1;
			int num = ((!m_CurrentSettings.Downsample) ? 1 : 2);
			bool flag = m_SupportsR8RenderTextureFormat && m_BlurType > BlurTypes.Bilateral;
			RenderTextureDescriptor desc = cameraTargetDescriptor;
			desc.colorFormat = (flag ? RenderTextureFormat.R8 : RenderTextureFormat.ARGB32);
			desc.width /= num;
			desc.height /= num;
			aoTexture = UniversalRenderer.CreateRenderGraphTexture(renderGraph, desc, "_SSAO_OcclusionTexture0", clear: false, FilterMode.Bilinear);
			finalTexture = (m_CurrentSettings.AfterOpaque ? resourceData.activeColorTexture : UniversalRenderer.CreateRenderGraphTexture(renderGraph, cameraTargetDescriptor, "_ScreenSpaceOcclusionTexture", clear: false, FilterMode.Bilinear));
			if (m_CurrentSettings.BlurQuality != ScreenSpaceAmbientOcclusionSettings.BlurQualityOptions.Low)
			{
				blurTexture = UniversalRenderer.CreateRenderGraphTexture(renderGraph, desc, "_SSAO_OcclusionTexture1", clear: false, FilterMode.Bilinear);
			}
			else
			{
				blurTexture = TextureHandle.nullHandle;
			}
			if (!m_CurrentSettings.AfterOpaque)
			{
				resourceData.ssaoTexture = finalTexture;
			}
		}

		public override void OnCameraCleanup(CommandBuffer cmd)
		{
			if (cmd == null)
			{
				throw new ArgumentNullException("cmd");
			}
			if (!m_CurrentSettings.AfterOpaque)
			{
				cmd.SetKeyword(in ShaderGlobalKeywords.ScreenSpaceOcclusion, value: false);
			}
		}

		public void Dispose()
		{
			m_SSAOParamsPrev = default(SSAOMaterialParams);
		}
	}
}
