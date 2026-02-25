using System;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal.Internal
{
	public class MainLightShadowCasterPass : ScriptableRenderPass
	{
		private static class MainLightShadowConstantBuffer
		{
			public static readonly int _WorldToShadow = Shader.PropertyToID("_MainLightWorldToShadow");

			public static readonly int _ShadowParams = Shader.PropertyToID("_MainLightShadowParams");

			public static readonly int _CascadeShadowSplitSpheres0 = Shader.PropertyToID("_CascadeShadowSplitSpheres0");

			public static readonly int _CascadeShadowSplitSpheres1 = Shader.PropertyToID("_CascadeShadowSplitSpheres1");

			public static readonly int _CascadeShadowSplitSpheres2 = Shader.PropertyToID("_CascadeShadowSplitSpheres2");

			public static readonly int _CascadeShadowSplitSpheres3 = Shader.PropertyToID("_CascadeShadowSplitSpheres3");

			public static readonly int _CascadeShadowSplitSphereRadii = Shader.PropertyToID("_CascadeShadowSplitSphereRadii");

			public static readonly int _ShadowOffset0 = Shader.PropertyToID("_MainLightShadowOffset0");

			public static readonly int _ShadowOffset1 = Shader.PropertyToID("_MainLightShadowOffset1");

			public static readonly int _ShadowmapSize = Shader.PropertyToID("_MainLightShadowmapSize");

			public static readonly int _MainLightShadowmapID = Shader.PropertyToID("_MainLightShadowmapTexture");
		}

		private class PassData
		{
			internal bool emptyShadowmap;

			internal bool setKeywordForEmptyShadowmap;

			internal UniversalRenderingData renderingData;

			internal UniversalCameraData cameraData;

			internal UniversalLightData lightData;

			internal UniversalShadowData shadowData;

			internal MainLightShadowCasterPass pass;

			internal TextureHandle shadowmapTexture;

			internal readonly RendererList[] shadowRendererLists = new RendererList[4];

			internal readonly RendererListHandle[] shadowRendererListsHandle = new RendererListHandle[4];
		}

		internal RTHandle m_MainLightShadowmapTexture;

		private int m_RenderTargetWidth;

		private int m_RenderTargetHeight;

		private int m_ShadowCasterCascadesCount;

		private bool m_CreateEmptyShadowmap;

		private bool m_SetKeywordForEmptyShadowmap;

		private float m_CascadeBorder;

		private float m_MaxShadowDistanceSq;

		private RenderTextureDescriptor m_MainLightShadowDescriptor;

		private readonly Vector4[] m_CascadeSplitDistances;

		private readonly Matrix4x4[] m_MainLightShadowMatrices;

		private readonly ProfilingSampler m_ProfilingSetupSampler = new ProfilingSampler("Setup Main Shadowmap");

		private readonly ShadowSliceData[] m_CascadeSlices;

		private const int k_EmptyShadowMapDimensions = 1;

		private const int k_MaxCascades = 4;

		private const int k_ShadowmapBufferBits = 16;

		private const string k_MainLightShadowMapTextureName = "_MainLightShadowmapTexture";

		private static Vector4 s_EmptyShadowParams = new Vector4(0f, 0f, 1f, 0f);

		private static readonly Vector4 s_EmptyShadowmapSize = new Vector4(1f, 1f, 1f, 1f);

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Configure(CommandBuffer cmd, RenderTextureDescriptor cameraTextureDescriptor)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public override void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		public MainLightShadowCasterPass(RenderPassEvent evt)
		{
			base.profilingSampler = new ProfilingSampler("Draw Main Light Shadowmap");
			base.renderPassEvent = evt;
			m_MainLightShadowMatrices = new Matrix4x4[5];
			m_CascadeSlices = new ShadowSliceData[4];
			m_CascadeSplitDistances = new Vector4[4];
		}

		public void Dispose()
		{
			m_MainLightShadowmapTexture?.Release();
		}

		public bool Setup(ref RenderingData renderingData)
		{
			ContextContainer frameData = renderingData.frameData;
			UniversalRenderingData renderingData2 = frameData.Get<UniversalRenderingData>();
			UniversalCameraData cameraData = frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = frameData.Get<UniversalLightData>();
			UniversalShadowData shadowData = frameData.Get<UniversalShadowData>();
			return Setup(renderingData2, cameraData, lightData, shadowData);
		}

		public bool Setup(UniversalRenderingData renderingData, UniversalCameraData cameraData, UniversalLightData lightData, UniversalShadowData shadowData)
		{
			bool mainLightShadowsEnabled = shadowData.mainLightShadowsEnabled;
			bool supportsMainLightShadows = shadowData.supportsMainLightShadows;
			using (new ProfilingScope(m_ProfilingSetupSampler))
			{
				bool stripShadowsOffVariants = cameraData.renderer.stripShadowsOffVariants;
				Clear();
				int mainLightIndex = lightData.mainLightIndex;
				if (mainLightIndex == -1 || (cameraData.camera.targetTexture != null && cameraData.camera.targetTexture.format == RenderTextureFormat.Depth))
				{
					if (mainLightShadowsEnabled)
					{
						return SetupForEmptyRendering(stripShadowsOffVariants, mainLightShadowsEnabled, null, cameraData, shadowData);
					}
					return false;
				}
				VisibleLight visibleLight = lightData.visibleLights[mainLightIndex];
				Light light = visibleLight.light;
				if (supportsMainLightShadows && light.shadows == LightShadows.None)
				{
					return SetupForEmptyRendering(stripShadowsOffVariants, mainLightShadowsEnabled, light, cameraData, shadowData);
				}
				if (!mainLightShadowsEnabled)
				{
					if (light.shadows != LightShadows.None && light.bakingOutput.isBaked && light.bakingOutput.mixedLightingMode != MixedLightingMode.IndirectOnly && light.bakingOutput.lightmapBakeType == LightmapBakeType.Mixed)
					{
						return SetupForEmptyRendering(stripShadowsOffVariants, mainLightShadowsEnabled, light, cameraData, shadowData);
					}
					return false;
				}
				if (!supportsMainLightShadows)
				{
					return SetupForEmptyRendering(stripShadowsOffVariants, mainLightShadowsEnabled, null, cameraData, shadowData);
				}
				if (visibleLight.lightType != LightType.Directional)
				{
					Debug.LogWarning("Only directional lights are supported as main light.");
				}
				if (!renderingData.cullResults.GetShadowCasterBounds(mainLightIndex, out var _))
				{
					return SetupForEmptyRendering(stripShadowsOffVariants, mainLightShadowsEnabled, light, cameraData, shadowData);
				}
				m_ShadowCasterCascadesCount = shadowData.mainLightShadowCascadesCount;
				m_RenderTargetWidth = shadowData.mainLightRenderTargetWidth;
				m_RenderTargetHeight = shadowData.mainLightRenderTargetHeight;
				ref URPLightShadowCullingInfos reference = ref shadowData.visibleLightsShadowCullingInfos.UnsafeElementAt(mainLightIndex);
				for (int i = 0; i < m_ShadowCasterCascadesCount; i++)
				{
					ref ShadowSliceData reference2 = ref reference.slices.UnsafeElementAt(i);
					Vector4[] cascadeSplitDistances = m_CascadeSplitDistances;
					int num = i;
					ShadowSplitData splitData = reference2.splitData;
					cascadeSplitDistances[num] = splitData.cullingSphere;
					m_CascadeSlices[i] = reference2;
					if (!reference.IsSliceValid(i))
					{
						return SetupForEmptyRendering(stripShadowsOffVariants, mainLightShadowsEnabled, light, cameraData, shadowData);
					}
				}
				UpdateTextureDescriptorIfNeeded();
				m_MaxShadowDistanceSq = cameraData.maxShadowDistance * cameraData.maxShadowDistance;
				m_CascadeBorder = shadowData.mainLightShadowCascadeBorder;
				m_CreateEmptyShadowmap = false;
				return true;
			}
		}

		private void UpdateTextureDescriptorIfNeeded()
		{
			if (m_MainLightShadowDescriptor.width != m_RenderTargetWidth || m_MainLightShadowDescriptor.height != m_RenderTargetHeight || m_MainLightShadowDescriptor.depthBufferBits != 16 || m_MainLightShadowDescriptor.colorFormat != RenderTextureFormat.Shadowmap)
			{
				m_MainLightShadowDescriptor = new RenderTextureDescriptor(m_RenderTargetWidth, m_RenderTargetHeight, RenderTextureFormat.Shadowmap, 16);
			}
		}

		private bool SetupForEmptyRendering(bool stripShadowsOffVariants, bool shadowsEnabled, Light light, UniversalCameraData cameraData, UniversalShadowData shadowData)
		{
			if (!stripShadowsOffVariants)
			{
				return false;
			}
			m_CreateEmptyShadowmap = true;
			m_SetKeywordForEmptyShadowmap = shadowsEnabled;
			if (light == null)
			{
				s_EmptyShadowParams = new Vector4(0f, 0f, 1f, 0f);
			}
			else
			{
				bool supportsSoftShadows = shadowData.supportsSoftShadows;
				float maxShadowDistance = cameraData.maxShadowDistance;
				float mainLightShadowCascadeBorder = shadowData.mainLightShadowCascadeBorder;
				bool softShadowsEnabled = light.shadows == LightShadows.Soft && supportsSoftShadows;
				float y = ShadowUtils.SoftShadowQualityToShaderProperty(light, softShadowsEnabled);
				ShadowUtils.GetScaleAndBiasForLinearDistanceFade(maxShadowDistance, mainLightShadowCascadeBorder, out var scale, out var bias);
				s_EmptyShadowParams = new Vector4(light.shadowStrength, y, scale, bias);
			}
			return true;
		}

		private void Clear()
		{
			for (int i = 0; i < m_MainLightShadowMatrices.Length; i++)
			{
				m_MainLightShadowMatrices[i] = Matrix4x4.identity;
			}
			for (int j = 0; j < m_CascadeSplitDistances.Length; j++)
			{
				m_CascadeSplitDistances[j] = new Vector4(0f, 0f, 0f, 0f);
			}
			for (int k = 0; k < m_CascadeSlices.Length; k++)
			{
				m_CascadeSlices[k].Clear();
			}
		}

		internal static void SetShadowParamsForEmptyShadowmap(RasterCommandBuffer rasterCommandBuffer)
		{
			rasterCommandBuffer.SetGlobalVector(MainLightShadowConstantBuffer._ShadowmapSize, s_EmptyShadowmapSize);
			rasterCommandBuffer.SetGlobalVector(MainLightShadowConstantBuffer._ShadowParams, s_EmptyShadowParams);
		}

		private void RenderMainLightCascadeShadowmap(RasterCommandBuffer cmd, ref PassData data, bool isRenderGraph)
		{
			UniversalLightData lightData = data.lightData;
			int mainLightIndex = lightData.mainLightIndex;
			if (mainLightIndex == -1)
			{
				return;
			}
			VisibleLight shadowLight = lightData.visibleLights[mainLightIndex];
			using (new ProfilingScope(cmd, ProfilingSampler.Get(URPProfileId.MainLightShadow)))
			{
				ShadowUtils.SetCameraPosition(cmd, data.cameraData.worldSpaceCameraPos);
				if (!isRenderGraph)
				{
					ShadowUtils.SetWorldToCameraAndCameraToWorldMatrices(cmd, data.cameraData.GetViewMatrix());
				}
				for (int i = 0; i < m_ShadowCasterCascadesCount; i++)
				{
					Vector4 shadowBias = ShadowUtils.GetShadowBias(ref shadowLight, mainLightIndex, data.shadowData, m_CascadeSlices[i].projectionMatrix, m_CascadeSlices[i].resolution);
					ShadowUtils.SetupShadowCasterConstantBuffer(cmd, ref shadowLight, shadowBias);
					cmd.SetKeyword(in ShaderGlobalKeywords.CastingPunctualLightShadow, value: false);
					RendererList shadowRendererList = (isRenderGraph ? ((RendererList)data.shadowRendererListsHandle[i]) : data.shadowRendererLists[i]);
					ShadowUtils.RenderShadowSlice(cmd, ref m_CascadeSlices[i], ref shadowRendererList, m_CascadeSlices[i].projectionMatrix, m_CascadeSlices[i].viewMatrix);
				}
				data.shadowData.isKeywordSoftShadowsEnabled = shadowLight.light.shadows == LightShadows.Soft && data.shadowData.supportsSoftShadows;
				cmd.SetKeyword(in ShaderGlobalKeywords.MainLightShadows, data.shadowData.mainLightShadowCascadesCount == 1);
				cmd.SetKeyword(in ShaderGlobalKeywords.MainLightShadowCascades, data.shadowData.mainLightShadowCascadesCount > 1);
				ShadowUtils.SetSoftShadowQualityShaderKeywords(cmd, data.shadowData);
				SetupMainLightShadowReceiverConstants(cmd, ref shadowLight, data.shadowData);
			}
		}

		private void SetupMainLightShadowReceiverConstants(RasterCommandBuffer cmd, ref VisibleLight shadowLight, UniversalShadowData shadowData)
		{
			Light light = shadowLight.light;
			bool softShadowsEnabled = shadowLight.light.shadows == LightShadows.Soft && shadowData.supportsSoftShadows;
			int shadowCasterCascadesCount = m_ShadowCasterCascadesCount;
			for (int i = 0; i < shadowCasterCascadesCount; i++)
			{
				m_MainLightShadowMatrices[i] = m_CascadeSlices[i].shadowTransform;
			}
			Matrix4x4 zero = Matrix4x4.zero;
			zero.m22 = (SystemInfo.usesReversedZBuffer ? 1f : 0f);
			for (int j = shadowCasterCascadesCount; j <= 4; j++)
			{
				m_MainLightShadowMatrices[j] = zero;
			}
			float num = 1f / (float)m_RenderTargetWidth;
			float num2 = 1f / (float)m_RenderTargetHeight;
			float num3 = 0.5f * num;
			float num4 = 0.5f * num2;
			float y = ShadowUtils.SoftShadowQualityToShaderProperty(light, softShadowsEnabled);
			ShadowUtils.GetScaleAndBiasForLinearDistanceFade(m_MaxShadowDistanceSq, m_CascadeBorder, out var scale, out var bias);
			cmd.SetGlobalMatrixArray(MainLightShadowConstantBuffer._WorldToShadow, m_MainLightShadowMatrices);
			cmd.SetGlobalVector(MainLightShadowConstantBuffer._ShadowParams, new Vector4(light.shadowStrength, y, scale, bias));
			if (m_ShadowCasterCascadesCount > 1)
			{
				cmd.SetGlobalVector(MainLightShadowConstantBuffer._CascadeShadowSplitSpheres0, m_CascadeSplitDistances[0]);
				cmd.SetGlobalVector(MainLightShadowConstantBuffer._CascadeShadowSplitSpheres1, m_CascadeSplitDistances[1]);
				cmd.SetGlobalVector(MainLightShadowConstantBuffer._CascadeShadowSplitSpheres2, m_CascadeSplitDistances[2]);
				cmd.SetGlobalVector(MainLightShadowConstantBuffer._CascadeShadowSplitSpheres3, m_CascadeSplitDistances[3]);
				cmd.SetGlobalVector(MainLightShadowConstantBuffer._CascadeShadowSplitSphereRadii, new Vector4(m_CascadeSplitDistances[0].w * m_CascadeSplitDistances[0].w, m_CascadeSplitDistances[1].w * m_CascadeSplitDistances[1].w, m_CascadeSplitDistances[2].w * m_CascadeSplitDistances[2].w, m_CascadeSplitDistances[3].w * m_CascadeSplitDistances[3].w));
			}
			if (shadowData.supportsSoftShadows)
			{
				cmd.SetGlobalVector(MainLightShadowConstantBuffer._ShadowOffset0, new Vector4(0f - num3, 0f - num4, num3, 0f - num4));
				cmd.SetGlobalVector(MainLightShadowConstantBuffer._ShadowOffset1, new Vector4(0f - num3, num4, num3, num4));
				cmd.SetGlobalVector(MainLightShadowConstantBuffer._ShadowmapSize, new Vector4(num, num2, m_RenderTargetWidth, m_RenderTargetHeight));
			}
		}

		private void InitPassData(ref PassData passData, UniversalRenderingData renderingData, UniversalCameraData cameraData, UniversalLightData lightData, UniversalShadowData shadowData)
		{
			passData.pass = this;
			passData.emptyShadowmap = m_CreateEmptyShadowmap;
			passData.setKeywordForEmptyShadowmap = m_SetKeywordForEmptyShadowmap;
			passData.renderingData = renderingData;
			passData.cameraData = cameraData;
			passData.lightData = lightData;
			passData.shadowData = shadowData;
		}

		private void InitRendererLists(ref PassData passData, ScriptableRenderContext context, RenderGraph renderGraph, bool useRenderGraph)
		{
			int mainLightIndex = passData.lightData.mainLightIndex;
			if (m_CreateEmptyShadowmap || mainLightIndex == -1)
			{
				return;
			}
			ShadowDrawingSettings shadowDrawingSettings = new ShadowDrawingSettings(passData.renderingData.cullResults, mainLightIndex);
			shadowDrawingSettings.useRenderingLayerMaskTest = UniversalRenderPipeline.asset.useRenderingLayers;
			ShadowDrawingSettings settings = shadowDrawingSettings;
			for (int i = 0; i < m_ShadowCasterCascadesCount; i++)
			{
				if (useRenderGraph)
				{
					passData.shadowRendererListsHandle[i] = renderGraph.CreateShadowRendererList(ref settings);
				}
				else
				{
					passData.shadowRendererLists[i] = context.CreateShadowRendererList(ref settings);
				}
			}
		}

		internal TextureHandle Render(RenderGraph graph, ContextContainer frameData)
		{
			UniversalRenderingData renderingData = frameData.Get<UniversalRenderingData>();
			UniversalCameraData cameraData = frameData.Get<UniversalCameraData>();
			UniversalLightData lightData = frameData.Get<UniversalLightData>();
			UniversalShadowData shadowData = frameData.Get<UniversalShadowData>();
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = graph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\MainLightShadowCasterPass.cs", 482);
			InitPassData(ref passData, renderingData, cameraData, lightData, shadowData);
			InitRendererLists(ref passData, default(ScriptableRenderContext), graph, useRenderGraph: true);
			TextureHandle textureHandle;
			if (!m_CreateEmptyShadowmap)
			{
				for (int i = 0; i < m_ShadowCasterCascadesCount; i++)
				{
					rasterRenderGraphBuilder.UseRendererList(in passData.shadowRendererListsHandle[i]);
				}
				textureHandle = UniversalRenderer.CreateRenderGraphTexture(graph, m_MainLightShadowDescriptor, "_MainLightShadowmapTexture", clear: true, (!ShadowUtils.m_ForceShadowPointSampling) ? FilterMode.Bilinear : FilterMode.Point);
				rasterRenderGraphBuilder.SetRenderAttachmentDepth(textureHandle);
			}
			else
			{
				textureHandle = graph.defaultResources.defaultShadowTexture;
			}
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			if (textureHandle.IsValid())
			{
				rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in textureHandle, MainLightShadowConstantBuffer._MainLightShadowmapID);
			}
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				RasterCommandBuffer cmd = context.cmd;
				if (!data.emptyShadowmap)
				{
					data.pass.RenderMainLightCascadeShadowmap(cmd, ref data, isRenderGraph: true);
				}
				else
				{
					if (data.setKeywordForEmptyShadowmap)
					{
						cmd.EnableKeyword(in ShaderGlobalKeywords.MainLightShadows);
					}
					SetShadowParamsForEmptyShadowmap(cmd);
				}
			});
			return textureHandle;
		}
	}
}
