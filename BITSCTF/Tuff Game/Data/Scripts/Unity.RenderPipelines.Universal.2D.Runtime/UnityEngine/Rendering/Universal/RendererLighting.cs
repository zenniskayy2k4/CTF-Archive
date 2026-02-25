using Unity.Mathematics;
using UnityEngine.Experimental.Rendering;

namespace UnityEngine.Rendering.Universal
{
	internal static class RendererLighting
	{
		private static readonly ProfilingSampler m_ProfilingSampler = new ProfilingSampler("Draw Normals");

		private static readonly ShaderTagId k_NormalsRenderingPassName = new ShaderTagId("NormalsRendering");

		public static readonly Color k_NormalClearColor = new Color(0.5f, 0.5f, 0.5f, 1f);

		private static readonly string k_UsePointLightCookiesKeyword = "USE_POINT_LIGHT_COOKIES";

		private static readonly string k_LightQualityFastKeyword = "LIGHT_QUALITY_FAST";

		private static readonly string k_UseNormalMap = "USE_NORMAL_MAP";

		private static readonly string k_UseShadowMap = "USE_SHADOW_MAP";

		private static readonly string k_UseAdditiveBlendingKeyword = "USE_ADDITIVE_BLENDING";

		private static readonly string k_UseVolumetric = "USE_VOLUMETRIC";

		private static readonly string[] k_UseBlendStyleKeywords = new string[4] { "USE_SHAPE_LIGHT_TYPE_0", "USE_SHAPE_LIGHT_TYPE_1", "USE_SHAPE_LIGHT_TYPE_2", "USE_SHAPE_LIGHT_TYPE_3" };

		private static readonly int[] k_BlendFactorsPropIDs = new int[4]
		{
			Shader.PropertyToID("_ShapeLightBlendFactors0"),
			Shader.PropertyToID("_ShapeLightBlendFactors1"),
			Shader.PropertyToID("_ShapeLightBlendFactors2"),
			Shader.PropertyToID("_ShapeLightBlendFactors3")
		};

		private static readonly int[] k_MaskFilterPropIDs = new int[4]
		{
			Shader.PropertyToID("_ShapeLightMaskFilter0"),
			Shader.PropertyToID("_ShapeLightMaskFilter1"),
			Shader.PropertyToID("_ShapeLightMaskFilter2"),
			Shader.PropertyToID("_ShapeLightMaskFilter3")
		};

		private static readonly int[] k_InvertedFilterPropIDs = new int[4]
		{
			Shader.PropertyToID("_ShapeLightInvertedFilter0"),
			Shader.PropertyToID("_ShapeLightInvertedFilter1"),
			Shader.PropertyToID("_ShapeLightInvertedFilter2"),
			Shader.PropertyToID("_ShapeLightInvertedFilter3")
		};

		public static readonly string[] k_ShapeLightTextureIDs = new string[4] { "_ShapeLightTexture0", "_ShapeLightTexture1", "_ShapeLightTexture2", "_ShapeLightTexture3" };

		private static GraphicsFormat s_RenderTextureFormatToUse = GraphicsFormat.R8G8B8A8_UNorm;

		private static bool s_HasSetupRenderTextureFormatToUse;

		private static readonly int k_SrcBlendID = Shader.PropertyToID("_SrcBlend");

		private static readonly int k_DstBlendID = Shader.PropertyToID("_DstBlend");

		private static readonly int k_CookieTexID = Shader.PropertyToID("_CookieTex");

		private static readonly int k_PointLightCookieTexID = Shader.PropertyToID("_PointLightCookieTex");

		private static readonly int k_L2DInvMatrix = Shader.PropertyToID("L2DInvMatrix");

		private static readonly int k_L2DColor = Shader.PropertyToID("L2DColor");

		private static readonly int k_L2DPosition = Shader.PropertyToID("L2DPosition");

		private static readonly int k_L2DFalloffIntensity = Shader.PropertyToID("L2DFalloffIntensity");

		private static readonly int k_L2DFalloffDistance = Shader.PropertyToID("L2DFalloffDistance");

		private static readonly int k_L2DOuterAngle = Shader.PropertyToID("L2DOuterAngle");

		private static readonly int k_L2DInnerAngle = Shader.PropertyToID("L2DInnerAngle");

		private static readonly int k_L2DInnerRadiusMult = Shader.PropertyToID("L2DInnerRadiusMult");

		private static readonly int k_L2DVolumeOpacity = Shader.PropertyToID("L2DVolumeOpacity");

		private static readonly int k_L2DShadowIntensity = Shader.PropertyToID("L2DShadowIntensity");

		private static readonly int k_L2DLightType = Shader.PropertyToID("L2DLightType");

		internal static LightBatch lightBatch = new LightBatch();

		internal static GraphicsFormat GetRenderTextureFormat()
		{
			if (!s_HasSetupRenderTextureFormatToUse)
			{
				if (SystemInfo.IsFormatSupported(GraphicsFormat.B10G11R11_UFloatPack32, GraphicsFormatUsage.Blend))
				{
					s_RenderTextureFormatToUse = GraphicsFormat.B10G11R11_UFloatPack32;
				}
				else if (SystemInfo.IsFormatSupported(GraphicsFormat.R16G16B16A16_SFloat, GraphicsFormatUsage.Blend))
				{
					s_RenderTextureFormatToUse = GraphicsFormat.R16G16B16A16_SFloat;
				}
				s_HasSetupRenderTextureFormatToUse = true;
			}
			return s_RenderTextureFormatToUse;
		}

		internal static void EnableBlendStyle(IRasterCommandBuffer cmd, int blendStyleIndex, bool enabled)
		{
			string keyword = k_UseBlendStyleKeywords[blendStyleIndex];
			if (enabled)
			{
				cmd.EnableShaderKeyword(keyword);
			}
			else
			{
				cmd.DisableShaderKeyword(keyword);
			}
		}

		internal static void DisableAllKeywords(IRasterCommandBuffer cmd)
		{
			string[] array = k_UseBlendStyleKeywords;
			foreach (string keyword in array)
			{
				cmd.DisableShaderKeyword(keyword);
			}
		}

		internal static void GetTransparencySortingMode(Renderer2DData rendererData, Camera camera, ref SortingSettings sortingSettings)
		{
			TransparencySortMode transparencySortMode = rendererData.transparencySortMode;
			if (transparencySortMode == TransparencySortMode.Default)
			{
				transparencySortMode = ((!camera.orthographic) ? TransparencySortMode.Perspective : TransparencySortMode.Orthographic);
			}
			switch (transparencySortMode)
			{
			case TransparencySortMode.Perspective:
				sortingSettings.distanceMetric = DistanceMetric.Perspective;
				break;
			case TransparencySortMode.Orthographic:
				sortingSettings.distanceMetric = DistanceMetric.Orthographic;
				break;
			default:
				sortingSettings.distanceMetric = DistanceMetric.CustomAxis;
				sortingSettings.customAxis = rendererData.transparencySortAxis;
				break;
			}
		}

		internal static bool CanCastShadows(Light2D light, int layerToRender)
		{
			if (light.shadowsEnabled && light.shadowIntensity > 0f)
			{
				return light.IsLitLayer(layerToRender);
			}
			return false;
		}

		internal static void SetLightShaderGlobals(IRasterCommandBuffer cmd, Light2DBlendStyle[] lightBlendStyles, int[] blendStyleIndices)
		{
			foreach (int num in blendStyleIndices)
			{
				if (num < k_BlendFactorsPropIDs.Length)
				{
					Light2DBlendStyle light2DBlendStyle = lightBlendStyles[num];
					cmd.SetGlobalVector(k_BlendFactorsPropIDs[num], light2DBlendStyle.blendFactors);
					cmd.SetGlobalVector(k_MaskFilterPropIDs[num], light2DBlendStyle.maskTextureChannelFilter.mask);
					cmd.SetGlobalVector(k_InvertedFilterPropIDs[num], light2DBlendStyle.maskTextureChannelFilter.inverted);
					continue;
				}
				break;
			}
		}

		private static float GetNormalizedInnerRadius(Light2D light)
		{
			return light.pointLightInnerRadius / light.pointLightOuterRadius;
		}

		private static float GetNormalizedAngle(float angle)
		{
			return angle / 360f;
		}

		private static void GetScaledLightInvMatrix(Light2D light, out Matrix4x4 retMatrix)
		{
			float pointLightOuterRadius = light.pointLightOuterRadius;
			Vector3 one = Vector3.one;
			Vector3 s = new Vector3(one.x * pointLightOuterRadius, one.y * pointLightOuterRadius, one.z * pointLightOuterRadius);
			Transform transform = light.transform;
			Matrix4x4 m = Matrix4x4.TRS(transform.position, transform.rotation, s);
			retMatrix = Matrix4x4.Inverse(m);
		}

		internal static void SetPerLightShaderGlobals(IRasterCommandBuffer cmd, Light2D light, int slot, bool isVolumetric, bool hasShadows, bool batchingSupported)
		{
			Color value = light.intensity * light.color.a * light.color;
			value.a = 1f;
			float num = (light.volumetricEnabled ? light.volumeIntensity : 1f);
			if (batchingSupported)
			{
				PerLight2D light2 = lightBatch.GetLight(slot);
				light2.Position = new float4(light.transform.position, light.normalMapDistance);
				light2.FalloffIntensity = light.falloffIntensity;
				light2.FalloffDistance = light.shapeLightFalloffSize;
				light2.Color = new float4(value.r, value.g, value.b, value.a);
				light2.VolumeOpacity = num;
				light2.LightType = (int)light.lightType;
				light2.ShadowIntensity = 1f;
				if (hasShadows)
				{
					light2.ShadowIntensity = (isVolumetric ? (1f - light.shadowVolumeIntensity) : (1f - light.shadowIntensity));
				}
				lightBatch.SetLight(slot, light2);
			}
			else
			{
				cmd.SetGlobalVector(k_L2DPosition, new float4(light.transform.position, light.normalMapDistance));
				cmd.SetGlobalFloat(k_L2DFalloffIntensity, light.falloffIntensity);
				cmd.SetGlobalFloat(k_L2DFalloffDistance, light.shapeLightFalloffSize);
				cmd.SetGlobalColor(k_L2DColor, value);
				cmd.SetGlobalFloat(k_L2DVolumeOpacity, num);
				cmd.SetGlobalInt(k_L2DLightType, (int)light.lightType);
				cmd.SetGlobalFloat(k_L2DShadowIntensity, (!hasShadows) ? 1f : (isVolumetric ? (1f - light.shadowVolumeIntensity) : (1f - light.shadowIntensity)));
			}
			if (hasShadows)
			{
				ShadowRendering.SetGlobalShadowProp(cmd);
			}
		}

		internal static void SetPerPointLightShaderGlobals(IRasterCommandBuffer cmd, Light2D light, int slot, bool batchingSupported)
		{
			GetScaledLightInvMatrix(light, out var retMatrix);
			float normalizedInnerRadius = GetNormalizedInnerRadius(light);
			float normalizedAngle = GetNormalizedAngle(light.pointLightInnerAngle);
			float normalizedAngle2 = GetNormalizedAngle(light.pointLightOuterAngle);
			float num = 1f / (1f - normalizedInnerRadius);
			if (batchingSupported)
			{
				PerLight2D light2 = lightBatch.GetLight(slot);
				light2.InvMatrix = new float4x4(retMatrix.GetColumn(0), retMatrix.GetColumn(1), retMatrix.GetColumn(2), retMatrix.GetColumn(3));
				light2.InnerRadiusMult = num;
				light2.InnerAngle = normalizedAngle;
				light2.OuterAngle = normalizedAngle2;
				lightBatch.SetLight(slot, light2);
			}
			else
			{
				cmd.SetGlobalMatrix(k_L2DInvMatrix, retMatrix);
				cmd.SetGlobalFloat(k_L2DInnerRadiusMult, num);
				cmd.SetGlobalFloat(k_L2DInnerAngle, normalizedAngle);
				cmd.SetGlobalFloat(k_L2DOuterAngle, normalizedAngle2);
			}
		}

		internal static void SetCookieShaderProperties(Light2D light, MaterialPropertyBlock properties)
		{
			if (light.useCookieSprite && light.m_CookieSpriteTextureHandle.IsValid())
			{
				properties.SetTexture((light.lightType == Light2D.LightType.Sprite) ? k_CookieTexID : k_PointLightCookieTexID, light.m_CookieSpriteTextureHandle);
			}
		}

		private static void SetBlendModes(Material material, BlendMode src, BlendMode dst)
		{
			material.SetFloat(k_SrcBlendID, (float)src);
			material.SetFloat(k_DstBlendID, (float)dst);
		}

		private static uint GetLightMaterialIndex(Light2D light, bool isVolume, bool useShadows)
		{
			bool isPointLight = light.isPointLight;
			int num = 0;
			uint num2 = (isVolume ? ((uint)(1 << num)) : 0u);
			num++;
			uint num3 = ((isVolume && !isPointLight) ? ((uint)(1 << num)) : 0u);
			num++;
			uint num4 = ((light.overlapOperation != Light2D.OverlapOperation.AlphaBlend) ? ((uint)(1 << num)) : 0u);
			num++;
			uint num5 = ((isPointLight && light.lightCookieSprite != null && light.lightCookieSprite.texture != null) ? ((uint)(1 << num)) : 0u);
			num++;
			int num6 = ((light.normalMapQuality == Light2D.NormalMapQuality.Fast) ? (1 << num) : 0);
			num++;
			uint num7 = ((light.normalMapQuality != Light2D.NormalMapQuality.Disabled) ? ((uint)(1 << num)) : 0u);
			num++;
			uint num8 = (useShadows ? ((uint)(1 << num)) : 0u);
			return (uint)num6 | num5 | num4 | num3 | num2 | num7 | num8;
		}

		private static Material CreateLightMaterial(Renderer2DData rendererData, Light2D light, bool isVolume, bool useShadows)
		{
			if (!GraphicsSettings.TryGetRenderPipelineSettings<Renderer2DResources>(out var settings))
			{
				return null;
			}
			bool isPointLight = light.isPointLight;
			Material material = CoreUtils.CreateEngineMaterial(settings.lightShader);
			if (!isVolume)
			{
				if (light.overlapOperation == Light2D.OverlapOperation.Additive)
				{
					SetBlendModes(material, BlendMode.One, BlendMode.One);
					material.EnableKeyword(k_UseAdditiveBlendingKeyword);
				}
				else
				{
					SetBlendModes(material, BlendMode.SrcAlpha, BlendMode.OneMinusSrcAlpha);
				}
			}
			else
			{
				material.EnableKeyword(k_UseVolumetric);
				if (light.lightType == Light2D.LightType.Point)
				{
					SetBlendModes(material, BlendMode.One, BlendMode.One);
				}
				else
				{
					SetBlendModes(material, BlendMode.SrcAlpha, BlendMode.One);
				}
			}
			if (isPointLight && light.lightCookieSprite != null && light.lightCookieSprite.texture != null)
			{
				material.EnableKeyword(k_UsePointLightCookiesKeyword);
			}
			if (light.normalMapQuality == Light2D.NormalMapQuality.Fast)
			{
				material.EnableKeyword(k_LightQualityFastKeyword);
			}
			if (light.normalMapQuality != Light2D.NormalMapQuality.Disabled)
			{
				material.EnableKeyword(k_UseNormalMap);
			}
			if (useShadows)
			{
				material.EnableKeyword(k_UseShadowMap);
			}
			return material;
		}

		internal static Material GetLightMaterial(this Renderer2DData rendererData, Light2D light, bool isVolume, bool useShadows)
		{
			uint lightMaterialIndex = GetLightMaterialIndex(light, isVolume, useShadows);
			if (!rendererData.lightMaterials.TryGetValue(lightMaterialIndex, out var value))
			{
				value = CreateLightMaterial(rendererData, light, isVolume, useShadows);
				rendererData.lightMaterials[lightMaterialIndex] = value;
			}
			return value;
		}

		internal static short GetCameraSortingLayerBoundsIndex(this Renderer2DData rendererData)
		{
			SortingLayer[] cachedSortingLayer = Light2DManager.GetCachedSortingLayer();
			for (short num = 0; num < cachedSortingLayer.Length; num++)
			{
				if (cachedSortingLayer[num].id == rendererData.cameraSortingLayerTextureBound)
				{
					return (short)cachedSortingLayer[num].value;
				}
			}
			return short.MinValue;
		}
	}
}
