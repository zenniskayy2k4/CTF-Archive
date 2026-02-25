using UnityEngine;
using UnityEngine.Rendering;
using UnityEngine.Rendering.RenderGraphModule;
using UnityEngine.Rendering.Universal;
using UnityEngine.Rendering.Universal.Internal;

[DisallowMultipleRendererFeature("On Tile Post Processing (Untethered XR)")]
public class OnTilePostProcessFeature : ScriptableRendererFeature
{
	[SerializeField]
	[HideInInspector]
	private PostProcessData m_PostProcessData;

	private Shader m_UberPostShader;

	private RenderPassEvent postProcessingEvent = (RenderPassEvent)599;

	private Material m_OnTilePostProcessMaterial;

	private ColorGradingLutPass m_ColorGradingLutPass;

	private OnTilePostProcessPass m_OnTilePostProcessPass;

	private bool TryLoadResources()
	{
		if (m_UberPostShader == null || m_OnTilePostProcessMaterial == null)
		{
			if (!GraphicsSettings.TryGetRenderPipelineSettings<OnTilePostProcessResource>(out var settings))
			{
				Debug.LogErrorFormat("Couldn't find the required resources for the OnTilePostProcessFeature render feature.");
				return false;
			}
			m_UberPostShader = settings.uberPostShader;
			m_OnTilePostProcessMaterial = new Material(m_UberPostShader);
		}
		return true;
	}

	public override void Create()
	{
		_ = m_PostProcessData == null;
		if (m_PostProcessData != null)
		{
			m_ColorGradingLutPass = new ColorGradingLutPass(RenderPassEvent.BeforeRenderingPrePasses, m_PostProcessData);
			m_OnTilePostProcessPass = new OnTilePostProcessPass(m_PostProcessData);
			m_OnTilePostProcessPass.requiresIntermediateTexture = true;
		}
	}

	private bool IsRuntimePlatformUntetheredXR()
	{
		return Application.platform == RuntimePlatform.Android;
	}

	public override void AddRenderPasses(ScriptableRenderer renderer, ref RenderingData renderingData)
	{
		bool flag = true;
		if (renderingData.cameraData.xr.enabled && IsRuntimePlatformUntetheredXR())
		{
			flag = false;
		}
		if (!renderingData.cameraData.postProcessEnabled)
		{
			return;
		}
		if ((renderer as UniversalRenderer).isPostProcessPassRenderGraphActive)
		{
			Debug.LogError("URP renderer(Universal Renderer Data) has post processing enabled, which conflicts with the On-Tile post processing feature. Only one of the post processing should be enabled. On-Tile post processing feature will not be added.");
		}
		else
		{
			if (m_ColorGradingLutPass == null || m_OnTilePostProcessPass == null || !TryLoadResources())
			{
				return;
			}
			GraphicsDeviceType graphicsDeviceType = SystemInfo.graphicsDeviceType;
			if (graphicsDeviceType != GraphicsDeviceType.Vulkan && graphicsDeviceType != GraphicsDeviceType.Metal && graphicsDeviceType != GraphicsDeviceType.Direct3D12)
			{
				Debug.LogError("The On-Tile post processing feature is not supported on the graphics devices that don't support frame buffer fetch.");
				return;
			}
			UniversalRenderPipeline.renderTextureUVOriginStrategy = RenderTextureUVOriginStrategy.PropagateAttachmentOrientation;
			m_ColorGradingLutPass.renderPassEvent = RenderPassEvent.BeforeRenderingPrePasses;
			m_OnTilePostProcessPass.Setup(ref m_OnTilePostProcessMaterial);
			m_OnTilePostProcessPass.renderPassEvent = postProcessingEvent;
			if (flag)
			{
				m_OnTilePostProcessPass.m_UseTextureReadFallback = true;
				UniversalRenderPipeline.renderTextureUVOriginStrategy = RenderTextureUVOriginStrategy.BottomLeft;
			}
			else
			{
				m_OnTilePostProcessPass.m_UseTextureReadFallback = false;
			}
			renderer.EnqueuePass(m_ColorGradingLutPass);
			renderer.EnqueuePass(m_OnTilePostProcessPass);
		}
	}

	protected override void Dispose(bool disposing)
	{
		m_ColorGradingLutPass?.Cleanup();
	}
}
