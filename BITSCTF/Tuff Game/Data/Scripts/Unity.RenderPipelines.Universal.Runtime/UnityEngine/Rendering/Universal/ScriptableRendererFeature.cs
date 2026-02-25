using System;

namespace UnityEngine.Rendering.Universal
{
	[ExcludeFromPreset]
	public abstract class ScriptableRendererFeature : ScriptableObject, IDisposable
	{
		[Obsolete("This enum is not used. #from(6000.3)", false)]
		public enum IntermediateTextureUsage
		{
			Unknown = 0,
			Required = 1,
			NotRequired = 2
		}

		[SerializeField]
		[HideInInspector]
		private bool m_Active = true;

		public bool isActive => m_Active;

		[Obsolete("This property is not used. #from(6000.3)", false)]
		protected virtual IntermediateTextureUsage useIntermediateTextures => IntermediateTextureUsage.Unknown;

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public virtual void SetupRenderPasses(ScriptableRenderer renderer, in RenderingData renderingData)
		{
		}

		public abstract void Create();

		public virtual void OnCameraPreCull(ScriptableRenderer renderer, in CameraData cameraData)
		{
		}

		public abstract void AddRenderPasses(ScriptableRenderer renderer, ref RenderingData renderingData);

		private void OnEnable()
		{
			if (RenderPipelineManager.currentPipeline is UniversalRenderPipeline)
			{
				Create();
			}
		}

		private void OnValidate()
		{
			if (RenderPipelineManager.currentPipeline is UniversalRenderPipeline)
			{
				Create();
			}
		}

		internal virtual bool RequireRenderingLayers(bool isDeferred, bool needsGBufferAccurateNormals, out RenderingLayerUtils.Event atEvent, out RenderingLayerUtils.MaskSize maskSize)
		{
			atEvent = RenderingLayerUtils.Event.DepthNormalPrePass;
			maskSize = RenderingLayerUtils.MaskSize.Bits8;
			return false;
		}

		public void SetActive(bool active)
		{
			m_Active = active;
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
		}
	}
}
