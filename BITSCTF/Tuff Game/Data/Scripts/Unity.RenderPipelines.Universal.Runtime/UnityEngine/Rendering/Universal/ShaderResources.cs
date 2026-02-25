using System;

namespace UnityEngine.Rendering.Universal
{
	[Serializable]
	[ReloadGroup]
	[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
	public sealed class ShaderResources
	{
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		[Reload("Shaders/Utils/Blit.shader", ReloadAttribute.Package.Root)]
		public Shader blitPS;

		[Reload("Shaders/Utils/CopyDepth.shader", ReloadAttribute.Package.Root)]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		public Shader copyDepthPS;

		[Obsolete("Obsolete, this feature will be supported by new 'ScreenSpaceShadows' renderer feature. #from(2023.3) #breakingFrom(2023.3)", true)]
		public Shader screenSpaceShadowPS;

		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		[Reload("Shaders/Utils/Sampling.shader", ReloadAttribute.Package.Root)]
		public Shader samplingPS;

		[Reload("Shaders/Utils/StencilDeferred.shader", ReloadAttribute.Package.Root)]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		public Shader stencilDeferredPS;

		[Reload("Shaders/Utils/FallbackError.shader", ReloadAttribute.Package.Root)]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		public Shader fallbackErrorPS;

		[Reload("Shaders/Utils/FallbackLoading.shader", ReloadAttribute.Package.Root)]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		public Shader fallbackLoadingPS;

		[Obsolete("Use fallbackErrorPS instead. #from(2023.3) #breakingFrom(2023.3)", true)]
		public Shader materialErrorPS;

		[Reload("Shaders/Utils/CoreBlit.shader", ReloadAttribute.Package.Root)]
		[SerializeField]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		internal Shader coreBlitPS;

		[Reload("Shaders/Utils/CoreBlitColorAndDepth.shader", ReloadAttribute.Package.Root)]
		[SerializeField]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		internal Shader coreBlitColorAndDepthPS;

		[Reload("Shaders/Utils/BlitHDROverlay.shader", ReloadAttribute.Package.Root)]
		[SerializeField]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		internal Shader blitHDROverlay;

		[Reload("Shaders/CameraMotionVectors.shader", ReloadAttribute.Package.Root)]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		public Shader cameraMotionVector;

		[Reload("Shaders/PostProcessing/LensFlareScreenSpace.shader", ReloadAttribute.Package.Root)]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		public Shader screenSpaceLensFlare;

		[Reload("Shaders/PostProcessing/LensFlareDataDriven.shader", ReloadAttribute.Package.Root)]
		[Obsolete("Moved to UniversalRenderPipelineRuntimeShaders on GraphicsSettings. #from(2023.3)")]
		public Shader dataDrivenLensFlare;
	}
}
