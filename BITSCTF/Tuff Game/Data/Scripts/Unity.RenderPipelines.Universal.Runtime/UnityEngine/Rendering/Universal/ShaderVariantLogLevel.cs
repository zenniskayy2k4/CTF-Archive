using System;

namespace UnityEngine.Rendering.Universal
{
	[Obsolete("This is obsolete, UnityEngine.Rendering.ShaderVariantLogLevel instead. #from(2022.2) #breakingFrom(2023.1)", true)]
	public enum ShaderVariantLogLevel
	{
		Disabled = 0,
		[InspectorName("Only URP Shaders")]
		OnlyUniversalRPShaders = 1,
		[InspectorName("All Shaders")]
		AllShaders = 2
	}
}
