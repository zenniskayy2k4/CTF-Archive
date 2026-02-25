using UnityEngine.Bindings;
using UnityEngine.Scripting.APIUpdating;

namespace UnityEngine.Rendering
{
	[NativeHeader("Runtime/Graphics/ShaderScriptBindings.h")]
	[MovedFrom("UnityEngine.Experimental.Rendering")]
	[NativeHeader("Runtime/Shaders/RayTracing/RayTracingShader.h")]
	[NativeHeader("Runtime/Graphics/RayTracing/RayTracingAccelerationStructure.h")]
	internal class RayTracingShaderHelpURLAttribute : HelpURLAttribute
	{
		public override string URL => $"https://docs.unity3d.com//{Application.unityVersionVer}.{Application.unityVersionMaj}/Documentation/ScriptReference/Rendering.RayTracingShader.html";

		public RayTracingShaderHelpURLAttribute()
			: base(null)
		{
		}
	}
}
