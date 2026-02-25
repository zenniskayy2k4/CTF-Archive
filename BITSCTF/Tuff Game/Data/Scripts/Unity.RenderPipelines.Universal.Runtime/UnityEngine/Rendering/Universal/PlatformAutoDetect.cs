namespace UnityEngine.Rendering.Universal
{
	internal static class PlatformAutoDetect
	{
		internal static bool isRunningOnPowerVRGPU = SystemInfo.graphicsDeviceName.Contains("PowerVR");

		internal static bool isXRMobile { get; private set; } = false;

		internal static bool isShaderAPIMobileDefined { get; private set; } = false;

		internal static bool isSwitch { get; private set; } = false;

		internal static bool isSwitch2 { get; private set; } = false;

		internal static void Initialize()
		{
			isXRMobile = false;
			isShaderAPIMobileDefined = GraphicsSettings.HasShaderDefine(BuiltinShaderDefine.SHADER_API_MOBILE);
			isSwitch = Application.platform == RuntimePlatform.Switch;
			isSwitch2 = Application.platform == RuntimePlatform.Switch2;
		}

		internal static ShEvalMode ShAutoDetect(ShEvalMode mode)
		{
			if (mode == ShEvalMode.Auto)
			{
				if (isXRMobile || isShaderAPIMobileDefined || isSwitch || isSwitch2)
				{
					return ShEvalMode.PerVertex;
				}
				return ShEvalMode.PerPixel;
			}
			return mode;
		}
	}
}
