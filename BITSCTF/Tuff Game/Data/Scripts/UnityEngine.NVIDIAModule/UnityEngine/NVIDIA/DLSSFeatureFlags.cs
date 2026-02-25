using System;

namespace UnityEngine.NVIDIA
{
	[Flags]
	public enum DLSSFeatureFlags
	{
		None = 0,
		IsHDR = 1,
		MVLowRes = 2,
		MVJittered = 4,
		DepthInverted = 8,
		[Obsolete("Sharpening is deprecated by NVIDIA. It is no longer used and will be removed in a future release.")]
		DoSharpening = 0x10,
		AutoExposure = 0x20
	}
}
