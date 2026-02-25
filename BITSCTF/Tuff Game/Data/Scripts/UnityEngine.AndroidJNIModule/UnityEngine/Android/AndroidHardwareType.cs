using System;

namespace UnityEngine.Android
{
	public enum AndroidHardwareType
	{
		Generic = 0,
		[Obsolete("ChromeOS is no longer supported.")]
		ChromeOS = 1
	}
}
