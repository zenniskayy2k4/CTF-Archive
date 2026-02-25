using System.Runtime.InteropServices;

namespace UnityEngine.Rendering.Universal
{
	[StructLayout(LayoutKind.Sequential, Size = 1)]
	internal struct DeprecationMessage
	{
		internal const string CompatibilityScriptingAPIHidden = "This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.";
	}
}
