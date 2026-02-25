using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngineInternal.Video
{
	[VisibleToOtherModules(new string[] { "UnityEditor.MediaModule" })]
	[UsedByNativeCode]
	internal enum VideoAlphaLayout
	{
		Native = 0,
		Split = 1
	}
}
