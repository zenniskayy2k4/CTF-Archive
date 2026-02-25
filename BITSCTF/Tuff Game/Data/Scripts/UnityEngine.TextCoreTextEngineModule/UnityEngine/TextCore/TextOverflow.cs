using UnityEngine.Bindings;

namespace UnityEngine.TextCore
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal enum TextOverflow
	{
		Clip = 0,
		Ellipsis = 1
	}
}
