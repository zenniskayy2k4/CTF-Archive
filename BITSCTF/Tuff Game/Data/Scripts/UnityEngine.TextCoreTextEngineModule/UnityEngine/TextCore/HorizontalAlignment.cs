using UnityEngine.Bindings;

namespace UnityEngine.TextCore
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal enum HorizontalAlignment
	{
		Left = 0,
		Center = 1,
		Right = 2,
		Justified = 3,
		Flush = 4
	}
}
