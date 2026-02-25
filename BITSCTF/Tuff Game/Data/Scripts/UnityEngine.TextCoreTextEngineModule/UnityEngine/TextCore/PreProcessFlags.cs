using UnityEngine.Bindings;

namespace UnityEngine.TextCore
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal enum PreProcessFlags
	{
		None = 0,
		CollapseWhiteSpaces = 1,
		ParseEscapeSequences = 2
	}
}
