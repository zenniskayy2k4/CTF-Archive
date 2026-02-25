using UnityEngine.Bindings;

namespace UnityEngine.TextCore
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal enum LanguageDirection
	{
		LTR = 0,
		RTL = 1
	}
}
