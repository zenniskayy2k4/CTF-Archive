using UnityEngine.Bindings;

namespace UnityEngine.TextCore
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal enum WhiteSpace
	{
		Normal = 0,
		NoWrap = 1,
		Pre = 2,
		PreWrap = 3
	}
}
