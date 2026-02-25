using UnityEngine.Bindings;

namespace UnityEngine.TextCore.Text
{
	[VisibleToOtherModules(new string[] { "UnityEngine.IMGUIModule", "UnityEngine.UIElementsModule" })]
	internal enum TextWrappingMode
	{
		NoWrap = 0,
		Normal = 1,
		PreserveWhitespace = 2,
		PreserveWhitespaceNoWrap = 3
	}
}
