using UnityEngine.Bindings;

namespace UnityEngine.UIElements.StyleSheets.Syntax
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum ExpressionType
	{
		Unknown = 0,
		Data = 1,
		Keyword = 2,
		Combinator = 3
	}
}
