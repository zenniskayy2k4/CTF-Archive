using UnityEngine.Bindings;

namespace UnityEngine.UIElements.StyleSheets.Syntax
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum DataType
	{
		None = 0,
		Number = 1,
		Integer = 2,
		Length = 3,
		Percentage = 4,
		Color = 5,
		Resource = 6,
		Url = 7,
		Time = 8,
		FilterFunction = 9,
		Prop = 10,
		Angle = 11,
		CustomIdent = 12,
		Ratio = 13
	}
}
