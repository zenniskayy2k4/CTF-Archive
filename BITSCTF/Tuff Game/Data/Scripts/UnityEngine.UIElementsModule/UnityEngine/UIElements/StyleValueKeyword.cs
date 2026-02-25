using UnityEngine.Bindings;

namespace UnityEngine.UIElements
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum StyleValueKeyword
	{
		Inherit = 0,
		Initial = 1,
		Auto = 2,
		Unset = 3,
		True = 4,
		False = 5,
		None = 6,
		Cover = 7,
		Contain = 8
	}
}
