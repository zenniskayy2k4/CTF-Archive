using UnityEngine.Bindings;

namespace UnityEngine.UIElements
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum StyleSelectorRelationship
	{
		None = 0,
		Child = 1,
		Descendent = 2
	}
}
