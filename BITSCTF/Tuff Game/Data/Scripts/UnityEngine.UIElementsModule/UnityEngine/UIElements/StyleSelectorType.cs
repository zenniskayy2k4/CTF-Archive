using UnityEngine.Bindings;

namespace UnityEngine.UIElements
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum StyleSelectorType
	{
		Unknown = 0,
		Wildcard = 1,
		Type = 2,
		Class = 3,
		PseudoClass = 4,
		RecursivePseudoClass = 5,
		ID = 6,
		Predicate = 7
	}
}
