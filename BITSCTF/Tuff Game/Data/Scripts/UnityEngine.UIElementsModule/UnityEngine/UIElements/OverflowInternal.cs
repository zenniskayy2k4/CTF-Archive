using UnityEngine.Bindings;

namespace UnityEngine.UIElements
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum OverflowInternal
	{
		Visible = 0,
		Hidden = 1,
		Scroll = 2
	}
}
