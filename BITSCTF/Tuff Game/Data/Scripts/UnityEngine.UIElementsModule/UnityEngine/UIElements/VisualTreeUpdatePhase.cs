using UnityEngine.Bindings;

namespace UnityEngine.UIElements
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum VisualTreeUpdatePhase
	{
		Bindings = 0,
		DataBinding = 1,
		Animation = 2,
		Styles = 3,
		Layout = 4,
		TransformClip = 5,
		Repaint = 6,
		Authoring = 7,
		Count = 8
	}
}
