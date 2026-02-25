using UnityEngine.Bindings;

namespace UnityEngine.UIElements
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum MaterialPropertyValueType
	{
		Float = 0,
		Vector = 1,
		Color = 2,
		Texture = 3
	}
}
