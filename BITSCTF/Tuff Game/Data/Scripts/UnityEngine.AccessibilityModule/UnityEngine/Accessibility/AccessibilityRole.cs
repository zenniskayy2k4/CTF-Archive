using UnityEngine.Bindings;

namespace UnityEngine.Accessibility
{
	[NativeHeader("Modules/Accessibility/Native/AccessibilityNodeData.h")]
	public enum AccessibilityRole : byte
	{
		None = 0,
		Button = 1,
		Image = 2,
		StaticText = 3,
		SearchField = 4,
		KeyboardKey = 5,
		Header = 6,
		TabBar = 7,
		Slider = 8,
		Toggle = 9,
		Container = 10,
		TextField = 11,
		Dropdown = 12,
		TabButton = 13,
		ScrollView = 14
	}
}
