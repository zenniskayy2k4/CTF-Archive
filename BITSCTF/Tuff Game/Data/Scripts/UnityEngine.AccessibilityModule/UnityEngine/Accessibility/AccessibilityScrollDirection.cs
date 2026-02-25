using UnityEngine.Bindings;

namespace UnityEngine.Accessibility
{
	[NativeHeader("Modules/Accessibility/Native/AccessibilityNodeData.h")]
	public enum AccessibilityScrollDirection : byte
	{
		Unknown = 0,
		Forward = 1,
		Backward = 2,
		Left = 3,
		Right = 4,
		Up = 5,
		Down = 6
	}
}
