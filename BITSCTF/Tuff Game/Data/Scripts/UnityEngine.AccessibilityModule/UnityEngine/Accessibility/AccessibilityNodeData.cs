using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.Accessibility
{
	[RequiredByNativeCode]
	[NativeType(CodegenOptions.Custom, "MonoAccessibilityNodeData")]
	[NativeHeader("Modules/Accessibility/Bindings/AccessibilityNodeData.bindings.h")]
	[NativeHeader("Modules/Accessibility/Native/AccessibilityNodeData.h")]
	internal struct AccessibilityNodeData
	{
		public int[] childIds { get; set; }

		public string label { get; set; }

		public string value { get; set; }

		public string hint { get; set; }

		public Rect frame { get; set; }

		public int nodeId { get; set; }

		public int parentId { get; set; }

		public AccessibilityRole role { get; set; }

		public AccessibilityState state { get; set; }

		public bool isActive { get; set; }

		public bool allowsDirectInteraction { get; set; }

		public bool implementsInvoked { get; set; }

		public bool implementsScrolled { get; set; }

		public bool implementsDismissed { get; set; }

		public AccessibilityNodeData()
		{
			nodeId = -1;
			parentId = -1;
			childIds = new int[0];
			isActive = true;
			frame = default(Rect);
			label = null;
			value = null;
			hint = null;
			role = AccessibilityRole.None;
			state = AccessibilityState.None;
			allowsDirectInteraction = false;
			implementsInvoked = false;
			implementsScrolled = false;
			implementsDismissed = false;
		}
	}
}
