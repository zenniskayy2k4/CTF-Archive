using UnityEngine.Bindings;

namespace UnityEngine.InputForUI
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal enum EventSource
	{
		Unspecified = 0,
		Keyboard = 1,
		Gamepad = 2,
		Mouse = 3,
		Pen = 4,
		Touch = 5,
		TrackedDevice = 6
	}
}
