using Unity.IntegerTime;
using UnityEngine.Bindings;

namespace UnityEngine.InputForUI
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal struct CommandEvent : IEventProperties
	{
		public enum Type
		{
			Validate = 1,
			Execute = 2
		}

		public enum Command
		{
			Invalid = 0,
			Cut = 1,
			Copy = 2,
			Paste = 3,
			SelectAll = 4,
			DeselectAll = 5,
			InvertSelection = 6,
			Duplicate = 7,
			Rename = 8,
			Delete = 9,
			SoftDelete = 10,
			Find = 11,
			SelectChildren = 12,
			SelectPrefabRoot = 13,
			UndoRedoPerformed = 14,
			OnLostFocus = 15,
			NewKeyboardFocus = 16,
			ModifierKeysChanged = 17,
			EyeDropperUpdate = 18,
			EyeDropperClicked = 19,
			EyeDropperCancelled = 20,
			ColorPickerChanged = 21,
			FrameSelected = 22,
			FrameSelectedWithLock = 23
		}

		public Type type;

		public Command command;

		public DiscreteTime timestamp { get; set; }

		public EventSource eventSource { get; set; }

		public uint playerId { get; set; }

		public EventModifiers eventModifiers { get; set; }

		public override string ToString()
		{
			return $"{type} {command}";
		}
	}
}
