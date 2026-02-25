using System;
using UnityEngine.Scripting.APIUpdating;

namespace UnityEngine
{
	[MovedFrom(true, "UnityEngine.IMUGI", "UnityEngine", null)]
	[Flags]
	public enum EventModifiers
	{
		None = 0,
		Shift = 1,
		Control = 2,
		Alt = 4,
		Command = 8,
		Numeric = 0x10,
		CapsLock = 0x20,
		FunctionKey = 0x40
	}
}
