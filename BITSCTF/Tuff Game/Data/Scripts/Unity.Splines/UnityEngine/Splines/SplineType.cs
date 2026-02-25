using System;

namespace UnityEngine.Splines
{
	[Obsolete("Replaced by GetTangentMode and SetTangentMode.")]
	public enum SplineType : byte
	{
		CatmullRom = 0,
		Bezier = 1,
		Linear = 2
	}
}
