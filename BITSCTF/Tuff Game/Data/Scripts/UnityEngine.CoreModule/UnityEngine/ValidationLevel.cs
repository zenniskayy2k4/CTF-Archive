using UnityEngine.Bindings;

namespace UnityEngine
{
	[NativeHeader("Runtime/Diagnostics/Validation.h")]
	public enum ValidationLevel
	{
		None = 0,
		Low = 1,
		Medium = 2,
		High = 3
	}
}
