using UnityEngine.Bindings;

namespace UnityEngine
{
	[NativeHeader("Runtime/Diagnostics/IntegrityCheck.h")]
	public enum IntegrityCheckLevel
	{
		Low = 1,
		Medium = 2,
		High = 3
	}
}
