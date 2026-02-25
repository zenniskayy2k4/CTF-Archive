using UnityEngine.Bindings;

namespace Unity.Scripting.LifecycleManagement
{
	[VisibleToOtherModules]
	internal enum CleanupStrategy
	{
		Unset = 0,
		Auto = 1,
		Clear = 2,
		CaptureInitializationExpression = 3,
		ResetToDefaultValue = 4
	}
}
