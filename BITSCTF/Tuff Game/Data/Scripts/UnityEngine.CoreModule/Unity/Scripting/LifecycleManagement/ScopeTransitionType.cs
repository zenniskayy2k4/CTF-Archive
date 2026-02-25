using UnityEngine.Bindings;

namespace Unity.Scripting.LifecycleManagement
{
	[VisibleToOtherModules]
	internal enum ScopeTransitionType
	{
		Unset = 0,
		Entering = 1,
		Exiting = 2,
		Both = 3
	}
}
