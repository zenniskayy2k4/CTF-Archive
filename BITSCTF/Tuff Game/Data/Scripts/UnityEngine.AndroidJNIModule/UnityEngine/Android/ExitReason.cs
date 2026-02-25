namespace UnityEngine.Android
{
	public enum ExitReason
	{
		Unknown = 0,
		ExitSelf = 1,
		Signaled = 2,
		LowMemory = 3,
		Crash = 4,
		CrashNative = 5,
		ANR = 6,
		InititalizationFailure = 7,
		PermissionChange = 8,
		ExcessiveResourceUsage = 9,
		UserRequested = 10,
		UserStopped = 11,
		DependencyDied = 12,
		Other = 13,
		Freezer = 14,
		PackageStateChange = 15,
		PackageUpdated = 16
	}
}
