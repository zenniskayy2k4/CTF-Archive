namespace UnityEngine.Audio
{
	internal enum ProcessorFunction : uint
	{
		Process = 1u,
		Update = 2u,
		OutputProcessEarly = 3u,
		OutputProcess = 4u,
		OutputProcessEnd = 5u,
		OutputRemoved = 6u
	}
}
