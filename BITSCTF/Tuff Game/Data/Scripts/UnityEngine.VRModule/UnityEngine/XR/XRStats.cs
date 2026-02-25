using System;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;

namespace UnityEngine.XR
{
	[Obsolete("UnityEngine.VRModule is deprecated and will be removed in a future version. Please use the APIs in the UnityEngine.XRModule instead")]
	[NativeConditional("ENABLE_VR")]
	public static class XRStats
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		[StaticAccessor("GetIVRDeviceScripting()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static extern bool TryGetGPUTimeLastFrame(out float gpuTimeLastFrame);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[StaticAccessor("GetIVRDeviceScripting()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static extern bool TryGetDroppedFrameCount(out int droppedFrameCount);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[StaticAccessor("GetIVRDeviceScripting()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static extern bool TryGetFramePresentCount(out int framePresentCount);
	}
}
