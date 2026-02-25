using System;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.XR
{
	[Obsolete("UnityEngine.VRModule is deprecated and will be removed in a future version. Please use the APIs in the UnityEngine.XRModule instead")]
	[NativeConditional("ENABLE_VR")]
	public static class XRDevice
	{
		[Obsolete("This is obsolete, and should no longer be used. Instead, find the active XRDisplaySubsystem and check that the running property is true (for details, see XRDevice.isPresent documentation).", true)]
		public static bool isPresent
		{
			get
			{
				throw new NotSupportedException("XRDevice is Obsolete. Instead, find the active XRDisplaySubsystem and check to see if it is running.");
			}
		}

		[NativeName("DeviceRefreshRate")]
		[StaticAccessor("GetIVRDeviceSwapChain()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static extern float refreshRate
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			get;
		}

		public static extern float fovZoomFactor
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			get;
			[MethodImpl(MethodImplOptions.InternalCall)]
			[NativeName("SetProjectionZoomFactor")]
			[StaticAccessor("GetIVRDeviceScripting()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
			set;
		}

		public static event Action<string> deviceLoaded;

		[MethodImpl(MethodImplOptions.InternalCall)]
		[StaticAccessor("GetIVRDeviceScripting()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static extern IntPtr GetNativePtr();

		[MethodImpl(MethodImplOptions.InternalCall)]
		[Obsolete("This is obsolete, and should no longer be used.  Please use XRInputSubsystem.GetTrackingOriginMode.")]
		[StaticAccessor("GetIVRDevice()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static extern TrackingSpaceType GetTrackingSpaceType();

		[MethodImpl(MethodImplOptions.InternalCall)]
		[Obsolete("This is obsolete, and should no longer be used.  Please use XRInputSubsystem.TrySetTrackingOriginMode.")]
		[StaticAccessor("GetIVRDevice()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static extern bool SetTrackingSpaceType(TrackingSpaceType trackingSpaceType);

		[NativeName("DisableAutoVRCameraTracking")]
		[StaticAccessor("GetIVRDevice()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static void DisableAutoXRCameraTracking([NotNull] Camera camera, bool disabled)
		{
			if ((object)camera == null)
			{
				ThrowHelper.ThrowArgumentNullException(camera, "camera");
			}
			IntPtr intPtr = Object.MarshalledUnityObject.MarshalNotNull(camera);
			if (intPtr == (IntPtr)0)
			{
				ThrowHelper.ThrowArgumentNullException(camera, "camera");
			}
			DisableAutoXRCameraTracking_Injected(intPtr, disabled);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		[NativeName("UpdateEyeTextureMSAASetting")]
		[StaticAccessor("GetIVRDeviceScripting()", StaticAccessorType.ArrowWithDefaultReturnIfNull)]
		public static extern void UpdateEyeTextureMSAASetting();

		[RequiredByNativeCode]
		private static void InvokeDeviceLoaded(string loadedDeviceName)
		{
			if (XRDevice.deviceLoaded != null)
			{
				XRDevice.deviceLoaded(loadedDeviceName);
			}
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void DisableAutoXRCameraTracking_Injected(IntPtr camera, bool disabled);
	}
}
