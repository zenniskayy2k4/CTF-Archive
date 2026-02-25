using System;
using System.Runtime.InteropServices;
using UnityEngine.Internal;
using UnityEngine.Scripting;

namespace UnityEngine.Analytics
{
	[Serializable]
	[StructLayout(LayoutKind.Sequential)]
	[RequiredByNativeCode(GenerateProxy = true)]
	[ExcludeFromDocs]
	public class VRDeviceAnalyticAspect : VRDeviceAnalyticBase
	{
		public float vr_aspect_ratio;

		[RequiredByNativeCode]
		internal static VRDeviceAnalyticAspect CreateVRDeviceAnalyticAspect()
		{
			return new VRDeviceAnalyticAspect();
		}
	}
}
