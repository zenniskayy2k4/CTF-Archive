using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine
{
	[UsedByNativeCode]
	[NativeType("Runtime/Graphics/DisplayInfo.h")]
	public struct DisplayInfo : IEquatable<DisplayInfo>
	{
		[RequiredMember]
		internal ulong handle;

		[RequiredMember]
		public int width;

		[RequiredMember]
		public int height;

		[RequiredMember]
		public RefreshRate refreshRate;

		[RequiredMember]
		public RectInt workArea;

		[RequiredMember]
		public string name;

		[RequiredMember]
		[NativeName("dpi")]
		public float physicalDpi;

		public Resolution[] resolutions
		{
			get
			{
				throw new NotSupportedException("DisplayInfo.resolutions is currently not supported on this platform.");
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public bool Equals(DisplayInfo other)
		{
			return handle == other.handle && width == other.width && height == other.height && refreshRate.Equals(other.refreshRate) && workArea.Equals(other.workArea) && name == other.name && physicalDpi == other.physicalDpi;
		}

		public static void GetLayout(List<DisplayInfo> displayLayout)
		{
			Screen.GetDisplayLayout(displayLayout);
		}

		private static Resolution[] GetResolutions(DisplayInfo displayInfo)
		{
			throw new NotSupportedException("DisplayInfo.GetResolutions() is not supported on this platform.");
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		[NativeConditional("PLATFORM_SUPPORTS_DISPLAYINFO_API")]
		[FreeFunction("DisplayInfoScripting::GetLayout")]
		private static extern void GetLayoutImpl(List<DisplayInfo> displayLayout);

		[NativeConditional("PLATFORM_SUPPORTS_DISPLAYINFO_API")]
		[FreeFunction("DisplayInfoScripting::GetResolutions")]
		private static Resolution[] GetResolutionsImpl(ulong handle)
		{
			BlittableArrayWrapper ret = default(BlittableArrayWrapper);
			Resolution[] result;
			try
			{
				GetResolutionsImpl_Injected(handle, out ret);
			}
			finally
			{
				Resolution[] array = default(Resolution[]);
				ret.Unmarshal(ref array);
				result = array;
			}
			return result;
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void GetResolutionsImpl_Injected(ulong handle, out BlittableArrayWrapper ret);
	}
}
