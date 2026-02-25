using System;
using System.Runtime.CompilerServices;

namespace UnityEngine.Bindings
{
	[VisibleToOtherModules]
	internal ref struct BlittableArrayWrapper
	{
		internal enum UpdateFlags
		{
			NoUpdateNeeded = 0,
			SizeChanged = 1,
			DataIsNativePointer = 2,
			DataIsNativeOwnedMemory = 3,
			DataIsEmpty = 4,
			DataIsNull = 5
		}

		internal unsafe void* data;

		internal int size;

		internal UpdateFlags updateFlags;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public unsafe BlittableArrayWrapper(void* data, int size)
		{
			this.data = data;
			this.size = size;
			updateFlags = UpdateFlags.NoUpdateNeeded;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal unsafe void Unmarshal<T>(ref T[] array) where T : unmanaged
		{
			switch (updateFlags)
			{
			case UpdateFlags.NoUpdateNeeded:
				break;
			case UpdateFlags.SizeChanged:
			case UpdateFlags.DataIsNativePointer:
				array = new Span<T>(data, size).ToArray();
				break;
			case UpdateFlags.DataIsNativeOwnedMemory:
				array = new Span<T>(BindingsAllocator.GetNativeOwnedDataPointer(data), size).ToArray();
				BindingsAllocator.FreeNativeOwnedMemory(data);
				break;
			case UpdateFlags.DataIsEmpty:
				array = Array.Empty<T>();
				break;
			case UpdateFlags.DataIsNull:
				array = null;
				break;
			}
		}
	}
}
