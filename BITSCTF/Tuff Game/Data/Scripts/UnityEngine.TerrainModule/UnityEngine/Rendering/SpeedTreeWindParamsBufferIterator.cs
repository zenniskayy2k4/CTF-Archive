using System;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.Rendering
{
	[NativeHeader("Modules/Terrain/Public/SpeedTreeWind.h")]
	[UsedByNativeCode]
	internal struct SpeedTreeWindParamsBufferIterator
	{
		public IntPtr bufferPtr;

		public unsafe fixed int uintParamOffsets[16];

		public int uintStride;

		public int elementOffset;

		public int elementsCount;
	}
}
