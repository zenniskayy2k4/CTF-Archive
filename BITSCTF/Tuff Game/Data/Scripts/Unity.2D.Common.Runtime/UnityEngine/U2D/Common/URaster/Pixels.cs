using Unity.Collections;
using Unity.Collections.LowLevel.Unsafe;
using Unity.Mathematics;

namespace UnityEngine.U2D.Common.URaster
{
	internal struct Pixels
	{
		internal int4 rect;

		internal int4 minmax;

		internal int4 texrect;

		internal int2 size;

		[NativeDisableContainerSafetyRestriction]
		internal NativeArray<byte> data;
	}
}
