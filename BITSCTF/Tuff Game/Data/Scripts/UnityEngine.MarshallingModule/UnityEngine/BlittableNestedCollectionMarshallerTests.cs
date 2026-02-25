using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;

namespace UnityEngine
{
	internal class BlittableNestedCollectionMarshallerTests
	{
		[NativeThrows]
		[NativeMethod("BlittableNestedCollectionMarshallerTests::PassInNestedCollection")]
		public unsafe static void PassInNestedLists([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(BlittableNestedCollectionMarshaller<int>))] List<List<int>> nested, int exectedCount, int[] expectedValues1, int[] expectedValues2)
		{
			NestedCollectionData nested2 = BlittableNestedCollectionMarshaller<int>.ConvertToUnmanaged(nested);
			Span<int> span = new Span<int>(expectedValues1);
			fixed (int* begin = span)
			{
				ManagedSpanWrapper expectedValues3 = new ManagedSpanWrapper(begin, span.Length);
				Span<int> span2 = new Span<int>(expectedValues2);
				fixed (int* begin2 = span2)
				{
					ManagedSpanWrapper expectedValues4 = new ManagedSpanWrapper(begin2, span2.Length);
					PassInNestedLists_Injected(ref nested2, exectedCount, ref expectedValues3, ref expectedValues4);
				}
			}
		}

		[NativeThrows]
		[NativeMethod("BlittableNestedCollectionMarshallerTests::PassInNestedCollection")]
		public unsafe static void PassInNestedArrays([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(BlittableNestedCollectionMarshaller<int>))] int[][] nested, int exectedCount, int[] expectedValues1, int[] expectedValues2)
		{
			NestedCollectionData nested2 = BlittableNestedCollectionMarshaller<int>.ConvertToUnmanaged(nested);
			Span<int> span = new Span<int>(expectedValues1);
			fixed (int* begin = span)
			{
				ManagedSpanWrapper expectedValues3 = new ManagedSpanWrapper(begin, span.Length);
				Span<int> span2 = new Span<int>(expectedValues2);
				fixed (int* begin2 = span2)
				{
					ManagedSpanWrapper expectedValues4 = new ManagedSpanWrapper(begin2, span2.Length);
					PassInNestedArrays_Injected(ref nested2, exectedCount, ref expectedValues3, ref expectedValues4);
				}
			}
		}

		[NativeThrows]
		[NativeMethod("BlittableNestedCollectionMarshallerTests::PassInNestedCollection")]
		public unsafe static void PassInListOfInts([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(BlittableNestedCollectionMarshaller<int>))] List<int[]> nested, int exectedCount, int[] expectedValues1, int[] expectedValues2)
		{
			NestedCollectionData nested2 = BlittableNestedCollectionMarshaller<int>.ConvertToUnmanaged(nested);
			Span<int> span = new Span<int>(expectedValues1);
			fixed (int* begin = span)
			{
				ManagedSpanWrapper expectedValues3 = new ManagedSpanWrapper(begin, span.Length);
				Span<int> span2 = new Span<int>(expectedValues2);
				fixed (int* begin2 = span2)
				{
					ManagedSpanWrapper expectedValues4 = new ManagedSpanWrapper(begin2, span2.Length);
					PassInListOfInts_Injected(ref nested2, exectedCount, ref expectedValues3, ref expectedValues4);
				}
			}
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void PassInNestedLists_Injected(ref NestedCollectionData nested, int exectedCount, ref ManagedSpanWrapper expectedValues1, ref ManagedSpanWrapper expectedValues2);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void PassInNestedArrays_Injected(ref NestedCollectionData nested, int exectedCount, ref ManagedSpanWrapper expectedValues1, ref ManagedSpanWrapper expectedValues2);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void PassInListOfInts_Injected(ref NestedCollectionData nested, int exectedCount, ref ManagedSpanWrapper expectedValues1, ref ManagedSpanWrapper expectedValues2);
	}
}
