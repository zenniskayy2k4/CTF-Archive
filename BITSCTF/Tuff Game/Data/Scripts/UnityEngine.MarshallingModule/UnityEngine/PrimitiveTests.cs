using System;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;
using UnityEngine.Internal;

namespace UnityEngine
{
	[NativeHeader("MarshallingScriptingClasses.h")]
	[NativeHeader("Modules/Marshalling/MarshallingTests.h")]
	[ExcludeFromDocs]
	internal class PrimitiveTests
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		[NativeThrows]
		public static extern void ParameterBool(bool param1, bool param2, int param3);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[NativeThrows]
		public static extern void ParameterInt(int param);

		[MethodImpl(MethodImplOptions.InternalCall)]
		public static extern void ParameterOutInt(out int param);

		[MethodImpl(MethodImplOptions.InternalCall)]
		public static extern void ParameterRefInt(ref int param);

		[MethodImpl(MethodImplOptions.InternalCall)]
		public static extern int ReturnInt();

		[NativeThrows]
		public unsafe static void ParameterIntVector(int[] param)
		{
			Span<int> span = new Span<int>(param);
			fixed (int* begin = span)
			{
				ManagedSpanWrapper param2 = new ManagedSpanWrapper(begin, span.Length);
				ParameterIntVector_Injected(ref param2);
			}
		}

		[NativeThrows]
		public unsafe static void ParameterIntNullableVector(int[] param)
		{
			Span<int> span = new Span<int>(param);
			fixed (int* begin = span)
			{
				ManagedSpanWrapper param2 = new ManagedSpanWrapper(begin, span.Length);
				ParameterIntNullableVector_Injected(ref param2);
			}
		}

		public static int[] ReturnIntVector()
		{
			BlittableArrayWrapper ret = default(BlittableArrayWrapper);
			int[] result;
			try
			{
				ReturnIntVector_Injected(out ret);
			}
			finally
			{
				int[] array = default(int[]);
				ret.Unmarshal(ref array);
				result = array;
			}
			return result;
		}

		public static int[] ReturnNullIntVector()
		{
			BlittableArrayWrapper ret = default(BlittableArrayWrapper);
			int[] result;
			try
			{
				ReturnNullIntVector_Injected(out ret);
			}
			finally
			{
				int[] array = default(int[]);
				ret.Unmarshal(ref array);
				result = array;
			}
			return result;
		}

		public static bool[] ReturnBoolVector()
		{
			BlittableArrayWrapper ret = default(BlittableArrayWrapper);
			bool[] result;
			try
			{
				ReturnBoolVector_Injected(out ret);
			}
			finally
			{
				bool[] array = default(bool[]);
				ret.Unmarshal(ref array);
				result = array;
			}
			return result;
		}

		public static char[] ReturnCharVector()
		{
			BlittableArrayWrapper ret = default(BlittableArrayWrapper);
			char[] result;
			try
			{
				ReturnCharVector_Injected(out ret);
			}
			finally
			{
				char[] array = default(char[]);
				ret.Unmarshal(ref array);
				result = array;
			}
			return result;
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterIntVector_Injected(ref ManagedSpanWrapper param);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterIntNullableVector_Injected(ref ManagedSpanWrapper param);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ReturnIntVector_Injected(out BlittableArrayWrapper ret);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ReturnNullIntVector_Injected(out BlittableArrayWrapper ret);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ReturnBoolVector_Injected(out BlittableArrayWrapper ret);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ReturnCharVector_Injected(out BlittableArrayWrapper ret);
	}
}
