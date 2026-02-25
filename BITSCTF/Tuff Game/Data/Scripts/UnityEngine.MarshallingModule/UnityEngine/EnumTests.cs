using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using UnityEngine.Bindings;
using UnityEngine.Internal;

namespace UnityEngine
{
	[NativeHeader("Modules/Marshalling/MarshallingTests.h")]
	[ExcludeFromDocs]
	internal class EnumTests
	{
		[NativeThrows]
		public unsafe static void ParameterVectorEnum(SomeEnum[] enumArray)
		{
			Span<SomeEnum> span = new Span<SomeEnum>(enumArray);
			fixed (SomeEnum* begin = span)
			{
				ManagedSpanWrapper enumArray2 = new ManagedSpanWrapper(begin, span.Length);
				ParameterVectorEnum_Injected(ref enumArray2);
			}
		}

		public unsafe static void ParameterOutVectorEnum([Out] SomeEnum[] enumArray)
		{
			//The blocks IL_001b are reachable both inside and outside the pinned region starting at IL_0004. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			BlittableArrayWrapper enumArray2 = default(BlittableArrayWrapper);
			try
			{
				if (enumArray != null)
				{
					fixed (SomeEnum[] array = enumArray)
					{
						if (array.Length != 0)
						{
							enumArray2 = new BlittableArrayWrapper(Unsafe.AsPointer(ref array[0]), array.Length);
						}
						ParameterOutVectorEnum_Injected(out enumArray2);
						return;
					}
				}
				ParameterOutVectorEnum_Injected(out enumArray2);
			}
			finally
			{
				enumArray2.Unmarshal(ref array);
			}
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterVectorEnum_Injected(ref ManagedSpanWrapper enumArray);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterOutVectorEnum_Injected(out BlittableArrayWrapper enumArray);
	}
}
