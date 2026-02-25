using System;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;

namespace UnityEngine
{
	[VisibleToOtherModules(new string[] { "UnityEngine.TextCoreTextEngineModule" })]
	[NativeHeader("Runtime/Utilities/CopyPaste.h")]
	internal class StytemCopyBuffer
	{
		public unsafe static string systemCopyBuffer
		{
			[FreeFunction("GetCopyBuffer")]
			get
			{
				ManagedSpanWrapper ret = default(ManagedSpanWrapper);
				string stringAndDispose;
				try
				{
					get_systemCopyBuffer_Injected(out ret);
				}
				finally
				{
					stringAndDispose = OutStringMarshaller.GetStringAndDispose(ret);
				}
				return stringAndDispose;
			}
			[FreeFunction("SetCopyBuffer")]
			set
			{
				//The blocks IL_0029 are reachable both inside and outside the pinned region starting at IL_0018. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
				try
				{
					ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
					if (!StringMarshaller.TryMarshalEmptyOrNullString(value, ref managedSpanWrapper))
					{
						ReadOnlySpan<char> readOnlySpan = value.AsSpan();
						fixed (char* begin = readOnlySpan)
						{
							managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
							set_systemCopyBuffer_Injected(ref managedSpanWrapper);
							return;
						}
					}
					set_systemCopyBuffer_Injected(ref managedSpanWrapper);
				}
				finally
				{
				}
			}
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void get_systemCopyBuffer_Injected(out ManagedSpanWrapper ret);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void set_systemCopyBuffer_Injected(ref ManagedSpanWrapper value);
	}
}
