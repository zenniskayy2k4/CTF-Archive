using System;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;

namespace UnityEngine
{
	internal static class CustomMarshallingTests
	{
		[UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(BindingsMarshaller))]
		public class CustomMarshalledClass : ICustomMarshalled
		{
			public static class BindingsMarshaller
			{
				public static int ConvertToUnmanaged(CustomMarshalledClass c)
				{
					return (c != null) ? int.Parse(c.Value) : 0;
				}

				public static CustomMarshalledClass ConvertToManaged(int n)
				{
					return new CustomMarshalledClass
					{
						Value = n.ToString()
					};
				}
			}

			public string Value { get; set; }
		}

		public class CustomMarshalledDerivedClass : CustomMarshalledClass
		{
		}

		public interface ICustomMarshalled
		{
			string Value { get; set; }
		}

		public class CustomMarshaller
		{
			public static int ConvertToUnmanaged(CustomMarshalledClass c)
			{
				return (c != null) ? (int.Parse(c.Value) * 2) : 0;
			}

			public static CustomMarshalledClass ConvertToManaged(int n)
			{
				return new CustomMarshalledClass
				{
					Value = (n * 2).ToString()
				};
			}
		}

		public class CustomMarshallerUsingInParameters
		{
			public static int ConvertToUnmanaged(in CustomMarshalledClass c)
			{
				return (c != null) ? (int.Parse(c.Value) * 2) : 0;
			}

			public static CustomMarshalledClass ConvertToManaged(in int n)
			{
				return new CustomMarshalledClass
				{
					Value = (n * 2).ToString()
				};
			}
		}

		public class CustomMarshaller_NeeedingMarshalling
		{
			public static string ConvertToUnmanaged(CustomMarshalledClass c)
			{
				return (c == null) ? null : (c.Value + "_ConvertedToUnmanaged");
			}

			public static CustomMarshalledClass ConvertToManaged(string s)
			{
				return new CustomMarshalledClass
				{
					Value = s + "_ConvertedToManaged"
				};
			}
		}

		public class CustomMarshaller_WithFree
		{
			private static int _lastFreeValue = int.MinValue;

			public static int GetLastFreeValue()
			{
				return _lastFreeValue;
			}

			public static int ConvertToUnmanaged(CustomMarshalledClass c)
			{
				return (c != null) ? (int.Parse(c.Value) * 3) : 0;
			}

			public static CustomMarshalledClass ConvertToManaged(int n)
			{
				return new CustomMarshalledClass
				{
					Value = (n * 3).ToString()
				};
			}

			public static void Free(int value)
			{
				_lastFreeValue = value;
			}
		}

		public class CustomMarshallerGeneric<T> where T : ICustomMarshalled, new()
		{
			public static int ConvertToUnmanaged(T c)
			{
				return (c != null) ? (int.Parse(c.Value) * 2) : 0;
			}

			public static T ConvertToManaged(int n)
			{
				return new T
				{
					Value = (n * 2).ToString()
				};
			}
		}

		public class CustomMarshallerInterface
		{
			public static int ConvertToUnmanaged(ICustomMarshalled c)
			{
				return (c != null) ? (int.Parse(c.Value) * 2) : 0;
			}
		}

		[UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(BindingsMarshaller))]
		public struct CustomMarshalledAsStruct
		{
			public static class BindingsMarshaller
			{
				public static StructInt ConvertToUnmanaged(in CustomMarshalledAsStruct s)
				{
					return new StructInt
					{
						field = s.field
					};
				}

				public static CustomMarshalledAsStruct ConvertToManaged(in StructInt s)
				{
					return new CustomMarshalledAsStruct
					{
						field = s.field
					};
				}
			}

			public int field;
		}

		public class MarshalThisAsStructInt
		{
			private static class BindingsMarshaller
			{
				public static StructInt ConvertToUnmanaged(MarshalThisAsStructInt s)
				{
					return new StructInt
					{
						field = s.field
					};
				}
			}

			public int field;

			[UnityMarshalThisAs(NativeType.Custom, CustomMarshaller = typeof(BindingsMarshaller))]
			public int GetField()
			{
				StructInt _unity_self = BindingsMarshaller.ConvertToUnmanaged(this);
				return GetField_Injected(ref _unity_self);
			}

			[MethodImpl(MethodImplOptions.InternalCall)]
			private static extern int GetField_Injected(ref StructInt _unity_self);
		}

		[UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(ClassWithPinnableInnerData))]
		public class ClassWithPinnableInnerData
		{
			public StructInt NativeData;

			internal static ref StructInt GetPinnableReference(ClassWithPinnableInnerData c)
			{
				return ref c.NativeData;
			}

			internal static StructInt ConvertToUnmanaged(ClassWithPinnableInnerData data)
			{
				return data.NativeData;
			}
		}

		[NativeThrows]
		public static void ParameterCustomMarshalled(CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalled_Injected(CustomMarshalledClass.BindingsMarshaller.ConvertToUnmanaged(arg), expected);
		}

		[NativeThrows]
		public static void ParameterCustomMarshalledIn(in CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalledIn_Injected(CustomMarshalledClass.BindingsMarshaller.ConvertToUnmanaged(arg), expected);
		}

		[NativeThrows]
		public static void ParameterCustomMarshalledOut(out CustomMarshalledClass arg, int expected)
		{
			CustomMarshalledClass c = default(CustomMarshalledClass);
			int arg2 = CustomMarshalledClass.BindingsMarshaller.ConvertToUnmanaged(c);
			ParameterCustomMarshalledOut_Injected(out arg2, expected);
			arg = CustomMarshalledClass.BindingsMarshaller.ConvertToManaged(arg2);
		}

		[NativeThrows]
		public static void ParameterCustomMarshalledRef(ref CustomMarshalledClass arg, int expected)
		{
			int arg2 = CustomMarshalledClass.BindingsMarshaller.ConvertToUnmanaged(arg);
			ParameterCustomMarshalledRef_Injected(ref arg2, expected);
			arg = CustomMarshalledClass.BindingsMarshaller.ConvertToManaged(arg2);
		}

		public static CustomMarshalledClass ParameterCustomMarshalledReturn(int value)
		{
			return CustomMarshalledClass.BindingsMarshaller.ConvertToManaged(ParameterCustomMarshalledReturn_Injected(value));
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalled")]
		public static void ParameterCustomMarshalled_Attribute([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller))] CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalled_Attribute_Injected(CustomMarshaller.ConvertToUnmanaged(arg), expected);
		}

		[NativeMethod("ParameterCustomMarshalledIn")]
		[NativeThrows]
		public static void ParameterCustomMarshalledIn_Attribute([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller))] in CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalledIn_Attribute_Injected(CustomMarshaller.ConvertToUnmanaged(arg), expected);
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledOut")]
		public static void ParameterCustomMarshalledOut_Attribute([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller))] out CustomMarshalledClass arg, int expected)
		{
			CustomMarshalledClass c = default(CustomMarshalledClass);
			int arg2 = CustomMarshaller.ConvertToUnmanaged(c);
			ParameterCustomMarshalledOut_Attribute_Injected(out arg2, expected);
			arg = CustomMarshaller.ConvertToManaged(arg2);
		}

		[NativeMethod("ParameterCustomMarshalledRef")]
		[NativeThrows]
		public static void ParameterCustomMarshalledRef_Attribute([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller))] ref CustomMarshalledClass arg, int expected)
		{
			int arg2 = CustomMarshaller.ConvertToUnmanaged(arg);
			ParameterCustomMarshalledRef_Attribute_Injected(ref arg2, expected);
			arg = CustomMarshaller.ConvertToManaged(arg2);
		}

		[NativeMethod("ParameterCustomMarshalledReturn")]
		[return: UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller))]
		public static CustomMarshalledClass ParameterCustomMarshalledReturn_Attribute(int value)
		{
			return CustomMarshaller.ConvertToManaged(ParameterCustomMarshalledReturn_Attribute_Injected(value));
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalled")]
		public static void ParameterCustomMarshalled_CustomMarshallerUsesInParameters([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerUsingInParameters))] CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalled_CustomMarshallerUsesInParameters_Injected(CustomMarshallerUsingInParameters.ConvertToUnmanaged(in arg), expected);
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledIn")]
		public static void ParameterCustomMarshalledIn_CustomMarshallerUsesInParameters([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerUsingInParameters))] in CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalledIn_CustomMarshallerUsesInParameters_Injected(CustomMarshallerUsingInParameters.ConvertToUnmanaged(in arg), expected);
		}

		[NativeMethod("ParameterCustomMarshalledOut")]
		[NativeThrows]
		public static void ParameterCustomMarshalledOut_CustomMarshallerUsesInParameters([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerUsingInParameters))] out CustomMarshalledClass arg, int expected)
		{
			CustomMarshalledClass c = default(CustomMarshalledClass);
			int arg2 = CustomMarshallerUsingInParameters.ConvertToUnmanaged(in c);
			ParameterCustomMarshalledOut_CustomMarshallerUsesInParameters_Injected(out arg2, expected);
			arg = CustomMarshallerUsingInParameters.ConvertToManaged(in arg2);
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledRef")]
		public static void ParameterCustomMarshalledRef_CustomMarshallerUsesInParameters([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerUsingInParameters))] ref CustomMarshalledClass arg, int expected)
		{
			int arg2 = CustomMarshallerUsingInParameters.ConvertToUnmanaged(in arg);
			ParameterCustomMarshalledRef_CustomMarshallerUsesInParameters_Injected(ref arg2, expected);
			arg = CustomMarshallerUsingInParameters.ConvertToManaged(in arg2);
		}

		[NativeMethod("ParameterCustomMarshalledReturn")]
		[return: UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerUsingInParameters))]
		public static CustomMarshalledClass ParameterCustomMarshalledReturn_CustomMarshallerUsesInParameters(int value)
		{
			return CustomMarshallerUsingInParameters.ConvertToManaged(ParameterCustomMarshalledReturn_CustomMarshallerUsesInParameters_Injected(value));
		}

		[NativeMethod("ParameterCustomMarshalled")]
		[NativeThrows]
		public static void ParameterCustomMarshalled_Free([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_WithFree))] CustomMarshalledClass arg, int expected)
		{
			int num = default(int);
			try
			{
				num = CustomMarshaller_WithFree.ConvertToUnmanaged(arg);
				ParameterCustomMarshalled_Free_Injected(num, expected);
			}
			finally
			{
				CustomMarshaller_WithFree.Free(num);
			}
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledIn")]
		public static void ParameterCustomMarshalledIn_Free([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_WithFree))] in CustomMarshalledClass arg, int expected)
		{
			int arg2 = default(int);
			try
			{
				arg2 = CustomMarshaller_WithFree.ConvertToUnmanaged(arg);
				ParameterCustomMarshalledIn_Free_Injected(in arg2, expected);
			}
			finally
			{
				CustomMarshaller_WithFree.Free(arg2);
			}
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledOut")]
		public static void ParameterCustomMarshalledOut_Free([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_WithFree))] out CustomMarshalledClass arg, int expected)
		{
			int arg2 = default(int);
			try
			{
				CustomMarshalledClass c = default(CustomMarshalledClass);
				arg2 = CustomMarshaller_WithFree.ConvertToUnmanaged(c);
				ParameterCustomMarshalledOut_Free_Injected(out arg2, expected);
			}
			finally
			{
				arg = CustomMarshaller_WithFree.ConvertToManaged(arg2);
				CustomMarshaller_WithFree.Free(arg2);
			}
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledRef")]
		public static void ParameterCustomMarshalledRef_Free([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_WithFree))] ref CustomMarshalledClass arg, int expected)
		{
			int arg2 = default(int);
			try
			{
				arg2 = CustomMarshaller_WithFree.ConvertToUnmanaged(arg);
				ParameterCustomMarshalledRef_Free_Injected(ref arg2, expected);
			}
			finally
			{
				arg = CustomMarshaller_WithFree.ConvertToManaged(arg2);
				CustomMarshaller_WithFree.Free(arg2);
			}
		}

		[NativeMethod("ParameterCustomMarshalledReturn")]
		[return: UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_WithFree))]
		public static CustomMarshalledClass ParameterCustomMarshalledReturn_Free(int value)
		{
			int num = default(int);
			CustomMarshalledClass result;
			try
			{
				num = ParameterCustomMarshalledReturn_Free_Injected(value);
			}
			finally
			{
				int num2 = num;
				int value2 = num2;
				CustomMarshalledClass customMarshalledClass = CustomMarshaller_WithFree.ConvertToManaged(num2);
				CustomMarshaller_WithFree.Free(value2);
				result = customMarshalledClass;
			}
			return result;
		}

		[NativeThrows]
		public unsafe static void ParameterCustomMarshalled_NeedingMarshalling([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_NeeedingMarshalling))] CustomMarshalledClass arg, string expected)
		{
			//The blocks IL_0030, IL_003d, IL_004c, IL_005a, IL_005f are reachable both inside and outside the pinned region starting at IL_001f. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_005f are reachable both inside and outside the pinned region starting at IL_004c. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_005f are reachable both inside and outside the pinned region starting at IL_004c. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			try
			{
				string text = CustomMarshaller_NeeedingMarshalling.ConvertToUnmanaged(arg);
				ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
				ref ManagedSpanWrapper arg2;
				ManagedSpanWrapper managedSpanWrapper2 = default(ManagedSpanWrapper);
				ReadOnlySpan<char> readOnlySpan2;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(text, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = text.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						arg2 = ref managedSpanWrapper;
						if (!StringMarshaller.TryMarshalEmptyOrNullString(expected, ref managedSpanWrapper2))
						{
							readOnlySpan2 = expected.AsSpan();
							fixed (char* begin2 = readOnlySpan2)
							{
								managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
								ParameterCustomMarshalled_NeedingMarshalling_Injected(ref arg2, ref managedSpanWrapper2);
								return;
							}
						}
						ParameterCustomMarshalled_NeedingMarshalling_Injected(ref arg2, ref managedSpanWrapper2);
						return;
					}
				}
				arg2 = ref managedSpanWrapper;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(expected, ref managedSpanWrapper2))
				{
					readOnlySpan2 = expected.AsSpan();
					fixed (char* begin2 = readOnlySpan2)
					{
						managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
						ParameterCustomMarshalled_NeedingMarshalling_Injected(ref arg2, ref managedSpanWrapper2);
						return;
					}
				}
				ParameterCustomMarshalled_NeedingMarshalling_Injected(ref arg2, ref managedSpanWrapper2);
			}
			finally
			{
			}
		}

		[NativeThrows]
		public unsafe static void ParameterCustomMarshalled_NeedingMarshalling_In([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_NeeedingMarshalling))] in CustomMarshalledClass arg, string expected)
		{
			//The blocks IL_0031, IL_003e, IL_004d, IL_005b, IL_0060 are reachable both inside and outside the pinned region starting at IL_0020. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_0060 are reachable both inside and outside the pinned region starting at IL_004d. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_0060 are reachable both inside and outside the pinned region starting at IL_004d. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			try
			{
				string text = CustomMarshaller_NeeedingMarshalling.ConvertToUnmanaged(arg);
				ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
				ref ManagedSpanWrapper arg2;
				ManagedSpanWrapper managedSpanWrapper2 = default(ManagedSpanWrapper);
				ReadOnlySpan<char> readOnlySpan2;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(text, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = text.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						arg2 = ref managedSpanWrapper;
						if (!StringMarshaller.TryMarshalEmptyOrNullString(expected, ref managedSpanWrapper2))
						{
							readOnlySpan2 = expected.AsSpan();
							fixed (char* begin2 = readOnlySpan2)
							{
								managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
								ParameterCustomMarshalled_NeedingMarshalling_In_Injected(in arg2, ref managedSpanWrapper2);
								return;
							}
						}
						ParameterCustomMarshalled_NeedingMarshalling_In_Injected(in arg2, ref managedSpanWrapper2);
						return;
					}
				}
				arg2 = ref managedSpanWrapper;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(expected, ref managedSpanWrapper2))
				{
					readOnlySpan2 = expected.AsSpan();
					fixed (char* begin2 = readOnlySpan2)
					{
						managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
						ParameterCustomMarshalled_NeedingMarshalling_In_Injected(in arg2, ref managedSpanWrapper2);
						return;
					}
				}
				ParameterCustomMarshalled_NeedingMarshalling_In_Injected(in arg2, ref managedSpanWrapper2);
			}
			finally
			{
			}
		}

		[NativeThrows]
		public unsafe static void ParameterCustomMarshalled_NeedingMarshalling_Out([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_NeeedingMarshalling))] out CustomMarshalledClass arg, string expected)
		{
			//The blocks IL_0033, IL_0040, IL_004f, IL_005d, IL_0062 are reachable both inside and outside the pinned region starting at IL_0022. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_0062 are reachable both inside and outside the pinned region starting at IL_004f. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_0062 are reachable both inside and outside the pinned region starting at IL_004f. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
			try
			{
				CustomMarshalledClass c = default(CustomMarshalledClass);
				string text = CustomMarshaller_NeeedingMarshalling.ConvertToUnmanaged(c);
				ref ManagedSpanWrapper arg2;
				ManagedSpanWrapper managedSpanWrapper2 = default(ManagedSpanWrapper);
				ReadOnlySpan<char> readOnlySpan2;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(text, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = text.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						arg2 = ref managedSpanWrapper;
						if (!StringMarshaller.TryMarshalEmptyOrNullString(expected, ref managedSpanWrapper2))
						{
							readOnlySpan2 = expected.AsSpan();
							fixed (char* begin2 = readOnlySpan2)
							{
								managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
								ParameterCustomMarshalled_NeedingMarshalling_Out_Injected(out arg2, ref managedSpanWrapper2);
								return;
							}
						}
						ParameterCustomMarshalled_NeedingMarshalling_Out_Injected(out arg2, ref managedSpanWrapper2);
						return;
					}
				}
				arg2 = ref managedSpanWrapper;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(expected, ref managedSpanWrapper2))
				{
					readOnlySpan2 = expected.AsSpan();
					fixed (char* begin2 = readOnlySpan2)
					{
						managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
						ParameterCustomMarshalled_NeedingMarshalling_Out_Injected(out arg2, ref managedSpanWrapper2);
						return;
					}
				}
				ParameterCustomMarshalled_NeedingMarshalling_Out_Injected(out arg2, ref managedSpanWrapper2);
			}
			finally
			{
				arg = CustomMarshaller_NeeedingMarshalling.ConvertToManaged(OutStringMarshaller.GetStringAndDispose(managedSpanWrapper));
			}
		}

		[NativeThrows]
		public unsafe static void ParameterCustomMarshalled_NeedingMarshalling_Ref([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_NeeedingMarshalling))] ref CustomMarshalledClass arg, string expected)
		{
			//The blocks IL_0031, IL_003e, IL_004d, IL_005b, IL_0060 are reachable both inside and outside the pinned region starting at IL_0020. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_0060 are reachable both inside and outside the pinned region starting at IL_004d. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_0060 are reachable both inside and outside the pinned region starting at IL_004d. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
			try
			{
				string text = CustomMarshaller_NeeedingMarshalling.ConvertToUnmanaged(arg);
				ref ManagedSpanWrapper arg2;
				ManagedSpanWrapper managedSpanWrapper2 = default(ManagedSpanWrapper);
				ReadOnlySpan<char> readOnlySpan2;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(text, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = text.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						arg2 = ref managedSpanWrapper;
						if (!StringMarshaller.TryMarshalEmptyOrNullString(expected, ref managedSpanWrapper2))
						{
							readOnlySpan2 = expected.AsSpan();
							fixed (char* begin2 = readOnlySpan2)
							{
								managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
								ParameterCustomMarshalled_NeedingMarshalling_Ref_Injected(ref arg2, ref managedSpanWrapper2);
								return;
							}
						}
						ParameterCustomMarshalled_NeedingMarshalling_Ref_Injected(ref arg2, ref managedSpanWrapper2);
						return;
					}
				}
				arg2 = ref managedSpanWrapper;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(expected, ref managedSpanWrapper2))
				{
					readOnlySpan2 = expected.AsSpan();
					fixed (char* begin2 = readOnlySpan2)
					{
						managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
						ParameterCustomMarshalled_NeedingMarshalling_Ref_Injected(ref arg2, ref managedSpanWrapper2);
						return;
					}
				}
				ParameterCustomMarshalled_NeedingMarshalling_Ref_Injected(ref arg2, ref managedSpanWrapper2);
			}
			finally
			{
				arg = CustomMarshaller_NeeedingMarshalling.ConvertToManaged(OutStringMarshaller.GetStringAndDispose(managedSpanWrapper));
			}
		}

		[return: UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshaller_NeeedingMarshalling))]
		public unsafe static CustomMarshalledClass ParameterCustomMarshalled_NeedingMarshalling_Return(string value)
		{
			//The blocks IL_0029, IL_003f, IL_004f, IL_005d, IL_0062 are reachable both inside and outside the pinned region starting at IL_0018. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_0062 are reachable both inside and outside the pinned region starting at IL_004f. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			//The blocks IL_0062 are reachable both inside and outside the pinned region starting at IL_004f. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			ManagedSpanWrapper managedSpanWrapper2 = default(ManagedSpanWrapper);
			CustomMarshalledClass result;
			try
			{
				ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
				ref ManagedSpanWrapper value2;
				CustomMarshalledClass c = default(CustomMarshalledClass);
				ReadOnlySpan<char> readOnlySpan2;
				if (!StringMarshaller.TryMarshalEmptyOrNullString(value, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = value.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						value2 = ref managedSpanWrapper;
						string text = CustomMarshaller_NeeedingMarshalling.ConvertToUnmanaged(c);
						if (!StringMarshaller.TryMarshalEmptyOrNullString(text, ref managedSpanWrapper2))
						{
							readOnlySpan2 = text.AsSpan();
							fixed (char* begin2 = readOnlySpan2)
							{
								managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
								ParameterCustomMarshalled_NeedingMarshalling_Return_Injected(ref value2, out managedSpanWrapper2);
							}
						}
						else
						{
							ParameterCustomMarshalled_NeedingMarshalling_Return_Injected(ref value2, out managedSpanWrapper2);
						}
					}
				}
				else
				{
					value2 = ref managedSpanWrapper;
					string text = CustomMarshaller_NeeedingMarshalling.ConvertToUnmanaged(c);
					if (!StringMarshaller.TryMarshalEmptyOrNullString(text, ref managedSpanWrapper2))
					{
						readOnlySpan2 = text.AsSpan();
						fixed (char* begin2 = readOnlySpan2)
						{
							managedSpanWrapper2 = new ManagedSpanWrapper(begin2, readOnlySpan2.Length);
							ParameterCustomMarshalled_NeedingMarshalling_Return_Injected(ref value2, out managedSpanWrapper2);
						}
					}
					else
					{
						ParameterCustomMarshalled_NeedingMarshalling_Return_Injected(ref value2, out managedSpanWrapper2);
					}
				}
			}
			finally
			{
				result = CustomMarshaller_NeeedingMarshalling.ConvertToManaged(OutStringMarshaller.GetStringAndDispose(managedSpanWrapper2));
			}
			return result;
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalled")]
		public static void ParameterCustomMarshalled_GenericMarshaller([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerGeneric<CustomMarshalledClass>))] CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalled_GenericMarshaller_Injected(CustomMarshallerGeneric<CustomMarshalledClass>.ConvertToUnmanaged(arg), expected);
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledIn")]
		public static void ParameterCustomMarshalledIn_GenericMarshaller([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerGeneric<CustomMarshalledClass>))] in CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalledIn_GenericMarshaller_Injected(CustomMarshallerGeneric<CustomMarshalledClass>.ConvertToUnmanaged(arg), expected);
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledOut")]
		public static void ParameterCustomMarshalledOut_GenericMarshaller([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerGeneric<CustomMarshalledClass>))] out CustomMarshalledClass arg, int expected)
		{
			CustomMarshalledClass c = default(CustomMarshalledClass);
			int arg2 = CustomMarshallerGeneric<CustomMarshalledClass>.ConvertToUnmanaged(c);
			ParameterCustomMarshalledOut_GenericMarshaller_Injected(out arg2, expected);
			arg = CustomMarshallerGeneric<CustomMarshalledClass>.ConvertToManaged(arg2);
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalledRef")]
		public static void ParameterCustomMarshalledRef_GenericMarshaller([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerGeneric<CustomMarshalledClass>))] ref CustomMarshalledClass arg, int expected)
		{
			int arg2 = CustomMarshallerGeneric<CustomMarshalledClass>.ConvertToUnmanaged(arg);
			ParameterCustomMarshalledRef_GenericMarshaller_Injected(ref arg2, expected);
			arg = CustomMarshallerGeneric<CustomMarshalledClass>.ConvertToManaged(arg2);
		}

		[NativeMethod("ParameterCustomMarshalledReturn")]
		[return: UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerGeneric<CustomMarshalledClass>))]
		public static CustomMarshalledClass ParameterCustomMarshalledReturn_GenericMarshaller(int value)
		{
			return CustomMarshallerGeneric<CustomMarshalledClass>.ConvertToManaged(ParameterCustomMarshalledReturn_GenericMarshaller_Injected(value));
		}

		[NativeMethod("ParameterCustomMarshalled")]
		[NativeThrows]
		public static void ParameterCustomMarshalled_DerivedType([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerGeneric<CustomMarshalledClass>))] CustomMarshalledDerivedClass arg, int expected)
		{
			ParameterCustomMarshalled_DerivedType_Injected(CustomMarshallerGeneric<CustomMarshalledClass>.ConvertToUnmanaged(arg), expected);
		}

		[NativeThrows]
		[NativeMethod("ParameterCustomMarshalled")]
		public static void ParameterCustomMarshalled_InterfaceMarshaller([UnityMarshalAs(NativeType.Custom, CustomMarshaller = typeof(CustomMarshallerInterface))] CustomMarshalledClass arg, int expected)
		{
			ParameterCustomMarshalled_InterfaceMarshaller_Injected(CustomMarshallerInterface.ConvertToUnmanaged(arg), expected);
		}

		[NativeThrows]
		[NativeMethod("BlittableStructTests::ParameterStructInt", true)]
		public static void ParameterCustomMarshalled_AsStruct(CustomMarshalledAsStruct arg)
		{
			StructInt arg2 = CustomMarshalledAsStruct.BindingsMarshaller.ConvertToUnmanaged(in arg);
			ParameterCustomMarshalled_AsStruct_Injected(ref arg2);
		}

		[NativeThrows]
		[NativeMethod("BlittableStructTests::ParameterStructIntIn", true)]
		public static void ParameterCustomMarshalled_AsStruct_In(in CustomMarshalledAsStruct arg)
		{
			ParameterCustomMarshalled_AsStruct_In_Injected(CustomMarshalledAsStruct.BindingsMarshaller.ConvertToUnmanaged(in arg));
		}

		[NativeThrows]
		[NativeMethod("BlittableStructTests::ParameterStructIntOut", true)]
		public static void ParameterCustomMarshalled_AsStruct_Out(out CustomMarshalledAsStruct arg)
		{
			CustomMarshalledAsStruct s = default(CustomMarshalledAsStruct);
			StructInt arg2 = CustomMarshalledAsStruct.BindingsMarshaller.ConvertToUnmanaged(in s);
			ParameterCustomMarshalled_AsStruct_Out_Injected(out arg2);
			arg = CustomMarshalledAsStruct.BindingsMarshaller.ConvertToManaged(in arg2);
		}

		[NativeMethod("BlittableStructTests::ParameterStructIntByRef", true)]
		[NativeThrows]
		public static void ParameterCustomMarshalled_AsStruct_Ref(ref CustomMarshalledAsStruct arg)
		{
			StructInt arg2 = CustomMarshalledAsStruct.BindingsMarshaller.ConvertToUnmanaged(in arg);
			ParameterCustomMarshalled_AsStruct_Ref_Injected(ref arg2);
			arg = CustomMarshalledAsStruct.BindingsMarshaller.ConvertToManaged(in arg2);
		}

		[NativeMethod("BlittableStructTests::ReturnStructInt", true)]
		public static CustomMarshalledAsStruct ParameterCustomMarshalled_AsStruct_Return()
		{
			CustomMarshalledAsStruct s = default(CustomMarshalledAsStruct);
			StructInt ret = CustomMarshalledAsStruct.BindingsMarshaller.ConvertToUnmanaged(in s);
			ParameterCustomMarshalled_AsStruct_Return_Injected(out ret);
			return CustomMarshalledAsStruct.BindingsMarshaller.ConvertToManaged(in ret);
		}

		[NativeMethod("BlittableStructTests::ParameterStructIntByRef", IsFreeFunction = true, ThrowsException = true)]
		public unsafe static void PassClassWithPinnableInnerData_PinnedRef(ClassWithPinnableInnerData c)
		{
			fixed (StructInt* ptr = &ClassWithPinnableInnerData.GetPinnableReference(c))
			{
				PassClassWithPinnableInnerData_PinnedRef_Injected(ref *ptr);
			}
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		[NativeMethod("BlittableStructTests::ParameterStructIntVector", IsFreeFunction = true, ThrowsException = true)]
		public static extern void PassClassWithPinnableInnerData_AsArray(ClassWithPinnableInnerData[] arr);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_Injected(int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledIn_Injected(in int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledOut_Injected(out int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledRef_Injected(ref int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern int ParameterCustomMarshalledReturn_Injected(int value);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_Attribute_Injected(int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledIn_Attribute_Injected(in int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledOut_Attribute_Injected(out int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledRef_Attribute_Injected(ref int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern int ParameterCustomMarshalledReturn_Attribute_Injected(int value);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_CustomMarshallerUsesInParameters_Injected(int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledIn_CustomMarshallerUsesInParameters_Injected(in int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledOut_CustomMarshallerUsesInParameters_Injected(out int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledRef_CustomMarshallerUsesInParameters_Injected(ref int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern int ParameterCustomMarshalledReturn_CustomMarshallerUsesInParameters_Injected(int value);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_Free_Injected(int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledIn_Free_Injected(in int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledOut_Free_Injected(out int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledRef_Free_Injected(ref int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern int ParameterCustomMarshalledReturn_Free_Injected(int value);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_NeedingMarshalling_Injected(ref ManagedSpanWrapper arg, ref ManagedSpanWrapper expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_NeedingMarshalling_In_Injected(in ManagedSpanWrapper arg, ref ManagedSpanWrapper expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_NeedingMarshalling_Out_Injected(out ManagedSpanWrapper arg, ref ManagedSpanWrapper expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_NeedingMarshalling_Ref_Injected(ref ManagedSpanWrapper arg, ref ManagedSpanWrapper expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_NeedingMarshalling_Return_Injected(ref ManagedSpanWrapper value, out ManagedSpanWrapper ret);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_GenericMarshaller_Injected(int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledIn_GenericMarshaller_Injected(in int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledOut_GenericMarshaller_Injected(out int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalledRef_GenericMarshaller_Injected(ref int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern int ParameterCustomMarshalledReturn_GenericMarshaller_Injected(int value);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_DerivedType_Injected(int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_InterfaceMarshaller_Injected(int arg, int expected);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_AsStruct_Injected(ref StructInt arg);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_AsStruct_In_Injected(in StructInt arg);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_AsStruct_Out_Injected(out StructInt arg);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_AsStruct_Ref_Injected(ref StructInt arg);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void ParameterCustomMarshalled_AsStruct_Return_Injected(out StructInt ret);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void PassClassWithPinnableInnerData_PinnedRef_Injected(ref StructInt c);
	}
}
