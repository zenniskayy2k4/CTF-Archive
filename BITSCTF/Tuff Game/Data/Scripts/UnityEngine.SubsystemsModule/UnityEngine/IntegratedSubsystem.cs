using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine
{
	[StructLayout(LayoutKind.Sequential)]
	[UsedByNativeCode]
	[NativeHeader("Modules/Subsystems/Subsystem.h")]
	public class IntegratedSubsystem : ISubsystem
	{
		internal static class BindingsMarshaller
		{
			public static IntPtr ConvertToNative(IntegratedSubsystem integratedSubsystem)
			{
				return integratedSubsystem.m_Ptr;
			}
		}

		[VisibleToOtherModules(new string[] { "UnityEngine.XRModule" })]
		internal IntPtr m_Ptr;

		internal ISubsystemDescriptor m_SubsystemDescriptor;

		public bool running => valid && IsRunning();

		internal bool valid => m_Ptr != IntPtr.Zero;

		internal void SetHandle([UnityMarshalAs(NativeType.ScriptingObjectPtr)] IntegratedSubsystem subsystem)
		{
			IntPtr intPtr = BindingsMarshaller.ConvertToNative(this);
			if (intPtr == (IntPtr)0)
			{
				ThrowHelper.ThrowNullReferenceException(this);
			}
			SetHandle_Injected(intPtr, subsystem);
		}

		public void Start()
		{
			IntPtr intPtr = BindingsMarshaller.ConvertToNative(this);
			if (intPtr == (IntPtr)0)
			{
				ThrowHelper.ThrowNullReferenceException(this);
			}
			Start_Injected(intPtr);
		}

		public void Stop()
		{
			IntPtr intPtr = BindingsMarshaller.ConvertToNative(this);
			if (intPtr == (IntPtr)0)
			{
				ThrowHelper.ThrowNullReferenceException(this);
			}
			Stop_Injected(intPtr);
		}

		public void Destroy()
		{
			IntPtr ptr = m_Ptr;
			SubsystemManager.RemoveIntegratedSubsystemByPtr(m_Ptr);
			SubsystemBindings.DestroySubsystem(ptr);
			m_Ptr = IntPtr.Zero;
		}

		internal bool IsRunning()
		{
			IntPtr intPtr = BindingsMarshaller.ConvertToNative(this);
			if (intPtr == (IntPtr)0)
			{
				ThrowHelper.ThrowNullReferenceException(this);
			}
			return IsRunning_Injected(intPtr);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void SetHandle_Injected(IntPtr _unity_self, IntegratedSubsystem subsystem);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void Start_Injected(IntPtr _unity_self);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void Stop_Injected(IntPtr _unity_self);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern bool IsRunning_Injected(IntPtr _unity_self);
	}
	[UsedByNativeCode("Subsystem_TSubsystemDescriptor")]
	public class IntegratedSubsystem<TSubsystemDescriptor> : IntegratedSubsystem where TSubsystemDescriptor : ISubsystemDescriptor
	{
		public TSubsystemDescriptor subsystemDescriptor => (TSubsystemDescriptor)m_SubsystemDescriptor;

		[Obsolete("The property 'SubsystemDescriptor' is deprecated. Use `subsystemDescriptor` instead. UnityUpgradeable -> subsystemDescriptor", false)]
		public TSubsystemDescriptor SubsystemDescriptor => subsystemDescriptor;
	}
}
