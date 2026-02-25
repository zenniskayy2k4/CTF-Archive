using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.Accessibility
{
	[NativeHeader("Modules/Accessibility/Native/AccessibilityNodeManager.h")]
	internal static class AccessibilityNodeManager
	{
		internal const int k_InvalidNodeId = -1;

		internal static bool CreateNativeNodeWithData(AccessibilityNodeData nodeData)
		{
			return CreateNativeNodeWithData_Injected(ref nodeData);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern void DestroyNativeNode(int nodeId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern void SetIsActive(int nodeId, bool isActive);

		internal unsafe static void SetLabel(int nodeId, string label)
		{
			//The blocks IL_002a are reachable both inside and outside the pinned region starting at IL_0019. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			try
			{
				ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
				if (!StringMarshaller.TryMarshalEmptyOrNullString(label, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = label.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						SetLabel_Injected(nodeId, ref managedSpanWrapper);
						return;
					}
				}
				SetLabel_Injected(nodeId, ref managedSpanWrapper);
			}
			finally
			{
			}
		}

		internal unsafe static void SetValue(int nodeId, string value)
		{
			//The blocks IL_002a are reachable both inside and outside the pinned region starting at IL_0019. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			try
			{
				ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
				if (!StringMarshaller.TryMarshalEmptyOrNullString(value, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = value.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						SetValue_Injected(nodeId, ref managedSpanWrapper);
						return;
					}
				}
				SetValue_Injected(nodeId, ref managedSpanWrapper);
			}
			finally
			{
			}
		}

		internal unsafe static void SetHint(int nodeId, string hint)
		{
			//The blocks IL_002a are reachable both inside and outside the pinned region starting at IL_0019. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			try
			{
				ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
				if (!StringMarshaller.TryMarshalEmptyOrNullString(hint, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = hint.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						SetHint_Injected(nodeId, ref managedSpanWrapper);
						return;
					}
				}
				SetHint_Injected(nodeId, ref managedSpanWrapper);
			}
			finally
			{
			}
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern void SetRole(int nodeId, AccessibilityRole role);

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern void SetAllowsDirectInteraction(int nodeId, bool allows);

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern void SetState(int nodeId, AccessibilityState state);

		internal static void SetFrame(int nodeId, Rect frame)
		{
			SetFrame_Injected(nodeId, ref frame);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern void SetParent(int nodeId, int parentId, int index = -1);

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern bool GetIsFocused(int nodeId);

		[RequiredByNativeCode]
		internal static void Internal_InvokeFocusChanged(int nodeId, bool isNodeFocused)
		{
			if (AccessibilityHierarchyService.TryGetNode(nodeId, out var node))
			{
				node.NotifyFocusChanged(isNodeFocused);
			}
		}

		[RequiredByNativeCode]
		internal static bool Internal_InvokeNodeInvoked(int nodeId)
		{
			AccessibilityNode node;
			return AccessibilityHierarchyService.TryGetNode(nodeId, out node) && node.InvokeNodeInvoked();
		}

		[RequiredByNativeCode]
		internal static bool Internal_InvokeIncremented(int nodeId)
		{
			AccessibilityNode node;
			return AccessibilityHierarchyService.TryGetNode(nodeId, out node) && node.InvokeIncremented();
		}

		[RequiredByNativeCode]
		internal static bool Internal_InvokeDecremented(int nodeId)
		{
			AccessibilityNode node;
			return AccessibilityHierarchyService.TryGetNode(nodeId, out node) && node.InvokeDecremented();
		}

		[RequiredByNativeCode]
		internal static bool Internal_InvokeScrolled(int nodeId, AccessibilityScrollDirection direction)
		{
			AccessibilityNode node;
			return AccessibilityHierarchyService.TryGetNode(nodeId, out node) && node.InvokeScrolled(direction);
		}

		[RequiredByNativeCode]
		internal static bool Internal_InvokeDismissed(int nodeId)
		{
			AccessibilityNode node;
			return AccessibilityHierarchyService.TryGetNode(nodeId, out node) && node.InvokeDismissed();
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern bool CreateNativeNodeWithData_Injected([In] ref AccessibilityNodeData nodeData);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void SetLabel_Injected(int nodeId, ref ManagedSpanWrapper label);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void SetValue_Injected(int nodeId, ref ManagedSpanWrapper value);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void SetHint_Injected(int nodeId, ref ManagedSpanWrapper hint);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void SetFrame_Injected(int nodeId, [In] ref Rect frame);
	}
}
