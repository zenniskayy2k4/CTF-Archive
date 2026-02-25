using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;
using UnityEngine.Pool;
using UnityEngine.Scripting;

namespace UnityEngine.Accessibility
{
	[VisibleToOtherModules(new string[] { "UnityEditor.AccessibilityModule" })]
	[NativeHeader("Modules/Accessibility/Native/AccessibilityManager.h")]
	internal class AccessibilityManager
	{
		public enum Notification : byte
		{
			None = 0,
			ScreenReaderStatusChanged = 1,
			ElementFocused = 2,
			ElementUnfocused = 3,
			FontScaleChanged = 4,
			BoldTextStatusChanged = 5,
			ClosedCaptioningStatusChanged = 6
		}

		public struct NotificationContext
		{
			public AccessibilityNode focusedNode { get; set; }

			public float fontScale { get; set; }

			public bool isBoldTextEnabled { get; set; }

			public bool isClosedCaptioningEnabled { get; set; }

			public bool isScreenReaderEnabled { get; set; }

			public Notification notification { get; set; }
		}

		private class Nested
		{
			internal static readonly AccessibilityManager s_Instance;

			static Nested()
			{
				s_Instance = new AccessibilityManager();
			}
		}

		private sealed class ExclusiveLock : IDisposable
		{
			private bool m_Disposed;

			public ExclusiveLock()
			{
				Lock();
			}

			~ExclusiveLock()
			{
				InternalDispose();
			}

			private void InternalDispose()
			{
				if (!m_Disposed)
				{
					Unlock();
					m_Disposed = true;
				}
			}

			public void Dispose()
			{
				InternalDispose();
				GC.SuppressFinalize(this);
			}
		}

		internal static Queue<NotificationContext> asyncNotificationContexts = new Queue<NotificationContext>();

		private bool m_RefreshNodeFramesRequested;

		public static AccessibilityManager instance => Nested.s_Instance;

		public static bool isSupportedPlatform
		{
			get
			{
				RuntimePlatform platform = Application.platform;
				return platform == RuntimePlatform.Android || platform == RuntimePlatform.IPhonePlayer || platform == RuntimePlatform.OSXPlayer || platform == RuntimePlatform.WindowsPlayer;
			}
		}

		public static event Action<bool> screenReaderStatusChanged;

		public static event Action<AccessibilityNode> nodeFocusChanged;

		private AccessibilityManager()
		{
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern bool IsScreenReaderEnabled();

		internal unsafe static void SendAnnouncementNotification(string announcement)
		{
			//The blocks IL_0029 are reachable both inside and outside the pinned region starting at IL_0018. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			try
			{
				ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
				if (!StringMarshaller.TryMarshalEmptyOrNullString(announcement, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = announcement.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						SendAnnouncementNotification_Injected(ref managedSpanWrapper);
						return;
					}
				}
				SendAnnouncementNotification_Injected(ref managedSpanWrapper);
			}
			finally
			{
			}
		}

		internal unsafe static void SendPageScrolledNotification(string announcement, int nodeId = -1)
		{
			//The blocks IL_0029 are reachable both inside and outside the pinned region starting at IL_0018. ILSpy has duplicated these blocks in order to place them both within and outside the `fixed` statement.
			try
			{
				ManagedSpanWrapper managedSpanWrapper = default(ManagedSpanWrapper);
				if (!StringMarshaller.TryMarshalEmptyOrNullString(announcement, ref managedSpanWrapper))
				{
					ReadOnlySpan<char> readOnlySpan = announcement.AsSpan();
					fixed (char* begin = readOnlySpan)
					{
						managedSpanWrapper = new ManagedSpanWrapper(begin, readOnlySpan.Length);
						SendPageScrolledNotification_Injected(ref managedSpanWrapper, nodeId);
						return;
					}
				}
				SendPageScrolledNotification_Injected(ref managedSpanWrapper, nodeId);
			}
			finally
			{
			}
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern void SendScreenChangedNotification(int nodeId = -1);

		[MethodImpl(MethodImplOptions.InternalCall)]
		internal static extern void SendLayoutChangedNotification(int nodeId = -1);

		[ExcludeFromCodeCoverage]
		[VisibleToOtherModules(new string[] { "UnityEditor.AccessibilityModule" })]
		[RequiredByNativeCode]
		internal static void Internal_Initialize()
		{
			AssistiveSupport.Initialize();
		}

		[RequiredByNativeCode]
		internal static void Internal_Update()
		{
			instance.Internal_Update_Impl();
		}

		private void Internal_Update_Impl()
		{
			if (asyncNotificationContexts.Count == 0)
			{
				return;
			}
			NotificationContext[] array;
			lock (asyncNotificationContexts)
			{
				if (asyncNotificationContexts.Count == 0)
				{
					return;
				}
				array = asyncNotificationContexts.ToArray();
				asyncNotificationContexts.Clear();
			}
			using (GetExclusiveLock())
			{
				NotificationContext[] array2 = array;
				for (int i = 0; i < array2.Length; i++)
				{
					NotificationContext notificationContext = array2[i];
					switch (notificationContext.notification)
					{
					case Notification.ScreenReaderStatusChanged:
						AccessibilityManager.screenReaderStatusChanged?.Invoke(notificationContext.isScreenReaderEnabled);
						break;
					case Notification.ElementFocused:
						notificationContext.focusedNode.InvokeFocusChanged(isNodeFocused: true);
						AccessibilityManager.nodeFocusChanged?.Invoke(notificationContext.focusedNode);
						break;
					case Notification.ElementUnfocused:
						notificationContext.focusedNode.InvokeFocusChanged(isNodeFocused: false);
						break;
					case Notification.FontScaleChanged:
						AccessibilitySettings.InvokeFontScaleChanged(notificationContext.fontScale);
						break;
					case Notification.BoldTextStatusChanged:
						AccessibilitySettings.InvokeBoldTextStatusChanged(notificationContext.isBoldTextEnabled);
						break;
					case Notification.ClosedCaptioningStatusChanged:
						AccessibilitySettings.InvokeClosedCaptionStatusChanged(notificationContext.isClosedCaptioningEnabled);
						break;
					}
				}
			}
		}

		[RequiredByNativeCode]
		internal static void Internal_LateUpdate()
		{
			if (instance.m_RefreshNodeFramesRequested)
			{
				instance.m_RefreshNodeFramesRequested = false;
				AssistiveSupport.activeHierarchy?.RefreshNodeFrames();
			}
		}

		[RequiredByNativeCode]
		internal static int[] Internal_GetRootNodeIds()
		{
			IReadOnlyList<AccessibilityNode> rootNodes = AccessibilityHierarchyService.GetRootNodes();
			if (rootNodes == null || rootNodes.Count == 0)
			{
				return null;
			}
			List<int> value;
			using (CollectionPool<List<int>, int>.Get(out value))
			{
				foreach (AccessibilityNode item in rootNodes)
				{
					value.Add(item.id);
				}
				return (value.Count == 0) ? null : value.ToArray();
			}
		}

		[RequiredByNativeCode]
		internal static bool Internal_GetNode(int nodeId, ref AccessibilityNodeData nodeData)
		{
			if (!AccessibilityHierarchyService.TryGetNode(nodeId, out var node))
			{
				return false;
			}
			nodeData = new AccessibilityNodeData();
			node.GetNodeData(ref nodeData);
			return true;
		}

		[RequiredByNativeCode]
		internal static int Internal_GetNodeIdAt(float x, float y)
		{
			AccessibilityNode node;
			return AccessibilityHierarchyService.TryGetNodeAt(x, y, out node) ? node.id : (-1);
		}

		[RequiredByNativeCode]
		internal static bool Internal_GetFirstOrLastRootNodeId(bool first, out int managedRootId)
		{
			managedRootId = -1;
			IReadOnlyList<AccessibilityNode> rootNodes = AccessibilityHierarchyService.GetRootNodes();
			if (rootNodes == null)
			{
				return false;
			}
			if (rootNodes.Count != 0)
			{
				int id;
				if (!first)
				{
					id = rootNodes[rootNodes.Count - 1].id;
				}
				else
				{
					id = rootNodes[0].id;
				}
				managedRootId = id;
			}
			return true;
		}

		[RequiredByNativeCode]
		internal static bool Internal_GetFirstOrLastChildId(int nodeId, bool first, out int childId)
		{
			childId = -1;
			if (!AccessibilityHierarchyService.TryGetNode(nodeId, out var node))
			{
				return false;
			}
			if (node.children.Count != 0)
			{
				int id;
				if (!first)
				{
					IReadOnlyList<AccessibilityNode> children = node.children;
					id = children[children.Count - 1].id;
				}
				else
				{
					id = node.children[0].id;
				}
				childId = id;
			}
			return true;
		}

		[RequiredByNativeCode]
		internal static bool Internal_GetNextOrPreviousSiblingId(int nodeId, bool next, out int siblingId)
		{
			siblingId = -1;
			if (!AccessibilityHierarchyService.TryGetNode(nodeId, out var node))
			{
				return false;
			}
			IReadOnlyList<AccessibilityNode> readOnlyList = node.parent?.children ?? AccessibilityHierarchyService.GetRootNodes();
			if (readOnlyList == null || readOnlyList.Count == 0)
			{
				throw new ArgumentException((node.parent == null) ? $"Node with ID {nodeId} without parent is not tracked as a root." : $"Node with ID {nodeId} is not a child of its parent.");
			}
			if (readOnlyList.Count == 1)
			{
				return true;
			}
			int num = IndexOf<AccessibilityNode>(node, readOnlyList);
			int num2 = (next ? (num + 1) : (num - 1));
			siblingId = ((num2 >= 0 && num2 < readOnlyList.Count) ? readOnlyList[num2].id : (-1));
			return true;
			static int IndexOf<T>(T elementToFind, IReadOnlyList<T> list)
			{
				int num3 = 0;
				foreach (T item in list)
				{
					if (object.Equals(item, elementToFind))
					{
						return num3;
					}
					num3++;
				}
				return -1;
			}
		}

		[RequiredByNativeCode]
		internal static void Internal_OnScreenReaderStatusChanged(bool enabled)
		{
			QueueNotification(new NotificationContext
			{
				notification = Notification.ScreenReaderStatusChanged,
				isScreenReaderEnabled = enabled
			});
		}

		[RequiredByNativeCode]
		internal static void Internal_OnWindowGeometryChanged()
		{
			instance.m_RefreshNodeFramesRequested = true;
		}

		internal static void QueueNotification(NotificationContext notification)
		{
			instance.QueueNotification_Impl(notification);
		}

		internal void QueueNotification_Impl(NotificationContext notification)
		{
			lock (asyncNotificationContexts)
			{
				asyncNotificationContexts.Enqueue(notification);
			}
		}

		internal static IDisposable GetExclusiveLock()
		{
			return new ExclusiveLock();
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		[ThreadSafe]
		private static extern void Lock();

		[MethodImpl(MethodImplOptions.InternalCall)]
		[ThreadSafe]
		private static extern void Unlock();

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void SendAnnouncementNotification_Injected(ref ManagedSpanWrapper announcement);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void SendPageScrolledNotification_Injected(ref ManagedSpanWrapper announcement, int nodeId);
	}
}
