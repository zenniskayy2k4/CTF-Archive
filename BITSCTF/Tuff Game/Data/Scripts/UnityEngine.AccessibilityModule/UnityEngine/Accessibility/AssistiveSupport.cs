using System;
using System.Diagnostics.CodeAnalysis;
using UnityEngine.Bindings;

namespace UnityEngine.Accessibility
{
	public static class AssistiveSupport
	{
		internal class NotificationDispatcher : IAccessibilityNotificationDispatcher
		{
			public void SendAnnouncement(string announcement)
			{
				AccessibilityManager.SendAnnouncementNotification(announcement);
			}

			public void SendPageScrolledAnnouncement(string announcement, AccessibilityNode nodeToFocus = null)
			{
				AccessibilityManager.SendPageScrolledNotification(announcement, nodeToFocus?.id ?? (-1));
			}

			public void SendScreenChanged(AccessibilityNode nodeToFocus = null)
			{
				AccessibilityManager.SendScreenChangedNotification(nodeToFocus?.id ?? (-1));
			}

			public void SendLayoutChanged(AccessibilityNode nodeToFocus = null)
			{
				AccessibilityManager.SendLayoutChangedNotification(nodeToFocus?.id ?? (-1));
			}
		}

		public enum ScreenReaderStatusOverride : byte
		{
			OSDriven = 0,
			ForceEnabled = 1,
			ForceDisabled = 2
		}

		private static ScreenReaderStatusOverride s_ScreenReaderStatusOverride;

		public static IAccessibilityNotificationDispatcher notificationDispatcher { get; } = new NotificationDispatcher();

		public static AccessibilityHierarchy activeHierarchy
		{
			get
			{
				return AccessibilityHierarchyService.activeHierarchy;
			}
			set
			{
				if (!Application.isEditor && !AccessibilityManager.isSupportedPlatform)
				{
					Debug.LogError(string.Format("{0} is not supported on {1}. ", "activeHierarchy", Application.platform) + "Please refer to the documentation for supported platforms.");
				}
				else if (isScreenReaderEnabled || Application.isEditor)
				{
					using (AccessibilityManager.GetExclusiveLock())
					{
						AccessibilityHierarchyService.activeHierarchy = value;
						AssistiveSupport.s_ActiveHierarchyChanged?.Invoke(value);
					}
				}
			}
		}

		public static bool isScreenReaderEnabled
		{
			get
			{
				ScreenReaderStatusOverride screenReaderStatusOverride = AssistiveSupport.screenReaderStatusOverride;
				if (1 == 0)
				{
				}
				bool result = screenReaderStatusOverride switch
				{
					ScreenReaderStatusOverride.ForceEnabled => true, 
					ScreenReaderStatusOverride.ForceDisabled => false, 
					_ => AccessibilityManager.IsScreenReaderEnabled(), 
				};
				if (1 == 0)
				{
				}
				return result;
			}
		}

		public static ScreenReaderStatusOverride screenReaderStatusOverride
		{
			get
			{
				return s_ScreenReaderStatusOverride;
			}
			set
			{
				if (s_ScreenReaderStatusOverride != value)
				{
					s_ScreenReaderStatusOverride = value;
					if (!isScreenReaderEnabled && !Application.isEditor)
					{
						AccessibilityHierarchyService.activeHierarchy = null;
					}
				}
			}
		}

		public static event Action<bool> screenReaderStatusChanged;

		private static event Action<AccessibilityHierarchy> s_ActiveHierarchyChanged;

		internal static event Action<AccessibilityHierarchy> activeHierarchyChanged
		{
			[VisibleToOtherModules(new string[] { "UnityEditor.AccessibilityModule" })]
			add
			{
				s_ActiveHierarchyChanged += value;
			}
			[VisibleToOtherModules(new string[] { "UnityEditor.AccessibilityModule" })]
			remove
			{
				s_ActiveHierarchyChanged -= value;
			}
		}

		public static event Action<AccessibilityNode> nodeFocusChanged;

		[ExcludeFromCodeCoverage]
		internal static void Initialize()
		{
			AccessibilityManager.screenReaderStatusChanged += ScreenReaderStatusChanged;
			AccessibilityManager.nodeFocusChanged += NodeFocusChanged;
		}

		internal static void ScreenReaderStatusChanged(bool enabled)
		{
			if (!isScreenReaderEnabled && !Application.isEditor)
			{
				AccessibilityHierarchyService.activeHierarchy = null;
			}
			AssistiveSupport.screenReaderStatusChanged?.Invoke(enabled);
		}

		private static void NodeFocusChanged(AccessibilityNode currentNode)
		{
			AssistiveSupport.nodeFocusChanged?.Invoke(currentNode);
		}
	}
}
