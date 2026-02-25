using System;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.Accessibility
{
	[NativeHeader("Modules/Accessibility/Native/AccessibilitySettings.h")]
	public static class AccessibilitySettings
	{
		public static float fontScale => GetFontScale();

		public static bool isBoldTextEnabled => IsBoldTextEnabled();

		public static bool isClosedCaptioningEnabled => IsClosedCaptioningEnabled();

		public static event Action<float> fontScaleChanged;

		public static event Action<bool> boldTextStatusChanged;

		public static event Action<bool> closedCaptioningStatusChanged;

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern float GetFontScale();

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern bool IsBoldTextEnabled();

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern bool IsClosedCaptioningEnabled();

		[RequiredByNativeCode]
		internal static void Internal_OnFontScaleChanged(float newFontScale)
		{
			AccessibilityManager.QueueNotification(new AccessibilityManager.NotificationContext
			{
				notification = AccessibilityManager.Notification.FontScaleChanged,
				fontScale = newFontScale
			});
		}

		[RequiredByNativeCode]
		internal static void Internal_OnBoldTextStatusChanged(bool enabled)
		{
			AccessibilityManager.QueueNotification(new AccessibilityManager.NotificationContext
			{
				notification = AccessibilityManager.Notification.BoldTextStatusChanged,
				isBoldTextEnabled = enabled
			});
		}

		[RequiredByNativeCode]
		internal static void Internal_OnClosedCaptioningStatusChanged(bool enabled)
		{
			AccessibilityManager.QueueNotification(new AccessibilityManager.NotificationContext
			{
				notification = AccessibilityManager.Notification.ClosedCaptioningStatusChanged,
				isClosedCaptioningEnabled = enabled
			});
		}

		internal static void InvokeFontScaleChanged(float newFontScale)
		{
			AccessibilitySettings.fontScaleChanged?.Invoke(newFontScale);
		}

		internal static void InvokeBoldTextStatusChanged(bool enabled)
		{
			AccessibilitySettings.boldTextStatusChanged?.Invoke(enabled);
		}

		internal static void InvokeClosedCaptionStatusChanged(bool enabled)
		{
			AccessibilitySettings.closedCaptioningStatusChanged?.Invoke(enabled);
		}
	}
}
