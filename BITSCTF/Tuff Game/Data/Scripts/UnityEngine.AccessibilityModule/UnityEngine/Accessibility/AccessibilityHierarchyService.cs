using System.Collections.Generic;

namespace UnityEngine.Accessibility
{
	internal static class AccessibilityHierarchyService
	{
		private static AccessibilityHierarchy s_ActiveHierarchy;

		internal static AccessibilityHierarchy activeHierarchy
		{
			get
			{
				return s_ActiveHierarchy;
			}
			set
			{
				if (s_ActiveHierarchy != value)
				{
					s_ActiveHierarchy?.FreeNative();
					s_ActiveHierarchy = value;
					s_ActiveHierarchy?.AllocateNative();
					AssistiveSupport.notificationDispatcher.SendScreenChanged();
				}
			}
		}

		internal static IReadOnlyList<AccessibilityNode> GetRootNodes()
		{
			return s_ActiveHierarchy?.rootNodes;
		}

		internal static bool TryGetNode(int id, out AccessibilityNode node)
		{
			node = null;
			return s_ActiveHierarchy?.TryGetNode(id, out node) ?? false;
		}

		internal static bool TryGetNodeAt(float x, float y, out AccessibilityNode node)
		{
			node = null;
			return s_ActiveHierarchy?.TryGetNodeAt(x, y, out node) ?? false;
		}
	}
}
