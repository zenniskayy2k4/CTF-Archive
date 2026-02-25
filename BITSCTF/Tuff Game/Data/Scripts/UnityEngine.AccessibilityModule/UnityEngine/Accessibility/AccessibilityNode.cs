using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace UnityEngine.Accessibility
{
	public class AccessibilityNode
	{
		private AccessibilityHierarchy m_Hierarchy;

		internal List<AccessibilityNode> childList = new List<AccessibilityNode>();

		private string m_Label;

		private string m_Value;

		private string m_Hint;

		private Rect m_Frame;

		private Func<Rect> m_FrameGetter;

		private AccessibilityRole m_Role;

		private AccessibilityState m_State;

		private bool m_IsActive = true;

		private bool m_AllowsDirectInteraction;

		public IReadOnlyList<AccessibilityNode> children => childList;

		public AccessibilityNode parent { get; private set; }

		public string label
		{
			get
			{
				return m_Label;
			}
			set
			{
				if (!string.Equals(m_Label, value))
				{
					m_Label = value;
					if (IsInActiveHierarchy())
					{
						AccessibilityNodeManager.SetLabel(id, value);
					}
				}
			}
		}

		public string value
		{
			get
			{
				return m_Value;
			}
			set
			{
				if (!string.Equals(m_Value, value))
				{
					m_Value = value;
					if (IsInActiveHierarchy())
					{
						AccessibilityNodeManager.SetValue(id, value);
					}
				}
			}
		}

		public string hint
		{
			get
			{
				return m_Hint;
			}
			set
			{
				if (!string.Equals(m_Hint, value))
				{
					m_Hint = value;
					if (IsInActiveHierarchy())
					{
						AccessibilityNodeManager.SetHint(id, value);
					}
				}
			}
		}

		public Rect frame
		{
			get
			{
				return (m_Frame == default(Rect)) ? (m_Frame = frameGetter?.Invoke() ?? Rect.zero) : m_Frame;
			}
			set
			{
				m_Frame = value;
				if (IsInActiveHierarchy())
				{
					AccessibilityNodeManager.SetFrame(id, value);
				}
			}
		}

		public Func<Rect> frameGetter
		{
			get
			{
				return m_FrameGetter;
			}
			set
			{
				m_FrameGetter = value;
				if (IsInActiveHierarchy())
				{
					AccessibilityNodeManager.SetFrame(id, frame);
				}
			}
		}

		public int id { get; private set; }

		public AccessibilityRole role
		{
			get
			{
				return m_Role;
			}
			set
			{
				if (m_Role != value)
				{
					m_Role = value;
					if (IsInActiveHierarchy())
					{
						AccessibilityNodeManager.SetRole(id, value);
					}
				}
			}
		}

		public AccessibilityState state
		{
			get
			{
				return m_State;
			}
			set
			{
				if (m_State != value)
				{
					m_State = value;
					if (IsInActiveHierarchy())
					{
						AccessibilityNodeManager.SetState(id, value);
					}
				}
			}
		}

		public bool isActive
		{
			get
			{
				return m_IsActive;
			}
			set
			{
				if (m_IsActive != value)
				{
					m_IsActive = value;
					if (IsInActiveHierarchy())
					{
						AccessibilityNodeManager.SetIsActive(id, value);
					}
				}
			}
		}

		public bool isFocused => IsInActiveHierarchy() && AccessibilityNodeManager.GetIsFocused(id);

		public bool allowsDirectInteraction
		{
			get
			{
				return m_AllowsDirectInteraction;
			}
			set
			{
				if (m_AllowsDirectInteraction != value)
				{
					m_AllowsDirectInteraction = value;
					if (IsInActiveHierarchy())
					{
						AccessibilityNodeManager.SetAllowsDirectInteraction(id, value);
					}
				}
			}
		}

		public event Action<AccessibilityNode, bool> focusChanged;

		public event Func<bool> invoked;

		public event Action incremented;

		public event Action decremented;

		public event Func<AccessibilityScrollDirection, bool> scrolled;

		public event Func<bool> dismissed;

		[Obsolete("AccessibilityNode.selected has been renamed to AccessibilityNode.invoked to avoid confusion with AccessibilityState.Selected. (UnityUpgradable) -> invoked", false)]
		public event Func<bool> selected
		{
			[ExcludeFromCodeCoverage]
			add
			{
				invoked += value;
			}
			[ExcludeFromCodeCoverage]
			remove
			{
				invoked -= value;
			}
		}

		internal AccessibilityNode(int nodeId, AccessibilityHierarchy hierarchy)
		{
			id = nodeId;
			m_Hierarchy = hierarchy;
			if (IsInActiveHierarchy())
			{
				AccessibilityNodeData nodeData = new AccessibilityNodeData
				{
					nodeId = nodeId
				};
				CreateNativeNodeWithData(ref nodeData);
			}
		}

		private void CreateNativeNodeWithData(ref AccessibilityNodeData nodeData)
		{
			if (AccessibilityManager.isSupportedPlatform)
			{
				while (!AccessibilityNodeManager.CreateNativeNodeWithData(nodeData))
				{
					Debug.LogWarning(string.Format("{0}: Node ID '{1}' is already ", "CreateNativeNodeWithData", nodeData.nodeId) + "used. Trying to create a node with an incremented node ID.");
					if (nodeData.nodeId == int.MaxValue)
					{
						nodeData.nodeId = 0;
					}
					else
					{
						nodeData.nodeId++;
					}
				}
			}
			id = nodeData.nodeId;
		}

		internal void GetNodeData(ref AccessibilityNodeData nodeData)
		{
			int[] array = new int[children.Count];
			for (int i = 0; i < children.Count; i++)
			{
				array[i] = children[i].id;
			}
			nodeData.childIds = array;
			nodeData.label = label;
			nodeData.value = value;
			nodeData.hint = hint;
			nodeData.frame = frame;
			nodeData.nodeId = id;
			nodeData.parentId = parent?.id ?? (-1);
			nodeData.role = role;
			nodeData.state = state;
			nodeData.isActive = isActive;
			nodeData.allowsDirectInteraction = allowsDirectInteraction;
			nodeData.implementsInvoked = this.invoked != null;
			nodeData.implementsScrolled = this.scrolled != null;
			nodeData.implementsDismissed = this.dismissed != null;
		}

		internal void AllocateNative()
		{
			if (!IsInActiveHierarchy())
			{
				return;
			}
			AccessibilityNodeData accessibilityNodeData = new AccessibilityNodeData();
			accessibilityNodeData.label = label;
			accessibilityNodeData.value = value;
			accessibilityNodeData.hint = hint;
			accessibilityNodeData.frame = frame;
			accessibilityNodeData.nodeId = id;
			accessibilityNodeData.parentId = parent?.id ?? (-1);
			accessibilityNodeData.role = role;
			accessibilityNodeData.state = state;
			accessibilityNodeData.isActive = isActive;
			accessibilityNodeData.allowsDirectInteraction = allowsDirectInteraction;
			accessibilityNodeData.implementsInvoked = this.invoked != null;
			accessibilityNodeData.implementsScrolled = this.scrolled != null;
			accessibilityNodeData.implementsDismissed = this.dismissed != null;
			AccessibilityNodeData nodeData = accessibilityNodeData;
			CreateNativeNodeWithData(ref nodeData);
			foreach (AccessibilityNode child in children)
			{
				child.AllocateNative();
			}
		}

		internal void FreeNative(bool freeChildren)
		{
			if (freeChildren)
			{
				foreach (AccessibilityNode child in children)
				{
					child.FreeNative(freeChildren: true);
				}
			}
			if (IsInActiveHierarchy())
			{
				AccessibilityNodeManager.DestroyNativeNode(id);
			}
		}

		internal void Destroy(bool destroyChildren)
		{
			FreeNative(destroyChildren);
			parent?.childList.Remove(this);
			if (destroyChildren)
			{
				for (int num = childList.Count - 1; num >= 0; num--)
				{
					childList[num].Destroy(destroyChildren: true);
				}
			}
			else
			{
				foreach (AccessibilityNode child in childList)
				{
					child.SetParent(parent);
					parent?.childList.Add(child);
				}
			}
			childList.Clear();
			m_Hierarchy = null;
		}

		private bool IsInActiveHierarchy()
		{
			return m_Hierarchy != null && AssistiveSupport.activeHierarchy == m_Hierarchy;
		}

		internal void SetParent(AccessibilityNode nodeParent, int index = -1)
		{
			parent = nodeParent;
			if (IsInActiveHierarchy())
			{
				int parentId = nodeParent?.id ?? (-1);
				AccessibilityNodeManager.SetParent(id, parentId, index);
			}
		}

		public override int GetHashCode()
		{
			return id;
		}

		public override string ToString()
		{
			return $"AccessibilityNode(ID: {id}, Label: \"{label}\")";
		}

		internal void NotifyFocusChanged(bool isNodeFocused)
		{
			AccessibilityManager.QueueNotification(new AccessibilityManager.NotificationContext
			{
				notification = (isNodeFocused ? AccessibilityManager.Notification.ElementFocused : AccessibilityManager.Notification.ElementUnfocused),
				focusedNode = this
			});
		}

		internal void InvokeFocusChanged(bool isNodeFocused)
		{
			this.focusChanged?.Invoke(this, isNodeFocused);
		}

		internal bool InvokeNodeInvoked()
		{
			return this.invoked?.Invoke() ?? false;
		}

		internal bool InvokeIncremented()
		{
			if (this.incremented == null)
			{
				return false;
			}
			this.incremented();
			return true;
		}

		internal bool InvokeDecremented()
		{
			if (this.decremented == null)
			{
				return false;
			}
			this.decremented?.Invoke();
			return true;
		}

		internal bool InvokeScrolled(AccessibilityScrollDirection direction)
		{
			return this.scrolled?.Invoke(direction) ?? false;
		}

		internal bool InvokeDismissed()
		{
			return this.dismissed?.Invoke() ?? false;
		}
	}
}
