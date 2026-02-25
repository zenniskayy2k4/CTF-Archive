using System;
using System.Collections.Generic;
using UnityEngine.Bindings;

namespace UnityEngine.Accessibility
{
	public class AccessibilityHierarchy
	{
		private readonly IDictionary<int, AccessibilityNode> m_Nodes;

		private List<AccessibilityNode> m_RootNodes;

		private Stack<AccessibilityNode> m_FirstLowestCommonAncestorChain;

		private Stack<AccessibilityNode> m_SecondLowestCommonAncestorChain;

		internal static int nextUniqueNodeId;

		public IReadOnlyList<AccessibilityNode> rootNodes => m_RootNodes;

		private event Action<AccessibilityHierarchy> m_Changed;

		internal event Action<AccessibilityHierarchy> changed
		{
			[VisibleToOtherModules(new string[] { "UnityEditor.AccessibilityModule" })]
			add
			{
				m_Changed += value;
			}
			[VisibleToOtherModules(new string[] { "UnityEditor.AccessibilityModule" })]
			remove
			{
				m_Changed -= value;
			}
		}

		public AccessibilityHierarchy()
		{
			m_FirstLowestCommonAncestorChain = new Stack<AccessibilityNode>();
			m_SecondLowestCommonAncestorChain = new Stack<AccessibilityNode>();
			m_Nodes = new Dictionary<int, AccessibilityNode>();
			m_RootNodes = new List<AccessibilityNode>();
		}

		public bool ContainsNode(AccessibilityNode node)
		{
			return node != null && m_Nodes.ContainsKey(node.id) && m_Nodes[node.id] == node;
		}

		public bool TryGetNode(int id, out AccessibilityNode node)
		{
			return m_Nodes.TryGetValue(id, out node);
		}

		public bool TryGetNodeAt(float horizontalPosition, float verticalPosition, out AccessibilityNode node)
		{
			node = FindNodeContainingPoint(pos: new Vector2(horizontalPosition, verticalPosition), nodes: m_RootNodes);
			return node != null;
			static AccessibilityNode FindNodeContainingPoint(IList<AccessibilityNode> nodes, Vector2 pos)
			{
				for (int num = nodes.Count - 1; num >= 0; num--)
				{
					AccessibilityNode accessibilityNode = nodes[num];
					AccessibilityNode accessibilityNode2 = FindNodeContainingPoint(accessibilityNode.childList, pos);
					if (accessibilityNode2 != null)
					{
						return accessibilityNode2;
					}
					if (accessibilityNode.isActive && accessibilityNode.frame.Contains(pos))
					{
						return accessibilityNode;
					}
				}
				return null;
			}
		}

		public AccessibilityNode AddNode(string label = null, AccessibilityNode parent = null)
		{
			if (parent != null && !ContainsNode(parent))
			{
				Debug.LogError(string.Format("{0}: Attempting to add an AccessibilityNode under {1}, which is ", "AddNode", parent) + "not part of this hierarchy.");
				return null;
			}
			return CreateNodeAndSetParent(-1, label, parent);
		}

		public AccessibilityNode InsertNode(int childIndex, string label = null, AccessibilityNode parent = null)
		{
			if (parent != null && !ContainsNode(parent))
			{
				Debug.LogError(string.Format("{0}: Attempting to insert an AccessibilityNode under {1}, ", "InsertNode", parent) + "which is not part of this hierarchy.");
				return null;
			}
			return CreateNodeAndSetParent(childIndex, label, parent);
		}

		public bool MoveNode(AccessibilityNode node, AccessibilityNode newParent, int newChildIndex = -1)
		{
			if (node == null)
			{
				Debug.LogError("MoveNode: No node provided to move.");
				return false;
			}
			if (!ContainsNode(node))
			{
				Debug.LogError(string.Format("{0}: Attempting to move {1}, which is not part of this hierarchy.", "MoveNode", node));
				return false;
			}
			if (newParent != null && !ContainsNode(newParent))
			{
				Debug.LogError(string.Format("{0}: Attempting to move {1} under {2}, which is not part ", "MoveNode", node, newParent) + "of this hierarchy.");
				return false;
			}
			if (node == newParent)
			{
				Debug.LogError(string.Format("{0}: Attempting to move {1} under itself.", "MoveNode", node));
				return false;
			}
			if (node.parent == newParent)
			{
				List<AccessibilityNode> list = ((newParent == null) ? m_RootNodes : newParent.childList);
				int num = list.IndexOf(node);
				if (num == newChildIndex)
				{
					return false;
				}
				if ((newChildIndex < 0 || newChildIndex >= list.Count) && num == list.Count - 1)
				{
					return false;
				}
			}
			if (CheckForLoopsAndSetParent(node, newParent, newChildIndex))
			{
				NotifyHierarchyChanged();
				return true;
			}
			return false;
		}

		public void RemoveNode(AccessibilityNode node, bool removeChildren = true)
		{
			if (node == null)
			{
				Debug.LogError("RemoveNode: No node provided to remove.");
				return;
			}
			if (!ContainsNode(node))
			{
				Debug.LogError(string.Format("{0}: Attempting to remove {1}, which is not part of this ", "RemoveNode", node) + "hierarchy.");
				return;
			}
			if (removeChildren)
			{
				RemoveFromNodes(node);
			}
			else
			{
				m_Nodes.Remove(node.id);
			}
			if (m_RootNodes.Contains(node))
			{
				m_RootNodes.Remove(node);
				if (!removeChildren)
				{
					m_RootNodes.AddRange(node.children);
				}
			}
			node.Destroy(removeChildren);
			NotifyHierarchyChanged();
			void RemoveFromNodes(AccessibilityNode child)
			{
				m_Nodes.Remove(child.id);
				foreach (AccessibilityNode child in child.children)
				{
					RemoveFromNodes(child);
				}
			}
		}

		public void Clear()
		{
			for (int num = m_RootNodes.Count - 1; num >= 0; num--)
			{
				RemoveNode(m_RootNodes[num]);
			}
		}

		public void RefreshNodeFrames()
		{
			foreach (AccessibilityNode value in m_Nodes.Values)
			{
				value.frame = value.frameGetter?.Invoke() ?? Rect.zero;
			}
			if (AssistiveSupport.activeHierarchy == this)
			{
				AssistiveSupport.notificationDispatcher.SendLayoutChanged();
			}
		}

		public AccessibilityNode GetLowestCommonAncestor(AccessibilityNode firstNode, AccessibilityNode secondNode)
		{
			if (firstNode == null || secondNode == null)
			{
				return null;
			}
			if (firstNode.parent == null || secondNode.parent == null)
			{
				return null;
			}
			if (!ContainsNode(firstNode) || !ContainsNode(secondNode))
			{
				Debug.LogError("GetLowestCommonAncestor: Attempting to find the lowest common ancestor of " + $"{firstNode} and {secondNode}, which are not in the same hierarchy.");
				return null;
			}
			m_FirstLowestCommonAncestorChain.Clear();
			m_SecondLowestCommonAncestorChain.Clear();
			BuildNodeIdStack(firstNode, ref m_FirstLowestCommonAncestorChain);
			BuildNodeIdStack(secondNode, ref m_SecondLowestCommonAncestorChain);
			AccessibilityNode result = null;
			for (int num = Mathf.Min(m_FirstLowestCommonAncestorChain.Count, m_SecondLowestCommonAncestorChain.Count); num > 0; num--)
			{
				AccessibilityNode accessibilityNode = m_FirstLowestCommonAncestorChain.Pop();
				AccessibilityNode accessibilityNode2 = m_SecondLowestCommonAncestorChain.Pop();
				if (accessibilityNode != accessibilityNode2)
				{
					break;
				}
				result = accessibilityNode;
			}
			return result;
			void BuildNodeIdStack(AccessibilityNode node, ref Stack<AccessibilityNode> nodeStack)
			{
				while (node != null)
				{
					nodeStack.Push(node);
					node = m_Nodes[node.id].parent;
				}
			}
		}

		private AccessibilityNode CreateNode()
		{
			AccessibilityNode accessibilityNode = new AccessibilityNode(nextUniqueNodeId, this);
			if (accessibilityNode.id == int.MaxValue)
			{
				nextUniqueNodeId = 0;
			}
			else
			{
				nextUniqueNodeId = accessibilityNode.id + 1;
			}
			return accessibilityNode;
		}

		private AccessibilityNode CreateNodeAndSetParent(int childIndex, string label, AccessibilityNode parent)
		{
			AccessibilityNode accessibilityNode = CreateNode();
			m_Nodes[accessibilityNode.id] = accessibilityNode;
			if (label != null)
			{
				accessibilityNode.label = label;
			}
			SetParent(accessibilityNode, parent, null, (parent == null) ? m_RootNodes : parent.childList, childIndex);
			NotifyHierarchyChanged();
			return accessibilityNode;
		}

		private bool CheckForLoopsAndSetParent(AccessibilityNode node, AccessibilityNode parent, int index)
		{
			if (parent == null)
			{
				SetParent(node, null, node.parent?.childList ?? m_RootNodes, m_RootNodes, index);
				return true;
			}
			if (node.parent == parent)
			{
				SetParent(node, parent, parent.childList, parent.childList, index);
				return true;
			}
			if (node.parent == null && parent.parent == null)
			{
				SetParent(node, parent, m_RootNodes, parent.childList, index);
				return true;
			}
			for (AccessibilityNode parent2 = parent.parent; parent2 != null; parent2 = parent2.parent)
			{
				if (parent2 == node)
				{
					Debug.LogError(string.Format("{0}: Attempting to move {1} under {2}, which would ", "MoveNode", node, parent) + "create a loop in the hierarchy.");
					return false;
				}
			}
			SetParent(node, parent, node.parent?.childList ?? m_RootNodes, parent.childList, index);
			return true;
		}

		private void SetParent(AccessibilityNode node, AccessibilityNode parent, IList<AccessibilityNode> previousParentChildren, IList<AccessibilityNode> newParentChildren, int index)
		{
			previousParentChildren?.Remove(node);
			node.SetParent(parent, index);
			if (index < 0 || index >= newParentChildren.Count)
			{
				newParentChildren.Add(node);
			}
			else
			{
				newParentChildren.Insert(index, node);
			}
		}

		private void NotifyHierarchyChanged()
		{
			this.m_Changed?.Invoke(this);
		}

		internal void AllocateNative()
		{
			foreach (AccessibilityNode rootNode in m_RootNodes)
			{
				rootNode.AllocateNative();
			}
		}

		internal void FreeNative()
		{
			foreach (AccessibilityNode rootNode in m_RootNodes)
			{
				rootNode.FreeNative(freeChildren: true);
			}
		}
	}
}
