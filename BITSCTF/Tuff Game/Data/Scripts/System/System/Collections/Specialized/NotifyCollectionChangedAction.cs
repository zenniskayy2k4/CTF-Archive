namespace System.Collections.Specialized
{
	/// <summary>Describes the action that caused a <see cref="E:System.Collections.Specialized.INotifyCollectionChanged.CollectionChanged" /> event.</summary>
	public enum NotifyCollectionChangedAction
	{
		/// <summary>An item was added to the collection.</summary>
		Add = 0,
		/// <summary>An item was removed from the collection.</summary>
		Remove = 1,
		/// <summary>An item was replaced in the collection.</summary>
		Replace = 2,
		/// <summary>An item was moved within the collection.</summary>
		Move = 3,
		/// <summary>The content of the collection was cleared.</summary>
		Reset = 4
	}
}
