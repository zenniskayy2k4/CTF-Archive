namespace System.Data
{
	/// <summary>Determines the action that occurs when the <see cref="M:System.Data.DataSet.AcceptChanges" /> or <see cref="M:System.Data.DataTable.RejectChanges" /> method is invoked on a <see cref="T:System.Data.DataTable" /> with a <see cref="T:System.Data.ForeignKeyConstraint" />.</summary>
	public enum AcceptRejectRule
	{
		/// <summary>No action occurs (default).</summary>
		None = 0,
		/// <summary>Changes are cascaded across the relationship.</summary>
		Cascade = 1
	}
}
