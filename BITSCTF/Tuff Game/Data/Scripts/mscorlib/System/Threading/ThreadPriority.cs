namespace System.Threading
{
	/// <summary>Specifies the scheduling priority of a <see cref="T:System.Threading.Thread" />.</summary>
	public enum ThreadPriority
	{
		/// <summary>The <see cref="T:System.Threading.Thread" /> can be scheduled after threads with any other priority.</summary>
		Lowest = 0,
		/// <summary>The <see cref="T:System.Threading.Thread" /> can be scheduled after threads with <see langword="Normal" /> priority and before those with <see langword="Lowest" /> priority.</summary>
		BelowNormal = 1,
		/// <summary>The <see cref="T:System.Threading.Thread" /> can be scheduled after threads with <see langword="AboveNormal" /> priority and before those with <see langword="BelowNormal" /> priority. Threads have <see langword="Normal" /> priority by default.</summary>
		Normal = 2,
		/// <summary>The <see cref="T:System.Threading.Thread" /> can be scheduled after threads with <see langword="Highest" /> priority and before those with <see langword="Normal" /> priority.</summary>
		AboveNormal = 3,
		/// <summary>The <see cref="T:System.Threading.Thread" /> can be scheduled before threads with any other priority.</summary>
		Highest = 4
	}
}
