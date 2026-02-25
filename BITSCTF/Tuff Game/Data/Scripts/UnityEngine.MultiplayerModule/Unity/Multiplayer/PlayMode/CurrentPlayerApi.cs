using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Unity.Multiplayer.PlayMode
{
	internal class CurrentPlayerApi
	{
		private List<string> m_Tags = new List<string>();

		public virtual bool IsMainEditor => false;

		protected void SetTags(IEnumerable<string> tags)
		{
			m_Tags.Clear();
			if (tags != null)
			{
				m_Tags.AddRange(tags);
			}
		}

		public virtual IReadOnlyList<string> ReadOnlyTags()
		{
			return m_Tags.AsReadOnly();
		}

		public virtual void ReportResult(bool condition, string message = "", [CallerFilePath] string callingFilePath = "", [CallerLineNumber] int lineNumber = 0)
		{
		}
	}
}
