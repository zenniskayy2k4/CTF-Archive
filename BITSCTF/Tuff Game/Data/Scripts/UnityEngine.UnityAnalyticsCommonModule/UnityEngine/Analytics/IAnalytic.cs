using System;
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using UnityEngine.Internal;

namespace UnityEngine.Analytics
{
	[ExcludeFromDocs]
	public interface IAnalytic
	{
		public interface IData
		{
		}

		public struct DataList<T> : IEnumerable, IData where T : struct
		{
			private readonly T[] m_UsageData;

			public DataList(T[] datas)
			{
				m_UsageData = datas;
			}

			public IEnumerator GetEnumerator()
			{
				return m_UsageData.GetEnumerator();
			}
		}

		bool TryGatherData(out IData data, [NotNullWhen(false)] out Exception error);
	}
}
