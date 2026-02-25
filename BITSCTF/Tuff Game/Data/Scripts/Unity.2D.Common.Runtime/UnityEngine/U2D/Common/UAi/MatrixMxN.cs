using System;
using System.Diagnostics;
using Unity.Collections;

namespace UnityEngine.U2D.Common.UAi
{
	[DebuggerDisplay("Length = {Length}")]
	[DebuggerTypeProxy(typeof(MatrixMxNDebugView<>))]
	internal struct MatrixMxN<T> : IDisposable where T : struct
	{
		internal NativeArray<T> m_Array;

		internal int m_Width;

		internal int m_Height;

		internal Allocator m_AllocLabel;

		internal NativeArrayOptions m_Options;

		private T this[int index]
		{
			get
			{
				return m_Array[index];
			}
			set
			{
				m_Array[index] = value;
			}
		}

		public bool IsCreated => m_Array.IsCreated;

		public int Length => m_Width * m_Height;

		public int DimensionX => m_Width;

		public int DimensionY => m_Height;

		public MatrixMxN(int width, int height, Allocator allocMode, NativeArrayOptions options)
		{
			m_Width = width;
			m_Height = height;
			m_Array = new NativeArray<T>(m_Width * m_Height, allocMode, options);
			m_AllocLabel = allocMode;
			m_Options = options;
		}

		public NativeArray<T> GetArray()
		{
			return m_Array;
		}

		public T Get(int x, int y)
		{
			return m_Array[x * m_Height + y];
		}

		public void Set(int x, int y, T v)
		{
			m_Array[x * m_Height + y] = v;
		}

		public void Dispose()
		{
			m_Array.Dispose();
			m_Width = 0;
			m_Height = 0;
		}

		public void CopyTo(T[] array)
		{
			m_Array.CopyTo(array);
		}
	}
}
