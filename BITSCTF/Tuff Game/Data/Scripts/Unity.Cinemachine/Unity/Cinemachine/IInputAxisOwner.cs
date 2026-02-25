using System.Collections.Generic;

namespace Unity.Cinemachine
{
	public interface IInputAxisOwner
	{
		public struct AxisDescriptor
		{
			public delegate ref InputAxis AxisGetter();

			public enum Hints
			{
				Default = 0,
				X = 1,
				Y = 2
			}

			public AxisGetter DrivenAxis;

			public string Name;

			public Hints Hint;
		}

		void GetInputAxes(List<AxisDescriptor> axes);
	}
}
