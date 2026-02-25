using System;

namespace UnityEngine.AdaptivePerformance
{
	[Serializable]
	public class AdaptivePerformanceScalerProfile : AdaptivePerformanceScalerSettings
	{
		[SerializeField]
		[Tooltip("Name of the scaler profile.")]
		private string m_Name = "Default Scaler Profile";

		public string Name
		{
			get
			{
				return m_Name;
			}
			set
			{
				m_Name = value;
			}
		}
	}
}
