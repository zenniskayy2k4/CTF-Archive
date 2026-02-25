using System;
using UnityEngine.Categorization;

namespace UnityEngine.Rendering.Universal
{
	[Serializable]
	[SupportedOnRenderPipeline(typeof(UniversalRenderPipelineAsset))]
	[CategoryInfo(Name = "Render Graph", Order = 50)]
	[ElementInfo(Order = -10)]
	public class RenderGraphSettings : IRenderPipelineGraphicsSettings
	{
		internal enum Version
		{
			Initial = 0
		}

		[SerializeField]
		[HideInInspector]
		private Version m_Version;

		[SerializeField]
		[Tooltip("When enabled, URP does not use the Render Graph API to construct and execute the frame. Use this option only for compatibility purposes.")]
		[RecreatePipelineOnChange]
		private bool m_EnableRenderCompatibilityMode;

		public int version => (int)m_Version;

		bool IRenderPipelineGraphicsSettings.isAvailableInPlayerBuild => true;

		public bool enableRenderCompatibilityMode
		{
			get
			{
				return false;
			}
			[Obsolete("Compatibility Mode is being removed. This setter is not accessible without the define URP_COMPATIBILITY_MODE. #from(6000.3) #breakingFrom(6000.3)", true)]
			set
			{
			}
		}

		internal void SetCompatibilityModeFromUpgrade(bool value)
		{
			m_EnableRenderCompatibilityMode = value;
		}
	}
}
