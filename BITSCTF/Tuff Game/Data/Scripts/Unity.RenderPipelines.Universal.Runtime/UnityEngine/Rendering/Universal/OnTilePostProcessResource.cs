using System;
using UnityEngine.Categorization;

namespace UnityEngine.Rendering.Universal
{
	[Serializable]
	[SupportedOnRenderPipeline(typeof(UniversalRenderPipelineAsset))]
	[CategoryInfo(Name = "R: On Tile Post Process Resources", Order = 1000)]
	[HideInInspector]
	internal class OnTilePostProcessResource : IRenderPipelineResources, IRenderPipelineGraphicsSettings
	{
		[SerializeField]
		[HideInInspector]
		private int m_Version;

		[SerializeField]
		[ResourcePath("Runtime/RendererFeatures/OnTileUberPost.shader", SearchType.ProjectPath)]
		private Shader m_UberPostShader;

		public int version => m_Version;

		bool IRenderPipelineGraphicsSettings.isAvailableInPlayerBuild => true;

		public Shader uberPostShader
		{
			get
			{
				return m_UberPostShader;
			}
			set
			{
				this.SetValueAndNotify(ref m_UberPostShader, value, "m_UberPostShader");
			}
		}
	}
}
