using UnityEngine.Rendering.Universal.Internal;

namespace UnityEngine.Rendering.Universal
{
	internal class TransparentSettingsPass : ScriptableRenderPass
	{
		private bool m_shouldReceiveShadows;

		public TransparentSettingsPass(RenderPassEvent evt, bool shadowReceiveSupported)
		{
			base.profilingSampler = new ProfilingSampler("Set Transparent Parameters");
			base.renderPassEvent = evt;
			m_shouldReceiveShadows = shadowReceiveSupported;
		}

		public bool Setup()
		{
			return !m_shouldReceiveShadows;
		}

		public static void ExecutePass(RasterCommandBuffer rasterCommandBuffer)
		{
			MainLightShadowCasterPass.SetShadowParamsForEmptyShadowmap(rasterCommandBuffer);
			AdditionalLightsShadowCasterPass.SetShadowParamsForEmptyShadowmap(rasterCommandBuffer);
		}
	}
}
