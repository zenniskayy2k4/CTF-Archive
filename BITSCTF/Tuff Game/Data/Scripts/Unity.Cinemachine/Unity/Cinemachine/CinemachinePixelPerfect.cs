using UnityEngine;
using UnityEngine.Rendering.Universal;

namespace Unity.Cinemachine
{
	[AddComponentMenu("Cinemachine/Procedural/Extensions/Cinemachine Pixel Perfect")]
	[ExecuteAlways]
	[DisallowMultipleComponent]
	[HelpURL("https://docs.unity3d.com/Packages/com.unity.cinemachine@3.1/manual/CinemachinePixelPerfect.html")]
	public class CinemachinePixelPerfect : CinemachineExtension
	{
		protected override void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime)
		{
			if (stage != CinemachineCore.Stage.Body)
			{
				return;
			}
			CinemachineBrain cinemachineBrain = CinemachineCore.FindPotentialTargetBrain(vcam);
			if (!(cinemachineBrain == null) && cinemachineBrain.IsLiveChild(vcam))
			{
				PixelPerfectCamera pixelPerfectCamera = GetPixelPerfectCamera(vcam, liveOnly: true);
				if (!(pixelPerfectCamera == null))
				{
					LensSettings lens = state.Lens;
					lens.OrthographicSize = pixelPerfectCamera.CorrectCinemachineOrthoSize(lens.OrthographicSize);
					state.Lens = lens;
				}
			}
		}

		private PixelPerfectCamera GetPixelPerfectCamera(CinemachineVirtualCameraBase vcam, bool liveOnly)
		{
			CinemachineBrain cinemachineBrain = CinemachineCore.FindPotentialTargetBrain(vcam);
			if (cinemachineBrain == null || (liveOnly && !cinemachineBrain.IsLiveChild(vcam)))
			{
				return null;
			}
			Camera outputCamera = cinemachineBrain.OutputCamera;
			if (outputCamera == null || !outputCamera.TryGetComponent<PixelPerfectCamera>(out var component) || !component.isActiveAndEnabled)
			{
				return null;
			}
			return component;
		}

		internal bool HasValidPixelPerfectCamera()
		{
			if (TryGetComponent<CinemachineVirtualCameraBase>(out var component))
			{
				return GetPixelPerfectCamera(component, liveOnly: false) != null;
			}
			return false;
		}
	}
}
