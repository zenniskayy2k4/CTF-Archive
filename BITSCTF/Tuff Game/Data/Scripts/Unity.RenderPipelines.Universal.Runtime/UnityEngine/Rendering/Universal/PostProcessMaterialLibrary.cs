namespace UnityEngine.Rendering.Universal
{
	internal class PostProcessMaterialLibrary
	{
		public readonly Material stopNaN;

		public readonly Material subpixelMorphologicalAntialiasing;

		public readonly Material gaussianDepthOfField;

		public readonly Material gaussianDepthOfFieldCoC;

		public readonly Material bokehDepthOfField;

		public readonly Material bokehDepthOfFieldCoC;

		public readonly Material temporalAntialiasing;

		public readonly Material motionBlur;

		public readonly Material paniniProjection;

		public readonly Material bloom;

		public readonly Material[] bloomUpsample;

		public readonly Material lensFlareScreenSpace;

		public readonly Material lensFlareDataDriven;

		public readonly Material uber;

		public readonly Material scalingSetup;

		public readonly Material easu;

		public readonly Material finalPass;

		internal PostProcessData m_Resources;

		public PostProcessData resources => m_Resources;

		public PostProcessMaterialLibrary(PostProcessData data)
		{
			stopNaN = Load(data.shaders.stopNanPS);
			subpixelMorphologicalAntialiasing = Load(data.shaders.subpixelMorphologicalAntialiasingPS);
			gaussianDepthOfField = Load(data.shaders.gaussianDepthOfFieldPS);
			gaussianDepthOfFieldCoC = Load(data.shaders.gaussianDepthOfFieldPS);
			bokehDepthOfField = Load(data.shaders.bokehDepthOfFieldPS);
			bokehDepthOfFieldCoC = Load(data.shaders.bokehDepthOfFieldPS);
			temporalAntialiasing = Load(data.shaders.temporalAntialiasingPS);
			motionBlur = Load(data.shaders.cameraMotionBlurPS);
			paniniProjection = Load(data.shaders.paniniProjectionPS);
			bloom = Load(data.shaders.bloomPS);
			lensFlareScreenSpace = Load(data.shaders.LensFlareScreenSpacePS);
			lensFlareDataDriven = Load(data.shaders.LensFlareDataDrivenPS);
			uber = Load(data.shaders.uberPostPS);
			scalingSetup = Load(data.shaders.scalingSetupPS);
			easu = Load(data.shaders.easuPS);
			finalPass = Load(data.shaders.finalPostPassPS);
			bloomUpsample = new Material[16];
			for (uint num = 0u; num < 16; num++)
			{
				bloomUpsample[num] = Load(data.shaders.bloomPS);
			}
			m_Resources = data;
		}

		private Material Load(Shader shader)
		{
			if (shader == null)
			{
				Debug.LogErrorFormat("Missing shader. PostProcessing render passes will not execute. Check for missing reference in the renderer resources.");
				return null;
			}
			if (!shader.isSupported)
			{
				return null;
			}
			return CoreUtils.CreateEngineMaterial(shader);
		}

		internal void Cleanup()
		{
			CoreUtils.Destroy(stopNaN);
			CoreUtils.Destroy(subpixelMorphologicalAntialiasing);
			CoreUtils.Destroy(gaussianDepthOfField);
			CoreUtils.Destroy(gaussianDepthOfFieldCoC);
			CoreUtils.Destroy(bokehDepthOfField);
			CoreUtils.Destroy(bokehDepthOfFieldCoC);
			CoreUtils.Destroy(temporalAntialiasing);
			CoreUtils.Destroy(motionBlur);
			CoreUtils.Destroy(paniniProjection);
			CoreUtils.Destroy(bloom);
			CoreUtils.Destroy(lensFlareScreenSpace);
			CoreUtils.Destroy(lensFlareDataDriven);
			CoreUtils.Destroy(scalingSetup);
			CoreUtils.Destroy(uber);
			CoreUtils.Destroy(easu);
			CoreUtils.Destroy(finalPass);
			for (uint num = 0u; num < 16; num++)
			{
				CoreUtils.Destroy(bloomUpsample[num]);
			}
		}
	}
}
