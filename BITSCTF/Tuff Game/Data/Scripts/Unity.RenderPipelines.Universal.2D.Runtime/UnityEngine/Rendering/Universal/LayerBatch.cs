using System.Collections.Generic;

namespace UnityEngine.Rendering.Universal
{
	internal struct LayerBatch
	{
		public int startLayerID;

		public int endLayerValue;

		public SortingLayerRange layerRange;

		public LightStats lightStats;

		public bool useNormals;

		public List<Light2D> lights;

		public List<int> shadowIndices;

		public List<ShadowCasterGroup2D> shadowCasters;

		internal int[] activeBlendStylesIndices;

		public void InitRTIds(int index)
		{
			lights = new List<Light2D>();
			shadowIndices = new List<int>();
			shadowCasters = new List<ShadowCasterGroup2D>();
		}
	}
}
