namespace UnityEngine.Rendering.Universal
{
	public enum BloomFilterMode
	{
		[Tooltip("Best quality.")]
		Gaussian = 0,
		[Tooltip("Balanced quality and speed.")]
		Dual = 1,
		[Tooltip("Lowest quality. Fastest at low resolutions. Saves memory.")]
		Kawase = 2
	}
}
