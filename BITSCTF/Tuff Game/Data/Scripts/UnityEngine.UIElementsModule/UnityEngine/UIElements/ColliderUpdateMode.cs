namespace UnityEngine.UIElements
{
	internal enum ColliderUpdateMode
	{
		[InspectorName("Match 3-D bounding box")]
		MatchBoundingBox = 0,
		[InspectorName("Keep existing colliders (if any)")]
		Keep = 1,
		[InspectorName("Match 2-D document rect")]
		MatchDocumentRect = 2
	}
}
