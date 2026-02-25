namespace UnityEngine.AI
{
	public struct NavMeshDataInstance
	{
		public bool valid => id != 0 && NavMesh.IsValidNavMeshDataHandle(id);

		internal int id { get; set; }

		public Object owner
		{
			get
			{
				return NavMesh.InternalGetOwner(id);
			}
			set
			{
				int num = ((value != null) ? value.GetInstanceID() : 0);
				if (!NavMesh.InternalSetOwner(id, num))
				{
					Debug.LogError("Cannot set 'owner' on an invalid NavMeshDataInstance");
				}
			}
		}

		public void Remove()
		{
			NavMesh.RemoveNavMeshDataInternal(id);
		}
	}
}
