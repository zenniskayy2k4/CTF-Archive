using UnityEngine;

public class FreezeCamera : MonoBehaviour
{
	private Vector3 lockedPosition;

	private void Start()
	{
		lockedPosition = base.transform.position;
	}

	private void LateUpdate()
	{
		base.transform.position = lockedPosition;
	}
}
