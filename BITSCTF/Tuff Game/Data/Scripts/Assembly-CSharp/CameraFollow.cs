using UnityEngine;

public class CameraFollow : MonoBehaviour
{
	public Transform target;

	[Header("Follow")]
	public float smoothSpeed = 5f;

	public float xOffset = 3f;

	[Header("Vertical Clamp")]
	public float minY = -2.5f;

	public float maxY = 2.5f;

	private float fixedZ;

	private void Start()
	{
		fixedZ = base.transform.position.z;
	}

	private void LateUpdate()
	{
		if (!(target == null))
		{
			float x = target.position.x + xOffset;
			float y = Mathf.Clamp(target.position.y, minY, maxY);
			Vector3 b = new Vector3(x, y, fixedZ);
			base.transform.position = Vector3.Lerp(base.transform.position, b, smoothSpeed * Time.deltaTime);
		}
	}
}
