using UnityEngine;

public class ShipMovement : MonoBehaviour
{
	[Header("Movement")]
	public float speed = 8f;

	public float forwardSpeed = 4f;

	[Header("Screen Clamp")]
	public float padding = 0.5f;

	private Camera cam;

	private void Start()
	{
		cam = Camera.main;
	}

	private void Update()
	{
		float axisRaw = Input.GetAxisRaw("Horizontal");
		float axisRaw2 = Input.GetAxisRaw("Vertical");
		Vector3 vector = new Vector3(axisRaw, axisRaw2, 0f) * speed;
		Vector3 vector2 = Vector3.right * forwardSpeed;
		base.transform.position += (vector + vector2) * Time.deltaTime;
		ClampToCamera();
	}

	private void ClampToCamera()
	{
		Vector3 vector = cam.ViewportToWorldPoint(new Vector3(0f, 0f, 0f));
		Vector3 vector2 = cam.ViewportToWorldPoint(new Vector3(1f, 1f, 0f));
		float min = vector.x + padding;
		float max = vector2.x - padding;
		float min2 = vector.y + padding;
		float max2 = vector2.y - padding;
		float x = Mathf.Clamp(base.transform.position.x, min, max);
		float y = Mathf.Clamp(base.transform.position.y, min2, max2);
		base.transform.position = new Vector3(x, y, 0f);
	}

	private void OnTriggerEnter2D(Collider2D other)
	{
		if (other.CompareTag("Enemy"))
		{
			Die();
		}
	}

	private void Die()
	{
		PlayerDeathManager.Instance?.HandlePlayerDeath();
	}
}
